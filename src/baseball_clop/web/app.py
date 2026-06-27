"""ローカルWeb UI(映像パス設定 + ROI調整画面)。

`baseball-clop ui` で起動する。127.0.0.1限定のFlaskサーバーで動作し、外部への
通信は行わない。状態はプロセス内のシングルトン(AppState)に保持するだけの
シングルユーザー想定の簡易実装。
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

import cv2
from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from .. import audio_sync, pipeline, roi_store
from ..config import MainCameraROIs, PipelineConfig
from ..scoring import count_state, timeline_io
from ..scoring.models import GameTimeline, InPlayInfo, PitchCall, PitchOutcome, PlayResult, Runners
from ..video_io import iter_frames


@dataclass
class DetectStatus:
    state: str = "idle"  # idle | running | done | error
    message: str = ""
    timeline_path: str = ""
    pitch_count: int = 0
    pickoff_count: int = 0


@dataclass
class AppState:
    main_path: str = ""
    wide_path: str = ""
    out_dir: str = ""
    wide_offset_sec: float = 0.0
    rois: MainCameraROIs = field(default_factory=MainCameraROIs)
    detect: DetectStatus = field(default_factory=DetectStatus)
    timeline: GameTimeline | None = None


def _last_setup_path() -> Path:
    """直前に使用したmain/wide/out_dirを記憶しておくファイル。

    サーバープロセスを再起動するたびにセットアップ画面の入力をやり直す手間を
    省くためのもので、AppState自体(検証済みの状態)とは別に持つ。
    テストからはBASEBALL_CLOP_CONFIG_DIR環境変数で保存先を上書きできる。
    """
    base = os.environ.get("BASEBALL_CLOP_CONFIG_DIR")
    if base:
        return Path(base) / "last_setup.json"
    return Path.home() / ".baseball_clop" / "last_setup.json"


def _load_last_setup() -> dict:
    path = _last_setup_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_last_setup(main_path: str, wide_path: str, out_dir: str, wide_offset_sec: float) -> None:
    path = _last_setup_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(
        json.dumps(
            {
                "main_path": main_path,
                "wide_path": wide_path,
                "out_dir": out_dir,
                "wide_offset_sec": wide_offset_sec,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


def _rois_path(out_dir: str) -> Path:
    return Path(out_dir) / "rois.json"


def _timeline_path(out_dir: str) -> Path:
    return Path(out_dir) / "events" / "game.json"


def _sorted_pitches(timeline: GameTimeline) -> list:
    return sorted(timeline.pitches, key=lambda p: p.clip_start_sec)


def _pitch_summary(p) -> dict:
    return {
        "id": p.id,
        "inning": p.inning,
        "half": p.half,
        "clip_start_sec": p.clip_start_sec,
        "clip_end_sec": p.clip_end_sec,
        "outcome": p.outcome.value,
        "pitch_call": p.pitch_call.value,
        "needs_review": p.needs_review,
        "count_after": p.count_after.to_dict(),
        "runners_after": p.runners_after.to_dict(),
    }


def create_app() -> Flask:
    app = Flask(__name__)
    state = AppState()
    detect_lock = threading.Lock()

    def _load_timeline_if_needed() -> GameTimeline | None:
        if state.timeline is None and state.out_dir:
            path = _timeline_path(state.out_dir)
            if path.exists():
                state.timeline = timeline_io.load_json(path)
        return state.timeline

    @app.get("/")
    def setup_page():
        # state.*はサーバー再起動でリセットされるため、再起動直後でも前回入力した
        # パスをフォームに復元できるよう、検証前の値として最後に保存した設定を補完する
        # (state.*が既にあればそちらを優先し、このプロセス内で入力済みの値は上書きしない)。
        last = _load_last_setup()
        return render_template(
            "setup.html",
            main_path=state.main_path or last.get("main_path", ""),
            wide_path=state.wide_path or last.get("wide_path", ""),
            out_dir=state.out_dir or last.get("out_dir", ""),
            wide_offset_sec=state.wide_offset_sec or last.get("wide_offset_sec", 0.0),
        )

    @app.post("/api/setup")
    def api_setup():
        data = request.get_json(force=True) or {}
        main_path = (data.get("main_path") or "").strip()
        wide_path = (data.get("wide_path") or "").strip()
        out_dir = (data.get("out_dir") or "").strip()

        if not main_path or not Path(main_path).exists():
            return jsonify({"error": f"メイン映像が見つかりません: {main_path}"}), 400
        if wide_path and not Path(wide_path).exists():
            return jsonify({"error": f"ワイド映像が見つかりません: {wide_path}"}), 400
        if not out_dir:
            return jsonify({"error": "出力先ディレクトリを指定してください"}), 400

        try:
            wide_offset_sec = float(data.get("wide_offset_sec") or 0.0)
        except (TypeError, ValueError):
            return jsonify({"error": "ワイドの時刻オフセットは数値で指定してください"}), 400

        state.main_path = main_path
        state.wide_path = wide_path
        state.out_dir = out_dir
        state.wide_offset_sec = wide_offset_sec

        loaded = roi_store.load(_rois_path(out_dir))
        state.rois = loaded if loaded is not None else MainCameraROIs()

        _save_last_setup(main_path, wide_path, out_dir, wide_offset_sec)

        # 既に検出済み(events/game.json がある)プロジェクトを読み込んだ場合は、
        # 毎回ROI調整画面を経由させずレビュー画面へ直接進めるようにする。
        has_timeline = _timeline_path(out_dir).exists()
        return jsonify({"ok": True, "has_timeline": has_timeline})

    @app.post("/api/sync-audio")
    def api_sync_audio():
        data = request.get_json(force=True) or {}
        main_path = (data.get("main_path") or "").strip()
        wide_path = (data.get("wide_path") or "").strip()

        if not main_path or not Path(main_path).exists():
            return jsonify({"error": f"メイン映像が見つかりません: {main_path}"}), 400
        if not wide_path or not Path(wide_path).exists():
            return jsonify({"error": f"ワイド映像が見つかりません: {wide_path}"}), 400

        try:
            max_offset_sec = float(data.get("max_offset_sec") or 20.0)
        except (TypeError, ValueError):
            return jsonify({"error": "探索範囲は数値で指定してください"}), 400
        if max_offset_sec <= 0:
            return jsonify({"error": "探索範囲は0より大きい値で指定してください"}), 400

        # 比較対象の音声がmax_offset_sec分のラグでも実際に重なるよう、抽出区間を
        # 探索範囲より十分長く取る(重なりが無いと相互相関が意味を持たない)。
        duration_sec = max_offset_sec + 30.0

        try:
            result = audio_sync.estimate_offset(main_path, wide_path, duration_sec=duration_sec, max_offset_sec=max_offset_sec)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except subprocess.CalledProcessError:
            return jsonify({"error": "音声の抽出に失敗しました(ffmpegエラー)"}), 500

        return jsonify({"offset_sec": result.offset_sec, "confidence": result.confidence})

    @app.post("/api/preview-paths")
    def api_preview_paths():
        """セットアップ画面のプレビュー再生用に、/api/setupより前にmain/wideのパスだけを反映する。"""
        data = request.get_json(force=True) or {}
        main_path = (data.get("main_path") or "").strip()
        wide_path = (data.get("wide_path") or "").strip()

        if not main_path or not Path(main_path).exists():
            return jsonify({"error": f"メイン映像が見つかりません: {main_path}"}), 400
        if not wide_path or not Path(wide_path).exists():
            return jsonify({"error": f"ワイド映像が見つかりません: {wide_path}"}), 400

        state.main_path = main_path
        state.wide_path = wide_path
        return jsonify({"ok": True})

    @app.get("/roi")
    def roi_page():
        if not state.main_path:
            return redirect(url_for("setup_page"))
        return render_template("roi.html", rois=state.rois.to_dict())

    @app.get("/api/frame.png")
    def api_frame():
        if not state.main_path:
            return jsonify({"error": "映像が設定されていません"}), 400
        try:
            t_sec = float(request.args.get("t_sec", 5.0))
        except ValueError:
            return jsonify({"error": "t_secは数値で指定してください"}), 400

        for _, frame in iter_frames(state.main_path, start_sec=t_sec):
            ok, buf = cv2.imencode(".png", frame)
            if not ok:
                return jsonify({"error": "フレームのエンコードに失敗しました"}), 500
            return send_file(io.BytesIO(buf.tobytes()), mimetype="image/png")
        return jsonify({"error": f"指定時刻 {t_sec}s のフレームを取得できませんでした"}), 404

    @app.get("/api/rois")
    def api_get_rois():
        return jsonify(state.rois.to_dict())

    @app.post("/api/rois")
    def api_save_rois():
        data = request.get_json(force=True) or {}
        try:
            state.rois = MainCameraROIs.from_dict(data)
        except KeyError as e:
            return jsonify({"error": f"枠の値が不足しています: {e}"}), 400
        roi_store.save(state.rois, _rois_path(state.out_dir))
        return jsonify({"ok": True})

    @app.post("/api/detect")
    def api_run_detect():
        if not state.main_path:
            return jsonify({"error": "メイン映像が設定されていません"}), 400
        if not state.wide_path:
            return jsonify({"error": "ワイド映像が設定されていません(検出にはワイド映像が必要です)"}), 400
        if not state.out_dir:
            return jsonify({"error": "出力先ディレクトリが設定されていません"}), 400

        if not detect_lock.acquire(blocking=False):
            return jsonify({"error": "既に検出処理を実行中です"}), 409

        state.detect = DetectStatus(state="running", message="検出処理を実行中です…(映像の長さによって数分かかります)")
        main_path, wide_path, out_dir = state.main_path, state.wide_path, state.out_dir
        wide_offset_sec, rois = state.wide_offset_sec, state.rois

        def _run() -> None:
            try:
                config = PipelineConfig()
                config.detection.main_rois = rois
                timeline = pipeline.detect(main_path, wide_path, config=config, wide_offset_sec=wide_offset_sec)
                timeline_path = str(_timeline_path(out_dir))
                timeline_io.save_json(timeline, timeline_path)
                state.timeline = None  # game.jsonが上書きされたため、メモリ上の古いタイムラインは破棄する
                state.detect = DetectStatus(
                    state="done",
                    message="検出が完了しました。あくまで暫定結果なので必ず確認してください。",
                    timeline_path=timeline_path,
                    pitch_count=len(timeline.pitches),
                    pickoff_count=len(timeline.pickoffs),
                )
            except Exception as e:
                state.detect = DetectStatus(state="error", message=str(e))
            finally:
                detect_lock.release()

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"ok": True})

    @app.get("/api/detect-status")
    def api_detect_status():
        d = state.detect
        return jsonify(
            {
                "state": d.state,
                "message": d.message,
                "timeline_path": d.timeline_path,
                "pitch_count": d.pitch_count,
                "pickoff_count": d.pickoff_count,
            }
        )

    @app.get("/review")
    def review_page():
        if not state.out_dir or not state.main_path:
            return redirect(url_for("setup_page"))
        timeline = _load_timeline_if_needed()
        if timeline is None:
            return redirect(url_for("roi_page"))
        pitches = [_pitch_summary(p) for p in _sorted_pitches(timeline)]
        return render_template("review.html", pitches=pitches)

    @app.get("/api/pitches")
    def api_list_pitches():
        timeline = _load_timeline_if_needed()
        if timeline is None:
            return jsonify({"error": "タイムラインがまだありません(検出を実行してください)"}), 400
        return jsonify([_pitch_summary(p) for p in _sorted_pitches(timeline)])

    @app.get("/api/pitches/<pitch_id>")
    def api_get_pitch(pitch_id):
        timeline = _load_timeline_if_needed()
        if timeline is None:
            return jsonify({"error": "タイムラインがまだありません(検出を実行してください)"}), 400
        for p in timeline.pitches:
            if p.id == pitch_id:
                return jsonify(p.to_dict())
        return jsonify({"error": f"投球が見つかりません: {pitch_id}"}), 404

    @app.post("/api/pitches/<pitch_id>")
    def api_update_pitch(pitch_id):
        timeline = _load_timeline_if_needed()
        if timeline is None:
            return jsonify({"error": "タイムラインがまだありません(検出を実行してください)"}), 400

        pitch = next((p for p in timeline.pitches if p.id == pitch_id), None)
        if pitch is None:
            return jsonify({"error": f"投球が見つかりません: {pitch_id}"}), 404

        data = request.get_json(force=True) or {}

        try:
            clip_start_sec = float(data["clip_start_sec"])
            clip_end_sec = float(data["clip_end_sec"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "不正な値です: clip_start_sec/clip_end_sec"}), 400
        if clip_start_sec >= clip_end_sec:
            return jsonify({"error": "clip_start_secはclip_end_secより前である必要があります"}), 400

        try:
            outcome = PitchOutcome(data["outcome"])
        except (KeyError, ValueError):
            return jsonify({"error": "不正な値です: outcome"}), 400
        try:
            pitch_call = PitchCall(data["pitch_call"])
        except (KeyError, ValueError):
            return jsonify({"error": "不正な値です: pitch_call"}), 400

        in_play_data = data.get("in_play") or {}
        try:
            in_play_result = PlayResult(in_play_data.get("result", "none"))
        except ValueError:
            return jsonify({"error": "不正な値です: in_play.result"}), 400

        try:
            outs_on_play = int(in_play_data.get("outs_on_play") or 0)
        except (TypeError, ValueError):
            return jsonify({"error": "不正な値です: in_play.outs_on_play"}), 400

        resolved_runners_data = in_play_data.get("resolved_runners")
        resolved_runners = Runners.from_dict(resolved_runners_data) if resolved_runners_data else None

        try:
            inning = int(data.get("inning", pitch.inning))
        except (TypeError, ValueError):
            return jsonify({"error": "不正な値です: inning"}), 400

        half = data.get("half", pitch.half)
        if half not in ("top", "bottom"):
            return jsonify({"error": "不正な値です: half"}), 400

        needs_review = bool(data.get("needs_review", pitch.needs_review))
        notes = data.get("notes", pitch.notes)
        apply_forward = bool(data.get("apply_inning_half_forward", True))
        inning_half_changed = inning != pitch.inning or half != pitch.half

        pitch.clip_start_sec = clip_start_sec
        pitch.clip_end_sec = clip_end_sec
        pitch.outcome = outcome
        pitch.pitch_call = pitch_call
        pitch.in_play = InPlayInfo(
            contact_sec=pitch.in_play.contact_sec,
            play_end_sec=pitch.in_play.play_end_sec,
            result=in_play_result,
            outs_on_play=outs_on_play,
            resolved_runners=resolved_runners,
        )
        pitch.inning = inning
        pitch.half = half
        pitch.needs_review = needs_review
        pitch.notes = notes

        forward_filled_count = 0
        if inning_half_changed and apply_forward:
            for other in timeline.pitches:
                if other.id != pitch.id and other.clip_start_sec > pitch.clip_start_sec:
                    other.inning = inning
                    other.half = half
                    forward_filled_count += 1

        count_state.recompute(timeline)
        timeline_io.save_json(timeline, _timeline_path(state.out_dir))

        result = pitch.to_dict()
        result["forward_filled_count"] = forward_filled_count
        return jsonify(result)

    @app.get("/api/video/<camera>")
    def api_video(camera):
        if camera == "main":
            path = state.main_path
        elif camera == "wide":
            path = state.wide_path
        else:
            return jsonify({"error": f"不正なカメラ名です: {camera}"}), 404
        if not path or not Path(path).exists():
            return jsonify({"error": "映像が設定されていません"}), 404
        return send_file(path, conditional=True)

    # テスト等から状態を直接差し込めるようにしておく。
    app.config["STATE"] = state
    return app
