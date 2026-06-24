"""ローカルWeb UI(映像パス設定 + ROI調整画面)。

`baseball-clop ui` で起動する。127.0.0.1限定のFlaskサーバーで動作し、外部への
通信は行わない。状態はプロセス内のシングルトン(AppState)に保持するだけの
シングルユーザー想定の簡易実装。
"""

from __future__ import annotations

import io
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

import cv2
from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from .. import audio_sync, pipeline, roi_store
from ..config import MainCameraROIs, PipelineConfig
from ..scoring import timeline_io
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


def _rois_path(out_dir: str) -> Path:
    return Path(out_dir) / "rois.json"


def create_app() -> Flask:
    app = Flask(__name__)
    state = AppState()
    detect_lock = threading.Lock()

    @app.get("/")
    def setup_page():
        return render_template(
            "setup.html",
            main_path=state.main_path,
            wide_path=state.wide_path,
            out_dir=state.out_dir,
            wide_offset_sec=state.wide_offset_sec,
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

        return jsonify({"ok": True})

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
            result = audio_sync.estimate_offset(main_path, wide_path)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except subprocess.CalledProcessError:
            return jsonify({"error": "音声の抽出に失敗しました(ffmpegエラー)"}), 500

        return jsonify({"offset_sec": result.offset_sec, "confidence": result.confidence})

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
                timeline_path = str(Path(out_dir) / "events" / "game.json")
                timeline_io.save_json(timeline, timeline_path)
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

    # テスト等から状態を直接差し込めるようにしておく。
    app.config["STATE"] = state
    return app
