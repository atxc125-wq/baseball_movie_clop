"""ローカルWeb UI(映像パス設定 + ROI調整画面)。

`baseball-clop ui` で起動する。127.0.0.1限定のFlaskサーバーで動作し、外部への
通信は行わない。状態はプロセス内のシングルトン(AppState)に保持するだけの
シングルユーザー想定の簡易実装。
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path

import cv2
from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

from .. import roi_store
from ..config import MainCameraROIs
from ..video_io import iter_frames


@dataclass
class AppState:
    main_path: str = ""
    wide_path: str = ""
    out_dir: str = ""
    rois: MainCameraROIs = field(default_factory=MainCameraROIs)


def _rois_path(out_dir: str) -> Path:
    return Path(out_dir) / "rois.json"


def create_app() -> Flask:
    app = Flask(__name__)
    state = AppState()

    @app.get("/")
    def setup_page():
        return render_template(
            "setup.html",
            main_path=state.main_path,
            wide_path=state.wide_path,
            out_dir=state.out_dir,
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

        state.main_path = main_path
        state.wide_path = wide_path
        state.out_dir = out_dir

        loaded = roi_store.load(_rois_path(out_dir))
        state.rois = loaded if loaded is not None else MainCameraROIs()

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

    # テスト等から状態を直接差し込めるようにしておく。
    app.config["STATE"] = state
    return app
