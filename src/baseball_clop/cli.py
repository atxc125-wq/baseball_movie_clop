"""コマンドラインエントリポイント。

例:
  baseball-clop detect --main data/raw/main/game1.mp4 --wide data/raw/wide/game1.mp4 \\
      --out data/output/events/game1.json
  baseball-clop export-csv --timeline data/output/events/game1.json --out data/output/events/game1.csv
  # ...CSVを編集...
  baseball-clop import-csv --timeline data/output/events/game1.json --csv data/output/events/game1.csv \\
      --out data/output/events/game1.json
  baseball-clop render --timeline data/output/events/game1.json --out-dir data/output
"""

from __future__ import annotations

import argparse
import sys

from . import pipeline, roi_preview
from .config import PipelineConfig
from .scoring import count_state, timeline_io


def _cmd_check_rois(args: argparse.Namespace) -> None:
    config = PipelineConfig()
    paths = roi_preview.save_roi_previews(args.video, config.detection.main_rois, args.out, t_secs=args.t_sec)
    for path in paths:
        print(f"ROIプレビュー画像を書き出しました: {path}")
    print("投手・捕手・バッターの枠が実際の選手の位置に合っているか目視で確認してください。")
    print("試合開始直後は投球練習などで選手が定位置にいないことが多いため、")
    print("--t-sec に実際のプレー中と思われる複数の時刻を指定して見比べてください。")
    print("ズレている場合は config.py の MainCameraROIs を調整してから detect を実行してください。")


def _cmd_detect(args: argparse.Namespace) -> None:
    config = PipelineConfig()
    timeline = pipeline.detect(
        args.main,
        args.wide,
        config=config,
        wide_offset_sec=args.wide_offset_sec,
        start_sec=args.start_sec,
        end_sec=args.end_sec,
    )
    timeline_io.save_json(timeline, args.out)
    print(f"検出した投球イベント数: {len(timeline.pitches)}, 牽制候補: {len(timeline.pickoffs)}")
    print(f"タイムラインを書き出しました: {args.out}")


def _cmd_export_csv(args: argparse.Namespace) -> None:
    timeline = timeline_io.load_json(args.timeline)
    timeline_io.export_csv(timeline, args.out)
    print(f"CSVを書き出しました: {args.out}")


def _cmd_import_csv(args: argparse.Namespace) -> None:
    timeline = timeline_io.load_json(args.timeline)
    timeline = timeline_io.import_csv(timeline, args.csv)
    count_state.recompute(timeline)
    timeline_io.save_json(timeline, args.out)
    print(f"CSVの修正を反映し、カウント/ランナーを再計算しました: {args.out}")


def _cmd_recompute(args: argparse.Namespace) -> None:
    timeline = timeline_io.load_json(args.timeline)
    count_state.recompute(timeline)
    timeline_io.save_json(timeline, args.out)
    print(f"カウント/ランナーを再計算しました: {args.out}")


def _cmd_render(args: argparse.Namespace) -> None:
    config = PipelineConfig()
    timeline = timeline_io.load_json(args.timeline)
    written = pipeline.render(timeline, args.out_dir, config=config)
    timeline_io.save_json(timeline, args.timeline)
    for path in written:
        print(f"書き出し: {path}")


def _cmd_all(args: argparse.Namespace) -> None:
    config = PipelineConfig()
    timeline = pipeline.detect(
        args.main, args.wide, config=config, wide_offset_sec=args.wide_offset_sec
    )
    events_path = f"{args.out_dir}/events/game.json"
    timeline_io.save_json(timeline, events_path)
    print(f"タイムラインを書き出しました: {events_path}")
    written = pipeline.render(timeline, args.out_dir, config=config)
    timeline_io.save_json(timeline, events_path)
    for path in written:
        print(f"書き出し: {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="baseball-clop")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check-rois", help="ROI(投手/捕手/打者など)の位置を画像で確認する(detect前の推奨ステップ)")
    p.add_argument("--video", required=True, help="確認したい映像のパス(main想定)")
    p.add_argument(
        "--t-sec",
        type=float,
        nargs="+",
        default=[5.0],
        help="プレビューに使うフレームの時刻(秒)。複数指定すると時刻ごとに別画像を書き出す(例: --t-sec 60 180 300)",
    )
    p.add_argument("--out", required=True, help="出力する画像のパス(.png/.jpg)。複数時刻指定時は時刻が自動でファイル名に付く")
    p.set_defaults(func=_cmd_check_rois)

    p = sub.add_parser("detect", help="2カメラ映像からタイムラインJSONを自動検出する")
    p.add_argument("--main", required=True, help="マウンド-ホーム4K映像のパス")
    p.add_argument("--wide", required=True, help="広角HD映像のパス")
    p.add_argument("--out", required=True, help="出力するタイムラインJSONのパス")
    p.add_argument("--wide-offset-sec", type=float, default=0.0, help="main開始時点でのwide映像内の再生位置(秒)")
    p.add_argument("--start-sec", type=float, default=0.0)
    p.add_argument("--end-sec", type=float, default=None)
    p.set_defaults(func=_cmd_detect)

    p = sub.add_parser("export-csv", help="タイムラインJSONを編集用CSVへ書き出す")
    p.add_argument("--timeline", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_export_csv)

    p = sub.add_parser("import-csv", help="編集済みCSVをタイムラインJSONへ反映する")
    p.add_argument("--timeline", required=True)
    p.add_argument("--csv", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_import_csv)

    p = sub.add_parser("recompute", help="カウント/ランナーだけを再計算する(検出はやり直さない)")
    p.add_argument("--timeline", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=_cmd_recompute)

    p = sub.add_parser("render", help="タイムラインJSONからクリップとオーバーレイファイルを書き出す")
    p.add_argument("--timeline", required=True)
    p.add_argument("--out-dir", required=True, help="data/output のようなディレクトリ(clips/overlaysを作成)")
    p.set_defaults(func=_cmd_render)

    p = sub.add_parser("all", help="detect + render を一括実行する")
    p.add_argument("--main", required=True)
    p.add_argument("--wide", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--wide-offset-sec", type=float, default=0.0)
    p.set_defaults(func=_cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
