# baseball_movie_clop

草野球の試合映像(マウンド〜ホーム間の4K映像 + フィールド全体を映す広角HD映像)から、
投球単位のハイライトクリップと、SBO(ストライク/ボール/アウト)・ランナー表示用の
オーバーレイ情報を生成するパイプライン。

自動判定(ストライク/ボール、ヒット結果、牽制の判定など)は本質的に精度が出ない
前提で設計しており、**検出結果は常に編集可能なタイムラインJSON/CSVとして出力し、
あとから人手で修正→再計算できる**ことを最優先にしている。

## 処理の流れ

1. `detect`: main(マウンド-ホーム4K)映像を解析し、投球候補ごとに
   - ワインドアップ/セットポジションに入る動き出しの1秒前 (`pre_roll_sec`、`config.py`で調整可) を `clip_start_sec` とする
   - 見逃し/空振りなら捕手到達直前を `clip_end_sec` とする
   - スイングして打球が出たら(`outcome=in_play`)、打球処理が終わる(広角映像の動きが収まる)までクリップ終了を保留し、確定したら `clip_end_sec` を確定する
   - 打球時はmain→wideへのカメラ切替区間(`segments`)を自動構成する(まれにmainに収まる場合の判定も試みるが、`camera_override` で常に手動上書きできる)
   - 牽制らしき動き(セットに入る前後どちらでも)はボールの送球方向で投球と判別し、`pickoffs` に分けて記録する(カウントには影響しない)
   という`PitchEvent`の一覧(タイムライン)をJSONに書き出す。
2. (任意) `export-csv` でレビュー用CSVを書き出し、ストライク/ボール判定や打球結果などの
   「自動判定が難しい」フィールドを表計算ソフトで修正し、`import-csv` でJSONへ反映する。
   細かいクリップ区間やカメラ切替区間(`segments`)を直す場合はJSONを直接編集する。
3. `render`: タイムラインJSON(必要なら修正済みのもの)から
   - 投球ごとのカウント/ランナー状況を先頭から決定的に再計算 (`recompute`)
   - `data/output/clips/<id>.mp4` にクリップを書き出し(カメラ切替がある場合はffmpegで結合)
   - `data/output/overlays/<id>.overlay.json` (+`.csv`) にクリップ自身の時間軸(0=クリップ開始)で
     SBO/ランナーのオーバーレイ情報を書き出す(動画への焼き込みはしない、別ファイル)

`detect`を一度実行した後は、JSON/CSVを直して`render`を再実行するだけで反映される。
CV検出をやり直す必要はない。

## ディレクトリ構成

```
data/
  raw/main/    マウンド-ホーム4K映像(容量が大きいためgit管理外)
  raw/wide/    広角HD映像(同上)
  samples/     動作確認用の短い(1分程度)サンプル映像。ここはgit管理対象。
  output/
    clips/     切り出したクリップ(再生成可能なためgit管理外)
    events/    タイムラインJSON/CSV(正本データ)
    overlays/  クリップ同期のオーバーレイJSON/CSV
src/baseball_clop/
  config.py              ROI・閾値などのチューニングパラメータ
  video_io.py             OpenCVでの動画読み込み
  detection/
    motion.py             ROIモーション時系列の生成と立ち上がり/静止検出
    ball_tracking.py       簡易ボール追跡、送球方向推定、打球処理終了検出
    pitcher_motion.py      投球動作開始の検出 + 牽制との切り分け
    swing_contact.py       見逃し/空振り/打球の判定、クリップ終了点の推定
    camera_selector.py     main/wideカメラの選択
  scoring/
    models.py              タイムラインのデータモデル(PitchEvent等)
    count_state.py          カウント/ランナーの決定的な再計算
    timeline_io.py          タイムラインのJSON/CSV入出力
  editor/clipper.py        ffmpegによるクリップ切り出し・カメラ切替結合
  overlay/overlay_writer.py オーバーレイファイルの生成
  pipeline.py              detect/renderの統合
  cli.py                   コマンドラインエントリポイント
tests/                     pytest(モーション検出・ボール追跡・カウント計算・クリップ結合)
```

## セットアップ

```
pip install -e .          # もしくは pip install -r requirements.txt
```

ffmpeg/ffprobeが別途必要(`apt install ffmpeg`等)。

## 使い方

```
# 1. 動画を配置
#    data/raw/main/game1_main.mp4 / data/raw/wide/game1_wide.mp4

# 2. 自動検出してタイムラインJSONを生成
baseball-clop detect --main data/raw/main/game1_main.mp4 --wide data/raw/wide/game1_wide.mp4 \
    --out data/output/events/game1.json

# 3. (任意) レビュー用CSVを出して人手で修正
baseball-clop export-csv --timeline data/output/events/game1.json --out data/output/events/game1.csv
#   -> game1.csv を表計算ソフトで開き、pitch_call / in_play_result / outs_on_play /
#      resolved_runner_1b・2b・3b / camera_override / inning / half などを修正
baseball-clop import-csv --timeline data/output/events/game1.json --csv data/output/events/game1.csv \
    --out data/output/events/game1.json

# 4. クリップとオーバーレイファイルを書き出す
baseball-clop render --timeline data/output/events/game1.json --out-dir data/output

# (1の動画ペアからdetect+renderを一括実行する場合)
baseball-clop all --main data/raw/main/game1_main.mp4 --wide data/raw/wide/game1_wide.mp4 \
    --out-dir data/output
```

2台のカメラの録画開始タイミングがズレている場合は `--wide-offset-sec` で
「mainの再生開始時点でwide映像の何秒目にあたるか」を指定する。

## Web UI

```
baseball-clop ui
```

映像パスの指定・音声同期・ROI調整・1球ずつのレビューをブラウザ上で行える(127.0.0.1限定)。
Windowsでコマンド入力が面倒な場合は、リポジトリ直下の `start_ui.bat` をダブルクリックすれば
同じコマンドを実行できる(`baseball-clop` コマンドがPATHに無い環境でも `python -m
baseball_clop.cli ui` 経由で起動するため動く)。

## 検出ロジックの設計と既知の限界

- **投球動作の検出**: マウンドROI内のモーションが「一定時間静止→動き出す」瞬間を
  すべて候補として拾い、直後にボールらしきブロブが追跡できればホーム方向か
  1塁/3塁方向かを判定して、投球と牽制を分ける(`detection/pitcher_motion.py`)。
  **セットに入る前の牽制**も、候補を一旦すべて拾ってから方向で分類する設計のため
  自然に扱える。方向が判定できない場合は安全側(投球として残す)に倒し
  `needs_review=True`を立てるので、誤分類はタイムラインJSON/CSVで直せる。
- **見逃し/空振り/打球の判定**: 打者ボックスROIのモーションでスイングの有無を、
  ボール追跡の軌道が捕手方向への単調な動きから外れるかどうかで打球(接触)の有無を
  判定する(`detection/swing_contact.py`)。ストライク/ボールの自動判定はボールの
  最終追跡位置とストライクゾーン矩形の重なりで仮決めするだけの精度の低い処理であり、
  見逃しの`pitch_call`は常に`needs_review=True`になる。
- **打球処理の終了**: 打球と判定された後、広角(wide)側(まれにmain側)の画面全体の
  モーションが一定時間落ち着いた瞬間を「プレー終了」とみなす(`detection/ball_tracking.detect_play_end`)。
- **カメラ選択**: 打球発生後、ボールがmainカメラの範囲内に収まり続けたかを追跡し、
  収まっていればmain、それ以外はwideを選ぶ。`PitchEvent.camera_override`で
  クリップ全体を強制的にmain/wideへ固定できる(まれにmainで収まる場合の手動選択)。
- **ヒット結果(単打/二塁打/アウト等)とランナー進塁**: 映像から正確に推定するのは
  非常に難しいため、検出側は基本`unknown`のまま残し、`outs_on_play`と
  `resolved_runners`(または`result`からの簡易進塁ヒューリスティック)を
  人手で確定させる前提にしている(`scoring/count_state.py`)。

検出パラメータ(ROI座標・各種閾値)はすべて`src/baseball_clop/config.py`にまとまっている。
実際の試合映像(`data/samples/`に短いサンプルを置く想定)でチューニングする際は、
まずこのファイルを調整すること。検出ロジック自体をより高精度なもの
(姿勢推定ベースの投球動作検出など)に差し替えたい場合も、`detection/`以下の
各関数を同じ入出力で置き換えれば`pipeline.py`はそのまま使える。

## カウント/ランナーの再計算について

`PitchEvent`の`count_before/after`・`runners_before/after`は、検出時にも書き込まれるが
**常に`count_state.recompute()`で先頭から再計算され直す**。利用者が`pitch_call`や
`in_play.result`・`outs_on_play`・`resolved_runners`・`inning`/`half`を直接編集して
`recompute`(または`render`、これは内部で毎回recomputeする)を実行し直すだけで、
以降のカウント/ランナー表示が自動的に整合する。

## オーバーレイファイルの仕様

`data/output/overlays/<id>.overlay.json`は、クリップ自身の時間軸(`t=0`がクリップ先頭)
でのキーフレーム列。動画への焼き込みは行わないので、再生/編集側でクリップと
同期させて読み込み、SBO・ランナー表示に使うことを想定している。

```json
{
  "clip_file": "p0001.mp4",
  "pitch_id": "p0001",
  "pitch_call": "strike",
  "outcome": "swing_miss",
  "needs_review": false,
  "keyframes": [
    {"t": 0.0, "inning": 1, "half": "top", "balls": 0, "strikes": 1, "outs": 0,
     "runners": {"1B": false, "2B": false, "3B": false}},
    {"t": 1.8, "inning": 1, "half": "top", "balls": 0, "strikes": 2, "outs": 0,
     "runners": {"1B": false, "2B": false, "3B": false}}
  ]
}
```

同内容の`.overlay.csv`も並べて出力する。

## テスト

```
pip install -e ".[dev]"
pytest
```
