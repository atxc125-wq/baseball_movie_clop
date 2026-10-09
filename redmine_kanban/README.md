# 設計課タスクボード（Redmine カンバン）

SharePoint に置くだけで動く、Redmine 連携の軽量カンバン。現在はモック（ダミーデータ）で動作する。

## ファイル

| ファイル | 用途 |
|---|---|
| `src/kanban.fragment.html` | 編集する元ファイル（CSS/JS 込み） |
| `build.py` | 元ファイルから配置用ファイルを生成（`python build.py`） |
| `kanban.aspx` | SharePoint に置くファイル（UTF-8 BOM + `<meta charset="utf-8">` 付き） |
| `kanban.html` | ローカルでダブルクリックして確認する用 |
| `kanban_relay.py` | 各自のPCで動かす中継プログラム。`kanban.aspx` と同じフォルダに置く |
| `tools/redmine_config_dump.py` | 実際の Redmine から CONFIG に貼る値を取り出す（読み取りのみ） |

## 列とステータスの対応

| 列 | Redmine ステータス | ドロップ時に設定 |
|---|---|---|
| 未着手 | 未着手 | 未着手 |
| 進行中 | 0% / 20% / 40% / 60% / 80% | 0%（カード内ボタンで 20〜80% に変更） |
| 担当完了 | 完了（実務者） | 完了（実務者） |
| 上司完了（上司の画面だけに表示） | 完了（確認済）（直近14日のみ表示） | 完了（確認済）（上司のみ） |
| （非表示） | 中止 | ドラッグ中に出る「中止」ゾーンへドロップ |

ステータス ID は `CONFIG.statuses` で実環境に合わせる。

## 名前のルール（画面はこれを読んで動く）

- **対象バージョン名の先頭の数字 = 優先度**（`01_不具合対応` → 1）。カードはこの番号の小さい順、
  同じ番号の中では締切の近い順に並ぶ。`CONFIG.urgentPriority` 以下（初期値 01）は赤いタグになる。
- **件名の先頭の【M/D】 = 本来の締切**。期限の強調はこの日付で判定する。
  Redmine の期日は「作業完了予定」として小さく表示し、締切より後なら「締切超え」と出す。
  【M/D】がない場合は Redmine の期日で代わりに判定する。
- タグの色は名前から自動で決まる（毎回同じ色）。固定したい場合は `CONFIG.versionColors`。

## 未整理タブ（新規タスクの振り分け）

Power Automate がメールから作った、担当またはバージョンが未設定のチケットを一覧にする。
選んで「締切」「件名」「対象バージョン」「担当」「作業完了予定」「説明」を入れて登録すると、
件名の先頭に【M/D】を付けて Redmine を更新し、担当者のボードの「未着手」に入る。
メールのノイズ（「教えてください」など）は「タスクではない」で中止にする。チケットは削除しないので、
Power Automate の重複判定はそのまま使える。
対象を特定のプロジェクトに絞る場合は `CONFIG.projectId` を設定する（全員共通の設定なのでファイル側に書く）。

## 親チケットの表示

子チケットを持ち、担当も期日もないチケットは「まとめ用」とみなし、未整理にもボードにも出さない。

親、親の親…とたどり、カード上部に `祖父 › 親` の形で直近 2 階層を表示する（全階層はマウスを乗せると出る）。

## 設定値の取り出し（最初に 1 回）

```
set REDMINE_API_KEY=自分のAPIキー
python tools\redmine_config_dump.py --url https://redmine.example.com
python tools\redmine_config_dump.py --url https://redmine.example.com --project 識別子 --origin https://〇〇.sharepoint.com
```

1 回目でプロジェクトの識別子を確認し、2 回目で `CONFIG` に貼る値（ステータス、メンバー、
上司の推定、projectId、childFilterSupported）と、SharePoint からの CORS が許可されているかを出力する。
結果は `redmine_config_output.txt` にも保存される。標準ライブラリだけで動き、Redmine のデータは変更しない。

## 中継プログラム（Redmine が CORS を許可しない場合の接続方法）

ブラウザは社外の Redmine に直接アクセスできないため、各自のPCで `kanban_relay.py` を動かし、
ボードはそれを通して Redmine を読み書きする。

```
kanban.aspx（SharePoint） ⇄ kanban_relay.py（各自のPC 127.0.0.1:8765） ⇄ Redmine
```

- 配布前に `kanban_relay.py` 冒頭の `REDMINE_URL` と `ALLOWED_ORIGINS`（SharePoint の URL）を書き換え、
  `kanban.aspx` と同じフォルダに置く。
- ボードを開いて中継が動いていなければ、ダウンロードボタン付きの案内が出る。
  ダブルクリックで起動すると、ページが自動でつながる。
- 初回だけ API キーを入力する。キーは Windows の DPAPI で暗号化して `%APPDATA%\DesignTaskBoard` に保存。
  ログオン時の自動起動も選べる（`--uninstall` で解除、`--setup` で設定し直し）。
- 中継は 127.0.0.1 からの接続だけを受け、呼び出し元を `ALLOWED_ORIGINS` に限定し、
  ボードが使う API（チケットの参照・更新、バージョン、ユーザー情報）以外は中継しない。
- ブラウザが「ローカルネットワークへのアクセス」を求めたら「許可」を押す。

## 本番接続の前に確認すること

1. **CORS**: ブラウザから社外の Redmine を直接呼ぶため、Redmine 側が
   `Access-Control-Allow-Origin: https://<自社>.sharepoint.com` と
   `Access-Control-Allow-Headers: X-Redmine-API-Key, Content-Type`、
   `Access-Control-Allow-Methods: GET, PUT, OPTIONS` を返す必要がある。
   Python で読めても、ブラウザでは CORS で止まることがある。
   `kanban.aspx` を SharePoint で開き「接続設定 → 接続テスト」で確認できる。
2. **API キー**: 各自が自分のキーを「接続設定」に入力する（ブラウザ内に保存）。
   共有キーを使うと、全員の操作が 1 人の名前で記録され、「自分のタスク」も判定できない。
3. **ステータス ID / メンバー ID / 上司の ID**: `CONFIG` を実環境の値に書き換える。

## 社内 AI に引き継ぐときの範囲

差し替えが必要なのは `CONFIG` と `createRedmineApi()` だけ。
画面側は `currentUser / issuesFor / issuesByIds / inboxIssues / versions / updateIssue` の 6 関数にしか依存しない。
