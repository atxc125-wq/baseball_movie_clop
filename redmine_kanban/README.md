# 設計課タスクボード（Redmine カンバン）

Redmine 連携の軽量カンバン。各自のPCで動く中継プログラムがボードの画面を出し、社外の Redmine とつなぐ。

```
ブラウザ（http://127.0.0.1:8765/） ⇄ kanban_relay.py（各自のPC） ⇄ Redmine（社外）
```

SharePoint に置く方式は、SharePoint Online がページ内のスクリプトを止めるため採用しなかった。
また Redmine が CORS を許可しないため、ブラウザから Redmine へ直接はつなげない。

## ファイル

| ファイル | 用途 |
|---|---|
| `kanban_relay.py` | 配布する中継プログラム。ボードの画面を出し、Redmine API を中継する |
| `kanban.html` | 配布するボードの画面。`kanban_relay.py` と同じフォルダに置く |
| `src/kanban.fragment.html` | ボードの元ファイル（CSS/JS 込み）。編集後に `python build.py` |
| `build.py` | 元ファイルから `kanban.html` を作る |
| `tools/redmine_config_dump.py` | 実際の Redmine から CONFIG に貼る値を取り出す（読み取りのみ） |

## 配布と使い方

1. `kanban_relay.py` 冒頭の `REDMINE_URL` を書き換える。
2. `kanban.html` の `CONFIG` に `tools/redmine_config_dump.py` の出力を貼る（UTF-8 で保存）。
3. 2 つのファイルを共有フォルダ（SharePoint / Teams など、置くだけ）に入れ、メンバーは同じフォルダにダウンロードする。
4. `kanban_relay.py` をダブルクリック。初回だけ API キーを入力し、自動起動するかを選ぶ。
   ボードがブラウザで開き、デスクトップに「設計課タスクボード」のショートカットができる。
5. 次回からはショートカットを開くだけ（自動起動にしなかった場合は先に `kanban_relay.py` をダブルクリック）。

- API キーは Windows の DPAPI で暗号化して `%APPDATA%\DesignTaskBoard` に保存。ブラウザには置かない。
- 自動起動を選ぶと、2 つのファイルを `%APPDATA%\DesignTaskBoard` にコピーしてそこから動く。
  更新版を配るときは、新しいファイルで `kanban_relay.py --setup` を実行し、PC を再ログオンする。
- `--uninstall` で自動起動を解除、`--setup` で API キーを設定し直す。

### 中継プログラムの安全対策

- 127.0.0.1 でだけ待ち受け、Host ヘッダーが 127.0.0.1 / localhost 以外なら断る（DNS リバインディング対策）。
- API を使えるのは、中継が出したボードのページ（同一オリジン）と `ALLOWED_ORIGINS` に書いたページだけ。
  他の Web サイトからの呼び出しは、Origin / Sec-Fetch-Site で判定して断る。
- 中継するのはボードが使う API（チケットの参照・更新、バージョン、ユーザー情報）だけ。

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
python tools\redmine_config_dump.py --url https://redmine.example.com --project 識別子
```

API キーは実行後に入力する（環境変数 `REDMINE_API_KEY` でも可）。`--project` を省くとプロジェクトの一覧を出す。
`CONFIG` に貼る値（ステータス、メンバー、上司の推定、projectId、childFilterSupported）を出力し、
`redmine_config_output.txt` にも保存する。標準ライブラリだけで動き、Redmine のデータは変更しない。

## 社内 AI に引き継ぐときの範囲

差し替えが必要なのは `CONFIG` と `createRedmineApi()` だけ。
画面側は `currentUser / issuesFor / issuesByIds / inboxIssues / versions / updateIssue` の 6 関数にしか依存しない。
