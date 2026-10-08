# 設計課タスクボード（Redmine カンバン）

SharePoint に置くだけで動く、Redmine 連携の軽量カンバン。現在はモック（ダミーデータ）で動作する。

## ファイル

| ファイル | 用途 |
|---|---|
| `src/kanban.fragment.html` | 編集する元ファイル（CSS/JS 込み） |
| `build.py` | 元ファイルから配置用ファイルを生成（`python build.py`） |
| `kanban.aspx` | SharePoint に置くファイル（UTF-8 BOM + `<meta charset="utf-8">` 付き） |
| `kanban.html` | ローカルでダブルクリックして確認する用 |

## 列とステータスの対応

| 列 | Redmine ステータス | ドロップ時に設定 |
|---|---|---|
| 未着手 | 未着手 | 未着手 |
| 進行中 | 0% / 20% / 40% / 60% / 80% | 0%（カード内ボタンで 20〜80% に変更） |
| 担当完了 | 完了 | 完了 |
| 上司完了 | 上司確認済（直近14日のみ表示） | 上司確認済（上司のみ） |
| （非表示） | 中止 | ドラッグ中に出る「中止」ゾーンへドロップ |

ステータス ID は `CONFIG.statuses` で実環境に合わせる。

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
画面側は `currentUser / issuesFor / issuesByIds / updateIssue` の 4 関数にしか依存しない。
