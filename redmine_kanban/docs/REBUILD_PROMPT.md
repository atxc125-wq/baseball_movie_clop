# タスクボード 再現用プロンプト

> **このプロンプトの渡し方（人間向けメモ）**
> - いちばん確実なのは、このプロンプトと一緒に次のソースを添付することです: `src/kanban.fragment.html`、`kanban_relay.py`（`# --- BOARD_HTML_BEGIN` より上だけで可）、`build.py`、`board_settings.example.json`、`setup.bat`、`README.md`。
>   その場合は「添付のソースを正とし、本書と食い違ったらソースに合わせる」と伝えてください。
> - ソースを渡せない場合も、末尾の付録（CSS 全文・画面の HTML 全文・初期設定・中継する API の一覧）をそのまま使えば、見た目は同じになります。
> - 長すぎて入らない場合: 本文（「付録について」まで）をプロンプトに入れ、付録 A・B の代わりに `docs/board.css` と `docs/board_body.html` を添付してください（中身は同じ）。
> - 実在の人名・社内 URL・API キーは入っていません（見本データの人名は架空）。

---

## 0. あなたへの依頼

あなたはシニアのフロントエンド／Python エンジニアです。以下の仕様どおりに「タスクボード」を**完全に再現**してください。
既存の動作・見た目・文言（日本語の UI 文言、トースト、ヘルプ文）をすべて同じにすることがゴールです。独自の改善・省略・ライブラリ追加はしないでください。
不明点があれば推測で埋めず、仕様の該当箇所を引用して質問してください。

作業は「7. 進め方」の順で、段階ごとに動作確認しながら進めてください。各段階の最後に、「8. 落とし穴」のうち該当するものを自分で点検した結果を報告してください。

---

## 1. 何を作るか（概要）

社外にある Redmine を、5 人前後の設計チームが**計画のメンテに時間を取られず**使うための、軽量なカンバン型タスクボード。

- 個人ボード（4 列: 未着手 / 進行中 0〜80% / 担当完了 / 上司完了）でワンクリック更新
- 未整理タブ（Power Automate がメールから作ったチケットの振り分け）
- 全体ボード（Teams 画面共有用。1 画面に収める）
- 工数（進捗を押したついでに 1 クリックで作業時間を記録、月次集計・CSV）
- 課題バラシ（親子 = 枠の入れ子、前後 = Redmine の「先行」矢印。予定工数から日程を自動計算）
- 使い方ページ（ブログ調）
- 中継プログラム（Python 標準ライブラリだけ）: CORS 非対応の Redmine に代わって API を中継し、ボードの HTML も配る

---

## 2. 絶対条件（制約）

1. **ボード**: 1 枚の HTML（素の JavaScript、フレームワーク・ビルドツールなし）。外部読み込みは Google Fonts（BIZ UDPGothic 400/700、IBM Plex Mono 500）だけ。
2. **中継プログラム**: Python 3（標準ライブラリだけ。サードパーティ禁止）。Windows で動くこと（DPAPI、レジストリの Run キー、pythonw）。Linux でも開発・テストできること。
3. **配布物は `kanban_relay.py` 1 本**（＋共有フォルダに置く `board_settings.json`、初回用 `setup.bat`）。ボードの HTML は `build.py` で `kanban_relay.py` の中に埋め込む（base64(zlib(html))）。
4. 画面の文言はすべて日本語。敬語は「です・ます」、短く。英語を混ぜない。
5. 実在の人名・社内 URL・API キーをコードに書かない。`board_settings.json` はリポジトリに入れない（.gitignore）。
6. API キーはブラウザに置かない（中継が付ける）。共有キーは使わず、1 人 1 キー。

---

## 3. ファイル構成とビルド

```
redmine_kanban/
  src/kanban.fragment.html   ボードの元（<head> 部分 + "<!--BODY-->" + <body> 部分）
  build.py                   fragment → kanban.html（確認用）を作り、kanban_relay.py に埋め込む
  kanban_relay.py            中継プログラム（配布物）。BOARD_HTML_BEGIN〜END の間を build.py が書き換える
  board_settings.example.json  設定の見本（実物の board_settings.json は配布フォルダにだけ置く）
  setup.bat                  初回設定（ASCII のみ。py -3 があれば使い、なければ python。--setup で起動）
  README.md
  tools/redmine_config_dump.py  （診断用、任意）
```

### build.py
- `src/kanban.fragment.html` を読み、`__BUILD__` を `YYYY-MM-DD HH:MM` に置換。
- `<!--BODY-->` で head と body に分け、`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">` + head + `</head><body>` + body + `</body></html>` を組み立てる。
- `kanban.html` を書き出す（確認用）。
- base64(zlib.compress(html, 9)) を 100 文字ずつの文字列リスト `BOARD_HTML = [ ... ]` にして、`kanban_relay.py` の `# --- BOARD_HTML_BEGIN ...` 行と `# --- BOARD_HTML_END ---` 行の間を置換（目印がなければ assert で止める）。
- `kanban_relay.py` の `BUILD = "..."` 行も同じ日時に置換（自動更新の新旧判定に使う）。

### 中継がボードを配るとき
- 埋め込み HTML を展開し、`/*__SERVER_CONFIG__*/` を `Object.assign(CONFIG, {…});` に 1 回だけ置換（JSON の `</` は `<\/` にエスケープ）。
- 開発用に環境変数 `DESIGN_BOARD_HTML` があればそのファイルを使う。

---

## 4. 中継プログラム（kanban_relay.py）の仕様

### 4.1 定数
- `PORT = 8765`、`VERSION = "15.3"`（大きな機能追加で整数を上げ、小さな改善・修正は 15.1, 15.2 …。比べるときは `version_key("15.2") → (15, 2)`、末尾の 0 は無視。`file_version` は `^VERSION = "([\d.]+)"` を読み (比較用, BUILD, 表記) を返す）、`BUILD`（build.py が書く）
- `APP_DIR = %APPDATA%\DesignTaskBoard`（なければ `~/.config/DesignTaskBoard`）
  - `relay.json`（API キー。Windows は DPAPI で暗号化 `key_dpapi`、それ以外は `key_plain` を権限 600 で保存し、保存時・起動時に「平文で保存しています」と警告）＋ `redmine_origin`（キーを送ってよい接続先）
  - `detected_config.json`（Redmine から読んだ設定の控え。読めなかったときに使う）
  - `install_source.txt`（更新を取りに行く共有フォルダ）
  - `relay.log`
- `HERE` = このファイルのフォルダ。`board_settings.json` は HERE から読む（なければエラーメッセージを出して止まる）。

### 4.2 HTTP サーバー（ThreadingHTTPServer, 127.0.0.1:8765 だけで待ち受け）
- **Host ヘッダーが 127.0.0.1 / localhost（:8765）以外なら 403**（DNS リバインディング対策）。
- `GET /` と `GET /kanban.html`: ボードの HTML（設定入り、チケットのデータは含まない）。`Cache-Control: no-store`。
- それ以外は呼び出し元チェック: 同一オリジン（`http://127.0.0.1:8765` / `http://localhost:8765`）か `ALLOWED_ORIGINS`（既定は空）。Origin がない場合は `Sec-Fetch-Site: same-origin` のときだけ許可（同じページからの GET には Origin が付かないため）。他サイトからは 403「このページからは使えません」。
- `GET /ping`: `{ok, version, pid, redmine_url, board_dir, warnings, update_available, user:{id,name}}`
- `GET /admin/restart`: Origin が自分のときだけ。応答を返してから**`threading.Thread(target=restart, daemon=False)`**（daemon を明示しないと要求スレッドの daemon を継承して再起動前にプロセスが終わる）。
- `/api/<path>`: **許可リスト（付録 D）にあるメソッドとパスだけ**中継。それ以外は 403「中継していない操作です」。本文は PUT/POST だけ読む（1MB まで）。`X-Redmine-API-Key` は中継が付ける。
- Redmine 呼び出し: タイムアウト 45 秒。**GET だけ**、接続切れ・時間切れ・`ConnectionError`・502/503/504 のとき 0.5 秒・1 秒あけて 2 回までやり直す。
- 例外は `URLError, socket.timeout, ConnectionError, OSError` をすべて捕まえて 502「中継プログラムから Redmine に接続できません。ネットワークを確認してください」を返す（**`RemoteDisconnected` を捕まえ損ねると処理ごと落ちる**）。
- OPTIONS（ALLOWED_ORIGINS 用）: `GET, PUT, POST, DELETE, OPTIONS`、`Access-Control-Allow-Private-Network: true`。

### 4.3 起動の流れ（main）
1. 引数: `--setup`（キーと自動起動を設定し直す）、`--uninstall`（自動起動を解除）。
2. `board_settings.json` を読む。`interactive = stdin が端末`。
3. （以前の版からの移行処理は、作り直しでは不要。古い起動用ファイルが残る環境では 8 章 7 を参照）
4. **from_elsewhere**（端末から、APP_DIR 以外の場所の py を実行し、APP_DIR に自動起動用コピーがある）: HERE の `kanban_relay.py` と `board_settings.json` を APP_DIR に「中身が違えば」コピー。`update_dir` 指定がなければ `install_source.txt` を HERE に向け直す。
5. すでに中継が動いている（ポートに接続できる）:
   - 端末から: まず `check_destination` → 動いている中継のフォルダに新しいファイルをコピー → `/admin/restart` → **`/ping` の version が自分と同じか確認**。違えば（古い版が自分の古いファイルで再起動した等）「古い版の中継（vX）が動き続けているので、止めて入れ替えます…」→ `/ping` の pid か、OS（Windows: `netstat -ano -p TCP` の LISTENING 行、Linux: `lsof -t -iTCP:8765 -sTCP:LISTEN`）でポートの持ち主を調べて停止（Windows: `taskkill /F /PID`、`CREATE_NO_WINDOW`）→ APP_DIR のコピーを画面なしで起動 → 版が一致するまで最大 20 秒待つ。成功したらブラウザでボードを開く。
   - 端末でなければ何もしない。
6. from_elsewhere でキーがある: `check_destination` → APP_DIR のコピーを**画面なしで起動**（Windows: `pythonw.exe`、`creationflags=DETACHED_PROCESS(0x8)`、それ以外 `start_new_session=True`、stdin/out/err は DEVNULL）→ 起動を待ってブラウザを開く → 「この画面は閉じて大丈夫です」。
7. HERE が APP_DIR（自動起動のコピー）: 取り込み元（`update_dir` > `install_source.txt`）を見る。
   - **プログラム（kanban_relay.py）は自動では入れ替えない**（共有フォルダに書ける人が全員の PC で黙ってコードを動かせてしまうため）。取り込み元の (VERSION, BUILD) が自分より新しければ `UPDATE_AVAILABLE = "v15.2（BUILD）"` にして /ping で返す（ボードが知らせる）。
   - `board_settings.json` だけは中身が違えば取り込む。
8. `check_destination`（4.4）→ キー読み込み（なければ端末なら setup、端末でなければログを出して終了）→ `/users/current.json` で確認（ダメなら理由を表示し、端末なら setup し直し）。
9. 初回設定で自動起動にした場合は、画面なしの常駐に切り替えて終了。
10. Redmine からボードの設定を作る（4.5）→ サーバー開始 → 端末ならブラウザを開く。

### 4.4 API キーの送り先の固定（check_destination）
- `url_origin(url)` = `scheme://host(小文字):port`（http/https 以外は空）。
- `relay.json` の `redmine_origin` と、今の `board_settings.json` の `redmine_url` を比べる。
  - キー未設定 → OK（このあと本人が接続先を見て入力）。
  - `redmine_origin` がない（以前の版）→ 今の接続先を記録して OK（1 回だけ）。
  - 一致 → OK。不一致 → 「board_settings.json の接続先が、API キーを設定したときと違います（設定したとき / いまの設定）。キーは送りません」。端末なら「この接続先（…）に API キーを送ってよいですか？ 正しいと確認できた場合だけ yes と入力」で `yes` のときだけ記録し直す。端末でなければ終了。
- `http://`（127.0.0.1/localhost 以外）には「暗号化されていません」と警告。
- setup では「API キーはこの接続先にだけ送ります。接続先が正しいことを確認してから入力してください。」と表示し、保存時に `redmine_origin` も保存。

### 4.5 ボードの設定（detect_config）
- `/issue_statuses.json` からステータスを読み、名前で列を推定: 「0%〜80%」の数字 → doing（ratio）、「未着手」「新規」「New」→ todo、「中止」「却下」→ cancelled、「確認済」「上司」→ approved、「完了」「解決」→ done。`status_columns`（名前 → 列）で上書き。推定できないものは警告。
- 人: プロジェクトのメンバー（グループは除く）＋ 未完了チケットの担当者・作成者 ＋ 実行している本人。名前のない（削除・ロックされた）ユーザーは除いて警告。
- `team`: `"auto"` なら未完了チケットを担当している人だけ、名前の一覧ならその人だけ。`team_exclude`、`team_order`（その順で先頭に）。
- `managers`: 名前（空白の有無を無視して照合）か ID（数値でも `"12"` でも可）。見つからなければ候補名を添えて警告。
- `childFilterSupported`: `child_id=*` と `child_id=!*` の件数の和が全件と一致するかで判定。
- `options`（board_settings.json）をそのまま CONFIG に上書き（urgentPriority, dueSoonDays, approvedDays, versionColors, hoursPerDay, holidays, versionCategories など）。
- 読めなかったら `detected_config.json` の控えを使い、警告に入れる。

### 4.6 自動起動
- Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` の `DesignTaskBoardRelay` に `"pythonw.exe" "%APPDATA%\DesignTaskBoard\kanban_relay.py"`。setup で「Windows にログオンしたとき自動で起動しますか？ [Y/n]」。
- デスクトップに `タスクボード.url`（`[InternetShortcut]` / `URL=http://127.0.0.1:8765/`）。

---

## 5. ボード（src/kanban.fragment.html）の仕様

画面の HTML 構造は付録 B、CSS は付録 A、初期設定は付録 C を**そのまま**使うこと。以下は振る舞いの仕様。

### 5.1 共通の作り
- `h(tag, attrs, ...children)`: DOM を作る小関数。`on*` 属性はイベント、`class` は className、`true` は空属性、`null/false` は付けない。子は**1 段だけ flat()**、`null/false` は捨てる。
- **`replaceChildren(...)` に null を渡すと「null」という文字が出る。必ず `.filter(Boolean)` する。**
- localStorage の読み書きはすべて try/catch（使えなくても動く）。
- 日付: ローカル日付で扱う（`isoDate`、`parseDate`、`addDays`、`jpDate` = `M/D(曜)`）。
- 状態 `state = { me, view, issues: Map, parents: Map, saving: Set, inbox, inboxSel, versions, team, doneOn, redmineUrl, bara }`。`view` はメンバー ID か `'inbox'`/`'dash'`/`'bara'`。
- 接続モード: `relay`（既定。中継の相対パス `/api` を使う）/ `mock`（見本データ）/ `live`（直接接続。CORS がある場合だけ）。設定は localStorage `designBoard.settings.v2`。
- 中継が止まっているとき: 中継から配られたページなら「中継プログラムが止まっています」と 3 秒ごとに /ping を待つ。それ以外の場所で開かれたら手順の案内と「モックで試す」。
- 起動時、/ping の `update_available` があれば「新しい版 … が共有フォルダにあります。共有フォルダの kanban_relay.py をダブルクリックすると更新されます」をトーストで出す。

### 5.2 API 層（モックと Redmine で同じ関数）
`currentUser, issuesFor(userId), teamIssues, issuesByIds(ids, include), inboxIssues, versions(projectId), withChildren(ids), childIssues(parentId), getIssue, issueDetail(id)(include=relations), issueJournals, issuesInVersion, createIssue, createVersion, updateIssue, addRelation(from,to), removeRelation, timeEntries({from,to,userId}), createTimeEntry, issuesTouchedOn(userId,date), priorities, milestones`
- 一覧は `limit=100` でページングして全部取る。`project_id` は CONFIG.projectId があれば付ける。
- `issuesFor`: 担当の未完了 ＋ `approvedDays` 以内に更新された完了。
- `issuesByIds`: **50 件ずつ**（URL が長くなりすぎないように）。`include=relations` を渡せる。
- `inboxIssues`: 「担当なし」と「バージョンなし」の未完了を 2 回取って合わせる（OR 検索ができないため）。
- `withChildren`: `child_id=*` が使えればそれで、使えなければ 1 件ずつ `include=children`（同時 4 件）。
- `updateIssue`: PUT のあと GET して、**ステータスと各項目（件名・担当・バージョン・期日・説明・親・予定工数・開始日）が本当に変わったか確かめる**。Redmine は権限やワークフローで許可されない変更をエラーにせず無視するため。ステータスが変わらなければ「Redmine がステータスの変更を受け付けませんでした（今は「…」のまま）。ワークフローで「…」→「…」が許可されているか確認してください。」、項目が反映されなければ `err.partial = true` で「反映されなかった項目があります: …」。
- 読むだけの要求（GET）は、通信失敗か 502/503/504 なら 0.6 秒あけて 1 回だけやり直す。401 は「API キーが正しくありません (401)」、403 は「この操作の権限がありません (403)」。
- 作業時間: `activity_id` は `/enumerations/time_entry_activities.json` の既定（なければ先頭、取れなければ付けない）。
- `milestones`: Lychee の `/lychee/api/v1/projects/<識別子>/milestones.json`（だめなら数値 ID で）。プロジェクトが決まっていなければ null、読めなければエラーを投げる。
- モックは本物の挙動をまねる: 非上司が「完了（確認済）」を触ると 422、親子間の先行や輪になる先行は 422、親を自分の子孫にすると 422。

### 5.3 名前のルール
- **件名の先頭の `【M/D】` = 本来の締切**（全角数字・全角スラッシュも可）。年は今日に一番近い年。表示は `【】` を外した本文。保存時は `buildTitle(本文, 締切)`。
- **Redmine の期日 = 作業完了予定**。締切がなければ期日で代用（ラベル「予定」）。
- 締切超過は赤（`締切 N日超過`）、今日・`dueSoonDays`（3）日以内は黄（`締切 今日` / `締切 あとN日`）。作業完了予定が締切より後なら「予定 M/D(曜) 締切超え」。
- **バージョン名 = `番号_カテゴリ-個別名`**（例: `05_開発業務-EV電池ケース`）。区切りは `_` か `-` のどちらでも読む（古い名前 `05_開発業務_EV電池ケース` も同じに読む。個別名の中の `-` は残す）。タグには個別名（なければカテゴリ）を出し、先頭に番号。番号が `urgentPriority`（1）以下は赤いタグ。タグの色は名前のハッシュで 6 色から決める（`versionColors` で固定可）。
- 新しいバージョンのカテゴリは `versionCategories`（付録 C）。末尾の区切りをそのまま使う（区切りがなければ `_` を足す）。

### 5.4 ヘッダーとタブ
- 左: 「タスクボード」、今日の日付、モード表示（リアルタイム接続 / Redmine直接接続 / モック）。
- 右: （モック時のみ）モックの操作ユーザー選択、`＋ 新規タスク`（primary）、`工数`、`再読み込み`、`接続設定`、`使い方`（まだ開いていない人には赤い点）。
- タブ: メンバー（自分には「自分」バッジ）｜区切り｜`全体`、`課題バラシ`、`未整理`（件数バッジ、0 件は灰色）。**全体と課題バラシは全員に出す**。
- タブの下にサマリー（チップ）: 締切超過 / 3日以内 / 予定が締切超え / 手持ち / 確認待ち ＋ 並び順の切り替え。未整理では「未整理 N」「締切未記入 N」。

### 5.5 個人ボード
- 列: 未着手 / 進行中（0〜80%）/ 担当完了（上司の確認待ち）/ 上司完了（直近14日、**上司が開いたときだけ表示**）。列の中だけ縦スクロール、ページはスクロールしない。
- ステータスの対応は付録 C の `statuses`。**列にドロップしたときのステータスは statuses から決める**（その列の最初、進行中は ratio が最小）。ID を直書きしない。
- カード: 上段に親・親の親（`… › 親 › 親`、長ければ省略）と右上にバージョンタグ、太字の件名、下段に `#番号`（Redmine へのリンク）・未着手で日程が決まっていれば「着手 M/D(曜)」・作業完了予定・締切、進行中なら進捗ボタン（0/20/40/60/80。今のものは塗り、過ぎたものは薄塗り）。締切超過のカードは左に赤線。保存中は薄く＋スピナー。
- ドラッグで列を移動（ステータス変更、元に戻すトースト）。ドラッグ中だけ画面下に「ここにドロップすると「中止」」の帯。上司完了への移動・そこからの差し戻しは上司だけ（禁止の列は斜線表示）。**ドロップ後に描き直すと dragend が来ないことがあるので、片付けは endDrag() にまとめて drop でも呼ぶ。**
- キーボード: カードで ← → で隣の列、Enter で編集。
- **詰まりのサイン**（件名の下）: ① 先行の仕事が未完了なら「⏳ 待ち: 名前「件名（16字）」ほかN件」（相手が同じ担当なら「自分」）、
  先行がすべて完了した未着手は「✓ 前の仕事が終わりました。着手できます」。② 進行中でステータスが `staleDays`（5）営業日以上変わっていなければ「N日動きなし」
  （変更履歴の status_id 変更日。なければ作成日。日程の書き直し・コメントでは動いた扱いにしない）。どちらも画面表示のあと裏で読む
  （つながりは `issuesByIds(ids,'relations')`、相手は `issuesByIds`、履歴は進行中だけ同時 4 件）。サマリーに「待ち」「止まっている」の件数。
- **★ 優先してほしい**: カード右上（タグの左）の `☆` / `★ 優先` ボタン（★ のカードは枠を黄色に）。保存先は Redmine の優先度（`/enumerations/issue_priorities.json`、一覧の並びは低い→高い）。既定より上なら ★。押すと既定の 1 つ上 ⇔ 既定を切り替え（元に戻すトースト）。編集画面にもチェック「★ 優先してほしい」。一覧が読めなければ出さない。サマリーに「★優先 N」。課題バラシの箱にも「★優先」。並び: 余裕が少ない順は 緊急 → ★ → 余裕、いつもの順は日程を決めていないカードの中で ★ を先に。
- **手持ちの上限**: 進行中が `wipLimit`（5）件を超えたら列見出しに「上限5件を超えています」（黄）と件数を黄色に。
- **同じ列の中で上下にドラッグ = 自分の作業順**（5.6）。差し込み位置に青い線（カードの上辺、列の最後なら下に線）。
- ステータスを変えたら、親チケットのステータスを子に合わせる（5.12）。自分のカードを進行中・担当完了にしたら工数を聞く（5.10）。

### 5.6 並び順と自分の作業順
- 並び順の切り替え（サマリーの右、localStorage `designBoard.boardSort`）: `並び: いつもの順` / `並び: 余裕が少ない順`（値 `mine` / `slack`。古い値 `deadline` は `slack` とみなす）。
- **いつもの順**: 未着手は「開始日が今日以降」のものを開始日順に上、それ以外はその後ろに 基本順（バージョン番号 → 締切 → 番号）。進行中は作業完了予定（期日）順、期日なしは後ろに基本順。担当完了は基本順、上司完了は更新が新しい順。
  - **Redmine は新規チケットの開始日に作成日を自動で入れる**ので、「開始日がある」だけでは並び替えた印にならない。今日以降の開始日だけを印とみなす。
- **余裕が少ない順**: 表示だけ。緊急（バージョン番号 ≤ `urgentPriority`）は常に上 → ★優先 → 余裕の少ない順 → 基本順。余裕 = 締切（【M/D】、なければ期日）までの営業日数（今日を含む。過ぎていればマイナス）− 残りの作業日数（ceil(予定工数（未入力は `hoursPerDay`）×(1 − 進捗率) ÷ `hoursPerDay`)、最低 1）。締切なしは下。カードに「余裕 N日」（<0 赤、≤1 黄、それ以外 緑、緊急は赤で「緊急」）。このあいだは上下の並び替えはせず「「余裕が少ない順」で表示中は並び替えできません…」と表示。`この順番で日程を決める` でこの順を作業順として日程を決め、いつもの順に戻す。
- **作業順の日程計算（scheduleQueue）**: 進行中（上から）→ 未着手（上から）の順に、今日（営業日）から詰める。期間 = 予定工数 ÷ `hoursPerDay`（8）を営業日に切り上げ（未入力は 1 日、進行中は残り = 予定 × (1 − 進捗率)）。土日と `holidays` は休み。先行の仕事（`issuesByIds(..., 'relations')` で取る。範囲外の仕事は期日を取る）が終わっていなければその翌営業日から。進行中の開始日はそのまま（先行待ちのときだけ後ろへ）。先行より上に並べたら「前後のつながりに合わない順番があります: #A は #B の後でないと始められません」。
- 書き込み: 変わったものだけ、**開始日の早い順に** `start_date`/`due_date` を PUT（前の仕事の期日を先に直さないと Redmine が後ろの開始日を受け付けない）。先に画面を並べ替え、保存中表示。成功で「並び順に合わせて N 件の日程（開始日・作業完了予定）を決めました」＋元に戻す（元の値を逆順で戻す）。

### 5.7 カードの編集・新規タスク・バージョン作成
- カードのクリック／Enter で編集ダイアログ: 本来の締切（日付）・作業完了予定（期日）・件名・「Redmine に登録される件名」プレビュー・対象バージョン（＋ 新しいバージョン）・担当・説明・コメント追加（Redmine の履歴に残る）。変わった項目だけ PUT。
- **説明欄の下に、説明に含まれる http/https の URL を「リンク1」「リンク2」…のボタンで並べる**（入力に合わせて更新。重複は 1 つ。末尾の句読点は除き、閉じ括弧は対応する開き括弧がないときだけ除く。別タブ・`rel="noopener noreferrer"`）。
- 新規タスク: 担当はチェックボックスで複数選択可（「全員」「外す」）。2 人以上なら「まとめ用の親チケットを作り、各自のチケットをその下に入れる」（既定オン。親は件名に「（全員）」、担当なし）。**担当を空（またはバージョンを空）にすると「未整理に登録」で 1 件作って未整理へ**。開いているタブの人に最初からチェック。
- 新しいバージョン: カテゴリ選択＋個別名 →「作られる名前: …」→ 作成。**全員に出す**（権限がなければ「バージョンを作る権限がありません（Redmine の役割に「バージョンの管理」が必要です）」）。

### 5.8 未整理タブ
- 対象: 担当かバージョンが空の未完了チケット。**子チケットを持つもの（中項目）は出さない**。
- 左: 受信日時の新しい順の一覧（`#番号` 受信日時、足りないもの「担当・バージョンなし」、親の連なり、件名）。右: 振り分けフォーム（5.7 と同じ欄、元の件名を表示）。
- ボタン: `タスクではない`（削除せず「中止」に。Power Automate の重複判定に使うため）、`課題バラシで分解する`（件名とバージョン必須、担当は任意。保存してそのチケットを親に課題バラシへ）、`整理して登録` / `締切なしで登録`（人数分なら「（N 人分）」）。

### 5.9 全体ボード（全員に出す。Teams の画面共有で 1 画面）
- 上のタイル 5 つ: 締切超過 / 今週の締切 / 2週間で完了 / 日程の見直しが必要な仕事（赤）/ 止まっている仕事（5営業日以上、赤）。
- 左パネル「いま抱えている仕事（多い順）」: 表示切替 `積み木` / `タイムライン`（localStorage）。
  - 積み木: 人ごとに、締切超過・間近の仕事を名前付きの積み木で最大 4 件、残りは「ほか N 件」を作業量に比例した長さで。行をクリックでその人のボード。
  - タイムライン: 過去の平日 10 日の完了数と、これからの平日 10 日の締切数（週末は金曜に含める）。
- 右パネル: 「みんなでやる仕事」（同じ親・同じ件名のチケット群。完了 n/m とまだの人）＋「仕事ごとの状況（締切が前後2週間のタスク）」: バージョンごとに進捗率とバッファ消費（CCPM）。バッファ = 締切 − 作業完了予定。消費が 0.3 + 進捗×0.7 を超えたら「見直し」（赤）、0.1 + 進捗×0.6 を超えたら「注意」（黄）、それ以外「順調」（緑）。
- **休みの予定**（右パネルの一番上「これからの休み（2週間）」）: 起動時に `milestones` を読み、名前に休みの言葉があるものだけを休みにする（1日: 年休|有休|有給|休暇|代休|振休|特休|夏休|冬休|全休|休み、半日: 半休|半日|午前休|午後休|AM休|PM休、「出勤」「出社」を含めば除く）。項目は name/title/subject と start_date/date/milestone_date/due_date/effective_date/end_date/target_date を順に探す（作成・更新日時は除く）。期間は土日を除いて毎日、31 日超は初日だけ。だれ: フルネーム → チームで一意の名字 →（同じ名字が複数なら）名字＋名の1文字目。「小林」の中の「林」は除く。決まらなければ「だれの休みか分からない予定: …。同じ名字の人がいるときは「田中太半休」のように…」。404 は何も出さない、それ以外のエラーは「休みの予定（Lychee のマイルストーン）を読めませんでした: …」、形が分からなければ項目名だけを出す。積み木の名前の下に「休み 10/22(木)・10/24(金)半休」、タイムラインの日の欄に「休」「半」、個人ボードのサマリーにも「休み …」。1日休みは `isOffDay(d, uid)` で担当者の作業日から外す（作業順・課題バラシの日程・余裕・止まっている日数）。半休は表示だけ。
- **親チケットのまとめての見直し（sweepParents）は上司が全体を開いたときだけ**（メンバーは「完了（確認済）」を付けられずエラーになる）。10 分に 1 回まで、裏で。

### 5.10 工数
- チームのメンバー（か自分）のカードを進行中・担当完了にしたら、右下に「#番号 件名 — 今回の作業時間は？（ほかの人のカードなら「— 伊藤さんの今回の作業時間は？」） [0.5h][1h][2h][4h][1日(8h)][記録しない]」（20 秒で消える。最新 1 件だけ）。押すとその日の**担当者の**作業時間を記録（自分以外なら `user_id` を付ける。403/422 は「ほかの人の作業時間として記録する権限がないようです（Redmine のロールで「他のユーザーの作業時間を記録」…）」、返ってきた user が違えば「…あなたの時間として記録されました」とエラー）、コメント「ボードから記録（ステータス名）」。接続設定でオフにできる。
- `工数` ダイアログ:
  - 日々の記録: 日付（今日まで）、その日に動かしたチケット＋その日に記録済みのチケットを並べ、`+0.5 +1 +2 +4` と数値欄で追加。合計／8h のバー（超えたら黄）。「ほかのチケットを追加…」は optgroup「自分の仕事」「ほかの人の仕事（自分の作業時間として記録）」（`teamIssues`、担当名つき、ダイアログを開くたびに読み直す）＋ `#番号` 欄と「追加」（`getIssue` で確かめる）。担当が自分でない行には「担当: ○○」。`記録する`。修正・削除は Redmine で。
  - 編集画面にも「作業時間を記録（今日）」: ほかの人の仕事なら切替「○○さん（担当）」（既定）／「自分（手伝った分）」。`+0.5h +1h +2h +4h +1日(8h)` で即記録。
  - 月の集計: 月（今月〜3か月前）、自分 / チーム全員、バージョン別 / プロジェクト別。表（行 = 個別名＋正式名、列 = 人、合計）。`CSV で保存`（BOM 付き UTF-8、CRLF、**ファイル名は ASCII `kousu_YYYY-MM[_team].csv`**。日本語名は環境によって無視される）。

### 5.11 課題バラシ
- 範囲（上の選択欄）: `バージョン: …`（番号順）/ `担当者: …` / `親チケット: …`（範囲内の枠をインデントで）。最初はいちばん番号の小さいバージョン。
- 上の 1 段目: 範囲、並び（`並び: つながり優先` / `並び: 締切が近い順`、localStorage）、`完了を隠す`（既定オン）、`一番長い流れを赤く`（既定オン）、合計（予定・実績・一番長い流れ N h（約 M 日））、`＋ タスク`。2 段目: `着手`（日付）、`工数を入れたら日程も反映`（既定オン）、`日程を反映（N件）`。その下に操作のヘルプ帯。
- **表示**: 親子 = 枠の入れ子（枠の見出しが親の箱。▾/▸ で畳む: 選択中の見出しをもう一度クリック）。前後 = Redmine の「先行」を左→右の矢印（SVG、ベジエ。**右から左へ戻る矢印は箱の下を回す**）。
- **配置**: 各枠の中は CSS グリッド。列 = 段（前の仕事がなければ 0、あれば前の段 + 1）、行 = レーン。**つながった仕事は同じ行に横一列**、分岐した先だけ下の行。長くつながる流れほど上、単独の仕事は下（締切順のときは締切の近い順を優先）。使っていない行は詰める。中の仕事どうしのつながりは、それぞれが属する兄弟に「持ち上げて」段を数える。**枠どうしで輪になることがある（A の中 → B の中、B の中 → A の中）ので、段・最長経路・日程計算はすべて「たどっている途中の仕事には戻らない」で守る**。
- 箱（幅 200px）: 担当者・親チケットの範囲ではバージョンタグ（左上）、件名、`#番号`・担当（押すとメンバー一覧で変更・担当を外す）・締切・子の数・ステータス（押すと選択肢で変更。上司完了は上司だけ）、進捗バー、予定工数（`予定工数 ＋` → 1h/2h/4h/1日/2日/3日/5日・数値・消す）と実績（実績 > 予定なら赤で「予定超え」）、📅 計算した日程（Redmine と違えば「未反映」、締切を超えれば「締切超え」、工数未入力なら「工数未入力→1日」）、範囲外とのつながり（`⏳ 待ち: 伊藤「…」` / `✓ 済: …` / `→ 次: …`）。
- 枠の見出し: 合計予定・実績・予定未入力の件数、完了を隠していれば「完了 N 件を隠し中」、担当者範囲の文脈の枠は「（この人の分だけ表示）」。
- つまみ（ホバー・選択で表示）: 左右下の ＋（前・後・中を追加）、⤳（ドラッグで矢印だけつなぐ）、✎（編集画面）、×（中止。枠には出さない）。枠の中のいちばん下に常に点線の `＋ ここに追加`（同じ階層に、つながりのない仕事）。
- 操作: 箱をドラッグして相手の左端（30%、見出しは 15%）＝前、右端＝後、真ん中＝中に入れる。枠の空き地に落とすと中に入れる、いちばん外に落とすと外に出す。矢印クリックで外す。**ダブルクリック = 編集画面**（保存したら読み直す）、**F2 = 名前だけ**、Alt+→/←/↓ で後・前・中を追加。新しい箱は**名前を入れて Enter で Redmine に作る**（入れずにやめれば作らない）。担当とバージョンは元の箱から（担当者範囲ではその人）。
- 制約: 親と中の仕事どうしはつなげない（Redmine の制限）、輪になるつながりは作らない。**親を変えるときは、新しい親・祖先とのつながりを先に外す**（残っていると Redmine が親の変更を拒む）。
- 読み込み: 範囲のチケットを取り、**つながりは一覧の `include=relations` でまとめて取る**（50 件ごと）。一覧につながりが付かない Redmine だけ 1 件ずつ（同時 4 件）。**実績工数は画面を出したあと裏で 1 件ずつ取る**（同時 3 件、失敗しても無視、範囲を切り替えたら中断）。中止のチケットは出さず、中止とのつながりは数えない。担当者範囲では、その人のチケットの親を 4 階層まで文脈として読む。範囲外の相手の件名・担当は `issuesByIds` で取る。
- 完了を隠す: 完了（担当完了・上司完了）の末端と、中がすべて完了の枠を外し、左の欄（幅 220px、狭い画面では出さない）に新しく終わった順で「親名 / 件名」を並べる。このとき一番長い流れは残りの仕事だけで数え「残りの一番長い流れ」。
- 一番長い流れ: 末端の仕事の単位で（枠から出る矢印は枠の中の最後の仕事から、枠へ入る矢印は最初の仕事へ）、予定工数の合計が最大の連なり（工数が 1 件もなければ件数）。3 件以上の連なりのとき赤い矢印。
- 日程の自動計算: 5.6 と同じ考え方を、範囲の末端の仕事について前後のつながりで行う（先頭は自分の開始日か「着手」の日、後ろは前の仕事が全部終わった翌営業日から。範囲外の先行の期日も見る。完了は動かさない。親の日付は書かない）。進行中で前の仕事が終わっていないときは、その翌営業日から（**Redmine は先行の期日より前の開始日を受け付けない**）。`工数を入れたら日程も反映` は、工数を変えた仕事とその後ろにつながる仕事だけ書く（手入力の日程を触らない）。`日程を反映（N件）` は範囲内の未反映すべて。開始日の早い順に書き、元に戻せる。
- ステータスの変更は 5.12 の親の同期と 5.10 の工数の確認を行う。

- **前後以外のつながり**: Redmine は 2 つの間に関連を 1 つしか持てない。前後をつなぐのは `addPrecedes(from, to)`: 失敗して文言に すでに|既に|already|taken|存在 があれば `issueDetail(from)` の relations から相手が to のものを探し、あれば `err.existing = { rels, from, to }` と「#A と #B の間には、すでに「種類」のつながりがあるので、前後でつなげません（Redmine は 2 つの間につながりを 1 つしか持てません）」。bRun はこのときエラーのトーストに `外して前後にする`（15 秒）を付け、押すと全部外して前後でつなぐ。種類の名前（このチケットから見て。逆向きは relates↔relates, duplicates↔duplicated, blocks↔blocked, precedes↔follows, copied_to↔copied_from）: relates 関連している / duplicates 重複している（相手が残る）/ duplicated 重複されている / blocks ブロックしている / blocked ブロックされている / precedes 後ろの仕事 / follows 前の仕事 / copied_to コピー先 / copied_from コピー元。編集画面の「つながり（Redmine の関連）」に全部（種類・#番号 件名（担当の名字）・`外す`）。外したら閉じたときに課題バラシを読み直す。モックは 4521–4523 に「関連している」を 1 つ持ち、同じ 2 つへの追加は 422「関連しているチケットはすでに存在します」。

- **操作のあとの読み直しは部分だけ**: bRun の間は `api` を Proxy（bTracking）に差し替え、updateIssue（親を変えたら新旧の親も）・addRelation（両端）・removeRelation（両端）・createIssue（作ったものと親）・createTimeEntry で触ったチケットを控える。終わったら `bRefresh(ids)`: 控えたものとその親・祖先を `issuesByIds(ids, 'relations')` の 1 回で読み直し、中止なら消す、範囲（バージョン／担当／親の下）から外れたら消す、見えなくなったものも消す。担当者の表示では新しく要る親を文脈として足す。つながりは全チケットの relations から組み直す（bBuildRels。範囲外の相手は `B.others` に控え、まだ読んでいない相手だけ読む）。失敗したら全部読み直す（loadBara）。実績工数は `B.spent` に控え、読み直しで消えないようにする（作業時間を記録したチケットだけ読み直す）。編集画面を閉じたときも、編集したチケットと外したつながりの相手だけ読み直す。

### 5.12 親チケットのステータスを子から決める（すべての親子、親の親まで）
- 子（中止を除く）が全員 未着手 → 未着手 / 全員 完了（確認済）→ 完了（確認済）/ 全員 完了以上 → 完了（実務者）/ それ以外 → 子の進捗の平均（未着手 0、完了 100）を 20% 刻みで切り捨てた進行中ステータス。
- 親が中止・未知のステータスなら触らない。変えたら「親チケットも子に合わせました: #… 「…」」。

### 5.13 使い方ページ
- 右上 `使い方` で全画面のダイアログ（付録 B の本文そのまま）。見出し「計画のメンテが面倒すぎたので、ボードにしました。」、署名「つくったひと より ／ 読む時間 約5分」。目次リンクはページ内スクロールだけ（URL を変えない）。Esc・外側クリックで閉じる。

- 使い方ページの最後（「おわりに」の後）に「10 変更履歴」（目次にも）。版ごとに `<dt><b>v15.2</b><span>日付</span></dt><dd><ul>…</ul></dd>`、新しい版が上。版を上げたらここに足す。

### 5.14 接続設定
- データの取得元（中継／モック／直接）、直接のときだけ URL と API キー、`工数` のチェック（進捗を動かしたときに作業時間を聞く）、接続テスト、ボードの版と中継の版・フォルダ・警告の表示。

---

## 6. デザイン（付録 A の CSS が正）

- フォント: 本文 `BIZ UDPGothic`（代替: Yu Gothic UI, Meiryo UI, Meiryo, Hiragino Sans）、数字 `IBM Plex Mono`（代替: Consolas, Menlo）。
- 色はすべて CSS 変数（`--bg #e9edf1`、`--surface #fff`、`--accent #0e6488`、`--late #b8322a`、`--soon #8a5a00`、`--ok #2c7a4b`、タグ 6 色 など）。ダークモードは `prefers-color-scheme: dark`（`:root:not([data-theme="light"])`）と `:root[data-theme="dark"]` の両方で同じ値に切り替える。
- レイアウト: 固定ヘッダー＋タブ＋サマリー、残りの高さにボード。列の中だけスクロール。860px 以下では横スクロールの列（最小 250px）と 1 列のフォーム。
- 角丸 6〜12px、影は弱め（`--shadow`）。トーストは右下に積む（エラーは赤、7 秒。通常 5 秒）。
- **CSS・HTML を自分で書き直さず、付録 A・B をそのまま使うこと。** クラス名・id を変えないこと（JS が依存している）。

---

## 7. 進め方（この順で、段階ごとに確認）

1. 付録 A・B・C を使って `src/kanban.fragment.html` の骨組みを作る（`<!--BODY-->` の位置、`/*__SERVER_CONFIG__*/` の位置を守る）。
2. 共通部品（h、日付、parseTitle/buildTitle、parseVersion、deadlineInfo）と**モック API**（見本データ: 6 人・6 バージョン・約 50 件・メール由来の未整理 6 件・作業時間 先月〜昨日・前後のつながり数本）。
3. 個人ボード → 編集・新規・バージョン作成 → 未整理 → 全体 → 工数 → 課題バラシ → 作業順 → 使い方 の順に実装し、毎回モックで確認。
4. Redmine API 層（5.2）。
5. build.py と kanban_relay.py（4 章）。
6. テスト（9 章）。

---

## 8. セルフデバッグで分かった落とし穴（必ず守る）

1. `replaceChildren` / `append` に null を渡すと「null」と表示される → 必ず `filter(Boolean)`。h() の子は 1 段しか flat しないので、配列の入れ子に注意。
2. Redmine は権限・ワークフローで許可されない変更を**エラーにせず黙って無視**する → PUT のあと GET で確かめる（5.2）。
3. ステータス ID は環境ごとに違う → 列へのドロップ先は statuses から決める。直書き禁止。
4. 「完了（確認済）」は上司だけ → メンバーの操作で親の一括見直しをしない（全体を開いたときの見直しは上司だけ）。
5. Redmine は CORS を許可しないことが多い → 中継経由が既定。SharePoint の .aspx ではスクリプトが止められる。
6. 再起動スレッドは `daemon=False` を明示。画面なしで起動する子プロセスは DETACHED_PROCESS / start_new_session。
7. 古い版の中継が残り続ける（別のフォルダで動いている、再起動に応じない、スタートアップの古い .cmd）→ /ping の版で確かめ、違えばポートの持ち主を止めて入れ替える。古い .cmd は見つけしだい消す。
8. 共有フォルダからプログラムを自動で入れ替えない（RCE になる）。新旧は (VERSION, BUILD) で比べ、知らせるだけ。設定ファイルの接続先は check_destination で守る。
9. 中継で `RemoteDisconnected` 等を捕まえないと処理が落ち、ボードからは「中継につながらない」に見える。GET は再試行。
10. チケットごとの詳細取得を大量に投げると不安定な回線で失敗する → 一覧の `include=relations` でまとめる。実績は後から裏で。
11. `issue_id=` の一覧は 50 件ずつ（URL が長すぎると失敗）。
12. 新規チケットの開始日には作成日が入る → 並び替えの印は「今日以降の開始日」だけ。
13. 先行関係: 親子間は不可、輪は不可、親を変える前に祖先とのつながりを外す、開始日は先行の期日より後。書き込みは開始日の早い順。
14. 枠どうしで輪になる → 段・最長経路・日程はすべて「たどり中には戻らない」。そうしないと列番号が 50 などに膨らみ、画面のはるか右に飛ぶ。
15. 新しい箱の名前入力は、描画直後に同期でフォーカスする（requestAnimationFrame だと打ち始めの 1 文字目を落とす）。
16. ドロップ後の描き直しで dragend が来ない → 中止帯などの片付けを endDrag() にまとめる。
17. 未整理には子を持つチケット（中項目）を出さない。
18. メンバー: 名前のないユーザー（削除・ロック）を除く。上司の ID は `"12"` のような文字列でも受ける。名前は空白の有無を無視して照合。
19. CSV のファイル名は ASCII（日本語は環境で無視され「download」になる）、BOM 付き。
20. 作業時間の記録には作業分類が要る → 既定の分類を自動で付ける。
21. バージョン名の区切りは `_` と `-` の両方を読む。
22. `.tag` は `margin-left:auto; max-width:55%` なので、課題バラシの箱の左上に置くときは `margin-left:0` に上書きし、右上のつまみ（64px）と重ならないようにする。
23. 長い保存（10 件以上の PUT）の途中で再読み込みすると中途半端な状態を読む → 保存中表示を出し、終わってから読み直す。
24. モックは本物と同じ制限（権限・422）を再現する。そうしないとモックでだけ動くものができる。
25. 「止まっている」を Redmine の更新日で判定しない。並び替えで日程を書き直すと全部「更新」されるので、変更履歴のステータス変更日を使う。

---

## 9. テスト（エラーゼロで終える）

- **モック**（`kanban.html` をダブルクリック → 「モックで試す」）と、**偽の Redmine**（Python の簡易サーバー: users/current、issue_statuses、memberships、versions、issues 一覧（issue_id / assigned_to_id / fixed_version_id / parent_id / status_id / child_id / include=relations）、issues/:id（include=relations で relations と spent_hours）、PUT/POST/DELETE、time_entries、enumerations）＋中継の両方で確認する。
- 自動テスト（Playwright など）で最低限これを確かめる。すべて **pageerror 0 件・画面に「null」の文字なし**:
  1. メンバーのタブ・全体・課題バラシ・未整理が出る（メンバーにも全体・課題バラシが出る）。
  2. 進捗ボタン → ステータス変更 → 工数の選択肢 → 記録。工数ダイアログの日々・月・CSV（ファイル名 `kousu_…csv`）。
  3. 列移動・中止帯・元に戻す。上司以外は上司完了に動かせない。
  4. 同じ列の上下の並び替え → 日程が書かれ、再読み込みしても順番が残る。余裕が少ない順（緊急が上、余裕の少ない順、「余裕 N日」）→ 並び替え不可の表示 → この順番で日程を決める。
  5. 未整理: 振り分け登録、タスクではない、課題バラシで分解する（子を作ると未整理から消える）。新規タスクの担当なし → 未整理に増える。
  6. 課題バラシ: 範囲切り替え（バージョン・担当者・親）、＋で前後中を追加、ここに追加、ドラッグで前・後・中、⤳でつなぐ、矢印クリックで外す、予定工数 → 日程の自動反映、ステータス・担当の変更、ダブルクリックで編集画面、F2、完了を隠す、締切が近い順。枠どうしの輪があっても箱が画面外に飛ばない。同じ枠の中の矢印は水平。
  7. 説明欄の URL がリンク1/リンク2…になる（`…/a(b)` の括弧を残す、末尾の「。」は除く）。
  8. 中継: Host 偽装・他オリジンの拒否、許可リスト外の 403、接続の 25% を切る不安定な偽 Redmine で課題バラシを 10 回読み込んで全部成功。
  9. 中継: 接続先を書き換えた board_settings.json → ログオン時起動はキーを送らずに止まる（偽の受け手にキーが届かない）。ダブルクリックで no → 中止、yes → 送り先を記録し直す。共有フォルダに新しい版 → 自動では入れ替わらず /ping に update_available。古い版の中継が動いている状態でダブルクリック → 止めて入れ替わる。
  10. スマホ幅（390px）とダークモードで横にはみ出さない。

---

## 付録について

以下の付録 A〜D は、元のソースからそのまま抜き出したものです。**一字一句そのまま使ってください**（書き換えると見た目や動作が変わります）。

## 付録 A. `<head>` の先頭と CSS 全文（src/kanban.fragment.html の `<style>` 〜 `</style>`）

```html
<title>タスクボード</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=BIZ+UDPGothic:wght@400;700&family=IBM+Plex+Mono:wght@500&display=swap">
<style>
/* Layout: 固定ヘッダー + 4列ボード（列の中だけ縦スクロール、ページはスクロールしない） */
:root {
  --bg: #e9edf1;
  --surface: #ffffff;
  --surface-2: #f4f6f9;
  --ink: #18212c;
  --ink-2: #576272;
  --ink-3: #8a94a2;
  --line: #d3dae2;
  --accent: #0e6488;
  --accent-ink: #ffffff;
  --accent-soft: #dcecf3;
  --accent-mid: #8fbcd3;
  --late: #b8322a;
  --late-bg: #fbe7e4;
  --soon: #8a5a00;
  --soon-bg: #fcefcf;
  --ok: #2c7a4b;
  --ok-bg: #e0f1e6;
  --drop: #cfe3ee;
  --shadow: 0 1px 2px rgba(20, 36, 52, .08), 0 2px 8px rgba(20, 36, 52, .05);
  --tag1-bg: #dfe9fb; --tag1-fg: #1f4c9a;
  --tag2-bg: #dff3ea; --tag2-fg: #1d6a46;
  --tag3-bg: #fbe8d9; --tag3-fg: #934514;
  --tag4-bg: #f3e1f1; --tag4-fg: #85306f;
  --tag5-bg: #e5e8ee; --tag5-fg: #3d4757;
  --tag6-bg: #f6f0d2; --tag6-fg: #6e5a0c;
  --font-ui: "BIZ UDPGothic", "Yu Gothic UI", "Meiryo UI", "Meiryo", "Hiragino Sans", sans-serif;
  --font-num: "IBM Plex Mono", "Consolas", "Menlo", monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #11161c; --surface: #1a2129; --surface-2: #212932; --ink: #e5eaf0; --ink-2: #a0abb8; --ink-3: #6f7a88;
    --line: #2d3641; --accent: #5fb0d8; --accent-ink: #0b1a22; --accent-soft: #183442; --accent-mid: #4b8fb0;
    --late: #ff8f80; --late-bg: #3b1d1a; --soon: #f0c064; --soon-bg: #362a0e; --ok: #74d39a; --ok-bg: #16301f;
    --drop: #1b3a4a; --shadow: 0 1px 2px rgba(0,0,0,.35);
    --tag1-bg: #1c2d4a; --tag1-fg: #9dbdf4; --tag2-bg: #17322a; --tag2-fg: #8fd8b3; --tag3-bg: #3a2516; --tag3-fg: #f2b184;
    --tag4-bg: #36203a; --tag4-fg: #e7a6da; --tag5-bg: #262d37; --tag5-fg: #b9c2cf; --tag6-bg: #332d12; --tag6-fg: #e3cf7c;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #11161c; --surface: #1a2129; --surface-2: #212932; --ink: #e5eaf0; --ink-2: #a0abb8; --ink-3: #6f7a88;
  --line: #2d3641; --accent: #5fb0d8; --accent-ink: #0b1a22; --accent-soft: #183442; --accent-mid: #4b8fb0;
  --late: #ff8f80; --late-bg: #3b1d1a; --soon: #f0c064; --soon-bg: #362a0e; --ok: #74d39a; --ok-bg: #16301f;
  --drop: #1b3a4a; --shadow: 0 1px 2px rgba(0,0,0,.35);
  --tag1-bg: #1c2d4a; --tag1-fg: #9dbdf4; --tag2-bg: #17322a; --tag2-fg: #8fd8b3; --tag3-bg: #3a2516; --tag3-fg: #f2b184;
  --tag4-bg: #36203a; --tag4-fg: #e7a6da; --tag5-bg: #262d37; --tag5-fg: #b9c2cf; --tag6-bg: #332d12; --tag6-fg: #e3cf7c;
  color-scheme: dark;
}

*, *::before, *::after { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.5 var(--font-ui);
  overflow: hidden;
}
[hidden] { display: none !important; }
button, input, select { font: inherit; color: inherit; }
button { cursor: pointer; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.app {
  height: 100%;
  display: grid;
  grid-template-rows: auto auto 1fr;
  padding-inline: 16px;
  padding-block: 12px 14px;
  gap: 10px;
}

/* ---------- ヘッダー ---------- */
.topbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 18px; }
.brand { display: flex; align-items: baseline; gap: 10px; min-width: 0; }
.brand h1 { margin: 0; font-size: 18px; font-weight: 700; letter-spacing: .02em; }
.brand .today { color: var(--ink-2); font-size: 13px; font-variant-numeric: tabular-nums; }
.mode-pill {
  font-size: 11px; letter-spacing: .08em; padding: 2px 8px; border-radius: 999px;
  background: var(--soon-bg); color: var(--soon); font-weight: 700;
}
.mode-pill.live { background: var(--ok-bg); color: var(--ok); }
.topbar .spacer { flex: 1 1 auto; }
.tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.btn {
  border: 1px solid var(--line); background: var(--surface); border-radius: 6px;
  padding: 5px 12px; font-size: 13px;
}
.btn:hover { border-color: var(--ink-3); }
.btn.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
.mock-user { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--ink-2); }
.mock-user select { border: 1px solid var(--line); background: var(--surface); border-radius: 6px; padding: 4px 6px; font-size: 13px; }

/* ---------- メンバー切替 + 状況サマリー ---------- */
.subbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; }
.tabs { display: flex; flex-wrap: wrap; gap: 4px; padding: 3px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; }
.tab {
  border: 0; background: transparent; border-radius: 6px; padding: 4px 12px; font-size: 13px; color: var(--ink-2);
}
.tab[aria-selected="true"] { background: var(--surface); color: var(--ink); font-weight: 700; box-shadow: var(--shadow); }
.tab .me { font-size: 10px; margin-left: 4px; padding: 0 5px; border-radius: 4px; background: var(--accent-soft); color: var(--accent); font-weight: 700; }
.summary { display: flex; flex-wrap: wrap; gap: 6px; font-size: 12px; }
.sort-ctl { display: inline-flex; gap: 6px; align-items: center; margin-left: 4px; }
.sort-ctl select { border: 1px solid var(--line); background: var(--surface); border-radius: 999px; padding: 1px 8px; font-size: 12px; color: var(--ink-2); }
.chip { padding: 2px 9px; border-radius: 999px; background: var(--surface-2); color: var(--ink-2); border: 1px solid var(--line); font-variant-numeric: tabular-nums; }
.chip b { font-family: var(--font-num); font-weight: 500; margin-left: 3px; }
.chip.late { background: var(--late-bg); color: var(--late); border-color: transparent; }
.chip.soon { background: var(--soon-bg); color: var(--soon); border-color: transparent; }

/* ---------- ボード ---------- */
.board-wrap { min-height: 0; overflow-x: auto; }
.board {
  height: 100%;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.col {
  min-height: 0; min-width: 0;
  display: flex; flex-direction: column;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 10px;
  transition: background-color .12s, border-color .12s;
}
.col-head {
  display: flex; align-items: baseline; gap: 8px;
  padding: 10px 12px 8px;
  border-bottom: 1px solid var(--line);
}
.col-head h2 { margin: 0; font-size: 14px; font-weight: 700; }
.col-head .sub { font-size: 11px; color: var(--ink-3); }
.col-head .count { margin-left: auto; font-family: var(--font-num); font-size: 12px; color: var(--ink-2); }
.col-head .lock { font-size: 11px; color: var(--ink-3); border: 1px solid var(--line); border-radius: 4px; padding: 0 5px; }
.col-body {
  flex: 1 1 auto; min-height: 0; overflow-y: auto;
  display: flex; flex-direction: column; gap: 8px;
  padding: 10px;
}
.col.drag-over { background: var(--drop); border-color: var(--accent); }
.col.drag-denied { opacity: .55; }
.col[data-col="approved"] .card { background: var(--surface-2); }
.col[data-col="approved"] .subject { color: var(--ink-2); }
.empty { margin: 4px 2px; font-size: 12px; color: var(--ink-3); }

/* ---------- カード ---------- */
.card {
  position: relative;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 9px 11px 10px;
  box-shadow: var(--shadow);
  display: flex; flex-direction: column; gap: 5px;
  cursor: grab;
}
.card:hover { border-color: var(--ink-3); }
.card.dragging { opacity: .4; }
.card.drop-before { box-shadow: 0 -4px 0 var(--accent), var(--shadow); }
.col-body.drop-end::after { content: ""; display: block; height: 4px; border-radius: 2px; background: var(--accent); margin: 2px 0; }
.card .flag { margin-left: auto; flex: none; border: 1px solid transparent; background: transparent; color: var(--ink-3); border-radius: 4px; padding: 0 5px; font-size: 12px; line-height: 1.6; cursor: pointer; }
.card .flag:hover { border-color: var(--soon); color: var(--soon); }
.card .flag.on { background: var(--soon-bg); color: var(--soon); font-weight: 700; border-color: var(--soon); }
.card .flag + .tag { margin-left: 6px; }
.card.flagged { box-shadow: inset 0 0 0 1px var(--soon), var(--shadow); }
.bara .bx .meta .flag-b { color: var(--soon); font-weight: 700; }
.card .slack { font-size: 11px; font-weight: 700; border-radius: 4px; padding: 0 6px; background: var(--ok-bg); color: var(--ok); font-variant-numeric: tabular-nums; }
.card .slack.low { background: var(--soon-bg); color: var(--soon); }
.card .slack.neg, .card .slack.urgent { background: var(--late-bg); color: var(--late); }
.card .start { font-size: 11px; color: var(--accent); font-variant-numeric: tabular-nums; }
.card.saving::after {
  content: "保存中…"; position: absolute; right: 8px; bottom: 6px;
  font-size: 10px; color: var(--accent);
}
.card-top { display: flex; align-items: flex-start; gap: 8px; min-height: 18px; }
.parent {
  min-width: 0; flex: 1 1 auto;
  font-size: 11px; color: var(--ink-3);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.tag {
  margin-left: auto; flex: 0 0 auto;
  font-size: 11px; font-weight: 700; line-height: 1.6;
  padding: 0 7px; border-radius: 4px;
  max-width: 55%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.tag.t1 { background: var(--tag1-bg); color: var(--tag1-fg); }
.tag.t2 { background: var(--tag2-bg); color: var(--tag2-fg); }
.tag.t3 { background: var(--tag3-bg); color: var(--tag3-fg); }
.tag.t4 { background: var(--tag4-bg); color: var(--tag4-fg); }
.tag.t5 { background: var(--tag5-bg); color: var(--tag5-fg); }
.tag.t6 { background: var(--tag6-bg); color: var(--tag6-fg); }
.subject { margin: 0; font-size: 14px; font-weight: 700; line-height: 1.45; overflow-wrap: anywhere; }
.card-foot { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.card-signals { display: flex; flex-direction: column; gap: 3px; }
.card-signals span { font-size: 11px; border-radius: 4px; padding: 1px 7px; align-self: flex-start; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-signals .wait { background: var(--soon-bg); color: var(--soon); }
.card-signals .ready { background: var(--ok-bg); color: var(--ok); font-weight: 700; }
.card-signals .stale { background: var(--surface-2); color: var(--ink-2); border: 1px dashed var(--ink-3); }
.col-head .wip { font-size: 11px; font-weight: 700; color: var(--soon); background: var(--soon-bg); border-radius: 4px; padding: 0 6px; }
.col.over-wip .col-head .count { background: var(--soon-bg); color: var(--soon); }
.num { font-family: var(--font-num); font-size: 11px; color: var(--ink-3); }
.num a { color: inherit; text-decoration: none; }
.num a:hover { text-decoration: underline; }
.due {
  margin-left: auto;
  font-size: 11px; font-variant-numeric: tabular-nums;
  padding: 1px 7px; border-radius: 4px; color: var(--ink-2); background: var(--surface-2);
}
.due.late { background: var(--late-bg); color: var(--late); font-weight: 700; }
.due.soon { background: var(--soon-bg); color: var(--soon); font-weight: 700; }
.due.none { color: var(--ink-3); background: transparent; padding-inline: 0; }
.card.is-late { border-left: 3px solid var(--late); padding-left: 9px; }

/* 進捗（ステータス 0%〜80% を切り替える） */
.progress { display: grid; grid-template-columns: repeat(5, 1fr); gap: 3px; margin-top: 2px; }
.progress button {
  border: 1px solid var(--line); background: var(--surface); border-radius: 4px;
  padding: 2px 0; font-family: var(--font-num); font-size: 11px; color: var(--ink-3);
  font-variant-numeric: tabular-nums;
}
.progress button.filled { background: var(--accent-soft); color: var(--accent); border-color: transparent; }
.progress button[aria-pressed="true"] { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
.progress button:hover:not([aria-pressed="true"]) { border-color: var(--accent); }

/* ---------- 中止ドロップゾーン ---------- */
.cancel-zone {
  position: fixed; left: 50%; bottom: calc(14px + env(safe-area-inset-bottom, 0px)); transform: translateX(-50%);
  padding: 10px 26px; border-radius: 999px; border: 2px dashed var(--late);
  background: var(--surface); color: var(--late); font-weight: 700; font-size: 13px;
  box-shadow: var(--shadow); z-index: 5;
}
.cancel-zone.drag-over { background: var(--late-bg); }

/* ---------- トースト ---------- */
.toasts {
  position: fixed; right: 16px; bottom: calc(16px + env(safe-area-inset-bottom, 0px));
  display: flex; flex-direction: column; gap: 8px; z-index: 10; max-width: min(420px, calc(100% - 32px));
}
.toast {
  display: flex; align-items: center; gap: 12px;
  background: var(--ink); color: var(--bg); border-radius: 8px; padding: 9px 14px; font-size: 13px;
  box-shadow: 0 6px 20px rgba(0,0,0,.18);
}
.toast.error { background: var(--late); color: #fff; }
.toast button { border: 0; background: transparent; color: inherit; text-decoration: underline; font-weight: 700; padding: 0; }

/* ---------- 設定ダイアログ ---------- */
.overlay { position: fixed; inset: 0; background: rgba(10, 16, 22, .45); display: grid; place-items: center; z-index: 20; padding: 16px; }
.dialog {
  width: min(520px, 100%); max-height: 100%; overflow: auto;
  background: var(--surface); border-radius: 12px; padding: 20px 22px; box-shadow: 0 12px 40px rgba(0,0,0,.25);
  display: flex; flex-direction: column; gap: 14px;
}
.dialog h2 { margin: 0; font-size: 16px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label, .field .label { font-size: 12px; color: var(--ink-2); font-weight: 700; }
.field input[type="text"], .field input[type="password"] {
  border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 7px 9px; font-family: var(--font-num); font-size: 13px;
}
.radios { display: flex; gap: 16px; flex-wrap: wrap; }
.hint { font-size: 12px; color: var(--ink-3); margin: 0; }
.test-result { font-size: 12px; margin: 0; padding: 8px 10px; border-radius: 6px; background: var(--surface-2); color: var(--ink-2); white-space: pre-wrap; }
.test-result.ok { background: var(--ok-bg); color: var(--ok); }
.test-result.ng { background: var(--late-bg); color: var(--late); }
#versionInfo { white-space: pre-wrap; }
.dialog-actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }

.loading { display: grid; place-items: center; color: var(--ink-3); font-size: 13px; }

/* 中継プログラムにつながっていないときの案内 */
.tabs:empty { display: none; }
.connect { grid-column: 1 / -1; display: grid; place-items: center; padding: 16px; }
.connect-card {
  width: min(560px, 100%); background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
  padding: 22px 24px; display: flex; flex-direction: column; gap: 14px; box-shadow: var(--shadow);
}
.connect-card h2 { margin: 0; font-size: 17px; }
.connect-card p { margin: 0; color: var(--ink-2); }
.steps { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 10px; counter-reset: step; }
.steps li { display: grid; grid-template-columns: 26px 1fr; gap: 10px; align-items: start; counter-increment: step; }
.steps li::before {
  content: counter(step); display: grid; place-items: center; width: 24px; height: 24px; border-radius: 50%;
  background: var(--accent-soft); color: var(--accent); font-family: var(--font-num); font-size: 12px;
}
.steps li span { padding-top: 2px; }
.connect-card .waiting { font-size: 12px; color: var(--ink-3); display: flex; align-items: center; gap: 8px; }
.connect-card .waiting::before {
  content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--soon);
  animation: blink 1.4s ease-in-out infinite;
}
@keyframes blink { 50% { opacity: .25; } }
.connect-card .links { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
a.btn { text-decoration: none; display: inline-block; }

/* タグ: 先頭の優先番号 + 名前 */
.tag .code { font-family: var(--font-num); font-weight: 500; margin-right: 4px; opacity: .85; }
.tag.urgent { background: var(--late); color: var(--surface); }
.plan { font-size: 11px; color: var(--ink-3); font-variant-numeric: tabular-nums; }
.plan.over { color: var(--soon); font-weight: 700; }

/* タブ: 未整理 */
.tab.inbox-tab { color: var(--ink); }
.tab .badge { margin-left: 5px; font-family: var(--font-num); font-size: 11px; padding: 0 6px; border-radius: 999px; background: var(--late); color: var(--surface); }
.tab .badge.zero { background: var(--line); color: var(--ink-2); }
.tab-sep { width: 1px; align-self: stretch; background: var(--line); margin: 2px 4px; }

/* ---------- 未整理の振り分け画面 ---------- */
.inbox {
  height: 100%; min-height: 0;
  display: grid; grid-template-columns: minmax(260px, 1fr) minmax(0, 1.7fr); gap: 12px;
}
.mail-list { list-style: none; margin: 0; padding: 10px; display: flex; flex-direction: column; gap: 6px; }
.mail {
  width: 100%; text-align: left; border: 1px solid var(--line); background: var(--surface); border-radius: 8px;
  padding: 8px 10px; display: flex; flex-direction: column; gap: 3px;
}
.mail:hover { border-color: var(--ink-3); }
.mail[aria-current="true"] { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.mail .meta { display: flex; gap: 8px; font-size: 11px; color: var(--ink-3); font-variant-numeric: tabular-nums; }
.mail .meta .missing { margin-left: auto; color: var(--soon); font-weight: 700; }
.mail .parent-line { font-size: 11px; color: var(--ink-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.mail .title { font-weight: 700; font-size: 13px; overflow-wrap: anywhere; }
.triage {
  min-height: 0; overflow-y: auto;
  background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px 18px; display: flex; flex-direction: column; gap: 14px;
}
.triage h2 { margin: 0; font-size: 15px; }
.triage .from { margin: 0; font-size: 12px; color: var(--ink-3); }
.triage .grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 16px; }
.triage input[type="text"], .triage input[type="date"], .triage select, .triage textarea {
  width: 100%; border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 7px 9px; font-size: 13px;
}
.triage textarea { min-height: 140px; resize: vertical; line-height: 1.6; }
.triage .row { display: flex; gap: 8px; align-items: center; }
.triage .row input { flex: 1 1 auto; min-width: 0; }
.triage .req { color: var(--late); margin-left: 3px; }
.preview { margin: 0; padding: 8px 10px; border-radius: 6px; background: var(--accent-soft); color: var(--ink); font-weight: 700; overflow-wrap: anywhere; }
.preview .lbl { display: block; font-size: 11px; font-weight: 400; color: var(--ink-2); }
.triage .error-msg { margin: 0; color: var(--late); font-size: 12px; }
.triage .actions { display: flex; gap: 8px; justify-content: flex-end; align-items: center; flex-wrap: wrap; }
.triage .actions .hint { margin-right: auto; }
.dialog.editor { width: min(760px, 100%); }
.editor .meta { margin: 0; font-size: 12px; color: var(--ink-3); display: flex; gap: 6px 14px; flex-wrap: wrap; }
.editor .head { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.editor .head a { font-size: 12px; color: var(--accent); }
.editor textarea#eNotes { min-height: 70px; }
.card { cursor: pointer; }
.new-version { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 6px; padding: 8px; border-radius: 6px; background: var(--surface-2); border: 1px dashed var(--line); }
.new-version select { width: auto !important; }
.new-version input { flex: 1 1 140px; min-width: 0; }
.new-version .pv { font-size: 12px; color: var(--ink-2); width: 100%; }
/* ---------- ダッシュボード（上司だけ）: Teams の画面共有で読める大きさにする ---------- */
.dash { height: 100%; min-height: 0; display: grid; grid-template-rows: auto minmax(0, 1fr); gap: 12px; font-size: 15px; }
.dash .tiles { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; }
.dash .tile { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; display: flex; align-items: baseline; gap: 10px; }
.dash .tile .v { font-family: var(--font-num); font-size: 30px; line-height: 1; }
.dash .tile .k { color: var(--ink-2); font-size: 14px; }
.dash .tile.bad .v { color: var(--late); }
.dash .main { min-height: 0; display: grid; grid-template-columns: minmax(0, 2.2fr) minmax(280px, 1fr); gap: 12px; }
.dash .panel { min-height: 0; overflow: auto; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; display: flex; flex-direction: column; gap: 10px; }
.dash .panel-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.dash h2 { margin: 0; font-size: 17px; }
.dash .seg, .hours .seg { margin-left: auto; display: flex; padding: 3px; gap: 3px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2); }
.dash .seg button, .hours .seg button { border: 0; background: transparent; color: var(--ink-2); font-size: 13px; padding: 4px 12px; border-radius: 6px; }
.dash .seg button[aria-pressed="true"], .hours .seg button[aria-pressed="true"] { background: var(--surface); color: var(--ink); font-weight: 700; box-shadow: var(--shadow); }
.dash .legend { display: flex; flex-wrap: wrap; gap: 6px 16px; font-size: 13px; color: var(--ink-2); }
.dash .legend i { display: inline-block; width: 14px; height: 12px; border-radius: 3px; vertical-align: -1px; margin-right: 5px; }
.dash .sw-late { background: var(--late-bg); box-shadow: inset 3px 0 var(--late); }
.dash .sw-soon { background: var(--soon-bg); box-shadow: inset 3px 0 var(--soon); }
.dash .sw-norm { background: var(--surface-2); border: 1px dashed var(--line); }
.dash .sw-done { background: var(--accent); }
.dash .sw-due { background: var(--accent-mid); }
.dash .who { display: flex; flex-direction: column; min-width: 0; }
.dash .who b { font-size: 18px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dash .who span { font-size: 13px; color: var(--ink-2); }
.dash .load { text-align: right; }
.dash .load b { font-family: var(--font-num); font-size: 22px; font-weight: 500; }
.dash .load span { display: block; font-size: 11px; color: var(--ink-3); }
.dash .clickable { cursor: pointer; border-radius: 6px; }
.dash .clickable:hover { background: var(--surface-2); }
/* 案C: 積み木 */
.dash .mrow { display: grid; grid-template-columns: 7.5em minmax(0, 1fr) 4.5em; gap: 2px 14px; align-items: center; padding: 7px 6px; border-top: 1px solid var(--line); }
.dash .mrow:first-child { border-top: 0; }
.dash .stack { display: flex; gap: 3px; height: 36px; }
.dash .blk { min-width: 6px; border-radius: 5px; background: var(--accent-soft); color: var(--ink); font-size: 12px; line-height: 1.25; padding: 4px 7px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; display: flex; align-items: center; }
.dash .blk.late { background: var(--late-bg); box-shadow: inset 4px 0 var(--late); padding-left: 9px; }
.dash .blk.soon { background: var(--soon-bg); box-shadow: inset 4px 0 var(--soon); padding-left: 9px; }
.dash .blk.named { flex: 0 0 9.5em; font-size: 13px; }
.dash .rest-lane { flex: 1 1 auto; min-width: 6em; display: flex; }
.dash .blk.rest { background: var(--surface-2); border: 1px dashed var(--line); color: var(--ink-2); min-width: 6em; gap: 6px; }
.dash .rest-late { color: var(--late); font-weight: 700; }
.dash .sub { grid-column: 2 / 4; display: flex; flex-wrap: wrap; gap: 4px 18px; font-size: 13px; color: var(--ink-2); }
.dash .sub b { font-family: var(--font-num); font-weight: 500; color: var(--ink); }
.dash .sub .warn b { color: var(--late); }
.dash .empty-row { color: var(--ink-3); font-size: 13px; }
/* 案A: タイムライン */
.dash .tl { display: grid; grid-template-columns: 7.5em minmax(0, 1fr) 4.5em; gap: 14px; align-items: end; padding-inline: 6px; }
.dash .days { display: grid; grid-template-columns: repeat(10, 1fr) 14px repeat(10, 1fr); gap: 3px; align-items: end; }
.dash .hd { font-size: 12px; color: var(--ink-3); text-align: center; line-height: 1.2; }
.dash .hd.wk { color: var(--ink-2); font-weight: 700; }
.dash .today { align-self: stretch; border-left: 2px dashed var(--ink-3); margin-left: 6px; }
.dash .half { font-size: 13px; color: var(--ink-2); display: grid; grid-template-columns: 1fr 14px 1fr; text-align: center; }
.dash .bar { position: relative; border-radius: 4px 4px 0 0; min-height: 2px; background: var(--line); }
.dash .bar.done { background: var(--accent); }
.dash .bar.due { background: var(--accent-mid); }
.dash .bar.due.hot { background: var(--soon); }
.dash .bar em { position: absolute; bottom: 100%; left: 0; right: 0; text-align: center; font-style: normal; font-family: var(--font-num); font-size: 12px; color: var(--ink); }
.dash .tlrow { padding: 12px 6px 8px; border-top: 1px solid var(--line); }
.dash .bar .lv { position: absolute; bottom: -1px; left: 50%; transform: translateX(-50%); font-size: 11px; line-height: 1; padding: 2px 3px; border-radius: 3px; background: var(--surface-2); color: var(--ink-2); border: 1px solid var(--line); }
.dash .bar .lv.full { color: var(--ink); font-weight: 700; }
.dash .who .lvs { font-size: 12px; color: var(--ink-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dash .leaves { list-style: none; margin: 0 0 12px; padding: 0; display: flex; flex-direction: column; gap: 4px; font-size: 14px; }
.dash .leaves li { display: flex; gap: 8px; align-items: baseline; }
.dash .leaves .d { color: var(--ink-3); font-family: var(--font-num); min-width: 6em; }
.dash .leaves .lv { margin-left: auto; font-size: 12px; color: var(--ink-2); }
.dash .leaves .lv.full { color: var(--ink); font-weight: 700; }
.dash .lv-note { font-size: 12px; color: var(--ink-2); margin: 0 0 12px; }
.dash .tlrow .days { height: 46px; }
/* 仕事ごとの状況 */
.dash .cats { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
.dash .cat .head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.dash .cat .st { font-size: 12px; font-weight: 700; padding: 1px 7px; border-radius: 4px; }
.dash .st.r { background: var(--late-bg); color: var(--late); } .dash .st.y { background: var(--soon-bg); color: var(--soon); } .dash .st.g { background: var(--ok-bg); color: var(--ok); }
.dash .cat .name { font-weight: 700; }
.dash .cat .kind { font-size: 12px; color: var(--ink-3); }
.dash .cat .n { margin-left: auto; font-size: 12px; color: var(--ink-3); }
.dash .meter { display: grid; grid-template-columns: 6.5em 1fr 3em; gap: 8px; align-items: center; font-size: 12px; color: var(--ink-2); margin-top: 3px; }
.dash .meter .tr { height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
.dash .meter .fl { height: 100%; border-radius: 4px; background: var(--accent); }
.dash .meter .fl.use-r { background: var(--late); } .dash .meter .fl.use-y { background: var(--soon); } .dash .meter .fl.use-g { background: var(--ok); }
.dash .meter b { font-family: var(--font-num); font-weight: 500; text-align: right; }
.dash .foot { font-size: 12px; color: var(--ink-3); margin: 0; }
@media (max-width: 860px) { .dash .main { grid-template-columns: 1fr; } .dash .tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); } .dash { height: auto; } }
.checks { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.checks label.chk { display: inline-flex; align-items: center; gap: 5px; border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 4px 9px; font-size: 13px; cursor: pointer; }
.checks label.chk:has(input:checked) { border-color: var(--accent); background: var(--accent-soft); font-weight: 700; }
.checks .all { margin-left: 4px; }
.group-opt { display: flex; gap: 8px; align-items: flex-start; padding: 8px 10px; border-radius: 6px; background: var(--accent-soft); font-size: 13px; }
.group-opt input { margin-top: 3px; }
.group-opt small { display: block; color: var(--ink-2); }
.dash .together { list-style: none; margin: 0 0 6px; padding: 0; display: flex; flex-direction: column; gap: 10px; }
.dash .together li { display: flex; flex-direction: column; gap: 3px; }
.dash .together .head { display: flex; gap: 8px; align-items: baseline; }
.dash .together .name { font-weight: 700; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dash .together .due { margin-left: auto; font-size: 12px; color: var(--ink-3); white-space: nowrap; }
.dash .together .due.late { color: var(--late); font-weight: 700; }
.dash .together .left { font-size: 12px; color: var(--ink-2); }
.dash .together .left b { color: var(--ink); font-weight: 400; }
.dash .panel h3 { margin: 4px 0 0; font-size: 14px; color: var(--ink-2); }
/* ---------- 工数 ---------- */
.toast.ask { background: var(--surface); color: var(--ink); border: 1px solid var(--accent); flex-wrap: wrap; max-width: min(560px, calc(100vw - 32px)); }
.toast.ask .q { flex: 1 1 100%; }
.toast.ask .q b { font-weight: 700; }
.toast.ask .chips { display: flex; gap: 6px; flex-wrap: wrap; }
.toast.ask .chips button { text-decoration: none; border: 1px solid var(--accent); color: var(--accent); background: var(--accent-soft); border-radius: 6px; padding: 4px 10px; font-family: var(--font-num); font-size: 13px; }
.toast.ask .chips button:hover { background: var(--accent); color: var(--accent-ink); }
.toast.ask .chips button.skip { border-color: var(--line); background: transparent; color: var(--ink-2); font-family: var(--font-ui); }
.dialog.hours { width: min(820px, 100%); }
.hours .seg { align-self: flex-start; }
.rel-list ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
.rel-list li { display: flex; gap: 8px; align-items: center; font-size: 13px; }
.rel-list .kind { color: var(--ink-2); white-space: nowrap; min-width: 9em; }
.rel-list .who { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hours-who { display: inline-flex; align-self: flex-start; padding: 3px; gap: 3px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2); margin-bottom: 6px; }
.hours-who button { border: 0; background: transparent; color: var(--ink-2); font-size: 13px; padding: 4px 12px; border-radius: 6px; }
.hours-who button[aria-pressed="true"] { background: var(--surface); color: var(--ink); font-weight: 700; box-shadow: var(--shadow); }
.hours .day-head { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.hours .day-head input[type="date"], .hours select { border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 5px 8px; font-size: 13px; }
.hours .total { margin-left: auto; display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); }
.hours .total b { font-family: var(--font-num); font-size: 18px; color: var(--ink); font-weight: 500; }
.hours .total .tr { width: 140px; height: 8px; border-radius: 4px; background: var(--surface-2); overflow: hidden; }
.hours .total .fl { height: 100%; background: var(--accent); }
.hours .total .fl.over { background: var(--soon); }
.hrows { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
.hrow { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 6px 10px; align-items: center; border: 1px solid var(--line); border-radius: 8px; padding: 7px 10px; }
.hrow .t { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.hrow .t .sj { font-weight: 700; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hrow .t .sub { font-size: 11px; color: var(--ink-3); display: flex; gap: 8px; align-items: center; }
.hrow .done-h { font-size: 12px; color: var(--ink-2); white-space: nowrap; font-family: var(--font-num); }
.hrow .add { display: flex; gap: 4px; align-items: center; }
.hrow .add button { border: 1px solid var(--line); background: var(--surface-2); border-radius: 5px; padding: 3px 7px; font-family: var(--font-num); font-size: 12px; }
.hrow .add button:hover { border-color: var(--accent); color: var(--accent); }
.hrow .add input { width: 64px; border: 1px solid var(--line); background: var(--surface-2); border-radius: 5px; padding: 4px 6px; font-family: var(--font-num); font-size: 13px; text-align: right; }
.hrow .add input:not(:placeholder-shown) { border-color: var(--accent); background: var(--accent-soft); }
.hours .addline { display: flex; gap: 8px; align-items: center; }
.hours .addline select { flex: 1 1 auto; min-width: 0; }
.htable-wrap { overflow: auto; max-height: 52vh; border: 1px solid var(--line); border-radius: 8px; }
.htable { border-collapse: collapse; width: 100%; font-size: 13px; }
.htable th, .htable td { padding: 6px 10px; border-bottom: 1px solid var(--line); text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
.htable th:first-child, .htable td:first-child { text-align: left; white-space: normal; }
.htable thead th { position: sticky; top: 0; background: var(--surface-2); font-size: 12px; color: var(--ink-2); }
.htable tfoot td { font-weight: 700; background: var(--surface-2); }
.htable td.zero { color: var(--ink-3); }
.htable .kind { display: block; font-size: 11px; color: var(--ink-3); }
/* ---------- 課題バラシ ---------- */
.bara { height: 100%; min-height: 0; display: flex; flex-direction: column; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.bara .btop { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 10px 14px; border-bottom: 1px solid var(--line); }
.bara .btop select { border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 5px 8px; max-width: min(460px, 100%); }
.bara .btop .sp { flex: 1; }
.bara .bhelp { display: flex; gap: 4px 14px; flex-wrap: wrap; padding: 6px 14px; font-size: 11px; color: var(--ink-2); background: var(--surface-2); border-bottom: 1px solid var(--line); }
.bara .bhelp b { color: var(--ink); }
.bara .sumbar { font-size: 12px; color: var(--ink-2); display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.bara .sumbar b { font-family: var(--font-num); font-weight: 500; color: var(--ink); }
.bara .sumbar .crit-v { color: var(--late); }
.bara .canvas { flex: 1; min-height: 0; overflow: auto; position: relative; padding: 20px; background: var(--bg); }
.bara .canvas.busy { opacity: .6; pointer-events: none; }
.bara .inner { position: relative; display: inline-block; min-width: 100%; padding-right: 40px; }
.bara svg.arrows { position: absolute; left: 0; top: 0; pointer-events: none; overflow: visible; }
.bara svg.arrows path.hit { stroke: transparent; stroke-width: 14; fill: none; pointer-events: stroke; cursor: pointer; }
.bara svg.arrows path.line { stroke: var(--ink-3); stroke-width: 1.8; fill: none; }
.bara svg.arrows path.line.crit { stroke: var(--late); stroke-width: 2.4; }
.bara svg.arrows g:hover path.line { stroke: var(--late); stroke-width: 2.6; stroke-dasharray: 5 3; }
.bara svg.arrows .head { fill: var(--ink-3); }
.bara svg.arrows .head.crit { fill: var(--late); }
.bara .flow { display: grid; gap: 14px 44px; align-items: start; justify-items: start; }
.bara .stage { display: flex; flex-direction: column; gap: 14px; }
.bara .flow.empty-flow { min-height: 54px; min-width: 220px; border: 1.5px dashed var(--line); border-radius: 8px; display: grid; place-items: center; color: var(--ink-3); font-size: 12px; padding: 8px; }
.bara .frame { background: var(--surface-2); border: 1px solid var(--line); border-radius: 12px; padding: 0 14px 14px; position: relative; }
.bara .frame > .bx { margin: 0 -14px 12px; border-radius: 12px 12px 0 0; border-width: 0 0 1px; width: auto; box-shadow: none; }
.bara .frame.drop-into { outline: 2px dashed var(--accent); outline-offset: 2px; }
.bara .bx { width: 200px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px 9px; box-shadow: var(--shadow);
  position: relative; display: flex; flex-direction: column; gap: 4px; cursor: grab; user-select: none; }
.bara .bx:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.bara .bx.sel { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.bara .bx.root { cursor: default; }
.bara .bx.dragging, .bara .frame.dragging { opacity: .4; }
.bara .bx.saving { opacity: .55; }
.bara .bx .sj { font-weight: 700; font-size: 13px; line-height: 1.35; overflow-wrap: anywhere; }
.bara .bx .sj input { width: 100%; border: 1px solid var(--accent); border-radius: 4px; padding: 2px 4px; font-weight: 700; font-size: 13px; background: var(--surface); }
.bara .bx .meta { display: flex; gap: 6px; align-items: center; font-size: 11px; color: var(--ink-3); flex-wrap: wrap; }
.bara .bx .meta .who { color: var(--ink-2); }
.bara .bx .meta .st { margin-left: auto; padding: 0 6px; border-radius: 4px; background: var(--surface-2); }
.bara .bx .meta .st.doing { background: var(--accent-soft); color: var(--accent); }
.bara .bx .meta .st.done { background: var(--ok-bg); color: var(--ok); }
.bara .bx .meta .st-btn { border: 1px solid transparent; font-size: 11px; cursor: pointer; line-height: 1.5; }
.bara .bx .meta .st-btn:hover { border-color: var(--accent); }
.bara .bx .meta .who-btn { border: 1px solid transparent; background: none; padding: 0 3px; border-radius: 4px; font-size: 11px; color: var(--ink-2); cursor: pointer; }
.bara .bx .meta .who-btn:hover { border-color: var(--accent); color: var(--accent); }
.bara .bx .vtag { display: flex; margin: -2px 64px -2px 0; min-width: 0; }
.bara .bx .vtag .tag { margin-left: 0; font-size: 10px; padding: 0 6px; max-width: 100%; white-space: normal; overflow-wrap: anywhere; }
.bara .bx .meta .dl.late { color: var(--late); font-weight: 700; } .bara .bx .meta .dl.soon { color: var(--soon); font-weight: 700; }
.bara .bx .bar { height: 3px; border-radius: 2px; background: var(--surface-2); overflow: hidden; }
.bara .bx .bar i { display: block; height: 100%; background: var(--accent); }
.bara .bx.done .bar i { background: var(--ok); }
.bara .bx.done .sj { color: var(--ink-2); }
.bara .frame > .bx .sj { font-size: 14px; }
.bara .frame > .bx .sj::before { content: "▾ "; color: var(--ink-3); }
.bara .frame.collapsed > .bx .sj::before { content: "▸ "; }
.bara .outside { font-size: 11px; color: var(--soon); }
.bara .ext { display: flex; flex-direction: column; gap: 2px; font-size: 11px; line-height: 1.4; }
.bara .ext span { border-radius: 4px; padding: 1px 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bara .ext .wait { background: var(--soon-bg); color: var(--soon); }
.bara .ext .ok { background: var(--ok-bg); color: var(--ok); }
.bara .ext .next { background: var(--surface-2); color: var(--ink-2); }
.bara .frame.ctx > .bx { background: var(--surface-2); }
.bara .sched { font-size: 11px; color: var(--ink-2); display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-variant-numeric: tabular-nums; }
.bara .sched.unsaved b { color: var(--accent); }
.bara .sched .tag-s { font-size: 10px; border-radius: 4px; padding: 0 5px; background: var(--accent-soft); color: var(--accent); }
.bara .sched .tag-s.late { background: var(--late-bg); color: var(--late); }
.bara .sched .tag-s.muted { background: var(--surface-2); color: var(--ink-3); }
.bara .btop input[type="date"] { border: 1px solid var(--line); background: var(--surface-2); border-radius: 6px; padding: 4px 6px; font-size: 12px; }
.bara .btop .grp { display: inline-flex; gap: 6px; align-items: center; font-size: 13px; }
.bara .frame.ctx > .bx .sj::after { content: "（この人の分だけ表示）"; font-size: 11px; font-weight: 400; color: var(--ink-3); margin-left: 6px; }
.bara .est-row { display: flex; gap: 6px; align-items: center; font-size: 11px; color: var(--ink-3); flex-wrap: wrap; }
.bara .est { border: 1px solid var(--line); background: var(--surface-2); border-radius: 5px; padding: 1px 6px; font-size: 11px; color: var(--ink-2); font-family: var(--font-num); white-space: nowrap; }
.bara button.est:hover { border-color: var(--accent); color: var(--accent); }
.bara .est.unset { border-style: dashed; color: var(--ink-3); font-family: var(--font-ui); }
.bara .est.over { border-color: var(--late); color: var(--late); background: var(--late-bg); }
.bara .est.sum { background: transparent; border-color: transparent; padding-left: 0; }
.bara .knob { position: absolute; width: 22px; height: 22px; border-radius: 50%; border: 1px solid var(--accent); background: var(--surface); color: var(--accent);
  display: grid; place-items: center; font-size: 14px; line-height: 1; padding: 0; opacity: 0; transition: opacity .12s; z-index: 2; }
.bara .bx:hover > .knob, .bara .bx.sel > .knob, .bara .bx:focus-within > .knob { opacity: 1; }
.bara .knob.l { left: -12px; top: calc(50% - 11px); }
.bara .knob.r { right: -12px; top: calc(50% - 11px); }
.bara .knob.b { left: calc(50% - 11px); bottom: -12px; }
.bara .knob.x, .bara .knob.link, .bara .knob.ed { top: 4px; width: 18px; height: 18px; font-size: 10px; }
.bara .knob.x { right: 4px; border-color: var(--line); color: var(--ink-3); font-size: 12px; }
.bara .knob.link { right: 24px; cursor: crosshair; }
.bara .knob.ed { right: 44px; }
.bara .knob:hover { background: var(--accent); color: var(--accent-ink); }
.bara .knob.x:hover { background: var(--late); border-color: var(--late); color: #fff; }
.bara .bx.zone-l::before, .bara .bx.zone-r::after { content: ""; position: absolute; top: -4px; bottom: -4px; width: 5px; border-radius: 3px; background: var(--accent); }
.bara .bx.zone-l::before { left: -9px; }
.bara .bx.zone-r::after { right: -9px; }
.bara .bx.zone-c { outline: 2px dashed var(--accent); outline-offset: 3px; }
.bara-tip { position: fixed; pointer-events: none; background: var(--ink); color: var(--bg); font-size: 12px; padding: 4px 8px; border-radius: 6px; z-index: 30; }
.bara-link { position: fixed; inset: 0; pointer-events: none; z-index: 25; width: 100vw; height: 100vh; }
.bara-link path { stroke: var(--accent); stroke-width: 2; fill: none; stroke-dasharray: 6 4; }
.bara-pop { position: fixed; z-index: 35; background: var(--surface); border: 1px solid var(--line); border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,.2); padding: 10px; display: flex; flex-direction: column; gap: 8px; width: 250px; }
.bara-pop .ttl { font-size: 12px; color: var(--ink-2); font-weight: 700; }
.bara-pop .chips { display: flex; flex-wrap: wrap; gap: 5px; }
.bara-pop .chips button { border: 1px solid var(--accent); background: var(--accent-soft); color: var(--accent); border-radius: 6px; padding: 3px 8px; font-family: var(--font-num); font-size: 12px; }
.bara-pop .chips button[aria-pressed="true"] { background: var(--accent); color: var(--accent-ink); }
.bara-pop .row { display: flex; gap: 6px; align-items: center; font-size: 12px; }
.bara-pop .row input { width: 70px; border: 1px solid var(--line); background: var(--surface-2); border-radius: 5px; padding: 4px 6px; font-family: var(--font-num); text-align: right; }
.bara-pop .row .gap { flex: 1; }
.bara-pop .row button { border: 1px solid var(--line); background: var(--surface); border-radius: 5px; padding: 3px 8px; font-size: 12px; }
.bara .bbody { flex: 1; min-height: 0; display: flex; }
.bara .bbody .canvas { flex: 1; min-width: 0; }
.bara .rail { width: 220px; flex: none; border-right: 1px solid var(--line); background: var(--surface); overflow: auto; padding: 10px 10px 16px; display: flex; flex-direction: column; gap: 6px; }
.bara .rail h3 { margin: 0 0 2px; font-size: 12px; color: var(--ok); display: flex; justify-content: space-between; }
.bara .rail .hint { font-size: 11px; }
.bara .rail .done-item { border: 1px solid var(--line); border-left: 3px solid var(--ok); border-radius: 6px; padding: 4px 8px; font-size: 12px; line-height: 1.4; background: var(--surface-2); }
.bara .rail .done-item .pt { display: block; font-size: 10px; color: var(--ink-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bara .rail .done-item .nm { color: var(--ink-2); overflow-wrap: anywhere; }
.bara .hidden-note { font-size: 11px; color: var(--ok); }
@media (max-width: 760px) { .bara .rail { display: none; } }
.bara .add-here { border: 1.5px dashed var(--line); background: transparent; color: var(--ink-3); border-radius: 8px; padding: 6px 14px; font-size: 12px; width: 200px; text-align: left; }
.bara .add-here:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
.bara .empty-scope { padding: 40px; text-align: center; color: var(--ink-3); }
/* ---------- 使い方（ブログ風の解説） ---------- */
.help-btn { position: relative; }
.help-btn .new-dot { position: absolute; top: -3px; right: -3px; width: 9px; height: 9px; border-radius: 50%; background: var(--late); border: 2px solid var(--surface); }
.overlay.guide { place-items: stretch center; padding: 24px 16px; }
.guide-page { width: min(780px, 100%); max-height: 100%; overflow: auto; background: var(--surface); border-radius: 14px; box-shadow: 0 12px 40px rgba(0,0,0,.25); position: relative; }
.guide-page .close { position: sticky; top: 0; display: flex; justify-content: flex-end; padding: 12px 14px 0; background: linear-gradient(var(--surface) 70%, transparent); z-index: 1; }
.guide-page article { padding: 0 clamp(18px, 5vw, 48px) 40px; line-height: 1.85; font-size: 15px; }
.guide-page .eyebrow { font-size: 12px; color: var(--accent); font-weight: 700; letter-spacing: .08em; margin: 0; }
.guide-page h1 { font-size: clamp(22px, 4vw, 28px); line-height: 1.4; margin: 6px 0 4px; text-wrap: balance; }
.guide-page .byline { font-size: 12px; color: var(--ink-3); margin: 0 0 22px; }
.guide-page .lead { font-size: 16px; color: var(--ink); background: var(--surface-2); border-left: 4px solid var(--accent); padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 0 0 8px; }
.guide-page nav.toc { margin: 22px 0 8px; padding: 14px 18px; border: 1px solid var(--line); border-radius: 10px; font-size: 14px; }
.guide-page nav.toc b { display: block; font-size: 12px; color: var(--ink-2); margin-bottom: 4px; }
.guide-page nav.toc ol { margin: 0; padding-left: 1.4em; columns: 2; column-gap: 28px; }
.guide-page nav.toc a { color: var(--accent); text-decoration: none; }
.guide-page nav.toc a:hover { text-decoration: underline; }
.guide-page h2 { font-size: 20px; margin: 38px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--line); scroll-margin-top: 50px; }
.guide-page h2 .no { font-family: var(--font-num); color: var(--accent); margin-right: 8px; }
.guide-page h3 { font-size: 16px; margin: 22px 0 6px; }
.guide-page p { margin: 0 0 12px; }
.guide-page ul, .guide-page ol { margin: 0 0 12px; padding-left: 1.4em; }
.guide-page li { margin: 2px 0; }
.guide-page .ui { display: inline-block; border: 1px solid var(--line); background: var(--surface-2); border-radius: 5px; padding: 0 7px; font-size: 13px; line-height: 1.7; white-space: nowrap; }
.guide-page .ui.pri { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.guide-page .ba { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 14px 0 16px; }
.guide-page .ba > div { border-radius: 10px; padding: 12px 14px; font-size: 14px; line-height: 1.7; }
.guide-page .ba .before { background: var(--late-bg); }
.guide-page .ba .after { background: var(--ok-bg); }
.guide-page .ba b { display: block; font-size: 12px; letter-spacing: .06em; margin-bottom: 4px; }
.guide-page .ba .before b { color: var(--late); } .guide-page .ba .after b { color: var(--ok); }
.guide-page .ba ul { margin: 0; }
.guide-page .log-lead { font-size: 13px; color: var(--ink-2); }
.guide-page .changelog { margin: 0; font-size: 14px; }
.guide-page .changelog dt { display: flex; gap: 10px; align-items: baseline; margin-top: 12px; }
.guide-page .changelog dt b { font-family: var(--font-num); color: var(--accent); }
.guide-page .changelog dt span { font-size: 12px; color: var(--ink-3); font-family: var(--font-num); }
.guide-page .changelog dd { margin: 2px 0 0; }
.guide-page .changelog ul { margin: 0; }
.guide-page .note { background: var(--soon-bg); color: var(--ink); border-radius: 8px; padding: 10px 14px; font-size: 14px; margin: 0 0 14px; }
.guide-page .note b { color: var(--soon); }
.guide-page .mini-cols { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; margin: 12px 0 16px; font-size: 12px; text-align: center; }
.guide-page .mini-cols div { border: 1px solid var(--line); border-radius: 8px; padding: 8px 4px; background: var(--surface-2); }
.guide-page .mini-cols div b { display: block; font-size: 13px; }
.guide-page .mini-cols .arrow { border: 0; background: none; }
.guide-page .mini-card { display: inline-block; border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px; background: var(--surface); box-shadow: var(--shadow); font-size: 13px; line-height: 1.6; margin: 6px 0 14px; }
.guide-page .mini-card .pc { font-size: 11px; color: var(--ink-3); }
.guide-page .mini-card .due { font-size: 11px; color: var(--late); font-weight: 700; }
.guide-page table { border-collapse: collapse; width: 100%; font-size: 14px; margin: 6px 0 16px; }
.guide-page th, .guide-page td { border-bottom: 1px solid var(--line); padding: 7px 8px; text-align: left; vertical-align: top; }
.guide-page th { font-size: 12px; color: var(--ink-2); background: var(--surface-2); }
.guide-page .end { margin-top: 36px; padding: 16px 18px; border-radius: 10px; background: var(--accent-soft); }
@media (max-width: 640px) { .guide-page .ba { grid-template-columns: 1fr; } .guide-page nav.toc ol { columns: 1; } .guide-page .mini-cols { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.desc-links { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.desc-links:empty { display: none; }
.desc-links a { display: inline-flex; align-items: baseline; gap: 6px; max-width: 100%; border: 1px solid var(--accent); background: var(--accent-soft); color: var(--accent);
  border-radius: 6px; padding: 3px 10px; font-size: 12px; text-decoration: none; }
.desc-links a:hover { background: var(--accent); color: var(--accent-ink); }
.desc-links a b { white-space: nowrap; }
.desc-links a span { font-size: 11px; opacity: .8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 260px; }
.btn-mini { border: 1px solid var(--line); background: var(--surface); border-radius: 6px; padding: 4px 8px; font-size: 12px; white-space: nowrap; }

@media (max-width: 860px) {
  body { overflow: auto; }
  .board { grid-template-columns: repeat(4, minmax(250px, 80%)); }
  .inbox { grid-template-columns: 1fr; height: auto; }
  .triage .grid2 { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
```

## 付録 B. 画面の HTML 全文（`<!--BODY-->` から `<script>` の直前まで。使い方ページの本文を含む）

```html
<!--BODY-->
<div class="app" id="app">
  <header class="topbar">
    <div class="brand">
      <h1>タスクボード</h1>
      <span class="today" id="today"></span>
      <span class="mode-pill" id="modePill">モック</span>
    </div>
    <div class="spacer"></div>
    <div class="tools">
      <label class="mock-user" id="mockUserWrap" for="mockUser">モックの操作ユーザー
        <select id="mockUser"></select>
      </label>
      <button class="btn primary" id="newTaskBtn" type="button">＋ 新規タスク</button>
      <button class="btn" id="hoursBtn" type="button" title="作業時間の記録と月の集計">工数</button>
      <button class="btn" id="reloadBtn" type="button">再読み込み</button>
      <button class="btn" id="settingsBtn" type="button">接続設定</button>
      <button class="btn help-btn" id="guideBtn" type="button" title="このボードの使い方">使い方</button>
    </div>
  </header>

  <div class="subbar">
    <div class="tabs" role="tablist" id="tabs" aria-label="表示するメンバー"></div>
    <div class="summary" id="summary" aria-live="polite"></div>
  </div>

  <div class="board-wrap">
    <main class="board" id="board"><div class="loading">読み込み中…</div></main>
    <div class="dash" id="dash" hidden></div>
    <div class="bara" id="bara" hidden></div>
    <div class="inbox" id="inbox" hidden>
      <section class="col" aria-label="未整理のチケット">
        <header class="col-head">
          <h2>未整理</h2>
          <span class="sub">担当またはバージョンが未設定</span>
          <span class="count" id="inboxCount">0</span>
        </header>
        <div class="col-body" style="padding:0"><ul class="mail-list" id="mailList"></ul></div>
      </section>
      <form class="triage" id="triage" novalidate></form>
    </div>
  </div>
</div>

<div class="cancel-zone" id="cancelZone" hidden>ここにドロップすると「中止」</div>
<div class="toasts" id="toasts" aria-live="polite"></div>

<div class="overlay" id="editor" hidden>
  <form class="dialog triage editor" id="editorForm" novalidate aria-label="チケットの編集"></form>
</div>

<div class="overlay" id="hoursDlg" hidden>
  <div class="dialog hours" id="hoursBody" role="dialog" aria-label="工数"></div>
</div>

<div class="overlay guide" id="guide" hidden>
  <div class="guide-page" role="dialog" aria-labelledby="guideTitle">
    <div class="close"><button class="btn" type="button" id="guideClose">閉じる</button></div>
    <article>
      <p class="eyebrow">タスクボード 使い方ガイド</p>
      <h1 id="guideTitle">計画のメンテが面倒すぎたので、ボードにしました。</h1>
      <p class="byline">つくったひと より ／ 読む時間 約5分</p>

      <p class="lead">
        Redmine でチケットを探して、開いて、進捗を選んで、保存して……。正直、これが毎日の地味なストレスでした。<br>
        「計画を守る」より「計画を<strong>直す</strong>」ほうに時間を取られていた気がします。<br>
        なので、<strong>見る・動かす・終わらせる</strong>をワンクリックでできるボードを作りました。中身は今までどおり Redmine です。
      </p>

      <nav class="toc" aria-label="目次">
        <b>目次</b>
        <ol>
          <li><a href="#g-why">なぜボードにしたのか</a></li>
          <li><a href="#g-daily">毎日の使い方（ここだけ読めばOK）</a></li>
          <li><a href="#g-deadline">締切と予定のルール</a></li>
          <li><a href="#g-inbox">メールで来た仕事の振り分け</a></li>
          <li><a href="#g-new">新規タスク・みんなでやる仕事</a></li>
          <li><a href="#g-hours">工数入力は「押すだけ」</a></li>
          <li><a href="#g-bara">課題バラシ</a></li>
          <li><a href="#g-dash">全体ボード（朝会・Teams用）</a></li>
          <li><a href="#g-faq">困ったとき</a></li>
          <li><a href="#g-log">変更履歴</a></li>
        </ol>
      </nav>

      <h2 id="g-why"><span class="no">01</span>なぜボードにしたのか</h2>
      <p>Redmine は記録としては優秀です。ただ、<strong>日々の更新</strong>がとにかく面倒でした。</p>
      <div class="ba">
        <div class="before"><b>これまで</b>
          <ul>
            <li>自分のチケットを検索して一覧を出す</li>
            <li>1件ずつ開いて進捗をプルダウンで選ぶ</li>
            <li>親チケットの進捗も手で合わせる</li>
            <li>月末に工数を思い出しながら入力</li>
            <li>誰が忙しいかは聞いてみないと分からない</li>
          </ul>
        </div>
        <div class="after"><b>これから</b>
          <ul>
            <li>開けば自分の仕事が優先順に並んでいる</li>
            <li>進捗はボタンをポンと押すだけ</li>
            <li>親チケットは子に合わせて自動で更新</li>
            <li>工数は進捗を押したついでに1クリック</li>
            <li>「全体」タブでチームの状況が一目で分かる</li>
          </ul>
        </div>
      </div>
      <p>ボードで動かした内容は、その場で Redmine に書き込まれます。ボード専用のデータはないので、Redmine 側で見ても同じです。</p>

      <h2 id="g-daily"><span class="no">02</span>毎日の使い方（ここだけ読めばOK）</h2>
      <p>開くと<strong>自分のタブ</strong>が選ばれた状態で始まります。列は左から右へ流れます。</p>
      <div class="mini-cols">
        <div><b>未着手</b>これから</div>
        <div><b>進行中</b>0〜80%</div>
        <div><b>担当完了</b>自分の作業は終わり</div>
        <div><b>上司完了</b>確認したら上司が移動</div>
      </div>
      <ol>
        <li><strong>始めたら</strong> カードを「進行中」へドラッグ。</li>
        <li><strong>進んだら</strong> カード下の <span class="ui">0</span> <span class="ui">20</span> <span class="ui">40</span> <span class="ui">60</span> <span class="ui">80</span> を押す。</li>
        <li><strong>終わったら</strong> 「担当完了」へドラッグ。あとは上司が確認して「上司完了」に動かします。</li>
        <li><strong>やらなくなったら</strong> ドラッグ中に下に出る「中止」の帯へ落とす。チケットは消えません。</li>
      </ol>
      <p>カードをクリックすると、件名・締切・担当・説明を直せます。コメントを書けば Redmine の履歴にも残ります。</p>
      <h3>やる順番は、上下に並べ替えるだけ</h3>
      <p>「未着手」「進行中」の列の中でカードを上下にドラッグすると、<strong>その順番で日程が決まります</strong>。上から順に、予定工数の分だけ詰めて、開始日と作業完了予定を Redmine に入れます（進行中 → 未着手の順）。</p>
      <p>課題バラシでつないだ「前の仕事」がまだ終わっていなければ、その後ろにずれます。並べた順番は次に開いたときもそのまま。間違えたら「元に戻す」で戻せます。</p>
      <p>上の「並び」を <span class="ui">余裕が少ない順</span> にすると、<strong>危ないものから</strong>並びます。余裕は「締切までの営業日数 − 残りの作業日数（予定工数と進捗から）」。締切が先でも残りが多ければ上に来ます。緊急（01_市場問題 など）は常にいちばん上。カードに「余裕 2日」のように出ます。<span class="ui">この順番で日程を決める</span> を押せば、その順番がそのまま作業順になります。</p>
      <div class="mini-card">
        <div class="pc">フロントバンパー設計 › 補強構造の検討</div>
        <b>ビーム断面の強度解析</b>
        <div><span class="due">締切 2日超過</span>　<span class="pc">予定 10/20</span></div>
      </div>
      <p>カードの上の小さい文字は<strong>親・親の親</strong>です。「何のための作業か」が分かるようにしています。右上の色付きタグはバージョン（仕事の区分）です。</p>
      <h3>★ 優先してほしい</h3>
      <p>カードの右上の <span class="ui">☆</span> を押すと <span class="ui">★ 優先</span> になります（Redmine の優先度が「高め」に）。「余裕が少ない順」では緊急の次に並びます。上司から「これ先にお願い」と頼むときにも使えます。</p>
      <h3>「すでに関連したチケットがあります」と言われたら</h3>
      <p>Redmine は 2 つのチケットの間につながりを 1 つしか持てません。「関連している」などが先にあると前後でつなげないので、出てきたお知らせの <span class="ui">外して前後にする</span> を押してください。カードの編集画面の「つながり」で、ボードに出ないつながりも見て外せます。</p>
      <h3>休みの予定</h3>
      <p>ガントチャートの一番上に入れている「田中半休」のようなマイルストーンを、そのまま休みとして読みます。自分の画面の上に「休み 10/22(木)」、全体タブに「これからの休み」が出ます。1日休みの日は、作業順や課題バラシで日程を決めるときに作業日から外します。同じ名字の人がいるときは「田中太半休」のように名の1文字目まで書いてください。</p>
      <h3>詰まりのサイン</h3>
      <ul>
        <li><strong>⏳ 待ち</strong>：前の仕事がまだ終わっていません。待っている相手と仕事の名前が出ます。</li>
        <li><strong>✓ 着手できます</strong>：前の仕事が全部終わりました。始めどきです。</li>
        <li><strong>N日動きなし</strong>：進捗が5営業日以上動いていません。困っていたら声をかけてください。</li>
        <li>進行中が5件を超えると、列の見出しに<strong>「上限を超えています」</strong>と出ます。広げすぎず、終わらせてから次へ。</li>
      </ul>
      <h3>並び順のルール</h3>
      <p>バージョン名の先頭の番号が小さいほど上に来ます（<span class="ui">01_市場問題</span> がいちばん急ぎ）。同じ番号なら締切が近い順です。</p>

      <h2 id="g-deadline"><span class="no">03</span>締切と予定のルール</h2>
      <table>
        <tr><th>どこに書く</th><th>意味</th></tr>
        <tr><td>件名の先頭の <strong>【10/24】</strong></td><td><strong>本来の締切</strong>（お客さん・関係部署との約束）</td></tr>
        <tr><td>Redmine の <strong>期日</strong></td><td><strong>作業完了予定</strong>（自分の見込み）</td></tr>
      </table>
      <p>締切を過ぎると<strong>赤</strong>、3日以内だと<strong>黄色</strong>になります。作業完了予定が締切より後ろだと「予定が締切超え」と出るので、早めに相談してください。</p>
      <p class="note"><b>ポイント：</b>締切と予定の差が「余裕（バッファ）」です。全体ボードでは、この余裕をどれだけ使ったかで、仕事ごとの危なさを見ています。</p>

      <h2 id="g-inbox"><span class="no">04</span>メールで来た仕事の振り分け</h2>
      <p>メールから自動で作られたチケット（担当やバージョンが空のもの）は<strong>「未整理」タブ</strong>に集まります。誰が振り分けてもOKです。</p>
      <ol>
        <li>左の一覧からチケットを選ぶ</li>
        <li>締切・件名・バージョン・担当を入れて <span class="ui pri">整理して登録</span></li>
        <li>仕事ではないメール（懇親会のお知らせなど）は <span class="ui">タスクではない</span> で「中止」に</li>
        <li>大きい仕事は <span class="ui">課題バラシで分解する</span> で、その場で中身に分ける</li>
      </ol>

      <h2 id="g-new"><span class="no">05</span>新規タスク・みんなでやる仕事</h2>
      <p>右上の <span class="ui pri">＋ 新規タスク</span> から作れます。バージョンが無ければ、その場で <span class="ui">＋ 新しいバージョン</span> も作れます（「番号_カテゴリ-個別名」の形になります。例：05_開発業務-EV電池ケース）。</p>
      <p>E-ラーニングのように<strong>全員がやる仕事</strong>は、担当を複数チェックすると人数分のチケットができます。「まとめ用の親チケット」を付けておくと、全体タブの「みんなでやる仕事」で、誰が終わって誰がまだかが分かります。</p>

      <h2 id="g-hours"><span class="no">06</span>工数入力は「押すだけ」</h2>
      <div class="ba">
        <div class="before"><b>これまで</b>月末にカレンダーとメールを見返して、思い出しながら入力。正直つらい。</div>
        <div class="after"><b>これから</b>進捗ボタンを押すと右下に時間が出るので、近いものを1回押すだけ。</div>
      </div>
      <p>出てくるのは <span class="ui">0.5h</span> <span class="ui">1h</span> <span class="ui">2h</span> <span class="ui">4h</span> <span class="ui">1日</span> <span class="ui">記録しない</span>。押さなければ何も記録されません。</p>
      <p>ほかの人のカードを動かしたときは、<strong>担当者の作業時間</strong>として記録します（「伊藤さんの今回の作業時間は？」）。手伝った分を自分の時間で入れたいときは、カードの編集画面で <span class="ui">自分（手伝った分）</span> を選んでください。</p>
      <p>右上の <span class="ui">工数</span> ボタンからは次のことができます。</p>
      <ul>
        <li><strong>日々の記録</strong>：その日に動かしたチケットが並ぶので、まとめて入れられます。8時間に届いているかも見えます。</li>
        <li><strong>月の集計</strong>：バージョン別・人別の合計時間。<span class="ui">CSV で保存</span> して月末の工数入力にそのまま使えます。</li>
      </ul>
      <p class="note"><b>ゆるく行きましょう：</b>きっちり正確じゃなくて大丈夫。月末に思い出すより、ずっと実態に近い数字になります。聞かれたくない人は「接続設定」でオフにできます。</p>

      <h2 id="g-bara"><span class="no">07</span>課題バラシ</h2>
      <p>ガントチャートの「前後のつながり」が見える良さを、もっと手軽に使えるようにした画面です。</p>
      <ul>
        <li><strong>中の仕事（子）</strong>は親の<strong>枠の中</strong>に入ります</li>
        <li><strong>順番</strong>は左から右への<strong>矢印</strong>。並行できる仕事は縦に並びます</li>
        <li>箱の <span class="ui">＋</span>（左・右・下）で前・後・中の仕事を追加</li>
        <li>枠のいちばん下の <span class="ui">＋ ここに追加</span> で、同じ階層に（つながりのない）仕事を追加</li>
        <li>箱をドラッグして、相手の左端なら前、右端なら後、真ん中なら中に入れる</li>
        <li><span class="ui">予定工数 ＋</span> で予定時間を入れると、<strong>一番長い流れ</strong>（順番にしかできない仕事の合計）が赤く出ます</li>
      </ul>
      <p>矢印は Redmine の「先行」として保存されるので、ガントチャートにも同じ矢印が出ます。前の仕事が遅れると、後ろの仕事の日程も Redmine が自動でずらします。</p>

      <h2 id="g-dash"><span class="no">08</span>全体ボード（朝会・Teams用）</h2>
      <p>「全体」タブは、Teams の画面共有でそのまま見せられるように、1画面に収めています。</p>
      <ul>
        <li><strong>上の数字</strong>：締切超過・今週の締切・2週間で完了した数・見直しが必要な仕事</li>
        <li><strong>積み木</strong>：いま抱えている仕事の量（多い順）。締切が危ないものは名前が出ます</li>
        <li><strong>タイムライン</strong>：これまでの2週間で終わった数と、これからの2週間の締切の数</li>
        <li><strong>仕事ごとの状況</strong>：進捗に対して余裕をどれだけ使ったかで「順調・注意・見直し」</li>
      </ul>
      <p>責めるための画面ではありません。<strong>早めに助けを出すための画面</strong>です。赤いものを見つけたら、遠慮なく声をかけてください（かけます）。</p>

      <h2 id="g-faq"><span class="no">09</span>困ったとき</h2>
      <table>
        <tr><th>こんなとき</th><th>こうする</th></tr>
        <tr><td>ボードが開かない</td><td>共有フォルダの <strong>kanban_relay.py</strong> をダブルクリック。自動で起動してボードが開きます。</td></tr>
        <tr><td>新しい機能が出てこない</td><td>共有フォルダの kanban_relay.py をダブルクリック（古い版から入れ替わります）。<span class="ui">接続設定</span> の一番下で版を確認できます。</td></tr>
        <tr><td>「更新できませんでした」と出る</td><td>Redmine 側の権限で止められています。メッセージをそのまま、つくったひとに送ってください。</td></tr>
        <tr><td>表示が古い気がする</td><td>右上の <span class="ui">再読み込み</span>。Redmine で直接変えた分も取り込みます。</td></tr>
        <tr><td>「上司完了」に動かせない</td><td>仕様です。担当完了まで動かしてもらえれば、上司が確認して動かします。</td></tr>
      </table>

      <div class="end">
        <strong>おわりに</strong><br>
        ボードは道具なので、使いにくいところはどんどん直します。「ここが面倒」「こうだったらいいのに」は気軽に言ってください。<br>
        計画を直す時間を減らして、設計に時間を使いましょう。
      </div>

      <h2 id="g-log"><span class="no">10</span>変更履歴</h2>
      <p class="log-lead">版は <span class="ui">接続設定</span> の一番下で確認できます。大きな機能追加で番号が 1 つ上がり、小さな改善・修正は v15.1、v15.2 のように増えます。</p>
      <dl class="changelog">
        <dt><b>v15.3</b><span>2026-10-22</span></dt>
        <dd><ul><li>課題バラシで箱を動かしたあとの読み込みを速くしました（変えたチケットとその親だけを読み直します）</li></ul></dd>
        <dt><b>v15.2</b><span>2026-10-21</span></dt>
        <dd><ul><li>前後をつなごうとして「すでに関連したチケットがあります」と断られたとき、邪魔しているつながりを見せて <span class="ui">外して前後にする</span> でつなぎ直せるようにしました</li><li>カードの編集画面に「つながり」の一覧と <span class="ui">外す</span> を追加（ボードに出ない「関連している」なども見えます）</li></ul></dd>
        <dt><b>v15.1</b><span>2026-10-20</span></dt>
        <dd><ul><li>ほかの人のカードを動かしたときの作業時間は、担当者の時間として記録するようにしました（編集画面で「自分（手伝った分）」も選べます）</li></ul></dd>
        <dt><b>v15</b><span>2026-10-19</span></dt>
        <dd><ul><li>ガントチャートのマイルストーン（「田中半休」など）を休みの予定として表示。1日休みは日程の計算で作業日から外します</li></ul></dd>
        <dt><b>v14</b><span>2026-10-19</span></dt>
        <dd><ul><li>★ 優先してほしいフラグ</li><li>並び順「余裕が少ない順」</li><li>詰まりのサイン（待ち・止まっている・手持ちの上限）</li><li>ほかの人のチケットにも自分の作業時間を記録できるように</li></ul></dd>
        <dt><b>v13</b><span>2026-10-16</span></dt>
        <dd><ul><li>列の中の並び替えを「自分の作業順」として日程に反映</li><li>課題バラシ: 締切が近い順、＋ここに追加、ダブルクリックで編集画面</li><li>担当なしの新規タスク（未整理へ）、バージョン名「番号_カテゴリ-個別名」</li><li>安全対策: プログラムの自動入れ替えをやめ、API キーの送り先を固定</li></ul></dd>
        <dt><b>v12</b><span>2026-10-16</span></dt>
        <dd><ul><li>課題バラシ: 予定工数からの自動日程、担当者ごとの表示、ステータス・担当の変更、読み込みの安定化</li></ul></dd>
        <dt><b>v11</b><span>2026-10-15</span></dt>
        <dd><ul><li>課題バラシ（タスクの分解と前後のつながり）</li><li>工数の記録と月の集計</li><li>使い方ページ（このページ）</li><li>アプリ名を「タスクボード」に</li><li>説明欄の URL をリンクとして表示</li><li>新しいバージョンの作成と全体タブを全員に</li></ul></dd>
        <dt><b>〜v10</b><span>2026-10-08〜</span></dt>
        <dd><ul><li>カンバンボード、未整理の振り分け、カードの編集、全体ダッシュボード、親チケットのステータス自動更新、中継プログラム</li></ul></dd>
      </dl>
    </article>
  </div>
</div>

<div class="overlay" id="settings" hidden>
  <form class="dialog" id="settingsForm" aria-labelledby="settingsTitle">
    <h2 id="settingsTitle">接続設定</h2>
    <div class="field">
      <span class="label">データの取得元</span>
      <div class="radios">
        <label><input type="radio" name="mode" id="modeRelay" value="relay"> 中継プログラム経由（通常はこれ）</label>
        <label><input type="radio" name="mode" id="modeMock" value="mock"> モック（ダミーデータ）</label>
        <label><input type="radio" name="mode" id="modeLive" value="live"> 直接接続</label>
      </div>
    </div>
    <p class="hint" id="relayHint">このPCで動いている中継プログラムを通して Redmine を読み書きします。API キーは中継プログラムに保存されています。</p>
    <div id="directFields" hidden>
      <p class="hint">Redmine 側で CORS が許可されている場合だけ使えます。</p>
      <div class="field">
        <label for="redmineUrl">Redmine の URL</label>
        <input type="text" id="redmineUrl" placeholder="https://redmine.example.com" autocomplete="off">
      </div>
      <div class="field">
        <label for="apiKey">自分の API キー</label>
        <input type="password" id="apiKey" placeholder="Redmine の「個人設定」→「APIアクセスキー」" autocomplete="off">
        <p class="hint">キーはこのブラウザの中だけに保存されます。</p>
      </div>
    </div>
    <div class="field">
      <span class="label">工数</span>
      <label><input type="checkbox" id="askHours"> 進捗を動かしたときに、作業時間を聞く（押さなければ記録しません）</label>
    </div>
    <p class="test-result" id="testResult" hidden></p>
    <p class="hint" id="versionInfo"></p>
    <div class="dialog-actions">
      <button class="btn" type="button" id="testBtn">接続テスト</button>
      <button class="btn" type="button" id="cancelSettings">閉じる</button>
      <button class="btn primary" type="submit">保存して再読み込み</button>
    </div>
  </form>
</div>
```

## 付録 C. 初期設定（`<script>` 冒頭の CONFIG。中継が `/*__SERVER_CONFIG__*/` の位置で上書きする）

`<script>` の最初は `'use strict';` と `const BOARD_BUILD = '__BUILD__';`、その次にこれ:

```js
const CONFIG = {
  // Redmine のステータス ID と、どの列に出すかの対応表。
  // ID は Redmine の「管理 → チケットのステータス」で確認して合わせる。
  statuses: [
    { id: 1, name: '未着手',     col: 'todo',      ratio: 0 },
    { id: 2, name: '0%',         col: 'doing',     ratio: 0 },
    { id: 3, name: '20%',        col: 'doing',     ratio: 20 },
    { id: 4, name: '40%',        col: 'doing',     ratio: 40 },
    { id: 5, name: '60%',        col: 'doing',     ratio: 60 },
    { id: 6, name: '80%',        col: 'doing',     ratio: 80 },
    { id: 7, name: '完了（実務者）', col: 'done',     ratio: 100 },
    { id: 8, name: '完了（確認済）', col: 'approved', ratio: 100 },
    { id: 9, name: '中止',       col: 'cancelled', ratio: null },
  ],
  // 列の定義。ドロップしたときに設定するステータスは statuses から自動で決まる
  // （その列の最初のステータス。進行中は進捗率がいちばん小さいもの）
  columns: [
    { key: 'todo',     title: '未着手',   sub: 'これから着手' },
    { key: 'doing',    title: '進行中',   sub: '0〜80%' },
    { key: 'done',     title: '担当完了', sub: '上司の確認待ち' },
    { key: 'approved', title: '上司完了', sub: '直近14日', managerOnly: true, managerView: true },
  ],
  // managerView の列（上司完了）は上司が開いたときだけ表示する。メンバーの画面は 3 列
  // 「完了（確認済）」に動かせるユーザー（Redmine 側のワークフローでも制限されている前提）
  managerUserIds: [1],
  // 表示切替タブと担当者の選択肢に並べるメンバー（Redmine のユーザー ID）
  members: [
    { id: 2, name: '高橋' },
    { id: 3, name: '伊藤' },
    { id: 4, name: '渡辺' },
    { id: 5, name: '中村' },
    { id: 6, name: '小林' },
    { id: 1, name: '山本（上司）' },
  ],
  // 対象バージョンの一覧を取るプロジェクト（識別子または ID）。
  // 未整理チケットもこのプロジェクトに絞る。null なら見える範囲すべて
  projectId: null,
  approvedDays: 14,     // 上司完了列に出す期間
  dueSoonDays: 3,       // この日数以内の締切を黄色で強調
  urgentPriority: 1,    // バージョン名の先頭番号がこの値以下なら「緊急」扱い（01 = 不具合など）
  syncDoneRatio: true,  // ステータス変更時に進捗率(done_ratio)も合わせて更新する
  // Redmine の検索条件「子チケット(child_id)」が使えるか。tools/redmine_config_dump.py の結果で設定する。
  // false の場合は候補のチケットを 1 件ずつ確認する（件数が多いと少し遅い）
  childFilterSupported: true,
  // 中継プログラム(kanban_relay.py)。ボードは中継プログラムが http://127.0.0.1:8765/ で出す
  relay: { port: 8765 },
  defaultMode: 'relay', // 'relay' | 'mock' | 'live'
  // タグの色は名前から自動で決まる（同じ名前は常に同じ色）。固定したい場合だけここに書く: { '05_開発業務_EV電池ケース': 1 }
  versionColors: {},
  // 工数: 進捗を動かしたときに出す時間の選択肢（時間）と、1日の所定時間
  hourChoices: [0.5, 1, 2, 4],
  hoursPerDay: 8,
  // 進行中のカードで、ステータス（進捗）がこの営業日数以上動いていなければ「N日動きなし」と出す
  staleDays: 5,
  // 1 人の「進行中」がこの件数を超えたら列の見出しで知らせる（手を広げすぎない）
  wipLimit: 5,
  // 課題バラシの日程計算で休みにする日（土日は自動で休み）。例: ['2026-12-29', '2026-12-30']
  holidays: [],
  // バージョンを新しく作るときに選ぶカテゴリ（バージョン名の先頭）。番号が小さいほど優先
  versionCategories: ['01_市場問題-', '02_供給問題-', '03_業務改善-', '03_風土改革-', '04_モジュール開発-',
    '05_開発業務-', '06_MBD開発-', '07_工場困りごと-', '08_原価低減-'],
};
/*__SERVER_CONFIG__*/
```

## 付録 D. 中継してよい API（kanban_relay.py）

```python
ALLOWED_API = [
    ("GET", re.compile(r"^/users/current\.json$")),
    ("GET", re.compile(r"^/issues\.json$")),
    ("GET", re.compile(r"^/issues/\d+\.json$")),
    ("PUT", re.compile(r"^/issues/\d+\.json$")),
    ("POST", re.compile(r"^/issues\.json$")),                          # 新規タスク
    ("GET", re.compile(r"^/projects/[\w\-]+/versions\.json$")),
    ("POST", re.compile(r"^/projects/[\w\-]+/versions\.json$")),     # バージョンの新規作成
    ("GET", re.compile(r"^/issue_statuses\.json$")),
    ("GET", re.compile(r"^/time_entries\.json$")),                    # 工数の集計
    ("POST", re.compile(r"^/time_entries\.json$")),                   # 工数の記録
    ("GET", re.compile(r"^/enumerations/time_entry_activities\.json$")),  # 作業分類（既定のものを使う）
    ("GET", re.compile(r"^/issues/\d+/relations\.json$")),             # 課題バラシ: 前後のつながり
    ("POST", re.compile(r"^/issues/\d+/relations\.json$")),
    ("DELETE", re.compile(r"^/relations/\d+\.json$")),
    ("GET", re.compile(r"^/enumerations/issue_priorities\.json$")),     # 優先度の一覧（★優先）
    ("GET", re.compile(r"^/lychee/api/v1/projects/[\w\-]+/milestones\.json$")),  # 休みの予定（Lychee のマイルストーン。読むだけ）
]
```

## 付録 E. build.py 全文

```python
"""src/kanban.fragment.html からボードの HTML を作り、kanban_relay.py に埋め込む。

    python build.py

- kanban_relay.py の BOARD_HTML_BEGIN〜END の間を書き換える（配布は kanban_relay.py だけでよい）
- 確認用に kanban.html も作る（ダブルクリックでモック表示できる）
"""
import base64
import re
import zlib
from datetime import datetime
from pathlib import Path

here = Path(__file__).parent
src = (here / "src" / "kanban.fragment.html").read_text(encoding="utf-8")
stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
src = src.replace("__BUILD__", stamp)
head, body = src.split("<!--BODY-->", 1)
html = (
    "<!DOCTYPE html>\n<html lang=\"ja\">\n<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
    + head.strip() + "\n</head>\n<body>\n" + body.strip() + "\n</body>\n</html>\n"
)
(here / "kanban.html").write_text(html, encoding="utf-8")

blob = base64.b64encode(zlib.compress(html.encode("utf-8"), 9)).decode()
lines = "\n".join(f'    "{blob[i:i + 100]}",' for i in range(0, len(blob), 100))
relay = here / "kanban_relay.py"
code = relay.read_text(encoding="utf-8")
code, n = re.subn(
    r"(# --- BOARD_HTML_BEGIN[^\n]*\n).*?(# --- BOARD_HTML_END ---)",
    lambda m: f"{m.group(1)}BOARD_HTML = [\n{lines}\n]\n{m.group(2)}",
    code, flags=re.S)
assert n == 1, "kanban_relay.py に BOARD_HTML_BEGIN/END の目印がありません"
# 自動更新で「古いものに戻さない」判定に使う（版番号が同じでも、埋め込んだ画面が新しいかどうか分かるように）
code, n = re.subn(r'^BUILD = "[^"]*"', f'BUILD = "{stamp}"', code, flags=re.M)
assert n == 1, "kanban_relay.py に BUILD = の行がありません"
relay.write_text(code, encoding="utf-8")
print(f"built kanban.html and embedded it in kanban_relay.py ({len(blob) // 1024} KB)")
```

## 付録 F. board_settings.example.json

```json
{
  "_説明": "board_settings.json という名前でコピーして kanban_relay.py と同じフォルダに置く。名前は Redmine に表示される名前（空白の有無は区別しない）か、ユーザー ID の数字で書く。",
  "redmine_url": "https://redmine.example.com",
  "project": "design-tasks",
  "_team の書き方": "\"auto\" なら未完了のチケットを担当している人だけ。名前の一覧を書けばその人だけ。",
  "team": "auto",
  "team_exclude": [],
  "_team_order の書き方": "タブの並び順。ここに書いた人がこの順で先頭に並び、残りはその後ろ。",
  "team_order": [],
  "_managers の書き方": "名前（Redmine の表示名）か ID（12 でも \"12\" でもよい）。プロジェクトのメンバーでなくても、チケットの担当者・作成者か、中継を動かしている本人なら見つかる。",
  "managers": [
    "山本 一郎"
  ],
  "status_columns": {},
  "update_dir": "",
  "options": {
    "urgentPriority": 1,
    "dueSoonDays": 3,
    "approvedDays": 14,
    "versionColors": {},
    "hoursPerDay": 8,
    "_holidays の書き方": "課題バラシの日程計算で休みにする日（土日は自動で休み）。例: [\"2026-12-29\", \"2026-12-30\"]",
    "holidays": []
  }
}
```

## 付録 G. setup.bat（ASCII のみ）

```bat
@echo off
rem Design task board: first-time setup (API key, auto start, desktop shortcut)
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 kanban_relay.py --setup
) else (
  python kanban_relay.py --setup
)
```
