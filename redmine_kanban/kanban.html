<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>設計課タスクボード</title>
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
    --line: #2d3641; --accent: #5fb0d8; --accent-ink: #0b1a22; --accent-soft: #183442;
    --late: #ff8f80; --late-bg: #3b1d1a; --soon: #f0c064; --soon-bg: #362a0e; --ok: #74d39a; --ok-bg: #16301f;
    --drop: #1b3a4a; --shadow: 0 1px 2px rgba(0,0,0,.35);
    --tag1-bg: #1c2d4a; --tag1-fg: #9dbdf4; --tag2-bg: #17322a; --tag2-fg: #8fd8b3; --tag3-bg: #3a2516; --tag3-fg: #f2b184;
    --tag4-bg: #36203a; --tag4-fg: #e7a6da; --tag5-bg: #262d37; --tag5-fg: #b9c2cf; --tag6-bg: #332d12; --tag6-fg: #e3cf7c;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #11161c; --surface: #1a2129; --surface-2: #212932; --ink: #e5eaf0; --ink-2: #a0abb8; --ink-3: #6f7a88;
  --line: #2d3641; --accent: #5fb0d8; --accent-ink: #0b1a22; --accent-soft: #183442;
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
.dialog-actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }

.loading { display: grid; place-items: center; color: var(--ink-3); font-size: 13px; }

@media (max-width: 860px) {
  body { overflow: auto; }
  .board { grid-template-columns: repeat(4, minmax(250px, 80%)); }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
<div class="app" id="app">
  <header class="topbar">
    <div class="brand">
      <h1>設計課タスクボード</h1>
      <span class="today" id="today"></span>
      <span class="mode-pill" id="modePill">モック</span>
    </div>
    <div class="spacer"></div>
    <div class="tools">
      <label class="mock-user" id="mockUserWrap" for="mockUser">モックの操作ユーザー
        <select id="mockUser"></select>
      </label>
      <button class="btn" id="reloadBtn" type="button">再読み込み</button>
      <button class="btn" id="settingsBtn" type="button">接続設定</button>
    </div>
  </header>

  <div class="subbar">
    <div class="tabs" role="tablist" id="tabs" aria-label="表示するメンバー"></div>
    <div class="summary" id="summary" aria-live="polite"></div>
  </div>

  <div class="board-wrap">
    <main class="board" id="board"><div class="loading">読み込み中…</div></main>
  </div>
</div>

<div class="cancel-zone" id="cancelZone" hidden>ここにドロップすると「中止」</div>
<div class="toasts" id="toasts" aria-live="polite"></div>

<div class="overlay" id="settings" hidden>
  <form class="dialog" id="settingsForm" aria-labelledby="settingsTitle">
    <h2 id="settingsTitle">接続設定</h2>
    <div class="field">
      <span class="label">データの取得元</span>
      <div class="radios">
        <label><input type="radio" name="mode" id="modeMock" value="mock"> モック（ダミーデータ）</label>
        <label><input type="radio" name="mode" id="modeLive" value="live"> Redmine</label>
      </div>
    </div>
    <div class="field">
      <label for="redmineUrl">Redmine の URL</label>
      <input type="text" id="redmineUrl" placeholder="https://redmine.example.com" autocomplete="off">
    </div>
    <div class="field">
      <label for="apiKey">自分の API キー</label>
      <input type="password" id="apiKey" placeholder="Redmine の「個人設定」→「APIアクセスキー」" autocomplete="off">
      <p class="hint">キーはこのブラウザの中だけに保存されます。他の人のキーは使わないでください（変更履歴がその人の名前で残ります）。</p>
    </div>
    <p class="test-result" id="testResult" hidden></p>
    <div class="dialog-actions">
      <button class="btn" type="button" id="testBtn">接続テスト</button>
      <button class="btn" type="button" id="cancelSettings">閉じる</button>
      <button class="btn primary" type="submit">保存して再読み込み</button>
    </div>
  </form>
</div>

<script>
'use strict';
/* =====================================================================
 * 1. CONFIG — 運用に合わせてここだけ書き換える
 * ===================================================================== */
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
    { id: 7, name: '完了',       col: 'done',      ratio: 100 },
    { id: 8, name: '上司確認済', col: 'approved',  ratio: 100 },
    { id: 9, name: '中止',       col: 'cancelled', ratio: null },
  ],
  // 列の定義。dropStatus = その列にドロップしたときに設定するステータス ID
  columns: [
    { key: 'todo',     title: '未着手',   sub: 'これから着手',  dropStatus: 1 },
    { key: 'doing',    title: '進行中',   sub: '0〜80%',        dropStatus: 2 },
    { key: 'done',     title: '担当完了', sub: '上司の確認待ち', dropStatus: 7 },
    { key: 'approved', title: '上司完了', sub: '直近14日',       dropStatus: 8, managerOnly: true },
  ],
  cancelStatus: 9,
  // 「上司確認済」に動かせるユーザー（Redmine 側のワークフローでも制限されている前提）
  managerUserIds: [1],
  // 表示切替タブに並べるメンバー（Redmine のユーザー ID）
  members: [
    { id: 2, name: '高橋' },
    { id: 3, name: '伊藤' },
    { id: 4, name: '渡辺' },
    { id: 5, name: '中村' },
    { id: 6, name: '小林' },
    { id: 1, name: '山本（課長）' },
  ],
  approvedDays: 14,     // 上司完了列に出す期間
  dueSoonDays: 3,       // この日数以内の期日を黄色で強調
  syncDoneRatio: true,  // ステータス変更時に進捗率(done_ratio)も合わせて更新する
  // 対象バージョン名 → タグ色(1〜6)。未登録の名前は自動で色を割り当てる
  versionColors: {
    '次期SUV車体': 1,
    'EV電池ケース': 2,
    '原価低減VA': 3,
    '法規対応': 4,
    '部内改善': 5,
  },
};

/* =====================================================================
 * 2. 日付ユーティリティ
 * ===================================================================== */
const DAY = 86400000;
function startOfToday() { const d = new Date(); d.setHours(0, 0, 0, 0); return d; }
function parseDate(s) { if (!s) return null; const [y, m, d] = s.slice(0, 10).split('-').map(Number); return new Date(y, m - 1, d); }
function isoDate(d) { const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`; }
function addDays(d, n) { const x = new Date(d); x.setDate(x.getDate() + n); return x; }
function daysFromToday(s) { const d = parseDate(s); return d ? Math.round((d - startOfToday()) / DAY) : null; }
function jpDate(d) { return `${d.getMonth() + 1}/${d.getDate()}(${'日月火水木金土'[d.getDay()]})`; }

/* =====================================================================
 * 3. API 層 — MockApi と RedmineApi は同じ関数を持つ。画面側はこの差を知らない
 *    currentUser()            → { id, name }
 *    issuesFor(userId)        → Redmine の issue 配列（未完了 + 直近に閉じたもの）
 *    issuesByIds(ids)         → 親チケット名の解決用
 *    updateIssue(id, fields)  → PUT /issues/:id.json
 * ===================================================================== */
function createMockApi(getMockUserId) {
  const t = startOfToday();
  const d = n => (n === null ? null : isoDate(addDays(t, n)));
  const ts = n => addDays(t, n).toISOString();
  const users = { 1: '山本 一郎', 2: '高橋 健', 3: '伊藤 さくら', 4: '渡辺 大輔', 5: '中村 美咲', 6: '小林 翔' };
  // [id, 担当, 件名, 親ID, 対象バージョン, ステータスID, 期日(今日からの日数), 更新日(今日からの日数)]
  const rows = [
    [4100, 1, 'フロントバンパー設計', null, '次期SUV車体', 3, 40, -1],
    [4200, 1, '電池ケース締結構造の検討', null, 'EV電池ケース', 3, 55, -2],
    [4300, 1, 'ブラケット部品のVA検討', null, '原価低減VA', 2, 30, -3],
    [4400, 1, '歩行者保護 法規対応', null, '法規対応', 4, 20, -1],
    [4500, 1, 'CAD標準テンプレートの整備', null, '部内改善', 3, 60, -5],
    [4600, 1, 'リアドア ヒンジ設計', null, '次期SUV車体', 2, 70, -4],

    [4521, 2, 'バンパービーム断面の強度解析', 4100, '次期SUV車体', 4, -2, -1],
    [4522, 2, 'バンパー取付ブラケットの図面作成', 4100, '次期SUV車体', 3, 2, 0],
    [4523, 2, '樹脂バンパーの型抜き方向を確認', 4100, '次期SUV車体', 1, 9, -3],
    [4531, 2, '電池ケースのボルト締結トルク計算', 4200, 'EV電池ケース', 5, 1, 0],
    [4532, 2, 'シール材メーカーへ仕様を問い合わせ', 4200, 'EV電池ケース', 1, 3, -2],
    [4533, 2, '締結部 FEMメッシュ作成', 4200, 'EV電池ケース', 2, 12, -1],
    [4541, 2, '歩行者頭部衝撃の試験条件を整理', 4400, '法規対応', 7, -1, -1],
    [4542, 2, 'フードヒンジ部の変位量確認', 4400, '法規対応', 6, 0, 0],
    [4551, 2, 'ブラケット板厚変更の原価試算', 4300, '原価低減VA', 7, 5, 0],
    [4561, 2, 'CADテンプレート 図枠の改訂案', 4500, '部内改善', 8, -6, -4],
    [4562, 2, '設計変更通知の書式見直し', 4500, '部内改善', 8, -12, -10],
    [4563, 2, '旧図面のPDF化', 4500, '部内改善', 8, -40, -30],
    [4571, 2, '【割込】量産部品の寸法問い合わせに回答', null, null, 3, -1, 0],
    [4572, 2, '試作車の取付確認に立会い', 4600, '次期SUV車体', 1, null, -6],
    [4573, 2, '社内レビュー資料の誤記修正', 4100, '次期SUV車体', 9, 4, -1],

    [4610, 3, 'ヒンジ取付部の板金形状検討', 4600, '次期SUV車体', 4, 6, -1],
    [4611, 3, 'ドア開閉耐久の試験計画書', 4600, '次期SUV車体', 1, 14, -2],
    [4612, 3, '【割込】仕入先の図面差異を確認', null, null, 2, -3, 0],
    [4613, 3, 'ヒンジ部品の重量見積り', 4600, '次期SUV車体', 7, 1, 0],
    [4614, 3, 'ストライカー位置の公差計算', 4600, '次期SUV車体', 8, -5, -3],

    [4410, 4, '頭部インパクタ試験の結果整理', 4400, '法規対応', 5, -4, -1],
    [4411, 4, 'フード裏 補強材の配置見直し', 4400, '法規対応', 3, 7, -2],
    [4412, 4, '認証機関への提出資料ドラフト', 4400, '法規対応', 1, 18, -5],
    [4413, 4, '衝撃吸収材メーカーとの打合せ', 4400, '法規対応', 7, -2, -1],

    [4310, 5, 'ブラケット材質変更の強度確認', 4300, '原価低減VA', 6, 2, 0],
    [4311, 5, '溶接点数削減案の作成', 4300, '原価低減VA', 3, 10, -1],
    [4312, 5, 'VA提案書のとりまとめ', 4300, '原価低減VA', 1, 25, -7],
    [4313, 5, '競合車の分解調査メモ', 4300, '原価低減VA', 8, -9, -8],
    [4314, 5, '【割込】生産技術からの成形性質問', null, null, 1, 1, 0],

    [4210, 6, '電池ケース 冷却水路の取り回し', 4200, 'EV電池ケース', 4, 8, -1],
    [4211, 6, '底面プロテクタの石はね解析', 4200, 'EV電池ケース', 2, 4, -1],
    [4212, 6, 'ケース締結ボルトの部品手配', 4200, 'EV電池ケース', 7, -1, 0],
    [4213, 6, 'CADテンプレート 部品表の項目整理', 4500, '部内改善', 1, 21, -9],
    [4214, 6, '防水コネクタの配置案', 4200, 'EV電池ケース', 3, -1, -2],
  ];
  const statusById = Object.fromEntries(CONFIG.statuses.map(s => [s.id, s]));
  const db = new Map(rows.map(([id, uid, subject, parent, ver, st, due, upd]) => [id, {
    id, subject,
    project: { id: 1, name: '設計課' },
    assigned_to: { id: uid, name: users[uid] },
    parent: parent ? { id: parent } : undefined,
    fixed_version: ver ? { id: ver.length, name: ver } : undefined,
    status: { id: st, name: statusById[st].name },
    done_ratio: statusById[st].ratio ?? 0,
    due_date: d(due),
    updated_on: ts(upd),
  }]));
  const clone = o => JSON.parse(JSON.stringify(o));
  const wait = (ms = 250) => new Promise(r => setTimeout(r, ms));
  const closedIds = new Set([8, 9]);
  return {
    async currentUser() { await wait(120); const id = getMockUserId(); return { id, name: users[id] }; },
    async issuesFor(userId) {
      await wait();
      const since = addDays(t, -CONFIG.approvedDays);
      return [...db.values()]
        .filter(i => i.assigned_to.id === userId)
        .filter(i => !closedIds.has(i.status.id) || new Date(i.updated_on) >= since)
        .map(clone);
    },
    async issuesByIds(ids) { await wait(80); return ids.map(id => db.get(id)).filter(Boolean).map(clone); },
    async updateIssue(id, fields) {
      await wait(350);
      const issue = db.get(id);
      if (!issue) throw new Error(`#${id} が見つかりません (404)`);
      const me = getMockUserId();
      const touchesApproved = fields.status_id === 8 || issue.status.id === 8;
      if (touchesApproved && !CONFIG.managerUserIds.includes(me)) {
        throw new Error('このステータスへの変更はワークフローで許可されていません (422)');
      }
      if (fields.status_id) issue.status = { id: fields.status_id, name: statusById[fields.status_id].name };
      if (fields.done_ratio != null) issue.done_ratio = fields.done_ratio;
      issue.updated_on = new Date().toISOString();
    },
  };
}

function createRedmineApi(baseUrl, apiKey) {
  const base = baseUrl.replace(/\/+$/, '');
  async function req(path, options = {}) {
    let res;
    try {
      res = await fetch(base + path, {
        ...options,
        headers: { 'X-Redmine-API-Key': apiKey, 'Content-Type': 'application/json', ...(options.headers || {}) },
      });
    } catch (e) {
      // fetch 自体が失敗するのは、ほぼ CORS 拒否かネットワーク遮断
      throw new Error('Redmine に接続できませんでした。Redmine 側で CORS が許可されていないか、ネットワークで遮断されています。');
    }
    if (!res.ok) {
      let detail = '';
      try { const j = await res.json(); detail = (j.errors || []).join(' / '); } catch (_) { /* 本文なし */ }
      if (res.status === 401) throw new Error('API キーが正しくありません (401)');
      if (res.status === 403) throw new Error('この操作の権限がありません (403)');
      throw new Error(`Redmine がエラーを返しました (${res.status}) ${detail}`);
    }
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }
  async function allIssues(query) {
    const out = [];
    for (let offset = 0; ; ) {
      const j = await req(`/issues.json?${query}&limit=100&offset=${offset}`);
      out.push(...j.issues);
      offset += j.issues.length;
      if (!j.issues.length || offset >= j.total_count) return out;
    }
  }
  return {
    async currentUser() {
      const j = await req('/users/current.json');
      return { id: j.user.id, name: `${j.user.lastname} ${j.user.firstname}` };
    },
    async issuesFor(userId) {
      const since = isoDate(addDays(startOfToday(), -CONFIG.approvedDays));
      const [open, closed] = await Promise.all([
        allIssues(`assigned_to_id=${userId}&status_id=open`),
        allIssues(`assigned_to_id=${userId}&status_id=closed&updated_on=${encodeURIComponent('>=' + since)}`),
      ]);
      return [...open, ...closed];
    },
    async issuesByIds(ids) {
      if (!ids.length) return [];
      return allIssues(`issue_id=${ids.join(',')}&status_id=*`);
    },
    async updateIssue(id, fields) {
      await req(`/issues/${id}.json`, { method: 'PUT', body: JSON.stringify({ issue: fields }) });
    },
  };
}

/* =====================================================================
 * 4. 設定の保存（このブラウザの中だけ）
 * ===================================================================== */
const STORE_KEY = 'designBoard.settings.v1';
function loadSettings() {
  const fallback = { mode: 'mock', url: '', key: '', mockUserId: 2, viewUserId: null };
  try { return { ...fallback, ...JSON.parse(localStorage.getItem(STORE_KEY) || '{}') }; } catch (_) { return fallback; }
}
function saveSettings() { try { localStorage.setItem(STORE_KEY, JSON.stringify(settings)); } catch (_) { /* 保存できなくても動作は続ける */ } }

/* =====================================================================
 * 5. 状態
 * ===================================================================== */
let settings = loadSettings();
let api = null;
const state = { me: null, viewUserId: null, issues: new Map(), parents: new Map(), saving: new Set() };
const statusById = Object.fromEntries(CONFIG.statuses.map(s => [s.id, s]));
const colOf = issue => (statusById[issue.status.id] || {}).col;
const isManager = () => state.me && CONFIG.managerUserIds.includes(state.me.id);

function buildApi() {
  api = settings.mode === 'live' && settings.url && settings.key
    ? createRedmineApi(settings.url, settings.key)
    : createMockApi(() => settings.mockUserId);
}

/* =====================================================================
 * 6. 描画
 * ===================================================================== */
const $ = id => document.getElementById(id);
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c.nodeType ? c : String(c));
  return el;
}

function tagClass(name) {
  if (CONFIG.versionColors[name]) return 't' + CONFIG.versionColors[name];
  let n = 0; for (const ch of name) n = (n * 31 + ch.charCodeAt(0)) >>> 0;
  return 't' + ((n % 6) + 1);
}

function dueInfo(issue) {
  const col = colOf(issue);
  const n = daysFromToday(issue.due_date);
  if (n === null) return { cls: 'none', text: '期日なし', level: 0 };
  const date = jpDate(parseDate(issue.due_date));
  if (col === 'done' || col === 'approved') return { cls: '', text: date, level: 0 };
  if (n < 0) return { cls: 'late', text: `${-n}日超過 ${date}`, level: 2 };
  if (n === 0) return { cls: 'soon', text: `今日まで ${date}`, level: 1 };
  if (n <= CONFIG.dueSoonDays) return { cls: 'soon', text: `あと${n}日 ${date}`, level: 1 };
  return { cls: '', text: date, level: 0 };
}

function issueUrl(id) { return settings.mode === 'live' && settings.url ? `${settings.url.replace(/\/+$/, '')}/issues/${id}` : null; }

function renderCard(issue) {
  const col = colOf(issue);
  const due = dueInfo(issue);
  const parentName = issue.parent ? (state.parents.get(issue.parent.id) || `#${issue.parent.id}`) : null;
  const version = issue.fixed_version ? issue.fixed_version.name : '未分類';
  const url = issueUrl(issue.id);

  let progress = null;
  if (col === 'doing') {
    const steps = CONFIG.statuses.filter(s => s.col === 'doing');
    const current = statusById[issue.status.id].ratio;
    progress = h('div', { class: 'progress', role: 'group', 'aria-label': '進捗' },
      steps.map(s => h('button', {
        type: 'button', draggable: 'false',
        class: s.ratio < current ? 'filled' : '',
        'aria-pressed': String(s.id === issue.status.id),
        title: `進捗を ${s.name} にする`,
        onclick: e => { e.stopPropagation(); if (s.id !== issue.status.id) changeStatus(issue.id, s.id); },
      }, s.ratio)));
  }

  return h('article', {
    class: ['card', due.level === 2 ? 'is-late' : '', state.saving.has(issue.id) ? 'saving' : ''].join(' ').trim(),
    draggable: 'true', tabindex: '0', 'data-id': issue.id,
    'aria-label': `#${issue.id} ${issue.subject}`,
  },
    h('div', { class: 'card-top' },
      h('span', { class: 'parent', title: parentName || '' }, parentName ? `親: ${parentName}` : ''),
      h('span', { class: `tag ${tagClass(version)}`, title: `対象バージョン: ${version}` }, version)),
    h('h3', { class: 'subject' }, issue.subject),
    h('div', { class: 'card-foot' },
      h('span', { class: 'num' }, url ? h('a', { href: url, target: '_blank', rel: 'noopener' }, `#${issue.id}`) : `#${issue.id}`),
      h('span', { class: `due ${due.cls}` }, due.text)),
    progress);
}

function sortIssues(a, b) {
  const da = a.due_date || '9999', db = b.due_date || '9999';
  return da < db ? -1 : da > db ? 1 : a.id - b.id;
}

function renderBoard() {
  const board = $('board');
  const scroll = {};
  board.querySelectorAll('.col').forEach(c => { scroll[c.dataset.col] = c.querySelector('.col-body').scrollTop; });
  const focusedId = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.id : null;

  const visible = [...state.issues.values()].filter(i => i.assigned_to && i.assigned_to.id === state.viewUserId);
  board.replaceChildren(...CONFIG.columns.map(col => {
    const items = visible.filter(i => colOf(i) === col.key).sort(col.key === 'approved' ? (a, b) => b.updated_on.localeCompare(a.updated_on) : sortIssues);
    const locked = col.managerOnly && !isManager();
    const body = h('div', { class: 'col-body' },
      items.length ? items.map(renderCard) : h('p', { class: 'empty' }, 'カードはありません'));
    const section = h('section', { class: 'col', 'data-col': col.key, 'aria-label': col.title },
      h('header', { class: 'col-head' },
        h('h2', {}, col.title),
        h('span', { class: 'sub' }, col.sub),
        locked ? h('span', { class: 'lock', title: '上司だけが移動できます' }, '上司のみ') : null,
        h('span', { class: 'count' }, items.length)),
      body);
    return section;
  }));
  board.querySelectorAll('.col').forEach(c => { c.querySelector('.col-body').scrollTop = scroll[c.dataset.col] || 0; });
  if (focusedId) { const el = board.querySelector(`.card[data-id="${focusedId}"]`); if (el) el.focus(); }
  renderSummary(visible);
}

function renderSummary(visible) {
  const active = visible.filter(i => ['todo', 'doing'].includes(colOf(i)));
  const late = active.filter(i => dueInfo(i).level === 2).length;
  const soon = active.filter(i => dueInfo(i).level === 1).length;
  const waiting = visible.filter(i => colOf(i) === 'done').length;
  $('summary').replaceChildren(
    h('span', { class: 'chip' + (late ? ' late' : '') }, '期限切れ', h('b', {}, late)),
    h('span', { class: 'chip' + (soon ? ' soon' : '') }, `${CONFIG.dueSoonDays}日以内`, h('b', {}, soon)),
    h('span', { class: 'chip' }, '手持ち', h('b', {}, active.length)),
    h('span', { class: 'chip' }, '確認待ち', h('b', {}, waiting)));
}

function renderTabs() {
  const members = CONFIG.members.some(m => m.id === state.me.id) ? CONFIG.members : [{ id: state.me.id, name: state.me.name }, ...CONFIG.members];
  $('tabs').replaceChildren(...members.map(m => h('button', {
    type: 'button', role: 'tab', class: 'tab',
    'aria-selected': String(m.id === state.viewUserId),
    onclick: () => switchView(m.id),
  }, m.name, m.id === state.me.id ? h('span', { class: 'me' }, '自分') : null)));
}

function renderChrome() {
  const live = settings.mode === 'live';
  $('modePill').textContent = live ? 'Redmine接続' : 'モック';
  $('modePill').classList.toggle('live', live);
  $('mockUserWrap').hidden = live;
  const now = startOfToday();
  $('today').textContent = `${now.getFullYear()}年${jpDate(now)}`;
  $('mockUser').replaceChildren(...CONFIG.members.map(m => h('option', { value: m.id, selected: m.id === settings.mockUserId }, m.name)));
}

/* =====================================================================
 * 7. データ読み込み
 * ===================================================================== */
async function loadUser(userId) {
  const issues = await api.issuesFor(userId);
  for (const [id, i] of state.issues) if (i.assigned_to && i.assigned_to.id === userId) state.issues.delete(id);
  for (const i of issues) if (statusById[i.status.id]) state.issues.set(i.id, i);
  const missing = [...new Set(issues.filter(i => i.parent).map(i => i.parent.id))].filter(id => !state.parents.has(id));
  if (missing.length) {
    const parents = await api.issuesByIds(missing);
    for (const p of parents) state.parents.set(p.id, p.subject);
  }
}

async function boot() {
  buildApi();
  renderChrome();
  $('board').replaceChildren(h('div', { class: 'loading' }, '読み込み中…'));
  try {
    state.me = await api.currentUser();
    state.issues.clear();
    state.viewUserId = state.me.id;
    renderTabs();
    await loadUser(state.viewUserId);
    renderBoard();
  } catch (e) {
    $('board').replaceChildren(h('div', { class: 'loading' }, e.message));
    toast(e.message, { error: true });
  }
}

async function switchView(userId) {
  state.viewUserId = userId;
  renderTabs();
  try { await loadUser(userId); } catch (e) { toast(e.message, { error: true }); }
  renderBoard();
}

/* =====================================================================
 * 8. 更新操作（先に画面を変え、失敗したら元に戻す）
 * ===================================================================== */
async function changeStatus(id, statusId, { undoable = false } = {}) {
  const issue = state.issues.get(id);
  if (!issue || state.saving.has(id)) return;
  const prev = { status: issue.status, done_ratio: issue.done_ratio };
  const next = statusById[statusId];
  const fields = { status_id: statusId };
  if (CONFIG.syncDoneRatio && next.ratio != null) fields.done_ratio = next.ratio;

  issue.status = { id: statusId, name: next.name };
  if (fields.done_ratio != null) issue.done_ratio = fields.done_ratio;
  state.saving.add(id);
  renderBoard();
  try {
    await api.updateIssue(id, fields);
    issue.updated_on = new Date().toISOString();
    const undo = undoable ? () => changeStatus(id, prev.status.id) : null;
    toast(`#${id} を「${next.name}」にしました`, { action: undo && { label: '元に戻す', run: undo } });
  } catch (e) {
    issue.status = prev.status;
    issue.done_ratio = prev.done_ratio;
    toast(`#${id} を更新できませんでした。${e.message}`, { error: true });
  } finally {
    state.saving.delete(id);
    renderBoard();
  }
}

function canMove(issue, targetCol) {
  const from = colOf(issue);
  if (from === targetCol) return { ok: false, quiet: true };
  if ((targetCol === 'approved' || from === 'approved') && !isManager()) {
    return { ok: false, reason: '「上司完了」への移動と、そこからの差し戻しは上司だけができます' };
  }
  return { ok: true };
}

function moveToColumn(id, targetCol) {
  const issue = state.issues.get(id);
  if (!issue) return;
  const check = canMove(issue, targetCol);
  if (!check.ok) { if (!check.quiet) toast(check.reason, { error: true }); return; }
  const col = CONFIG.columns.find(c => c.key === targetCol);
  changeStatus(id, col.dropStatus, { undoable: true });
}

/* =====================================================================
 * 9. ドラッグ＆ドロップ / キーボード
 * ===================================================================== */
let dragId = null;
const board = $('board');

board.addEventListener('dragstart', e => {
  const card = e.target.closest && e.target.closest('.card');
  if (!card) return;
  dragId = Number(card.dataset.id);
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(dragId));
  card.classList.add('dragging');
  const issue = state.issues.get(dragId);
  board.querySelectorAll('.col').forEach(c => { const r = canMove(issue, c.dataset.col); if (!r.ok && !r.quiet) c.classList.add('drag-denied'); });
  $('cancelZone').hidden = false;
});
board.addEventListener('dragend', () => {
  dragId = null;
  board.querySelectorAll('.dragging, .drag-over, .drag-denied').forEach(el => el.classList.remove('dragging', 'drag-over', 'drag-denied'));
  $('cancelZone').hidden = true;
  $('cancelZone').classList.remove('drag-over');
});
board.addEventListener('dragover', e => {
  const col = e.target.closest && e.target.closest('.col');
  if (!col || dragId == null) return;
  e.preventDefault();
  board.querySelectorAll('.col.drag-over').forEach(c => c !== col && c.classList.remove('drag-over'));
  col.classList.add('drag-over');
});
board.addEventListener('dragleave', e => {
  const col = e.target.closest && e.target.closest('.col');
  if (col && !col.contains(e.relatedTarget)) col.classList.remove('drag-over');
});
board.addEventListener('drop', e => {
  const col = e.target.closest && e.target.closest('.col');
  if (!col || dragId == null) return;
  e.preventDefault();
  moveToColumn(dragId, col.dataset.col);
});

const cancelZone = $('cancelZone');
cancelZone.addEventListener('dragover', e => { e.preventDefault(); cancelZone.classList.add('drag-over'); });
cancelZone.addEventListener('dragleave', () => cancelZone.classList.remove('drag-over'));
cancelZone.addEventListener('drop', e => {
  e.preventDefault();
  if (dragId != null) changeStatus(dragId, CONFIG.cancelStatus, { undoable: true });
});

// キーボード: カードを選んで ← → で隣の列へ
board.addEventListener('keydown', e => {
  const card = e.target.closest && e.target.closest('.card');
  if (!card || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
  e.preventDefault();
  const id = Number(card.dataset.id);
  const keys = CONFIG.columns.map(c => c.key);
  const idx = keys.indexOf(colOf(state.issues.get(id))) + (e.key === 'ArrowRight' ? 1 : -1);
  if (idx >= 0 && idx < keys.length) moveToColumn(id, keys[idx]);
});

/* =====================================================================
 * 10. トースト / 設定ダイアログ
 * ===================================================================== */
function toast(message, { error = false, action = null } = {}) {
  const el = h('div', { class: 'toast' + (error ? ' error' : ''), role: error ? 'alert' : 'status' }, h('span', {}, message));
  if (action) el.append(h('button', { type: 'button', onclick: () => { el.remove(); action.run(); } }, action.label));
  $('toasts').append(el);
  setTimeout(() => el.remove(), error ? 7000 : 5000);
}

function openSettings() {
  $(settings.mode === 'live' ? 'modeLive' : 'modeMock').checked = true;
  $('redmineUrl').value = settings.url;
  $('apiKey').value = settings.key;
  $('testResult').hidden = true;
  $('settings').hidden = false;
  $('redmineUrl').focus();
}
function closeSettings() { $('settings').hidden = true; }

$('settingsBtn').addEventListener('click', openSettings);
$('cancelSettings').addEventListener('click', closeSettings);
$('settings').addEventListener('click', e => { if (e.target === $('settings')) closeSettings(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('settings').hidden) closeSettings(); });

$('testBtn').addEventListener('click', async () => {
  const out = $('testResult');
  out.hidden = false; out.className = 'test-result'; out.textContent = '接続を確認しています…';
  const url = $('redmineUrl').value.trim(), key = $('apiKey').value.trim();
  if (!url || !key) { out.className = 'test-result ng'; out.textContent = 'URL と API キーを入力してください。'; return; }
  try {
    const me = await createRedmineApi(url, key).currentUser();
    out.className = 'test-result ok';
    out.textContent = `接続できました。ログインユーザー: ${me.name}（ID ${me.id}）`;
  } catch (e) {
    out.className = 'test-result ng';
    out.textContent = `${e.message}\nこのページを開いている場所: ${location.origin}`;
  }
});

$('settingsForm').addEventListener('submit', e => {
  e.preventDefault();
  const mode = $('modeLive').checked ? 'live' : 'mock';
  const url = $('redmineUrl').value.trim(), key = $('apiKey').value.trim();
  if (mode === 'live' && (!url || !key)) {
    const out = $('testResult'); out.hidden = false; out.className = 'test-result ng';
    out.textContent = 'Redmine に接続するには URL と API キーが必要です。';
    return;
  }
  settings = { ...settings, mode, url, key };
  saveSettings();
  closeSettings();
  boot();
});

$('mockUser').addEventListener('change', e => {
  settings.mockUserId = Number(e.target.value);
  saveSettings();
  boot();
});

$('reloadBtn').addEventListener('click', async () => {
  try { await loadUser(state.viewUserId); renderBoard(); toast('最新の状態を読み込みました'); }
  catch (e) { toast(e.message, { error: true }); }
});

boot();
</script>
</body>
</html>
