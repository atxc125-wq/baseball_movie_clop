"""docs/REBUILD_PROMPT.md の付録 A〜G と docs/board.css・docs/board_body.html を、いまのソースから作り直す。

    python tools/update_rebuild_prompt.py

本文（「## 付録について」まで）は手で書く。付録はソースからそのまま抜き出すので、手で直さない。
"""
from pathlib import Path

here = Path(__file__).resolve().parent.parent
src = (here / "src" / "kanban.fragment.html").read_text(encoding="utf-8")
relay = (here / "kanban_relay.py").read_text(encoding="utf-8")
prompt_path = here / "docs" / "REBUILD_PROMPT.md"
prompt = prompt_path.read_text(encoding="utf-8")

head = src[:src.index("<style>")]
css = src[src.index("<style>"):src.index("</style>") + len("</style>")]
body = src[src.index("<!--BODY-->"):src.index("<script>")]
config = src[src.index("const CONFIG = {"):src.index("/*__SERVER_CONFIG__*/") + len("/*__SERVER_CONFIG__*/")]
start = relay.index("ALLOWED_API = [")
api = relay[start:relay.index("\n]\n", start) + 2]   # 行頭の ] まで（正規表現の中の ] では切らない）


def fence(lang: str, text: str) -> str:
    assert "```" not in text, "付録の中に ``` があると壊れる"
    return f"```{lang}\n{text.rstrip()}\n```\n"


appendix = (
    "## 付録 A. `<head>` の先頭と CSS 全文（src/kanban.fragment.html の `<style>` 〜 `</style>`）\n\n" + fence("html", head + css) + "\n"
    "## 付録 B. 画面の HTML 全文（`<!--BODY-->` から `<script>` の直前まで。使い方ページの本文を含む）\n\n" + fence("html", body) + "\n"
    "## 付録 C. 初期設定（`<script>` 冒頭の CONFIG。中継が `/*__SERVER_CONFIG__*/` の位置で上書きする）\n\n"
    "`<script>` の最初は `'use strict';` と `const BOARD_BUILD = '__BUILD__';`、その次にこれ:\n\n" + fence("js", config) + "\n"
    "## 付録 D. 中継してよい API（kanban_relay.py）\n\n" + fence("python", api) + "\n"
    "## 付録 E. build.py 全文\n\n" + fence("python", (here / "build.py").read_text(encoding="utf-8")) + "\n"
    "## 付録 F. board_settings.example.json\n\n" + fence("json", (here / "board_settings.example.json").read_text(encoding="utf-8")) + "\n"
    "## 付録 G. setup.bat（ASCII のみ）\n\n" + fence("bat", (here / "setup.bat").read_text(encoding="utf-8"))
)
cut = prompt.index("## 付録 A.")
prompt_path.write_text(prompt[:cut] + appendix, encoding="utf-8")
(here / "docs" / "board.css").write_text(
    "/* タスクボードの CSS 全文（src/kanban.fragment.html の <style> の中身。一字一句そのまま使う） */\n"
    + src[src.index("<style>") + 7:src.index("</style>")].strip("\n") + "\n", encoding="utf-8")
(here / "docs" / "board_body.html").write_text(
    "<!-- タスクボードの画面の HTML 全文（<body> の中身、<script> より前。クラス名・id を変えない） -->\n"
    + body[len("<!--BODY-->"):].strip("\n") + "\n", encoding="utf-8")
print("updated", prompt_path)
