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
