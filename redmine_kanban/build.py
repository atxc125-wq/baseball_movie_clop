"""src/kanban.fragment.html から SharePoint 配置用の完全な HTML を作る。

SharePoint では拡張子を .aspx にして置く。文字化け防止のため
<meta charset="utf-8"> を head の先頭に必ず入れる。
"""
from pathlib import Path

here = Path(__file__).parent
src = (here / "src" / "kanban.fragment.html").read_text(encoding="utf-8")
head, body = src.split("<!--BODY-->", 1)
html = (
    "<!DOCTYPE html>\n<html lang=\"ja\">\n<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
    + head.strip() + "\n</head>\n<body>\n" + body.strip() + "\n</body>\n</html>\n"
)
for name in ("kanban.html", "kanban.aspx"):
    # BOM 付き UTF-8 にしておくと SharePoint/IE 系でも文字コード判定を誤りにくい
    (here / name).write_text(html, encoding="utf-8-sig")
print("built kanban.html / kanban.aspx")
