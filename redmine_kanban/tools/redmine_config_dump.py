"""Redmine から設定値を読み、タスクボードの CONFIG に貼れる形で出力する。

使い方（Windows のコマンドプロンプト / PowerShell）:
    python redmine_config_dump.py --url https://redmine.example.com --project design-tasks ^
        --origin https://contoso.sharepoint.com

    --project を省略すると、見えるプロジェクトの一覧を表示して終わる。
    --origin には kanban.aspx を置く SharePoint のサイトの URL（https://〇〇.sharepoint.com まで）を指定する。
    API キーは環境変数 REDMINE_API_KEY から読む。なければ入力を求める（画面には表示されない）。

結果は画面に表示し、同じ内容を redmine_config_output.txt に保存する。
読み取りしかしない（Redmine のデータは変更しない）。標準ライブラリだけで動く。
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class Redmine:
    def __init__(self, url: str, key: str):
        self.base = url.rstrip("/")
        self.key = key

    def get(self, path: str, **params) -> dict:
        query = urllib.parse.urlencode(params, safe="!*,>=")
        url = f"{self.base}{path}" + (f"?{query}" if query else "")
        req = urllib.request.Request(url, headers={"X-Redmine-API-Key": self.key})
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode("utf-8"))

    def get_all(self, path: str, key: str, **params) -> list[dict]:
        out: list[dict] = []
        offset = 0
        while True:
            j = self.get(path, limit=100, offset=offset, **params)
            items = j.get(key, [])
            out.extend(items)
            offset += len(items)
            if not items or offset >= j.get("total_count", 0):
                return out

    def count(self, **params) -> int:
        return self.get("/issues.json", limit=1, **params)["total_count"]

    def preflight(self, origin: str) -> dict:
        """ブラウザが PUT の前に送る確認(OPTIONS)を再現し、CORS の応答ヘッダーを返す。"""
        req = urllib.request.Request(
            f"{self.base}/issues.json",
            method="OPTIONS",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "x-redmine-api-key,content-type",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                status, headers = res.status, res.headers
        except urllib.error.HTTPError as e:
            status, headers = e.code, e.headers
        return {"status": status, **{k.lower(): v for k, v in headers.items() if k.lower().startswith("access-control-")}}


# ---------------------------------------------------------------------------
# ステータス名から列を推定する（推定できないものは TODO として出す）
# ---------------------------------------------------------------------------
def guess_status(name: str) -> tuple[str, int | None] | None:
    n = name.replace(" ", "").replace("　", "")
    m = re.match(r"^(\d{1,3})[%％]", n)
    if m:
        return "doing", int(m.group(1))
    if "未着手" in n or n in ("新規", "New"):
        return "todo", 0
    if "中止" in n or "却下" in n:
        return "cancelled", None
    if "確認済" in n or "上司" in n:
        return "approved", 100
    if "完了" in n or "解決" in n:
        return "done", 100
    return None


def js(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass

    ap = argparse.ArgumentParser(description="Redmine の設定値をタスクボード用に書き出す")
    ap.add_argument("--url", required=True, help="Redmine の URL（例: https://redmine.example.com）")
    ap.add_argument("--project", help="プロジェクト識別子。省略すると一覧を表示して終わる")
    ap.add_argument("--origin", help="kanban.aspx を置く SharePoint の URL（例: https://contoso.sharepoint.com）")
    args = ap.parse_args()

    key = os.environ.get("REDMINE_API_KEY") or getpass.getpass("API キー（入力しても表示されません）: ").strip()
    rm = Redmine(args.url, key)
    lines: list[str] = []
    notes: list[str] = []

    def say(text: str = "") -> None:
        print(text)
        lines.append(text)

    try:
        me = rm.get("/users/current.json")["user"]
    except urllib.error.HTTPError as e:
        print(f"接続できましたが、Redmine がエラーを返しました ({e.code})。API キーと URL を確認してください。")
        return 1
    except urllib.error.URLError as e:
        print(f"Redmine に接続できませんでした: {e.reason}")
        return 1
    say(f"ログインユーザー: {me['lastname']} {me['firstname']}（ID {me['id']}）")

    if not args.project:
        projects = rm.get_all("/projects.json", "projects")
        say("\n見えるプロジェクト（--project に「識別子」を指定して再実行してください）")
        for p in projects:
            say(f"  識別子 {p['identifier']:<24} {p['name']}")
        return 0

    project = rm.get(f"/projects/{urllib.parse.quote(args.project)}.json")["project"]
    say(f"プロジェクト: {project['name']}（識別子 {project['identifier']} / ID {project['id']}）")

    # ---- ステータス -------------------------------------------------------
    statuses = rm.get("/issue_statuses.json")["issue_statuses"]
    status_lines, drop = [], {}
    for s in statuses:
        g = guess_status(s["name"])
        closed = "（Redmine上は終了扱い）" if s.get("is_closed") else ""
        if g is None:
            status_lines.append(f"    // TODO 列が決められません: {{ id: {s['id']}, name: {js(s['name'])} }}{closed}")
            notes.append(f"ステータス「{s['name']}」の列を手で決めてください。")
            continue
        col, ratio = g
        drop.setdefault(col, s["id"])
        if col == "doing" and ratio == 0:
            drop["doing"] = s["id"]
        status_lines.append(f"    {{ id: {s['id']}, name: {js(s['name'])}, col: '{col}', ratio: {js(ratio)} }},{('  // ' + closed) if closed else ''}")
    for col in ("todo", "doing", "done", "approved", "cancelled"):
        if col not in drop:
            notes.append(f"列「{col}」に当たるステータスが見つかりません。")

    # ---- メンバー ---------------------------------------------------------
    memberships = rm.get_all(f"/projects/{project['id']}/memberships.json", "memberships")
    members, manager_guess = [], []
    for m in memberships:
        if "user" not in m:
            continue  # グループは担当者の選択肢に出さない
        roles = [r["name"] for r in m.get("roles", [])]
        members.append((m["user"]["id"], m["user"]["name"], roles))
        if any(re.search(r"管理|マネージャ|Manager", r) for r in roles):
            manager_guess.append(m["user"]["id"])
    if not manager_guess:
        notes.append("上司のユーザー ID（managerUserIds）を推定できませんでした。手で設定してください。")

    # ---- バージョン -------------------------------------------------------
    versions = rm.get(f"/projects/{project['id']}/versions.json")["versions"]
    open_versions = [v for v in versions if v["status"] == "open"]
    no_prefix = [v["name"] for v in open_versions if not re.match(r"^[0-9０-９]{1,3}", v["name"])]
    if no_prefix:
        notes.append("先頭に優先番号がないバージョン（並びは最後になります）: " + "、".join(no_prefix))

    # ---- 子チケット条件(child_id)が使えるか --------------------------------
    pid = project["id"]
    total = rm.count(project_id=pid, status_id="*")
    try:
        has_child = rm.count(project_id=pid, status_id="*", child_id="*")
        no_child = rm.count(project_id=pid, status_id="*", child_id="!*")
        # 条件が無視される Redmine では、どちらも全件が返るので合計が合わない
        child_ok = total > 0 and has_child + no_child == total
    except urllib.error.HTTPError:
        has_child = no_child = None
        child_ok = False
    child_msg = (f"使えます（子チケットあり {has_child} 件 / なし {no_child} 件 / 全 {total} 件）" if child_ok
                 else "使えません。1 件ずつ確認する方式で動かします")

    # ---- 未整理の件数 -----------------------------------------------------
    no_assignee = rm.count(project_id=pid, status_id="open", assigned_to_id="!*")
    no_version = rm.count(project_id=pid, status_id="open", fixed_version_id="!*")

    # ---- 出力 -------------------------------------------------------------
    say("\n========== ここから kanban の CONFIG に貼り付け ==========")
    say("  statuses: [")
    for l in status_lines:
        say(l)
    say("  ],")
    say(f"  managerUserIds: {js(manager_guess)},{'' if manager_guess else '  // TODO 上司の ID を入れる'}")
    say("  members: [")
    for uid, name, roles in members:
        say(f"    {{ id: {uid}, name: {js(name)} }},  // {'・'.join(roles)}")
    say("  ],")
    say(f"  projectId: {js(project['identifier'])},")
    say(f"  childFilterSupported: {'true' if child_ok else 'false'},")
    say("========== ここまで ==========")

    say("\n対象バージョン（未完了のもの）")
    for v in open_versions:
        say(f"  {v['name']}")
    say(f"\n子チケット条件(child_id): {child_msg}")
    say(f"未整理の目安: 担当なし {no_assignee} 件 / バージョンなし {no_version} 件（重複あり）")

    if args.origin:
        origin = args.origin.rstrip("/")
        try:
            pf = rm.preflight(origin)
        except urllib.error.URLError as e:
            pf = {"status": f"接続失敗 {e.reason}"}
        allow_origin = pf.get("access-control-allow-origin", "")
        allow_headers = pf.get("access-control-allow-headers", "").lower()
        allow_methods = pf.get("access-control-allow-methods", "").upper()
        cors_ok = allow_origin in ("*", origin) and "x-redmine-api-key" in allow_headers and "PUT" in allow_methods
        say(f"\nCORS（{origin} からの書き込み）: {'許可されています' if cors_ok else '許可されていません'}")
        for k, v in pf.items():
            say(f"  {k}: {v}")
        if not cors_ok:
            notes.append("CORS が許可されていません。Redmine の管理元に README の「本番接続の前に確認すること」の設定を依頼してください。")
    else:
        notes.append("--origin を付けると、SharePoint からの接続(CORS)が許可されているかも確認できます。")

    if notes:
        say("\n確認が必要なこと")
        for n in notes:
            say(f"  - {n}")

    out = Path("redmine_config_output.txt")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
    print(f"\n{out.resolve()} に保存しました。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
