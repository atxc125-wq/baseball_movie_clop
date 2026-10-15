"""タスクボードの中継プログラム。

このPCの中でタスクボードの画面を出し、社外の Redmine との間をつなぐ。
ボードの画面(HTML)はこのファイルに埋め込まれている。チームの設定は同じフォルダの
board_settings.json に書き、ステータスなどそれ以外の設定は起動時に Redmine から自動で読む。

    初回:   kanban_relay.py をダブルクリック（setup.bat でも同じ）→ API キーを入力 → ボードが開く
    2回目〜: ログオン時に自動で起動する。ブラウザで http://127.0.0.1:8765/ を開く
    更新:   共有フォルダの kanban_relay.py / board_settings.json を新しくしておけば、
            次の起動時に自動で入れ替わる。すぐ反映したいときは共有フォルダの kanban_relay.py をダブルクリック
            （動いている中継を入れ替えて再起動する。ファイルが同じでも設定を読み直す）
    自動起動をやめる: python kanban_relay.py --uninstall

安全のため次の制限をかけている。
  - このPCの中(127.0.0.1)からの接続だけを受け付ける
  - 呼び出し元はこのプログラムが出したボード（と ALLOWED_ORIGINS）だけ。他のWebサイトからは使えない
  - 中継する Redmine の API は、ボードが使うものだけ
  - API キーは Windows の機能(DPAPI)で暗号化し、このユーザーにしか読めない形で保存する
標準ライブラリだけで動く。
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# このPC以外のページ（SharePoint など）からも使わせる場合だけ書く。通常は空でよい
ALLOWED_ORIGINS: list[str] = []
PORT = 8765

VERSION = "11"
BUILD = "2026-10-15 23:35"  # build.py が埋め込んだ画面の作成日時を入れる
HERE = Path(__file__).resolve().parent
SETTINGS_FILE = "board_settings.json"
BOARD_URL = f"http://127.0.0.1:{PORT}/"
SELF_ORIGINS = (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}")
APP_DIR = Path(os.environ.get("APPDATA") or Path.home() / ".config") / "DesignTaskBoard"
CONFIG_FILE = APP_DIR / "relay.json"              # API キー（暗号化）
DETECTED_FILE = APP_DIR / "detected_config.json"  # Redmine から読んだ設定の控え（読めなかったときに使う）
SOURCE_FILE = APP_DIR / "install_source.txt"      # 更新を取りに行く共有フォルダ
LOG_FILE = APP_DIR / "relay.log"

SETTINGS: dict = {}
INSTALLED = False  # このセッションで自動起動を設定したか

# 中継してよい API（メソッドとパス）
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
]


def redmine_url() -> str:
    return str(SETTINGS.get("redmine_url", "")).rstrip("/")


# ---------------------------------------------------------------------------
# API キーの保存（Windows では DPAPI で暗号化）
# ---------------------------------------------------------------------------
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    src, dst = BLOB(len(data), buf), BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(dst)):
        raise OSError("API キーの暗号化/復号に失敗しました")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(dst.pbData)


def save_key(key: str) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        record = {"key_dpapi": base64.b64encode(_dpapi(key.encode(), True)).decode()}
    else:
        record = {"key_plain": key}
    CONFIG_FILE.write_text(json.dumps(record), encoding="utf-8")
    if os.name != "nt":
        CONFIG_FILE.chmod(0o600)


def load_key() -> str | None:
    if os.environ.get("DESIGN_BOARD_API_KEY"):
        return os.environ["DESIGN_BOARD_API_KEY"]
    try:
        record = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if "key_dpapi" in record:
        return _dpapi(base64.b64decode(record["key_dpapi"]), False).decode()
    return record.get("key_plain")


# ---------------------------------------------------------------------------
# Redmine 呼び出し
# ---------------------------------------------------------------------------
def redmine(method: str, path_qs: str, key: str, body: bytes | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(
        redmine_url() + path_qs,
        data=body,
        method=method,
        headers={"X-Redmine-API-Key": key, **({"Content-Type": "application/json"} if body is not None else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check_key(key: str) -> tuple[dict | None, str]:
    """(ユーザー情報, うまくいかなかった理由) を返す。理由は画面に出して原因の切り分けに使う。"""
    url = redmine_url() + "/users/current.json"
    try:
        status, body = redmine("GET", "/users/current.json", key)
    except urllib.error.URLError as e:
        return None, (f"Redmine に接続できません（{e.reason}）。\n  接続先: {url}\n"
                      f"  {SETTINGS_FILE} の redmine_url とネットワーク（プロキシ）を確認してください。")
    if status == 200:
        try:
            return json.loads(body)["user"], ""
        except (ValueError, KeyError):
            head = body[:80].decode("utf-8", "replace").replace("\n", " ")
            return None, (f"Redmine 以外の画面が返ってきました（{head}…）。\n  接続先: {url}\n"
                          f"  {SETTINGS_FILE} の redmine_url が正しいか、プロキシのログイン画面になっていないか確認してください。")
    reasons = {
        401: "Redmine が API キーを受け付けませんでした (401)。\n"
             "  キーが正しいか、Redmine の「管理 → 設定 → API」で「RESTによるWebサービスを有効にする」がオンか確認してください。",
        403: "アクセスが拒否されました (403)。Redmine かプロキシで接続が制限されている可能性があります。",
        404: f"ページが見つかりません (404)。{SETTINGS_FILE} の redmine_url が正しいか確認してください"
             "（/redmine のような続きが必要な場合があります）。",
        407: "プロキシの認証が必要です (407)。社内のプロキシ設定を確認してください。",
    }
    return None, reasons.get(status, f"Redmine がエラーを返しました ({status})。") + f"\n  接続先: {url}"


def read_key() -> str:
    """API キーを受け取る。貼り付けがうまくいかない環境のため、クリップボードからも読める。"""
    raw = getpass.getpass("Redmine の API キーを貼り付けて Enter（何も入力せず Enter → クリップボードから読み取り）: ")
    if not raw.strip():
        try:
            import tkinter
            root = tkinter.Tk()
            root.withdraw()
            raw = root.clipboard_get()
            root.destroy()
        except Exception:  # noqa: BLE001 - クリップボードが空、または tkinter がない
            print("クリップボードから読み取れませんでした。キーをコピーしてからもう一度試してください。")
            return ""
    # 貼り付けの失敗で混ざる制御文字(Ctrl+V の ^V など)や空白・改行を取り除く
    key = re.sub(r"[\x00-\x20\x7f]", "", raw)
    if key:
        print(f"受け取ったキー: {key[:4]}…（{len(key)} 文字。Redmine の API キーは通常 40 文字です）")
    return key


# ---------------------------------------------------------------------------
# チームの設定（board_settings.json）
# ---------------------------------------------------------------------------
class SettingsError(Exception):
    pass


def load_settings(folder: Path) -> dict:
    f = folder / SETTINGS_FILE
    try:
        data = json.loads(f.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise SettingsError(f"{SETTINGS_FILE} が見つかりません。kanban_relay.py と同じフォルダ（{folder}）に置いてください。")
    except ValueError as e:
        raise SettingsError(f"{SETTINGS_FILE} の書き方に誤りがあります（{e}）。カンマや \" の閉じ忘れを確認してください。")
    for k in ("redmine_url", "project"):
        if not str(data.get(k, "")).strip():
            raise SettingsError(f"{SETTINGS_FILE} に {k} を書いてください。")
    return data


# ---------------------------------------------------------------------------
# Redmine からボードの設定を読む（ステータス、メンバー、子チケット条件）
# ---------------------------------------------------------------------------
def redmine_json(key: str, path_qs: str) -> dict:
    status, body = redmine("GET", path_qs, key)
    if status != 200:
        raise OSError(f"{path_qs} が {status} を返しました")
    return json.loads(body)


def redmine_all(key: str, path: str, item: str) -> list[dict]:
    out: list[dict] = []
    sep = "&" if "?" in path else "?"
    while True:
        j = redmine_json(key, f"{path}{sep}limit=100&offset={len(out)}")
        out.extend(j.get(item, []))
        if not j.get(item) or len(out) >= j.get("total_count", 0):
            return out


def guess_status(name: str) -> tuple[str, int | None] | None:
    """ステータス名から列を推定する。推定できなければ None。"""
    n = re.sub(r"\s", "", name)
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


def column_of(status_name: str) -> tuple[str, int | None] | None:
    """設定の status_columns を優先し、なければ名前から推定する。"""
    col = (SETTINGS.get("status_columns") or {}).get(status_name)
    if not col:
        return guess_status(status_name)
    if col == "doing":
        m = re.match(r"^(\d{1,3})", status_name)
        return "doing", int(m.group(1)) if m else 0
    return col, {"todo": 0, "done": 100, "approved": 100}.get(col)


def _norm_name(s: str) -> str:
    return re.sub(r"\s", "", str(s)).lower()


def _as_id(e) -> int | None:
    """12 でも "12" でも ID として扱う。"""
    if isinstance(e, int):
        return e
    if isinstance(e, str) and e.strip().isdigit():
        return int(e.strip())
    return None


def match_people(entries: list, people: list[dict]) -> tuple[list[dict], list[str]]:
    """設定に書いた名前（または ID）を、知っている人と突き合わせる。空白の有無・全角半角の空白は区別しない。"""
    found, missing = [], []
    for e in entries:
        uid = _as_id(e)
        hit = next((p for p in people if (uid is not None and p["id"] == uid)
                    or (uid is None and isinstance(e, str) and _norm_name(p["name"]) == _norm_name(e))), None)
        if hit is None:
            missing.append(str(e))
        elif hit not in found:
            found.append(hit)
    return found, missing


def detect_config(key: str) -> tuple[dict, list[str]]:
    warnings: list[str] = []
    project = redmine_json(key, f"/projects/{urllib.parse.quote(str(SETTINGS['project']))}.json")["project"]

    statuses = []
    for st in redmine_json(key, "/issue_statuses.json")["issue_statuses"]:
        guess = column_of(st["name"])
        if guess is None:
            warnings.append(f"ステータス「{st['name']}」をどの列に出すか決められません（status_columns で指定できます）")
            continue
        statuses.append({"id": st["id"], "name": st["name"], "col": guess[0], "ratio": guess[1]})
    for col, label in (("todo", "未着手"), ("doing", "進行中"), ("done", "担当完了"), ("cancelled", "中止")):
        if not any(x["col"] == col for x in statuses):
            warnings.append(f"「{label}」に当たるステータスが見つかりません")

    # 知っている人: プロジェクトのメンバー + 未完了チケットの担当者・作成者 + 自分。
    # グループ経由で参加している人や、メンバー登録されていない上司も名前で見つけられるように
    people: list[dict] = []
    nameless: list[int] = []

    def know(u: dict | None) -> None:
        if not u or "id" not in u or any(p["id"] == u["id"] for p in people):
            return
        if not u.get("name"):
            nameless.append(u["id"])  # 名前が取れない（削除・ロックされたユーザーなど）
            return
        people.append({"id": u["id"], "name": u["name"]})

    memberships = redmine_all(key, f"/projects/{project['id']}/memberships.json", "memberships")
    project_members = [m["user"] for m in memberships if "user" in m]
    for u in project_members:
        know(u)
    open_issues = redmine_all(key, f"/issues.json?project_id={project['id']}&status_id=open", "issues")
    for i in open_issues:
        know(i.get("assigned_to"))
        know(i.get("author"))
    me = redmine_json(key, "/users/current.json")["user"]
    know({"id": me["id"], "name": f"{me.get('lastname', '')} {me.get('firstname', '')}".strip()})
    if nameless:
        warnings.append("名前が取れないユーザーを除きました（削除・ロックされた人の可能性）: ID " + "、".join(map(str, sorted(set(nameless)))))
    member_ids = {u["id"] for u in project_members}
    group_ids = {m["group"]["id"] for m in memberships if "group" in m}

    def not_found(label: str, missing: list[str]) -> None:
        names = "、".join(sorted(p["name"] for p in people)[:15])
        warnings.append(f"{label} に書いた人が見つかりません: {'、'.join(missing)}（見つかる名前の例: {names}）")

    team = SETTINGS.get("team")
    if team == "auto":
        # 未完了のチケットを担当している人だけ（担当がグループのものは除く）
        assigned = {i["assigned_to"]["id"] for i in open_issues if i.get("assigned_to")} - group_ids
        members = sorted((p for p in people if p["id"] in assigned), key=lambda p: p["name"])
    elif team:
        members, missing = match_people(team, people)
        if missing:
            not_found("team", missing)
    else:
        members = [p for p in people if p["id"] in member_ids]
        warnings.append("team が空なので、プロジェクトのメンバー全員を表示しています")
    hidden, _ = match_people(SETTINGS.get("team_exclude") or [], people)
    members = [m for m in members if m not in hidden]
    managers, missing = match_people(SETTINGS.get("managers") or [], people)
    if missing:
        not_found("managers", missing)
    members += [m for m in managers if m not in members]

    # 表示順: team_order に書いた人をその順で先頭に。残りは今の順のまま後ろに
    order, _ = match_people(SETTINGS.get("team_order") or [], people)
    rank = {p["id"]: k for k, p in enumerate(order)}
    members.sort(key=lambda p: rank.get(p["id"], len(rank)))

    # 子チケット条件(child_id)が使えるか。使えない Redmine は条件を無視して全件返すので合計が合わない
    def count(**q) -> int:
        qs = urllib.parse.urlencode({"project_id": project["id"], "status_id": "*", "limit": 1, **q}, safe="!*")
        return redmine_json(key, f"/issues.json?{qs}")["total_count"]
    try:
        total = count()
        child_ok = total > 0 and count(child_id="*") + count(child_id="!*") == total
    except OSError:
        child_ok = False

    config = {
        "statuses": statuses,
        "members": members,
        "managerUserIds": [m["id"] for m in managers],
        "projectId": project["identifier"],
        "projectNumericId": project["id"],
        "childFilterSupported": child_ok,
        "defaultMode": "relay",
    }
    config.update(SETTINGS.get("options") or {})
    return config, warnings


def board_config(key: str) -> tuple[dict, list[str]]:
    """Redmine から設定を読む。読めなければ前回の控えを使う。"""
    try:
        config, warnings = detect_config(key)
        APP_DIR.mkdir(parents=True, exist_ok=True)
        DETECTED_FILE.write_text(json.dumps(config, ensure_ascii=False, indent=1), encoding="utf-8")
        return config, warnings
    except (OSError, ValueError, KeyError) as e:
        log(f"Redmine から設定を読めませんでした: {e}")
        try:
            cached = json.loads(DETECTED_FILE.read_text(encoding="utf-8"))
            return cached, ["Redmine から設定を読めなかったため、前回の設定で表示しています"]
        except (OSError, ValueError):
            return {"defaultMode": "relay"}, [f"Redmine から設定を読めませんでした（{e}）"]


# ---------------------------------------------------------------------------
# ボードの画面。build.py が src/kanban.fragment.html から作って下に埋め込む
# ---------------------------------------------------------------------------
def board_html(config: dict) -> bytes:
    override = os.environ.get("DESIGN_BOARD_HTML")  # 開発用: 埋め込みの代わりにファイルを使う
    if override:
        html = Path(override).read_text(encoding="utf-8-sig")
    else:
        html = zlib.decompress(base64.b64decode("".join(BOARD_HTML))).decode("utf-8")
    payload = json.dumps(config, ensure_ascii=False).replace("</", "<\\/")
    return html.replace("/*__SERVER_CONFIG__*/", f"Object.assign(CONFIG, {payload});", 1).encode("utf-8")


# ---------------------------------------------------------------------------
# 中継サーバー
# ---------------------------------------------------------------------------
class Relay(BaseHTTPRequestHandler):
    server_version = "DesignTaskBoardRelay/" + VERSION
    key: str = ""
    user: dict = {}
    config: dict = {}
    warnings: list[str] = []

    def log_message(self, fmt, *args):  # noqa: N802 - 標準の名前
        log(f"{self.address_string()} {fmt % args}")

    # --- 共通チェック ---------------------------------------------------
    def _caller(self) -> tuple[bool, str | None]:
        """(使ってよいか, 付ける CORS ヘッダーの値) を返す。"""
        origin = self.headers.get("Origin")
        if origin in SELF_ORIGINS:
            return True, None
        if origin in ALLOWED_ORIGINS:
            return True, origin
        # 同じページからの GET には Origin が付かない。ブラウザが付ける Sec-Fetch-Site で見分ける
        if origin is None and self.headers.get("Sec-Fetch-Site") == "same-origin":
            return True, None
        return False, None

    def _host_ok(self) -> bool:
        # DNS リバインディング対策: Host が 127.0.0.1 / localhost 以外なら断る
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _send(self, status: int, body: bytes = b"", origin: str | None = None, ctype="application/json; charset=utf-8"):
        self.send_response(status)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _error(self, status: int, message: str, origin: str | None = None):
        self._send(status, json.dumps({"errors": [message]}, ensure_ascii=False).encode(), origin)

    # --- ブラウザの事前確認 ---------------------------------------------
    def do_OPTIONS(self):  # noqa: N802
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS or not self._host_ok():
            return self._error(403, "このページからは使えません")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_PUT(self):  # noqa: N802
        self._handle("PUT")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def do_DELETE(self):  # noqa: N802
        self._handle("DELETE")

    def _handle(self, method: str):
        if not self._host_ok():
            return self._error(403, "このページからは使えません")
        path, _, query = self.path.partition("?")

        # ボードの画面そのもの（チームの設定は入るが、チケットのデータは含まない）
        if method == "GET" and path in ("/", "/kanban.html"):
            return self._send(200, board_html(self.config), ctype="text/html; charset=utf-8")

        allowed, origin = self._caller()
        if not allowed:
            return self._error(403, "このページからは使えません")

        if path == "/ping":
            info = {"ok": True, "version": VERSION, "pid": os.getpid(), "redmine_url": redmine_url(), "board_dir": str(HERE),
                    "warnings": self.warnings,
                    "user": {"id": self.user.get("id"),
                             "name": f"{self.user.get('lastname', '')} {self.user.get('firstname', '')}".strip()}}
            return self._send(200, json.dumps(info, ensure_ascii=False).encode(), origin)

        # 新しい版を置いたあとの再起動。このPCの中の kanban_relay.py からだけ呼ぶ
        if path == "/admin/restart" and self.headers.get("Origin") in SELF_ORIGINS:
            self._send(200, b'{"ok": true}', origin)
            # daemon=False を明示する。要求を処理するスレッドは daemon で、作ったスレッドはそれを引き継ぐため、
            # そのままだと待ち受けが止まった直後にプロセスが終わり、新しい中継を起動する前に打ち切られる
            threading.Thread(target=restart, daemon=False).start()
            return

        if not path.startswith("/api/"):
            return self._error(404, "見つかりません", origin)
        api_path = path[len("/api"):]
        if not any(m == method and rx.match(api_path) for m, rx in ALLOWED_API):
            return self._error(403, f"中継していない操作です: {method} {api_path}", origin)

        body = None
        if method in ("PUT", "POST"):
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                return self._error(413, "送信データが大きすぎます", origin)
            body = self.rfile.read(length)
        try:
            status, data = redmine(method, api_path + (f"?{query}" if query else ""), self.key, body)
        except (urllib.error.URLError, socket.timeout) as e:
            log(f"Redmine に接続できません: {e}")
            return self._error(502, "中継プログラムから Redmine に接続できません。ネットワークを確認してください", origin)
        self._send(status, data, origin)


# ---------------------------------------------------------------------------
# 起動・更新まわり
# ---------------------------------------------------------------------------
SERVER: ThreadingHTTPServer | None = None


def log(text: str) -> None:
    line = text.rstrip()
    if sys.stdout is not None:
        try:
            print(line, flush=True)
            return
        except (OSError, ValueError):
            pass
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1_000_000:
            LOG_FILE.unlink()
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(time.strftime("%m/%d %H:%M:%S ") + line + "\n")
    except OSError:
        pass


def pause() -> None:
    """ダブルクリックで開いた画面がすぐ閉じてメッセージが読めない、を防ぐ。"""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            input("\nEnter キーで閉じます")
        except EOFError:
            pass


def already_running() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=1):
            return True
    except OSError:
        return False


def running_info() -> dict | None:
    """起動中の中継に版・フォルダ・プロセス番号を聞く。古い版は一部しか答えない。"""
    req = urllib.request.Request(f"{BOARD_URL}ping", headers={"Origin": SELF_ORIGINS[0]})
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            return json.loads(res.read())
    except (OSError, ValueError):
        return None


def running_dir() -> Path | None:
    """起動中の中継が動いているフォルダを聞く。"""
    info = running_info()
    return Path(info["board_dir"]) if info and info.get("board_dir") else None


def port_owner_pid() -> int | None:
    """ポートで待ち受けているプロセスの番号（古い版は自分の番号を答えないので、OS に聞く）。"""
    try:
        if os.name == "nt":
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, timeout=10,
                                 creationflags=0x08000000).stdout  # CREATE_NO_WINDOW
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1].endswith(f":{PORT}") and parts[3].upper() == "LISTENING":
                    return int(parts[4])
        else:
            out = subprocess.run(["lsof", "-t", f"-iTCP:{PORT}", "-sTCP:LISTEN"], capture_output=True, text=True, timeout=10).stdout
            return int(out.split()[0]) if out.split() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def stop_running() -> bool:
    """動いている中継を止める（再起動の依頼に応じない古い版向け）。止まったら True。"""
    info = running_info() or {}
    pid = info.get("pid") or port_owner_pid()
    if not pid or pid == os.getpid():
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10, creationflags=0x08000000)
        else:
            os.kill(pid, 15)
    except (OSError, subprocess.SubprocessError):
        return False
    for _ in range(40):
        if not already_running():
            return True
        time.sleep(0.25)
    return False


def latest_is_running() -> bool:
    info = running_info()
    return bool(info and str(info.get("version")) == VERSION)


def replace_old_running(folder: Path) -> bool:
    """古い版が動き続けている → 止めて、folder の kanban_relay.py を画面なしで起動する。"""
    info = running_info() or {}
    log(f"古い版の中継（v{info.get('version', '?')}）が動き続けているので、止めて入れ替えます…")
    if not stop_running():
        return False
    flags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
    subprocess.Popen([pythonw(), str(folder / "kanban_relay.py")], cwd=str(folder), creationflags=flags,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=os.name != "nt")
    for _ in range(80):  # Redmine から設定を読むので最大 20 秒待つ
        time.sleep(0.25)
        if latest_is_running():
            return True
    return False


def copy_if_changed(src_dir: Path, dst_dir: Path) -> list[str]:
    """kanban_relay.py と board_settings.json を、中身が違うときだけコピーする。"""
    return copy_if_changed_names(src_dir, dst_dir, ["kanban_relay.py", SETTINGS_FILE])


def copy_if_changed_names(src_dir: Path, dst_dir: Path, names: list[str]) -> list[str]:
    changed: list[str] = []
    if src_dir.resolve() == dst_dir.resolve():
        return changed
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        src, dst = src_dir / name, dst_dir / name
        if src.exists() and (not dst.exists() or src.read_bytes() != dst.read_bytes()):
            shutil.copy2(src, dst)
            changed.append(name)
    return changed


def file_version(path: Path) -> tuple[int, str]:
    """kanban_relay.py に書かれた (版の番号, 画面の作成日時)。読めなければ (0, "")。"""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0, ""
    m = re.search(r'^VERSION = "(\d+)"', text, re.M)
    b = re.search(r'^BUILD = "([^"]*)"', text, re.M)
    return (int(m.group(1)) if m else 0), (b.group(1) if b else "")


def update_source() -> Path | None:
    """更新を取りに行く共有フォルダ。設定の update_dir、なければ初回設定をしたフォルダ。"""
    configured = os.path.expandvars(str(SETTINGS.get("update_dir") or "")).strip()
    if configured:
        return Path(configured)
    try:
        return Path(SOURCE_FILE.read_text(encoding="utf-8").strip())
    except OSError:
        return None


def pythonw() -> str:
    w = Path(sys.executable).with_name("pythonw.exe")
    return str(w if w.exists() else sys.executable)


def restart() -> None:
    """画面なしで自分を起動し直す（新しい版や設定を読み込むため）。"""
    time.sleep(0.3)  # 応答を返し終えてから
    if SERVER:
        SERVER.shutdown()
        SERVER.server_close()
    flags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
    subprocess.Popen([pythonw(), str(HERE / "kanban_relay.py")], cwd=str(HERE), creationflags=flags,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=os.name != "nt")  # 起動した画面を閉じても止まらないように
    os._exit(0)


def ask_running_to_restart() -> bool:
    req = urllib.request.Request(f"{BOARD_URL}admin/restart", headers={"Origin": SELF_ORIGINS[0]})
    try:
        urllib.request.urlopen(req, timeout=3).close()
    except OSError:
        return False
    time.sleep(1)
    for _ in range(60):  # 起動し直すまで最大 15 秒待つ
        if running_dir():
            return True
        time.sleep(0.25)
    return False


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "DesignTaskBoardRelay"


def legacy_startup_file() -> Path | None:
    """以前の版がスタートアップフォルダに置いていた起動用ファイル。"""
    if os.name != "nt":
        return None
    return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup/DesignTaskBoardRelay.cmd"


def set_autostart(command: str | None) -> bool:
    """ログオン時に実行する一覧（このユーザーのレジストリ）に登録する。None なら削除。削除できたら True。"""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if command:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, command)
            return True
        try:
            winreg.DeleteValue(k, RUN_NAME)
            return True
        except FileNotFoundError:
            return False


def desktop_dir() -> Path:
    if os.name == "nt":
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf) == 0:  # CSIDL_DESKTOPDIRECTORY
            return Path(buf.value)
    return Path.home() / "Desktop"


def make_shortcut() -> None:
    try:
        old = desktop_dir() / "設計課タスクボード.url"  # 以前の名前のショートカットは置き換える
        if old.exists():
            old.unlink()
        f = desktop_dir() / "タスクボード.url"
        f.write_text(f"[InternetShortcut]\r\nURL={BOARD_URL}\r\n", encoding="utf-8")
        print(f"デスクトップに「タスクボード」を作りました。（{f}）")
    except OSError as e:
        print(f"デスクトップにショートカットを作れませんでした（{e}）。ブラウザで {BOARD_URL} を開いてください。")


def install_startup() -> None:
    """%APPDATA%\\DesignTaskBoard にコピーし、ログオン時に画面なしで起動するよう登録する。"""
    copy_if_changed(HERE, APP_DIR)
    if HERE != APP_DIR.resolve():
        SOURCE_FILE.write_text(str(HERE), encoding="utf-8")  # 次からここを見て自動更新する
    set_autostart(f'"{pythonw()}" "{APP_DIR / "kanban_relay.py"}"')
    legacy = legacy_startup_file()
    if legacy and legacy.exists():
        legacy.unlink()
    print("ログオン時に自動で起動するよう設定しました（タスクマネージャーの「スタートアップ」で確認・無効化できます）。")
    global INSTALLED
    INSTALLED = True


def start_in_background() -> bool:
    """自動起動用のコピーを、画面なしで今すぐ起動する（この画面を閉じても動き続けるように）。"""
    if already_running():
        current = running_dir()
        if current:
            copy_if_changed(HERE, current)
        if ask_running_to_restart() and latest_is_running():
            return True
        return replace_old_running(APP_DIR)
    flags = 0x00000008 if os.name == "nt" else 0  # DETACHED_PROCESS
    subprocess.Popen([pythonw(), str(APP_DIR / "kanban_relay.py")], cwd=str(APP_DIR), creationflags=flags,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=os.name != "nt")  # 起動した画面を閉じても止まらないように
    for _ in range(80):  # Redmine から設定を読むので最大 20 秒待つ
        time.sleep(0.25)
        if running_dir():
            return True
    return False


def uninstall() -> None:
    if os.name != "nt":
        print("自動起動は Windows でだけ設定できます。")
        return
    removed = set_autostart(None)
    legacy = legacy_startup_file()
    if legacy and legacy.exists():
        legacy.unlink()
        removed = True
    print("自動起動の設定を削除しました。" if removed else "自動起動は設定されていません。")


def setup() -> str:
    print("タスクボード 中継プログラムの初期設定")
    print(f"接続先: {redmine_url()}\n")
    while True:
        key = read_key()
        if not key:
            continue
        user, reason = check_key(key)
        if user:
            break
        print(reason + "\n")
    save_key(key)
    print(f"\n{user['lastname']} {user['firstname']} さんとして接続します。")
    make_shortcut()
    if os.name == "nt":
        ans = input("Windows にログオンしたとき自動で起動しますか？ [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            install_startup()
    return key


def main() -> int:
    global SETTINGS, SERVER
    for stream in (sys.stdout, sys.stderr):
        if stream is not None:
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except AttributeError:
                pass

    ap = argparse.ArgumentParser(description="タスクボードの中継プログラム")
    ap.add_argument("--setup", action="store_true", help="API キーと自動起動を設定し直す")
    ap.add_argument("--uninstall", action="store_true", help="自動起動をやめる")
    args = ap.parse_args()

    if args.uninstall:
        uninstall()
        return 0
    try:
        SETTINGS = load_settings(HERE)
    except SettingsError as e:
        log(str(e))
        pause()
        return 1
    interactive = sys.stdin is not None and sys.stdin.isatty()

    # 以前の名前（設計課タスクボード）のデスクトップのショートカットは、新しい名前に置き換える
    try:
        legacy_link = desktop_dir() / "設計課タスクボード.url"
        if legacy_link.exists():
            (desktop_dir() / "タスクボード.url").write_text(f"[InternetShortcut]\r\nURL={BOARD_URL}\r\n", encoding="utf-8")
            legacy_link.unlink()
    except OSError:
        pass

    # 初期の版がスタートアップフォルダに置いた起動用ファイルが残っていると、ログオンのたびに古い中継が先に起動して
    # ポートを取り、新しい版が動けない。どの起動でも見つけしだい消す
    legacy = legacy_startup_file()
    if legacy and legacy.exists():
        try:
            legacy.unlink()
            log(f"古い版の自動起動ファイルを削除しました: {legacy}")
        except OSError as e:
            log(f"古い版の自動起動ファイルを削除できませんでした（{e}）。手で削除してください: {legacy}")

    # 自動起動を設定済みの PC で、別の場所（共有フォルダなど）の kanban_relay.py をダブルクリックした
    # → 自動起動用のコピーを必ず新しくする（次のログオンで古い版が動かないように）。
    #   更新の取り込み元も、update_dir の指定がなければこの場所に向け直す
    from_elsewhere = (interactive and not args.setup and HERE != APP_DIR.resolve()
                      and (APP_DIR / "kanban_relay.py").exists())
    updated: list[str] = []
    if from_elsewhere:
        updated = copy_if_changed(HERE, APP_DIR)
        if not str(SETTINGS.get("update_dir") or "").strip():
            SOURCE_FILE.write_text(str(HERE), encoding="utf-8")
        if updated:
            log("自動起動用のコピーを新しい版にしました: " + "、".join(updated))

    if already_running() and not args.setup:
        if interactive:
            # 共有フォルダの新しい版をダブルクリックした → 動いている中継を入れ替えて再起動
            # ファイルが同じでも再起動する（board_settings.json や Redmine のメンバーを読み直すため）
            current = running_dir()
            changed = sorted(set(updated + (copy_if_changed(HERE, current) if current else [])))
            log("中継を再起動しています…")
            ok = ask_running_to_restart() and latest_is_running()
            if not ok:
                # 再起動の依頼に応じない、または別のフォルダの古いファイルで起動し直した古い版 → 止めて入れ替える
                ok = replace_old_running(APP_DIR if (APP_DIR / "kanban_relay.py").exists() and from_elsewhere else HERE)
            if ok:
                log("新しい版（" + "、".join(changed) + "）に入れ替えて、再起動しました。" if changed
                    else "再起動して、設定を読み直しました。")
                log(f"ボードを開きます（{BOARD_URL}）。")
                webbrowser.open(BOARD_URL)
            else:
                log("中継を入れ替えられませんでした。古い版が動いている可能性があります。\n"
                    "タスクマネージャーの「詳細」タブで pythonw.exe（と python.exe）を終了してから、もう一度ダブルクリックしてください。")
                pause()
        return 0

    # 中継が止まっていた → このフォルダからではなく、自動起動用のコピーを画面なしで起動する
    # （ここで動かすと、この画面を閉じたときに止まり、次のログオンとも別の版になるため）
    if from_elsewhere and load_key():
        log("ボードを起動しています…")
        if start_in_background():
            log(f"準備ができました。ボードを開きます（{BOARD_URL}）。この画面は閉じて大丈夫です。")
            webbrowser.open(BOARD_URL)
        else:
            log(f"起動に時間がかかっています。少し待ってからボードを開いてください。（記録: {LOG_FILE}）")
        pause()
        return 0

    # 自動起動のコピーは、起動時に共有フォルダの新しい版を取り込む
    if HERE == APP_DIR.resolve():
        src = update_source()
        theirs = file_version(src / "kanban_relay.py") if src else (0, "")
        if src and src.exists() and theirs <= (int(VERSION), BUILD):
            # 取り込み元が同じか古い版なら py は取り込まない（設定ファイルだけ）。古い版に戻ると、
            # ログオンのたびに古い画面になる
            if theirs < (int(VERSION), BUILD) and (src / "kanban_relay.py").exists():
                log(f"取り込み元の kanban_relay.py は古い版（v{theirs[0]} {theirs[1]}）なので取り込みません: {src}")
            changed = [n for n in copy_if_changed_names(src, HERE, [SETTINGS_FILE])]
            if changed:
                log("共有フォルダから新しい設定を取り込みました: " + "、".join(changed))
                SETTINGS = load_settings(HERE)
        elif src and src.exists():
            changed = copy_if_changed(src, HERE)
            if changed:
                log("共有フォルダから新しい版を取り込みました: " + "、".join(changed))
                if "kanban_relay.py" in changed:
                    restart()
                SETTINGS = load_settings(HERE)

    key = setup() if args.setup else load_key()
    if not key:
        if not interactive:
            log("API キーが未設定です。setup.bat を実行して初期設定してください。")
            return 1
        key = setup()

    user, reason = check_key(key)
    if user is None:
        log(reason)
        if interactive:
            log("保存されている API キーで接続できませんでした。設定し直します。")
            key = setup()
            user, _ = check_key(key)

    # 初回設定で自動起動にした → 画面なしの常駐に切り替える（この画面を閉じても止まらないように）
    if INSTALLED and HERE != APP_DIR.resolve():
        print("\nボードを起動しています…")
        if start_in_background():
            print("準備ができました。ボードを開きます。この画面は閉じて大丈夫です。")
            webbrowser.open(BOARD_URL)
        else:
            print(f"起動に時間がかかっています。少し待ってからデスクトップの「タスクボード」を開いてください。"
                  f"（記録: {LOG_FILE}）")
        pause()
        return 0

    Relay.key, Relay.user = key, user or {}
    log("Redmine からボードの設定を読んでいます…")
    Relay.config, Relay.warnings = board_config(key)
    names = "、".join(m["name"] for m in Relay.config.get("members", []))
    log(f"メンバー: {names or '（なし）'}")
    bosses = [m["name"] for m in Relay.config.get("members", []) if m["id"] in Relay.config.get("managerUserIds", [])]
    log(f"上司: {'、'.join(bosses) or '（なし。managers を確認してください）'}")
    for w in Relay.warnings:
        log(f"  ! {w}")

    try:
        SERVER = ThreadingHTTPServer(("127.0.0.1", PORT), Relay)
    except OSError as e:
        if already_running():  # 設定のあいだに別の中継が起動していた
            webbrowser.open(BOARD_URL)
            return 0
        log(f"ポート {PORT} を使えません（{e}）。他のソフトが使っている可能性があります。")
        pause()
        return 1
    log(f"タスクボードを開始しました（{BOARD_URL}）。この画面を閉じると止まります。")
    if interactive:
        webbrowser.open(BOARD_URL)
    try:
        SERVER.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# --- BOARD_HTML_BEGIN (build.py が書き換える。手で編集しない) ---
BOARD_HTML = [
    "eNrMfWl3U0e26Hd+xWluEkuJJWvygA3Oy9SvebfTyUrSfe99NA+OpSNbQZbUksxwuV7LA7NNIAMQAoQhBAwEOyTpQIDAWu+ntJFs",
    "f+q/8PZQVafqDJJs6L4v3YBUqto17bl27dr6m7ffe+uj/3j/HWusPl4c3rQV/7GKdml02+aP7c1Y4Ng5+GfcqdtWdsyu1pz6ts0T",
    "9XxsYLMsLtnjzrbNewvOvkq5Wt9sZcululOCavsKufrYtpyzt5B1YvSl2yqUCvWCXYzVsnbR2ZbstmS7WL5Q35Yt73WqCLheqBed",
    "4eWZp8szvyzPLC3PXlyefbw8e3xrD/+yaWuxUNpjVZ3its2VqgNdlpws9D1WdfLbNo/V65XaYE9PHkZSi4+Wy6NFx64UavFseXyz",
    "0bZWP1B0amOO01Hbnmytlno9b48Xige2vbn9f7/2x7ff/5/l+lghO7hvdKz+PzKJxFB/IvGKqLH9zXdfe7/o7H/t3XKpzDV64ddc",
    "oVYp2ge21fbZFRwNjWF4U8+r1u/tA+WJ+qDVuPCwsfjV8uyXy7Ozy7NTMHXrNSvTOHZOrcPfHx/Dr9OLzx7cXZ6+sjz96cqDG3Kt",
    "7lKdO8tT08uzX+HnmQfL00veX6eh+e3l6UN/f3zcerVn02C1XK5bBzdZViw2Mjpo/Yuzxcnlk0NUUJuo5u2sA6V5+s8ojaWwPJPv",
    "y2/hclhdKEkOpJKprCqhWr39fan+lFuWhrIBe0vGFmWwMdhJLp2zHVFkZ7OATFCYcPoyAwN6oehIH5L4oVbOY5Nc1snm08Yv44Uc",
    "9pkfyebED0W7jn2ODKRTKdst4kXIjzj9TkZMt1wu0Xh7bdhnVSQqZp18VgyijKNKZfvtzIgsEEuayCedPi7LVcsVKMrmnbTjCGhj",
    "dq68b9BKWMnKfisFf6qjI3Yklei20n3dVm+q24onBqLdUAF/HAiu0BtlaHV7NMnd5vLOlvzIkCzLY1kyn8lusVXNlKyZTzv2kCzj",
    "mrk+O9OnaqbVwgzktgzJMqq5JZ3pTWZUzYyomXaSgEeyjGoO9KYTfXlVs1csT68zAGshy6hmOpfp7+1XNfsEzL58IpcakmVUs8+B",
    "fRH4hsQbmygMWpuBSi1FpZu7rc3/MWHxF+uP2/H7u06heqBsfMFPvytU7dFCqWx9aJdqUFCDf2I1p1rIaz2UJsahCyBzC8ncQjLH",
    "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",
    "E20=",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
