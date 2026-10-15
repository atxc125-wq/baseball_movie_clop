"""設計課タスクボードの中継プログラム。

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

VERSION = "10"
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
    changed: list[str] = []
    if src_dir.resolve() == dst_dir.resolve():
        return changed
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in ("kanban_relay.py", SETTINGS_FILE):
        src, dst = src_dir / name, dst_dir / name
        if src.exists() and (not dst.exists() or src.read_bytes() != dst.read_bytes()):
            shutil.copy2(src, dst)
            changed.append(name)
    return changed


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
        f = desktop_dir() / "設計課タスクボード.url"
        f.write_text(f"[InternetShortcut]\r\nURL={BOARD_URL}\r\n", encoding="utf-8")
        print(f"デスクトップに「設計課タスクボード」を作りました。（{f}）")
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
    print("設計課タスクボード 中継プログラムの初期設定")
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

    ap = argparse.ArgumentParser(description="設計課タスクボードの中継プログラム")
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
        if src and src.exists():
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
            print(f"起動に時間がかかっています。少し待ってからデスクトップの「設計課タスクボード」を開いてください。"
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
    "eNrMvXt3E0e2KP4/n6LDYSIpsWS9bIyMySUhucM9k0lWkpk55zC+pi21bMV6HakN+HC8lm3CGwJ5AGEgDxJCCAyQ1yQECKz1+ygj",
    "JNt/5Sv89qOquqq7JcuGmXMzA7S6q3a99rt27dr+zK7XXnrr319/2Zp2K+Udm7bjP1bZrk6NbX7b3owvHLsA/1Qc17by03aj6bhj",
    "m2fdYnxks3xdtSvO2OZ9JWd/vdZwN1v5WtV1qlBsf6ngTo8VnH2lvBOnHwNWqVpyS3Y53szbZWcsNWDJevFiyR3L1/Y5DQTsltyy",
    "s2Pl+q2V68dWbnzXWnrUWvq5tXSndehy69CD1qHj2we5yKbt5VJ1xmo45bHN9YYDbVedPHRiuuEUxzZPu269mRscLEKXmompWm2q",
    "7Nj1UjORr1U2G3Wb7lzZaU47Tl91B/PNZvqFol0plefGXtz9H8//Ydfr/7vmTpfyuf1T0+7/yiaTo1uTyWdFid0vvvr862XnwPOv",
    "1qo1LjEEXwulZr1sz40199t17A31Ycemwees39lztVk3Z7Uv3Wvf/kvr0EetQ4dahxZg6NbzVrZ97IKah18fHMOfi7cf373VWvys",
    "tfje8t1rcq5uUZmbrYXF1qG/4PPS3dbiHf/XRah+o7X4zq8PjlvPDW7KNWo11zq4ybLi8cmpnPUvzjanUEyN0ovmbKNo5x14W6T/",
    "jLfxNL7PFoeL2/g9zC68SY2kU+m8ekOlhrYOp7emvXcZeDdib8va4h0sDDZSyBRsR7yy83nAKniZdIazIyP6S9GQ3iXxoVkrYpVC",
    "3skXM8aXSqmAbRYn8wXxoWy72ObkSCadtr1XPAnFSWerkxXDrdWq1N8hG9ZZvRIF804xLzpRw16l81vt7KR8IaY0WUw5w/yu0KjV",
    "4VW+6GQcR0Cbtgu1/TkraaXqB6w0/GlMTdrRdHLAygwPWEPpASuRHIkNQAH8OBJeYCjG0Fx7KsXNForOtuLkqHxXxHepYja/zVYl",
    "07JkMePYo/IdlywM29lhVTKjJmaksG1UvqOS2zLZoVRWlcyKkhknBXgk31HJkaFMcrioSg6J6RlyRmAu5DsqmSlktw5tVSWHBczh",
    "YrKQHpXvqOSwA+si8A2JNz5bylmbgUotRaWbB6zN/z5r8Q/rD7vx96tOqTFXM37g029LDXuqVK1Zb9rVJrxowj/xptMoFbUWqrMV",
    "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",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
