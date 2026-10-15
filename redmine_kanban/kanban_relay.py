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

VERSION = "6"
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
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
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
            info = {"ok": True, "version": VERSION, "redmine_url": redmine_url(), "board_dir": str(HERE),
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


def running_dir() -> Path | None:
    """起動中の中継が動いているフォルダを聞く。"""
    req = urllib.request.Request(f"{BOARD_URL}ping", headers={"Origin": SELF_ORIGINS[0]})
    try:
        with urllib.request.urlopen(req, timeout=3) as res:
            info = json.loads(res.read())
    except (OSError, ValueError):
        return None
    return Path(info["board_dir"]) if info.get("board_dir") else None


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
        return ask_running_to_restart()
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
            if ask_running_to_restart():
                log("新しい版（" + "、".join(changed) + "）に入れ替えて、再起動しました。" if changed
                    else "再起動して、設定を読み直しました。")
                log(f"ボードを開きます（{BOARD_URL}）。")
                webbrowser.open(BOARD_URL)
            else:
                log("中継を再起動できませんでした。古い版が動いている可能性があります。\n"
                    "タスクマネージャーの「詳細」タブで pythonw.exe を終了してから、もう一度ダブルクリックしてください。")
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
    "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",
    "/0Kug6c2/ScbnXGl",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
