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

VERSION = "5"
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
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

    if already_running() and not args.setup:
        if interactive:
            # 共有フォルダの新しい版をダブルクリックした → 動いている中継を入れ替えて再起動
            # ファイルが同じでも再起動する（board_settings.json や Redmine のメンバーを読み直すため）
            current = running_dir()
            changed = copy_if_changed(HERE, current) if current else []
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
    "WN8VY5PYSvQWygFyVxOmUGQ831bcakROkdHVNncBkzBz1RFdpJlKk3YGPlCsdbZ6BWUSBewFyiiU+Wk3jCkYLiev81zRhlEUAUF5",
    "Ft/f1Fg8sn71s5DWHqNBy2EnXqgEc4Mya6n4IDO/eYWeloGUSw6JREbsLaHQDk5mZJy3cOPZOfhDMWaowmwZzefBjAi1VK8jmMKd",
    "n9+E4oorLNLFP/VwFB3TlBBilxaekpdZ9EDHS5tcW6WyVFUtuhPUGNpBNbSDsSnROJXxt32gXKEUEvrJAlpXPr3qYAw1K292iNHY",
    "FKxrOzYVGYwLcxAe5Dn2PW69vjy0ev5k2lq//z5qc3I5H6zPza/9/Rq9Emv34G8PFkV4/fxJeKgvzFHypG/Wlr4T2ZLQMezypuZP",
    "i2vf30dD55cXeccGez7ZeuPw0vqhJY1tX+fiOB9PWezwhtblhvAW2URvYf5fvssR78+4Az0k699F9kLKbKuMtb+y4ovY3+2ypLAK",
    "sEVNgoKE9RLM3cxC06RrjIUGTA2HiXp/2oyUJas97DvTBiV1KSqnM/1dPKVd3Eehv/hyesxYFTqQOE03sI3RcblBO4Z1hmA+Az+P",
    "8mcSt+FRzDTPM191DFaO5v3hV1/fG5itCQ3pmGBJT9Uk32n5i2Q+kaCsSQZ8zpw0ipFp1VCL1En6Zz11Euq8ouUinZhtmz3JaLaL",
    "MkcFZUtau/4J0eMxmfxMZEtau7q0eu0e0BWL7+blR0y2nDPJ71mwOEK7eXXxxbTFecKax7/The7K/fMr905gBkmgV05+uHAngQmE",
    "MYfQBZGihl/hcYdvTsGqIls49PD99S/IvIer5cwpNIcsnCWn+yW+Q0aPRKnPL8EKIePksmpIehwWEyv37lmv7Xn1pb3Dr+75k2Fj",
    "FJDnT5KhEg2Sjcv3QJNo/HKY86XRCJf5CjfMw8gJ06zXCArlXwQmrI+FVuRD9E8AOFymn6IZ5/zPxCPOSlDLHHiyfvQ03uhy59zK",
    "wxMUTXCZTaLCQ0JoIFPpWQFh/gYUpuQox5jjuL2kUfbE63NXUnEe44KIWVlYgI6sPPhk7TYeKqGRziGM+VOG8VZHwjUOkaQGscsy",
    "FYuLxV1WasAXcE1UTJLHsGxUKSO2FlYMotHHpHFzQqsVHzQ1pVzJUuDUjNiExDn4h+9lhB2QSnVmnoqm7QkeqqjF9CM5mhoiPxgn",
    "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",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
