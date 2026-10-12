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
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
