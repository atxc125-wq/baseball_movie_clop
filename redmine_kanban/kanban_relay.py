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
