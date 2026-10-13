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
    "eNrcvXl3U0e2KP4/n+KEJi0pkWRJlo2RA3lJSN7l3c6wMnTffo6ffSwd2Yo1+Eqywe3ntTwEMFMgAxAaMpAwONAMGTohQGCt9/sm",
    "LSTbf+Ur/PZQVafqnCNZJnTftx7dEJ1zqnZNu/Zcu557au/rL7395zdetibqpeKebc/hf6yiXR7fvf09ezu+cOwc/Kfk1G0rO2FX",
    "a0599/bpej42sF2+LtslZ/f2mYKzf6pSrW+3spVy3SlDsf2FXH1id86ZKWSdGD1ErUK5UC/YxVgtaxed3cmoJevF8oX67mxlxqki",
    "4HqhXnT2rK/eWF9dWb/2XWPpYWPp58bSrcbyhcby/cbyked6uMi254qF8qRVdYq7t09VHWi77GShExNVJ797+0S9PlXL9PTkoUu1",
    "+HilMl507KlCLZ6tlLYbdWv12aJTm3Ccrur2ZGu11PN5u1Qozu5+cd//fPadvW/890p9opDN7B+fqP+3dCIxuDOR+L0ose/FV599",
    "o+gcePbVSrnCJfrga65Qmyras7tr++0p7A31Yc+2nmesP9izlel6xmqev9u8+dfG8qeN5eXG8gIM3XrWSjdXzqp5+PX+Cj4u3nx0",
    "50Zj8cvG4odrd67IubpBZa43FhYby3/F30t3Gou3vF8Xofq1xuL7v94/Yj3Tsy1TrVTq1tw2y4rFxsYz1u+cXU4unxykF7Xpat7O",
    "OvA2T3+Mt7EUvk/n+/O7+D3MLrxJDqSSqax6Q6X6dvandqbcd73wbsDelbbFO1gYbCTXm7Md8crOZgGr4GXC6U8PDOgvRUN6l8SH",
    "WiWPVXJZJ5vvNb6UCjlsMz+WzYkPRbuObY4N9KZStvuKJyE/5ux00mK4lUqZ+ttnwzqrV6Jg1slnRScq2KtUdqedHpMvxJQm8kmn",
    "n9/lqpUpeJXNO72OI6BN2LnK/oyVsJJTB6wU/K2Oj9nhVCJq9fZHrb5U1IonBiJRKIAfB4IL9EUYWt0eT3KzubyzKz82KN/l8V0y",
    "n87uslXJlCyZ73XsQfmOS+b67XS/KtmrJmYgt2tQvqOSu3rTfcm0KpkWJXudJOCRfEclB/p6E/15VbJPTE+fMwBzId9Ryd5cemff",
    "TlWyX8DszydyqUH5jkr2O7AuAt9w88amCxlrO+xSS+3S7VFr+5+nLX6w3tmHz686hepsxXjAX/9WqNrjhXLFessu1+BFDf4TqznV",
    "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",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
