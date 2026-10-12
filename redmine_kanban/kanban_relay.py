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
    "eNrsvWt3E0e2MPydX9HhkEhKJFmSLxg5kCcJyTM8JxdWIDNnHscvbkstW0G3kWSDx0dr+RLA3AK5QQgkgYQAgQFym4QACWu9P2WE",
    "ZPtT/sK7L1XVVd0tWSbknPPhzQzQ6q7addu1b7X3rmef2Pn6i3v/uvsla6peLOzY9Cz+YxXs0uT2zW/bm/GFY2fhn6JTt63MlF2t",
    "OfXtm6frudjwZvm6ZBed7Ztn8s6BSrla32xlyqW6U4JiB/LZ+tT2rDOTzzgx+hG18qV8PW8XYrWMXXC2J6OWrBfL5evbM+UZp4qA",
    "6/l6wdmxeu3m6rXl1evfNRcfNBd/bi7ebi5daC7dby4dfbaPi2x6tpAv7beqTmH75krVgbZLTgY6MVV1cts3T9XrlVq6ry8HXarF",
    "J8vlyYJjV/K1eKZc3GzUrdVnC05tynF6qtuXqdVSz+XsYr4wu/2FXf/3mTd37v7f5fpUPpM+MDlV/18DicTI1kTiKVFi1wuvPrO7",
    "4Bx85tVyqcwlBuFrNl+rFOzZ7bUDdgV7Q33YsanvaesVe7Y8XU9brfN3W7c+aS593Fxaai7Nw9CtZ6yB1vJZNQ+/3V/Gnwu3Ht65",
    "2Vy42Fx4b+XOFTlXN6nMjeb8QnPpE3xevNNcuO39ugDVrzcX3vnt/lHr6b5N6Wq5XLfmNllWLDYxmbb+zdnmZHPJEXpRm67m7IwD",
    "b3P0n/E2lsL3A7mh3DZ+D7MLb5LDqWQqo95QqcGtQ6mtKfddP7wbtrcN2OIdLAw2ku3P2o54ZWcygFXwMuEMDQwP6y9FQ3qXxIda",
    "OYdVshknk+sXoO06gp4Y7k+lbPcVjzU34Wx1BsSoyuUSdWvQhuVUr0TBjJPLiLbK2Hgqs9UemJAvxMwlcklniN9lq+UKvMrknH7H",
    "EdCm7Gz5QNpKWMnKQSsFf6qTE3Y4lYha/UNRazAVteKJ4UgUCuDH4eACgxGGVrcnk9xsNudsy02MyHc5fJfMDWS22apkSpbM9Tv2",
    "iHzHJbND9sCQKtmvJmY4u21EvqOS2/oHBpMDquSAKNnvJAFd5DsqOTzYnxjKqZKDYnoGnWGYC/mOSvZnB7YOblUlhwTMoVwimxqR",
    "76jkkAPrItAK92hsOp+2NsNmtNRm3By1Nv912uIf1pu78PerTr46WzZ+4NOf8lV7Ml8qW3vsUg1e1OCfWM2p5nNaC6XpIjQBu9nC",
    "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",
    "pyAbR9SnC1F5Cv4F/PuRvv8CsP+qrA==",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
