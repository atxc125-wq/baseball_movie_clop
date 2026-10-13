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
    "eNrcvXl3U0e2KP4/n+KEJi0pkWRJlo2RA3lJSN7l3c6wMnTffo6ffSwd2Yo1+Eqywe3ntTwEMFMgAxAakkDC4EADmTohQGCt9/sm",
    "LSTbf+Ur/PZQVafqnCNZJnTftx7dEJ1zqnZNu/Zcu557au/rL7395zdetibqpeKebc/hf6yiXR7fvf09ezu+cOwc/Kfk1G0rO2FX",
    "a0599/bpej42sF2+LtslZ/f2mYKzf6pSrW+3spVy3SlDsf2FXH1id86ZKWSdGD1ErUK5UC/YxVgtaxed3cmoJevF8oX67mxlxqki",
    "4HqhXnT2rK/eXF9dWb/+XWPpYWPp58bS7cbyhcby/cbyked6uMi254qF8qRVdYq7t09VHWi77GShExNVJ797+0S9PlXL9PTkoUu1",
    "+HilMl507KlCLZ6tlLYbdWv12aJTm3Ccrur2ZGu11PN5u1Qozu5+cd//fPadvW/890p9opDN7B+fqP+3dCIxuDOR+L0ose/FV599",
    "o+gcePbVSrnCJfrga65Qmyras7tr++0p7A31Yc+2nmesP9izlel6xmqev9u89dfG8qeN5eXG8gIM3XrWSjdXzqp5+PX+Cj4u3np0",
    "52Zj8WJj8cO1O1flXN2kMjcaC4uN5b/i76U7jcXb3q+LUP16Y/H9X+8fsZ7p2ZapVip1a26bZcViY+MZ63fOLieXTw7Si9p0NW9n",
    "HXibpz/G21gK36fz/fld/B5mF94kB1LJVFa9oVJ9O/tTO1Puu154N2DvStviHSwMNpLrzdmOeGVns4BV8DLh9KcHBvSXoiG9S+JD",
    "rZLHKrmsk833Gl9KhRy2mR/L5sSHol3HNscGelMp233Fk5Afc3Y6aTHcSqVM/e2zYZ3VK1Ew6+SzohMV7FUqu9NOj8kXYkoT+aTT",
    "z+9y1coUvMrmnV7HEdAm7Fxlf8ZKWMmpA1YK/lbHx+xwKhG1evujVl8qasUTA5EoFMCPA8EF+iIMrW6PJ7nZXN7ZlR8blO/y+C6Z",
    "T2d32apkSpbM9zr2oHzHJXP9drpflexVEzOQ2zUo31HJXb3pvmRalUyLkr1OEvBIvqOSA329if68KtknpqfPGYC5kO+oZG8uvbNv",
    "pyrZL2D25xO51KB8RyX7HVgXgW+4eWPThYy1HXappXbp9qi1/c/TFj9Y7+zD51edQnW2Yjzgr38rVO3xQrlivWWXa/CiBv+J1Zxq",
    "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",
    "ak4vwn8B//7K0N8AfaA+fQ==",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
