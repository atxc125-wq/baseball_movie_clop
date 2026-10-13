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
    "eNrcvWl3U0e6KPydX7FDk5aUSLIky8bIgdwkJPdwT2dYGbpPX8fX3pa2bMUafCTZ4PbxWrYJYKZABiA0ZCBhcKAxZOiEAIG17vtP",
    "Wki2P+UvvM9QVbtq7y1ZJnSfd710Q7T3rnpqeuqZ66nnntr7+ktv//mNl62Jeqm4Z9tz+B+raJfHd29/z96OLxw7B/8pOXXbyk7Y",
    "1ZpT3719up6PDWyXr8t2ydm9fabg7J+qVOvbrWylXHfKUGx/IVef2J1zZgpZJ0YPUatQLtQLdjFWy9pFZ3cyasl6sXyhvjtbmXGq",
    "CLheqBedPesrN9dXltevf9dYethY+rmxdKtx8GLj4P3GwaPP9XCRbc8VC+VJq+oUd2+fqjrQdtnJQicmqk5+9/aJen2qlunpyUOX",
    "avHxSmW86NhThVo8WyltN+rW6rNFpzbhOF3V7cnWaqnn83apUJzd/eK+//3sO3vf+J+V+kQhm9k/PlH/H+lEYnBnIvF7UWLfi68+",
    "+0bROfDsq5VyhUv0wddcoTZVtGd31/bbU9gb6sOebT3PWH+wZyvT9YzVvHC3ufrXxsFPGwcPNg4uwNCtZ610c/mcmodf7y/j4+Lq",
    "ozs3G4tfNhY/XLtzVc7VTSpzo7Gw2Dj4V/y9dKexeMv7dRGqX28svv/r/aPWMz3bMtVKpW7NbbOsWGxsPGP9ztnl5PLJQXpRm67m",
    "7awDb/P0x3gbS+H7dL4/v4vfw+zCm+RAKpnKqjdUqm9nf2pnyn3XC+8G7F1pW7yDhcFGcr052xGv7GwWsApeJpz+9MCA/lI0pHdJ",
    "fKhV8lgll3Wy+V7jS6mQwzbzY9mc+FC069jm2EBvKmW7r3gS8mPOTicthluplKm/fTass3olCmadfFZ0ooK9SmV32ukx+UJMaSKf",
    "dPr5Xa5amYJX2bzT6zgC2oSdq+zPWAkrOXXASsHf6viYHU4lolZvf9TqS0WteGIgEoUC+HEguEBfhKHV7fEkN5vLO7vyY4PyXR7f",
    "JfPp7C5blUzJkvlexx6U77hkrt9O96uSvWpiBnK7BuU7KrmrN92XTKuSaVGy10kCHsl3VHKgrzfRn1cl+8T09DkDMBfyHZXszaV3",
    "9u1UJfsFzP58IpcalO+oZL8D6yLwDTdvbLqQsbbDLrXULt0etbb/edriB+udffj8qlOozlaMB/z1b4WqPV4oV6y37HINXtTgP7Ga",
    "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",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
