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
