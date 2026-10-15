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

VERSION = "7"
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
    "0e3t8VZtpvO4+gsia+C/UFz38S3/CxU5+Dw=",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
