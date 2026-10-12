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


def match_people(entries: list, people: list[dict]) -> tuple[list[dict], list[str]]:
    """設定に書いた名前（または ID）を、プロジェクトのメンバーと突き合わせる。空白の有無は区別しない。"""
    found, missing = [], []
    for e in entries:
        hit = next((p for p in people if (isinstance(e, int) and p["id"] == e)
                    or (isinstance(e, str) and _norm_name(p["name"]) == _norm_name(e))), None)
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

    # メンバーは team に書いた人だけ。プロジェクトの全員は出さない
    people = [{"id": m["user"]["id"], "name": m["user"]["name"]}
              for m in redmine_all(key, f"/projects/{project['id']}/memberships.json", "memberships") if "user" in m]
    team = SETTINGS.get("team")
    if team == "auto":
        # 未完了のチケットを担当している人だけ（担当がグループのものは除く）
        open_issues = redmine_all(key, f"/issues.json?project_id={project['id']}&status_id=open", "issues")
        assigned = {i["assigned_to"]["id"] for i in open_issues if i.get("assigned_to")}
        members = sorted((p for p in people if p["id"] in assigned), key=lambda p: p["name"])
    elif team:
        members, missing = match_people(team, people)
        if missing:
            warnings.append("team に書いた人がプロジェクトのメンバーにいません: " + "、".join(missing))
    else:
        members = people
        warnings.append("team が空なので、プロジェクトのメンバー全員を表示しています")
    hidden, _ = match_people(SETTINGS.get("team_exclude") or [], people)
    members = [m for m in members if m not in hidden]
    managers, missing = match_people(SETTINGS.get("managers") or [], people)
    if missing:
        warnings.append("managers に書いた人がプロジェクトのメンバーにいません: " + "、".join(missing))
    members += [m for m in managers if m not in members]

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
    "3Wzhbsa6L5ZLtXLBrjHEUgFfFuFbrQKbYmRTY9P/KjrZvG2FgUDlnGotlikXylUggVNOEVAxa1f3R2jD0dZLl8r18GjWrtuxOhbY",
    "vrmQB4qxeYzLqG2ZTCaHkpkRY1Mmbdhq20Y8WxLf9dPs8T6BebdziRFtO9oJe2JieETbjEO5rTZvMm07prL9QwO0tGozDuYmEtnh",
    "Ee9WTExAV1Ijvo2YHO4fGEgpsLwVc7nh3DD1x92I/RPJbJIwU2zDXCKTGBoYMTZh/1DKThAC0RbcOpDt32aPaBswOdSfSOZkc2IL",
    "Jif67QEGHbwBE1H8X7yfd5a5t5KZVHbANvfWtuxENjcwYuys5FYiL8bOGs5lhyf6R4x91W+nBpND5r7KpSaSwwNa2wNquIl+29xZ",
    "zlZ7KGuPGPsqNQQLtdXcVxPbMimgV8au6u9PZZOeXeX0Z3JbM9y2H03xfQMQmhDVwFH8unlMZxv/Vfj5h2DnfyluPipm/vfh5X8f",
    "VgbhZGPTpqej1tPp9ISTK1cderRzdadqzVkT5YOxWv7v+RKAmShXs041Bq9GAItR1I3Cu+wsFJtykMamrWQi8SR+5NfQXtGuAluA",
    "hcDGJ+zM/slqebqUTVszdjWMmB5RvZLvAMfoJbIMgDhQOdiXjA+Kj4JTUQEUdnMFXOapfDbrlHAko/wIO8kS4mHaKpVLjvVEvohi",
    "sl2qU/+m6/VyCcXpynQduJVTAKkX6nCb+dIUcC4oKPqlfsuKUDIzXa3ht0o5D+J6Fb+lc+XMdC02k6/lJwoOlAEZlPcWIiCwuHxW",
    "jIK3TWREloiVcznQDKggQtoUtysVmj9jYuG3GtRkNZ/FF/hvrO4UK7S/quUDtbRlT9fL/FcyV8VCFTubhSWEqeX+JIegHe39RKGc",
    "gV2WxH7ihBNgu4LN4g/oEAjVMfWfZUjU2nsQf+P1cmXCrurznwNmP0J/xw5UESr+PWLZwJdLsTz0HbqM84GzqFq1ksM8F/GJql3K",
    "+uEZ1SdsWEIYmgZgxCrmS6w2Ifq5kKaSAMzFS1pzxHGcF2qTXhwQEw9qyIhVcOrQuxgKJLQT4omUU9RAwqCzNu4DLyLHUhGzgX7V",
    "AJTJ2ywUAXJl0lbdnpgu2FV8USPYxXLWiVXyhQJhgg4liVD8nRrGTok1TUuZd0Tu26qdzU/DXG3bto1X2L8dBfmNjJgDwdeRgHnZ",
    "pHcyXsjPINL7oRLF9sIswybHQQp0iZOwh2iDqwtDhP8hBosy5UJtHQwwEIiX0YtwuFz1Ek0mT0mauIO+MRGHoF8BM8P8NuKbTXMn",
    "pa1BRN2UWmVt2Tdx++kppFtEWgmQD2X6I7Kr8Uo1D4g6GzirioYYAFw+7XY1oEBEIFhmf2y65lQ3MrdD3rHRYAMR32hC0djHO/fu",
    "zAPd8neuXxBUL/261Fz6vrl0GuhXa/lI+/wD6xlr5diP7e8Xmov/bC591ly6HkDaatMTv5e0oRJK1Jfw2p6o9QCNKg4YY6VhdZwp",
    "mvz1ptmcymG3S8YGSZjN1IHcwU6tOshG112N4H0QiCubuO1RJIoxRhUnu31zvTrtoFjcFSv80kMACSdBRkiFAgD9iqhhx4uOkABk",
    "b5mLEKeIFRwUcc1VSOBu983DQPDaaKJy8KYN7HYDsa4oiEBPiBK8PwFOZioPMoXJH7Z15A/rYFfgfl8H5Xpke9TPCbkUbAJM6+If",
    "lPTO1SDOlbFS/dqo4ygbBSKRUEq8A8LXPvpp4L6EjKwxGD27stKukH3EStgqveRoomxXs4QAKNDAyKWwCHMhZePYwbTLR6nCo4iV",
    "0M/pYglwo+pUHLseHohie0X7IGhUKGNGIq7EmBKsDuqwBmB2zBDK9JY1nM7mq7D/86gbcssdpBUXH9dl6aqAQnMWbS2e/Dy35rbB",
    "S2PFk6la1FgteiUHGEPzPo1yA8LpsEdiYGlXSmtuRyfKoGoUOw5I78FUqrNIOxAs0urVkbF5SF8ykFAL0cStmIG5qqu2xdZjfOth",
    "9/YiQLhtoY7Scy83xv0CybpoXKmyXsG0046bFTPQM3J3Rgu5yvFs1Z6MSbnRtxHQ/NGDuKcAgYKcd1ClKqPuUIf+xQcHZRE2S8HD",
    "9s2ghFah0Sxw4HiGSMc6XKErBECyt1kC7LTWQG7qsxomD7DtphdsYcz0Us7FG8GUMyPpYKUst37VAUoHGkxXUvNIhMa7sNtwu2Nl",
    "SYE6iyYbRKFBhidNE5NVe4IxCIbbq9qBZQlLYAUmDRQZcL/X7BkcirQSkQWHDi3T1uaHDz5t3fz44Z2b/5q/snlEm2EQdqGzdSCD",
    "Vd40QjllKif0KJ/4FYjNclAx0B7X0V1owmp1u1rXdUN97ypDA3NgxbRc04Fn5wcp40HTCeUOTEE3SEV30A7FYprPbmXVnYP1mPva",
    "KRTylVq+JqTiSc2SZpJY6lcC/texXwG2DLQ3qbHHhwzcTFhbO0i01IODclIGB58ceUyDi9eTgXRF2Ga9ApQwz0qxHaqnOlVPBVdP",
    "mdX7O1XvD67eb1Yf6FR9ILj6gFl9sFP1weDqg2b1oU7Vh4KrD6nqLjXemNzgQZ+BQY3zsS5il2YPTDlVR5EL4Pt4Iv4YzDcgO/Sm",
    "F/QixSAw2+VGyshL+Jp1MuWqzYQL7cduDUVIfeVgBZwqC3pQODvtdNi3Hfdpd93IEA6AfXTaqR10s67iM/f3UfWkQOkS4T2idtQR",
    "Hlny5zpIfJ3MFF7jd8LlY/laTA6Z51HpjiZn52FKQFxom2tZWpv/rn3y7G/3l9E1ZOkweYqgw42VeLI5f2E48SRIIu+3lo80F4+1",
    "zz9oLkC548JbJA7y0WTVqRl2IFLC1lHBBlnxEjumX7NU1PEsTCr9Crw8uHisxs8Bj2iDSkxi5HFsULlH1tkS/hHGc/lCwcl2MZl2",
    "N8F01/k9jbG5qoJv1rFWPQZrradtpkPs7RDUjUgHWU8D6RGXQWZr3/wCxGXybVpqLp1tLv5KAvT3fgG6lHEKsb/TfjTk6Fz+oJPF",
    "w4kcmWWedCW8jF3IhJGtWM9YTmkmXLNzTgym1obx15y60HejFoh9EegeTX2uXC2KVcBd8B/hGICM+NXn1FAXQ5ZAd0TOrF2bcsxt",
    "3V3e75He+Wz93aR66+8w4iyKboNCklWTuY6i55LhACvRMtEdIEDL/iM5u1avBS+UkMWTQ7owzks11ONSPYKi605Bkgx3SrAEwTs8",
    "kAK4UdGJBFDPmNWf4pYaYjDr2lzM88RUpwMv3nnGGtP0BlnHTQVuIPCIx1z2BGo1Fo7GcD9IDmsjiTvVarnzaru9Q/c8cRqGE6AO",
    "onux1K8r4miiix+5Xe0gAO9Wr90kF8v55uLl5uIXSDoWv/EiICJ0gQ5IffhHCOXrPU1XEo2LQ1ErhX56A4MwFR4OCc8gv3hWXGFW",
    "Su+6OnPJ5u1CmTUqDeUGGeUQ2yKMj6ZHg6u+SAluA1ySTRYukySCleL9piML2QAHvNiSGtzwDuMjfHew3cyDcl5yeaeQ7XDG0Kmd",
    "AaNuwZ5wCrBS/CtOPz32us6WvkCRjyGRj8ZofbbiAGsDxN08phrRP1XsWu0ATLzwonpUIUc7yOhwsrVVnpv0LubI418EWA448uNV",
    "G+qk9kzlS/WeZrI/MqKvMxILp1aPgWAwXQiEoBVW4xuWpqnAaXiEYyHDTgBSSkwNTOtdvLz/EZwHtPpkrdqo5tLY9G+ws2uA2rtK",
    "uTIA6NxX3ksgPuFG6LSGxCjenq7V87nZmLKJ0Zo6pWzg6m6KF8p2lo1tvdC3wEXvcOQNEt3Kj+dQkCOy3Fz6url0sblwo7lwmXzW",
    "TzQXvmwuXGkuvMMu7M2Fa82Fk82FW+1Ly63Dh1h4sCdqaWmZNXyqhL2XIgbgG+krTB/QWNZnxZK9UWw/kRZAY8pOq5PqIZ1Ur0+G",
    "ez0DkEKCS6eRHKeIxm2Y+Haz6XrH1406bw2akIpZvpM1vVZ3KjWzqM7JC3nYOxQyIVdzQ6MUxtlpXELcgsjEsUWt6UK+Z6UW5Xdy",
    "VtOhGwKdMOHKFvOlTNUp0u7ytSodGU3DtKgZxlI9ihIC6xgHpECQGgggjYN8jPo7Tv17PinbpM8vEKqSe6Zvqv4GzsQP2CB3EZHp",
    "jY1szFjXqbngpdi8Wc3tsD61wx1mtoMBieQiu5QvCiF2gsKRkvGBmuXYNVjNUqw8XQchIYdRUxxJsN+ZzVXtolMTpeewAeOYI4Un",
    "Yf4BYemuVL83J6DGJpud0DqZGRV8Nlexa6ak52RW+iZttQ4tr128CXS69c51eF756Hrr1E+gq7VOn2wdPSnI9iQez2adR3ekEKoh",
    "4bs7P8ODyvw8XZ2kA5N1dRcvZUZrRoEwtzdrbY+eIwgzLpTnXu2KclqXzqSt9oXr7Y9+WDl9WDK+eL6EhJycooLcjKTn0ISdnXS8",
    "x+CDG5MRk54z6KGNuOasO91uN+N/d6rl4DVjvtiJnwCIWM1B5iP2btIl0jWnkENKXHXqmamRzrAlLyJNJ9A1T60BSiEnbjcXj7WW",
    "D2NY3of31j79wqtY0vr4PVo8Z/M+B5dObEg4taSEiJGrRnQ/l/hW1+CqSHHRzhdiyEthXvwsNYj3MnPbCLOVYhG2pYtDPFYiJLQM",
    "aTK7jTxGA6/37NrVDTbS/35trno9h8aybNfMTFerFA/rmle7mTVNnTohQkACnF9xMuMUgduNqj9O+qQ1GS/mazXmxwEHuz0fijBE",
    "CuWVxLSrXbLrWV0d+j/pBDltBfm2PEbJO+F1fRlS/v+PZPYQA+kmWEsPH1E0nquWi51Ld/M5USCQpqQ2eoyT8nvSuQRG8xTmNgJN",
    "IQHfstCU/o0dat3fWBfNuX5i8l9lNvEYRnz9Mj00BojkgJZBtQAZ6/mMXQjwZdDXo1o+0G1ndxDPjOo0pwExCb7IElXJ+ZtXUhCs",
    "OdA5tVJ1MH6/g5K2UUNMF12jk1d0N3IgOxcvTBT0iRQSaXdXE4zg7yxJiNki03esWJvsotDqRy4eh2YJ5veZZALxIMgK521OmuVM",
    "aVk527K9KO5k83Wy72smjK2GCQMd37iQ5EYbpkJB4x5yTykCBiNbZAfWDcVWpXqCaa+raerMWFSV+//fnNfKdafmIQNbE1LVZF/E",
    "gBC8eMk5EBMWvQ74MNRx8/vGpB+om8Rs+NHMozp1NY8imbx6BqBCZgTuUEifGcholPeTK0E5ffRKrxWvzPRspjd4RcN3BDmPx8aL",
    "PzWXvtITbDy8c6x16g5n10C3B48MjxPhCyH1CCAbEt9ZVh/UpPf+hBLoDSwmp78SHVN0kHjkhn7M0o4m6wwoPr9x+5vq/7oO4Kpk",
    "vFSuO50Ld/WYqjt2UVP/NIEB16BgV2oOdZOeHj3ukZqpT0kbiaHaPArX6Y8YivWwjBML9F+UwoVslo+6jX7VinZhPY4ol4frZPW4",
    "G512EGnpgDfenhTz2WzB6dBt1RS5q9erHcijUUaoYvWe/LqpZhxzFQUqGm4JctHTF44Y43qWEFVfWCe6omD8gF0tSc+tnh3StKrC",
    "L61nNQtPaAIj/9Yxi2p0N5mSKCGBgUBhc0SDR7rsZg4dWJ/J+D1w9UZzFE/sobYbiWCLGPCEAXqDwR7avKTigxi1HIAwaOeu2NX9",
    "vTh4kyRH854ybPWSyjOgfMCmFd0IsralROqIhNc7wTMdhqpiNig9FjsaxFCacQqFQF2lB5u7qPoo0XLdFiXZbVFAvKt3kK3kdFOR",
    "LrO9TV+kZIe5/50Brqob8UKyu0uea9vuH1zPAVCCTPUKcqhnkP3dQfYE5MB+r0FJ+Wg4SOtrM5NeBi6XQWi2mutLvyJZXDmOHmox",
    "OkICIuI9oG9YRrFZTzHX49dTsOopqPu4yYL2wTwqA7V6tbzf8e4gBQ645X4PsKDz8cT6dnm3ZdZ9vSBTQbZ7t1KlbmXy1Qzb5Myq",
    "UNEchStG8ntFFz0AcS8GgguWiDZACPRmhEgQ2Hud/M8Ii/cfcrY80CmCmVs1j5W7mnVc1VXVjtfqgQKMRv364zK7h6oSr3aQNAD7",
    "3EKzHWQKo9Ckt5B0ZhFFhA2gi2/PBsIs3dxpmo/lMJof0D1Yql4d1Ck6jzfJQ0NkpojBdOX/4FwOw4Fo0EH67TZO8gajNEVera4B",
    "n2RUdM8hz6lBUiaHE09GIgKEOIbayERiNa/luFv1RkAevKqTnc442VixLGMY8Teu7NMog2uBzf4USADw2T6RMfPZPpGmFKcJ/snm",
    "Z6xMwa7VKIBzs5XP8sMO6DRlNEUSwd85fQt9gW9aRUqMI95jrWT3bKTwXRYlkVKBz9qz3AF+3AGdhu+BhVUqGq6AP3fjrx3NpS/I",
    "MHFbr/xsH/TW32/OQ4PtBH6mVDTusNjJUbUvcp3I9jP734RffwEU3QyIXHVfaV3CY84PTj78BWbiCjlw/wh/C/A4PjYB6fBoDui1",
    "6kYf9UP9FL7BciXqJUskkuGOlZwDe+3a/hfqpc0Wnxdwhc07frt/3Gqf+Wb1yim1Rs/28cfOwBlo1UGVIABm6/DJ1es3mwsPVn+9",
    "D3/3Cq/m1NGBpBYAsf3uVys/fsKOxyY4tWiM0U51x6ZNnuWlFC4B+Ipubputarng0DPSYoF39IFOImmWt29evXRt5fLd5sK55uJx",
    "PZNMR6QRGTzEwOQPBpmfQd9VIJ11R6svHjyddxM+yAEU7XzJ+Mpt8OMOva5wMty8Q18MjtLlxp7tQ2D+ziOPYKj8xEplp6ESJeTi",
    "4lGUVxuWWb4sD0TOnFz9/L+5tNBc/JZCUZbVnvORIJkhQCuBZVI7FCjAhpTxUacagBGAUscPtX75oLnwa3Phc0zxS+uJ6X6XruLy",
    "LpwAWBLhdPrjg0ZeZtr4X6TfOxLeai6CqjfaLMq8A5stotDo3MyMMQGLOu0SHOl7IAgO/HwFf8HiTBf0FcL2xMSrFxhao5CfGJHA",
    "d/FcKs+ALIUniQAJC/u2GD1ITDW67wa0MEx+8X/pt8CH5sIH9P8bRrwR76mFa835EyIaaf6kbMigwhjQIvkCP3feTkZVEYrAdfnY",
    "QcdRY1qE+7xg07KwW/FlKKtPlIHIOvICLq/8dG3t/OHNai7X7ZskgOv0zizMPXK7UXCyE7Pu573oKCBpx1TKqCq+mcRV7hu9l+R6",
    "vzmQA1ObyNyOiBjIhVutU2dav55tHVryMG4NIHvF6xuc2dmzfJ7BxJ8KbRbJ0pG1u0z+DYcmDVZh2iFGhHJCsO/zyj9PrHz47W/3",
    "l9fmP2ndoWzegISLJ367f9TDRDfci1eBPatOIK+GPiguj7GheDryOck7YnYeQ6OvAL6rRhH5odGV8z/AIvI6eiUDjWhrjxW5Enii",
    "qdi5Pfsn/Mk79dbuF5sLV1vHPyIvcfIYXzwe7F6++D5MLmVFv2K94WRBanYw/pX5Tvv8HfIwP0u09lxzfvH53bvgMyVTX7jdyWGd",
    "k0o0Fz6CtZIO66L+s30VDUeJT5Fe+TKiac3Hf8yx7pAdbC38AOOzXnz9jT0WkPvVa9+2Tt022ls83rr4Q+v0Mp9jPfyF4nh9nei2",
    "VZS8SLJglVt+s1pwewHzbL35xit+rNDRgRw/xCIpEOzAPFUuAE9xc++LAnHnoA1KhUNp+0kBgQf4XQdo5VxucwB69D4Ou5L/dwc2",
    "3OqR6+Spd8tyV7T7QFTEjlAwCI45EG1igCW05o8/vHtXRJzNn/zX4ffhJbSGcWcgSS/eI5GVUGn+ZLeB+vFAYSBje3PpDOLe4hWU",
    "x7XLAXyoGLD+6+wxLWZFMDB48Yb4rYSrSuetqQWsbN5hYr/BGWSoyuZuorYhWavuoNAtOAHGs1NQaS+Cux8ac/49kpftWDtztLnw",
    "MWym9cG5SguDBUGtmIelkguABKarcqGJKh6eW8tU8xVQn0KgraHdLZ+ph0bwNHv74/hvE6jfyTjQktde3vW/rX/Nf2itLRxf+fAa",
    "IA/Sj8VTzYXzRFRYAkK8YrLYPnWekwMghMfSFTxgzwAO1K0XXn/+jZ37Xnhz1ys7re1WKJVIDcWSiVgyZSVT6dRAaMTq67MmpvOF",
    "bLwyiyQQVNL28un22a/a5xYxfcGhrxDhQTqbX2wufI0SzdFlpJRCGTIoZXPhOBb44u7q9ZMwcNEFMSHbySIDremb25M4YddOi6TA",
    "BW6Krui40TpCShfBbt3+tfXgAjQO3WFoVOW2ZVKMlVuX0J0bKIXlkcc8LQLBAPrPPRaopZaKxgyN1Op2HRCmlrZGCb/mAMPTVjJK",
    "nDlthUBHWPl0vn30eChqifzv8LZezpbFC4tc/fEMuhHVIKQUhMSTsqSqni3DxhFvg6v3q+opvX7H6ilP/QFVf6Cn+gOe+oOq/lBP",
    "9Yc89YdU/eGe6g976m9V9Vu3Tjy8exivdLn1eev4udX5QyBiQWUJquSYkJIJD6hhPyhGifadZR2UTGsGLzqB2qZAsSKjBsYQmC4W",
    "dBCl6UKBYYxFGaX5Zhpgdiu/fo3bztCUzpKqyvF6NwRPZPXJg9mwKSTmWrh5Fo8iq0ZJ7mr727vIwpDgYHsopS58KvfbrfaF+dby",
    "p0F7ZXFt/rvVSyeILd7m7Ccr7x6heEIQzC41F75pLn7Q+uYUkgUkCEAxbsH8caZ3NmrKLbTfmTU3CTkz+3YTEH94x8I6D0J8dGed",
    "IWkIIyGpzmqQEpyYJaC6QhLVEbINMELAJ64vfZoEkWv9egjG7YOm4YmExhU90EBkX33wXnIAqC28K9ol0Derr5fQpI9O7+rVn/PO",
    "AX5lIor22eLlU25XEpGPknTNnT6xduY4rZRCIORBhlkLsc21bOE4Kf4Ckakf8ZLbRZksaKMQNb1BOHZcUFDNugmFDbEbpK3b9BH+",
    "/kjcq7RwFbCmtfzj2rnTXin8KPDJ04xNYtxoFd2VRaRKyhnhwXBuZw7vgaHySgJZgDbXFu60j322CpIjiHR3APbPHmue1kvqott/",
    "YDWieac4AcKYyQ9car524+P21zqGmtT64f1jq2cvhzoR4/adS6u/3g11orVIVT59L9SJlMLma3921vPZZVWtb79tX/gHDHH1+ndr",
    "H/2EtM1Dem7/uvrtJZ8dDCTh+dUrV1EeOHWGJow1tTvNxau0fssI8+bHreWvWjdPK3saz5hi1a6NT+fJSCVY9vbChCVa+ednjJZE",
    "JTFaGcjYleMsLq3cfqd1/juSDYDcXcFQgmoZs5vtyjJZxUHJvbjTnsUzlQHe5NAbfZ/ogkb7wudrZz7A2KFpZ0+5XOKK/ZKOI/pT",
    "f1FE+uibh/e+ah0+RIaei5Tq6f21e++sHv0Oteb7P61efwCAOF5udzVfrpJzQDIqAZnz3DqNMdgc5MexfURasbHW/GVo6eGd4zwF",
    "KOL8dKw9/xXsuPbRb+kWsuVEEmSsh3dOtg79RPrqdRCiGGFrs6XMTqBwbzDHYdpCHTApfOvy0fb5H1DwW7ihyHsYaeM+YlYR3Jya",
    "KIuFz3zDpMMn27UvX1j54Yv2p5ce3vsRCQbghbbs4cwUyJz78tkIEY0TQrFmGXJ+kc5bpB67D+TIXH5yX3a6WGEp9dbKP0+3P7sA",
    "k2xwQIloObtQoz5I1f12a/7c6pcXPLZlWCwraWH3FgDCZSkFnqM0XcvwHtYXuta6/AnHyLe+AUXw7NrCIb71DdkaDuLlfKHuVPdM",
    "V/CUzcmK+d0kkCzAsBHeb5cm7NI+MrbAgCJEdsWZWGdryAkL9XtQ75OprfEE/C+ZHt46NIj4eJVRF9okmGnKuFJFXzIowDs86+Rs",
    "0DVfLWeREFAx4DnQRfFs/acVQvMVPaBJKSRoPcWewswRUt/mUNNO8gTKYKcBZT+WxW6Tte0GvwQITA7E/XxClnlHN7Ao+zCpRqdw",
    "JKFEal/7H5dgX+5588+r9449/OWDEPrN4VmqUIpfxFNz2KVzMNQGanT79u156Y0/v/TGPlY+9u17uq/jcshN9gFagugIZZ80jsbf",
    "roFuCkuvITaNHJTPRdThBPoBXfzpFowH1dHF+U2PVaVMxS0gNQ/vfdxcuien9dbq1S/Xjiz/Afrizuf/ClRkeGgggf+NbMpNl/jg",
    "hgLxX8/txePYcIQ8FbB8FkqXQPzYadedMIYkxGHu/lSertbQH1v8P4JBPPXpasnK4om2glnBizGpZg0h5nNW+Al4EmWRgo+IZkZn",
    "QRiKWtkxaK4WrxXyGYf8vROReK1SyNfDoVgoEi/alfBr08ic3RZV5xCCFUPim40YvcjXylQg646qgqOytu+w9tSrgAfhUiResbN7",
    "cAowdCuUCLkNjG+Zy8YnnfrL0N2/OnY1HGnEtsxVwvTy1XKpPgXT9YyV1F/zbEUa40ZH7CxxqXAW+LXbl4P6DGPXD+IU06+DLixo",
    "oeT26aABN5vP5RgwQhVFXrXrU3Hy0QiHszAv5vpGrD5EBXOi3q648+QZvDbORp94xx1rhLfMhZBXXlhegV39zQ/tC9fWjrzXuvB5",
    "aFQUg/bGGhFzLqamisUwrEwHTMMvvhVgtIs00lvmxLpx3/Kl6boDH/yL6FmAevlPdiH3F3QjYYwUDdTiVYfsk+G+0d/un479dv/c",
    "b/dPjfVNgmLoYgkFE744ZVdfBBobzsQz4vH5ejgRgRlOHHz5pZcSEZHFrQ8Zj87xyXJxOpnoSw42598DkgJME4S19qdfudIFsspr",
    "bKcgEjSPxPTnH5Bn3DsGk0xC7TzIDqBWIGHFT1D+AQkD58QW37tr7ysv7dv5/N6XYEb7/p+3ak9Du/B3eDQR2yaGNzaXjKYaEXg7",
    "+lYfjrXjd+gr/N034tnVdKwUFtlmIzIPBLRehEbdHsSdg05GFrP+E1hPiNI7ECkoKlIwB+zLznIeTxLsyC8ubRkVrcaI20oZmmFS",
    "ENZXtQiqQiQSJWQK/Jwai0RcMHUkN8bGwG8Fp25NODX8SDSKklZWrTDXmbXKOWu0bpIEJjyel74XuH3UfZUMLaNjPZKwsqJhVIom",
    "ijoDc0B72p6ohTNQCGb9WfcNFcGXEdn1DN9KaAXNMRbxzLEgusXRxFi84JQm61MRnHBt95AVkdcda0YVPG0nyVfWc9Y4YB1sXPEi",
    "iIhonwQtAWTbMofAG+NWmvonN1MXURpl0Y++ad08i2yaEme07l7x7CMSn/cp4ZnNjGQ/TKKkZ+L2n1noCKNSxatFq8A/1WxWqtK6",
    "g+ajrMJcOhphQ0dr+fDapc9MxKU96d1q/Y3I6Fu1ffG3Yunf7n8CgkBzfmHs6XD86ciWPt5C1Li7cxAbniBs7rlDFONBPfHU6LKN",
    "GIzvi4KJPWAseawiUX+cDpta314mMzsewT5fyetyGv+8zXLn2pkvUJJffL99YgFTYM0vslWDrBDi5Aflt8X3Vz7/CrUrSoqFDVmU",
    "VR+9rdHWAKhp/IfogRp2VMydqJGv1aYdPJIPT5OBImLWYFPbw7t38cyMylprh06y7QZxghRSvJeKjEOoifHZCYjKrkFNa+iF2V3Z",
    "WjifrUU8XVu9cl3XdnhLgOAI0joa5wUM9FbZRYCChte7gwwZDkXv9WZFO0JQr4WVih7R21lbuMOmmEADhDWqT/OYAHkgX596ERUw",
    "WB/P+BEkvCELzsLh5sIlj/bp4gJNKa7EHqcu4E5X0KmD5iSMrdIpKENHuLvf3Gv18dT3pfNZUhEeqyCuiE2m6kBHBHaHiUCyKyBO",
    "3tw6TEoTmlBECZewg2xsfo7/SSvJVwqedRQ8df6HCFzDkxsrqaxHoETNry29C8pjShm7rNYCWjD7lXnLIhPwKdhM8HpAmbWs1uWr",
    "q/c/hHeDypZlrfz6buv97+DdkDJgWSsPPjTIokAfdHOC7oyG/MQ6FA1UFPFt/76X/rx2/l7724uEAJgtl94P7Gt//9HqlVMagMF9",
    "rXc/f/jrpYe/vNu+c/7Pz9PLbfvWlq61Dh9qf/hz68w7oTFivKRsENmNWvkITbGwtiUSsHvzElv16fwz9P115qYoK75UArkR9p02",
    "OII6g9BGZyjqztV1UkBWZ4R0AgxvFFGTt2dUiJJR3PK7dka9zJBtSVGvtQdLKhmUBcwwyJDQjCCitKU/h1fb8VDwq5u8uR/eXYbt",
    "LkqyBQie6feYGileSIoLRVM1OgBzEkWpJSQtvd9T3uLT9PAe9IidhGG2mSXBSiI6AeoMwh+oG2MLL8FKKVha/S8vtO7/1L56fG3+",
    "ItueVq8hinLLClx/gv9o4FKyax4MgQlBI5MPouxgP0McgtqD0MlYSkHsdwfL3gSC6CASfQBE59afn/dBG8TtpPWvX0EbkNDaN79e",
    "vXRidf7Qwwefrt78yfLgroQ0gKMGYAn+o410UEJ68fmd7Wvn2nfPEDZ8T+aQf5D1aZlkpR9ai+c0iNvckeKf2KCCOOSO9DolAT4K",
    "fwP2vY9QF+8ELiqMcmuC/8QGFKRhhCSKrX59BfCtH1AW9rDl2ebEiq41Fxc0sMkQ9YJ/8t+0HHLcqSQ1ayBMc+kD+vti+8xNOuC4",
    "BfgDciHyx89OE+akFOYM0ATEUuZ0Yn5iL9jWqTNkqTEWHoGf/x5a4bN1P1oOEaCEBrqfQbev/bz6zqLRb4D12fH2sQvoN3Dm59Zp",
    "1BTZcumBC4NOAoxtBjYN9ou58GA7WUYvNJduQHcZ82mD3mgu3oYlXLl1FoGnGDhi/iDDNzrdL+cDMwHA1N5of3qaTlbuiwuZFu48",
    "vPdR++rHKId/dAr1U2lL9kDnPvYbu2qwX8wJdw82k/XyS68SfJF7wJ1dDRTUQJt/0rN2A2Ia1KYCPQFArl76tP3+EopJX19Zu/aB",
    "MF6DsEDHFgh6gEHjLttKxq1Y0gNZYcVHwqArtwPAx9W7fPThLyfXjpxyF02DKTDBmNdBhb4GVrU/fdB69xM22SNc4lvQb7FY/Qx0",
    "kDu6lZZMAzokgAIt8FMBC9C1/RmRvQ9/Xr222L6Eu5gJCNODYdy98GfI2MWDQ2LwvPO5b2vzn6BYDbDO32ndP7V65fgKdvhsAMQk",
    "zSctld5VuRnOXuVthG6JO19unTgTAIKoJ3GMfg3EVon1MO0ffqkIcev2HaCiHlxEc/X5z1ZufuihMP1yrY153CpHTEQLCBb7vgIR",
    "kMcJN1ZuHH94H48QsLtDxgY1SNaQBlXi+uVf8XQJ1+UDyq5xf/X7I+0z5xBDr19evfbxwwe32je/9Oz8bUSxBky83Dqgd1RSV4Wl",
    "rXt3kXAtvKcdICFOtc5fXL3+oP35PWxjmNtI8r4aIHRNuIR2CNevnzBVoDzPBCM+4Cva/X75Ai/cVfxZm48BWsEho9tDyaQEibxl",
    "7cxx0IZW508//PmQ2qVIoD68B9jln1/a+gMGHRlKMmkJAS1qHfqqdcglz6ADrpCeqLamvv6Ilv38J6FB6/cMWSHX2hHc5YjuX59s",
    "Lh7zdG6rn4AOJQcELHK8o71+mUknUIyVX26RReMf0EuXJGsQEfsHxZ9+DeigZ7jtox/Q6p5fvfnNw7vH1058h3C//QjmNmRipOAg",
    "Aj2T7kIP4EIP4H4iqondZP6E3pgPeFXUIV0g7RwU9MNE0gFc7QGdeK5+ecoSsh0wE5jUQzgRBg3RoPbTvG4z1nsgyagaghVdvXa/",
    "/fXna2eAgqAPR/vU6daRu2JHIaH+mtpd9kDFaRjmP5rsM4ArT3CJZ7ROA7K/6+N4hPhywv38g0SKlDm5/Ti5g0H0/vTq99ddek/i",
    "istENHrPTMSQKPpxZhFo++6P6OC5+DOaxI4eAyUHiDvaIxTz1AD14wkL/9FWqR9nFGGBHHvqNFSno7pbJJYd0+UzHRQS4EH+E9uq",
    "gepnUCs3QA9ZFuRz+TBIYUx1aDa/8MDChdgm/gxrsAYErA8/ByLfPja/eukDPq7DRVg+DaSnPX8V5xAJfjCRT+rbUmoIOP4hv8xk",
    "tQ7/1Dr5Q/ubH1Z/us1kH9OWnv9MIKYmhTBpGzYVD1wSBNu6+xEyNT6URLfb2xxCsfL592SeuunKpKZg4yPyKVyZIaIghhajRDvc",
    "QUSf2kePw1bygNwaxOFSSRZQO0gKDA4dMgH0xUMr52+5+11jzbj84k9smwZ7QMzsx9/BNDYXAfZJNX7e60L20LrJvJF6ytt8TKjE",
    "u8sHnKr1/HS9XMSoHDzX5c0IYyc8wHBLzHz/eXN+QVi2Fhe9Ni20CFFSfMOIJc2zdr6gK7ZbE8kAnqqL69eQpiwSZIwEIQH+5+/a",
    "d47KfPwYVxEimW/Yehq9JJ9Bqivco6Vccf076+Evp5vzh9oXrqGTFHmfv1V6q2Q0TTT3HebjWGp+oZO+vXLjNnFlf+9OrPzwTqpY",
    "lH086wm7eKvUOnxu5cLn5Br8bfvCUQLwNaHXPAo7yKZOUnE63acat39duXmG6Uxz4UNm/njAtXBs7dLHBN2NC2l/+tXa/LfM3GFk",
    "IDkBn0IPh4vftt47hu4YDw6tXllQkxBS2LQ1QVLy/OnVI9+Ta8x7urhnecgpy34g7aBr0xGkqGvzX67881KIUSs5JBcDhEm5GIjp",
    "319H/fvafav95S1jJRSDfR6ktubiMhJDXACj1TCAWPnoujWYTPUPxP7jPyK4ZF//IPn7CSngXkvGB4tF9Esx3KuvqW6S08KiJLju",
    "VLMgQ+51ICHS9+PQjdUvf1mbv8jvgfytXUJvytbyZdB+Oy2EPrH9Hpn+4a+frl28b+188bVYqj857JtbFoDdcd3ianJuE3JuB9XU",
    "6kTban13aeXDb4zZBbwGOVrIROSS1vrpKxRUGU8X31/DU873aJYAORdgzN5eAMYeRZ0ZsLS/WFy5eo+cV4QPitaYX3kJy4HScp27",
    "CypjL7OG0oHP8mh51OvW/GXlTsrTGmKZINkvZ6lfw8Bbn6PEC+Sg/el7D+9+ZM4RQZbi11VyqTpsNCRFW7LOcjDCKfK7IX9dhLJy",
    "6leQz5VI3D5xhJxDbwPnfu3//aloiQYB+2CCj54kbie2Kn2Cgim3oMBL8ua/RIz4BKgr4tPiEbLNH/fMGkkpH52jMCujf0wkt6l9",
    "udVFnp9OtY6fswBnyDVZmxJFTYQF98iR1SvXSRu7BaJf+x8XSbkPaMzTqSGmLCwmA2VJJtoX8BjRat062jp0bfXSeUDg1tUPWx9c",
    "YuhKuJY4v1X226XtrdPvAGpiNyU4cvteB2Anytu+eH/lBxVip2b+Q6RvGCsTMLYx1zTNruJ4lhRso2Y/qrj0KCc7dY3s1LU4WqJr",
    "xrl5dkIcW78KxSKeA3KyXE9TJT5ajlqc0SiKZn54qx0dRzEurBTFM5kxPFdHu7I8IM9OoCMMHdHMiSnVgKb182jVkDp/9h+GaIcg",
    "6uA6ItdKnFqlfR61KruF8rm1LLtWy0+WnOy+ejmNA4U2uNq0PMRK88nKKLwYsxoWX8SWgxazqkGakbT4V0EQPwOr0M1q+8RhAqVL",
    "pmrxePzPo/CjQ0O8onJgOPfcQRchRmv1Mc4AqEbouoT6CtJb67nnLEW0sg7HXVGvQiH1etrZhwdtaSsbxkVWc83HXtl9dHm4uyiA",
    "Auj6kIjE6+Vde14XHj6qFp/aBdUKrNCISPcHL2a6uGLPUvIXdB6KUioZQkESAT1OGtxj3VVDxyZ7NoI+DHvzRXbUEjCJIMB/nv6N",
    "9IDc0Y0hpLnGQZFLUNZY1ODFwzmIagsnfAm09RLPUWM55EvPxIu5K2COmu1WGYnJ/9nz+mtx8rEI02ON5iSfmw2XdfKCt8xAlXAR",
    "RfHUYIKO33DqdwPFykPlKr6o8ZSXp+thoCrFmg4BWq052V3ZmlizPTDXo6CfbRuL6B4Qm3g7z5YyHj+AOcumTuBf4WQqEZGOinnE",
    "AuOoNuw6qrmn2JIA0P4fkSvFLfn9ByQGaG0KNFHkO1/K4CxqaBcTJFt3gFe1RIdGgTgAplEgeS0cGVNxspgvEm9NyuNE5uMaRbOe",
    "esp8EcchAzUVnQ0G8YSa8PiUXQvnBSOBuhF0VXH9+uIu4kSsHdt5YBpQ5DuEMmIoATOnOUQYyzSs+aHCVwKFfd+Bm22SNlskInv9",
    "QrlccIAo6Q2ajWFeUeU4EbBCiJd/yCJ1X5vw75zqSA9T/H/K0C+7gJMcOPQB78ihq9oky2/ktiUyJeAtPPOtX0/QOQFHFVyVeqcv",
    "EA015+tCk0fvnWv0RkQh6DM3ZxAnfcTI5OtIydNYCia/4lTrFLtVr1dDikLy3O3LYyhXuQDcFRcBQx6xiHNA/ha025jrBuzssaAZ",
    "NDxuAmYvqSFOLyjQbcEJIUwcQc+wfNwQFtZbdOW802VHUWXdlcG7X3glpO/cPuUHxHMdvIUS7kyQX5vYLWb8VxzwtjANjCrsobuR",
    "iFWfwjypiPMv4aUD4ZCI3eHUW/Bw7WsKNdOV6fPNxQ8swOH+SMiDxjPkCuM6eeiOG+wTiTptIqr50mm+T1SsMl2bCs9411dMXtDc",
    "87SxN5I+adIrKWDa+hO+/YdciXxBMZMdI9N+ZxZ9otHcZBYuwYzpTv1B4okCTP5r21UvPCI4dzL+aFKLR5AWsLR3+zTROvCryWsD",
    "i3SQin3StKhsvJXtw3zqSwyAsuzDMyN5Y4fakU6NP4rAZopqokXtHTtJu224YpwsK14Ql/BJdoAVplSHLwQwhema1EqYEYzn+icD",
    "1/0efQHYPexFbtaJDEmuO8fkCkzzjFdIMr1dljDztH4MhoQG0SzT3GwkEjSgTq6EQZvWJy7IveVnnEQLeRZ9FG7837bM5bMNymaD",
    "gZKXyfRtUraByLinraITILZqrWmMEBiYbxzKFbE8nZlyas8LacZSmK+q03YYRhSj/ru8ij+MuHQEWvWCA262HgsATqJ3y+rEAXwi",
    "xR1lpSQ/14DI5IDkQNqkplIau2AFRwxEG6fiH95pCdC6vUWkDi7baGjLI3ewIgjWE2zeiIjmtS9qTdx35kozsTbWWYxBRFts99B1",
    "o7pGcQJA6PRoewCRMkEJghQER9Kq7Z2olwHJpPkB8HQBaft/DasZ8a8f3tEBXWICGX9bSNnQIc8LGOLoWIRliTmLaqlu0S8P6e7A",
    "yoUurmbJy54C5skoYm3/L2GLqo/UA5cFrSukECkW0Qd9FieawpRklggmv6HyDnZPGrdemrIT4sQN41+Pet233YCEMKalfrMKfJW7",
    "ovtw4ycYjyjhhpu91ffMlr6ojIpipqIaqDp/C1dAqAPVpMJ3UwF5aUjyh1FKVafGU1GvziqqCC9RCSXWk8OLO6ljIAcyLJd4wgIK",
    "wK7UwOkrSTSBz2Exqbjcof+IibHGnt+9KwavQ2k56bie0DM8ReabuGJ7ZytOiFNlFPIZugq3Dz3pQa9CuKLduGgOMR5HpmRDibkN",
    "C+pmpqywpkBgADgOy1o9cv0hBi+caF3+tv2RyjJ5Cwk8phi611y4z6nf2sffb52+gpxy6aTw2ZQcYA2UhDM3Ka8GLT7F38vnE5iq",
    "EpnAl+qQjgPDgzgPz4WayeeskBtUfENk3UKl96RiK/oZSu8Z68SV7sfp9NE7HKjLIwpMqhdSvWP3/MCkfMFdnV/0RLVT7/75kzxk",
    "c1NE6dmWvMcSclnd2DbA1nh5v7u6iNasumM+q5AkDoTgYjO9rdAbKyNWUWSyrBR+m2+gU3T07XK+FA5ZfVaIkrYLjNqHym7f0xbG",
    "YJ45QrN61nq6z+C7CF9ydqBnA4lkgMqpZzrk46+zNGyfwpnUJIhA6P2PT6H1iY0uLp5oLl6jxb6P6RsffKgfKVnhLXNut2BHYpge",
    "zmtj3Fg6IQ7i5QX6WuALSZ2FfE1lntMtv/gmYqUVF2/4KZ9dKAgLyt+mneqsaY2vZcoVJKZCUlQ6M8Ycih/AZLZvmXNKGL/25hu7",
    "XiwXKyAMlephb51I4ymMNJR4xg3g7eLbAXP4HZ0fIFaWczlQfuBLYsQasVyM9SPl38LjIoKIsPO5LXPU58aWORpO46lCvpivb08m",
    "Ek8xUOgsPzRcwR16wRIA0Mu34wzO/ch9eWa7JT8JA4WhQni+4X4QFXdgxXq5bhf2UWpjFUYIrbrr3PDG57xog7zuPfpb35jeZaJC",
    "fSRR9YkaNF8hr47GctnbcSwad2Wx8S1z4l3BrtXxXcNSr3L5qng3LmXqHq3wpjHXG0NlRmJ1sPB6tK9RWPxSVBxKjKnxi9OMOGB7",
    "eNQ1iijcHzflS0AS7mrjKaU0bEfI45HoI9bmHj3lylzBuya0Y3sI5Ac2IDfc5saC7Jg8VngQww2Y+0DT+v+YaQ+ZsxsKnt3/9kns",
    "bKnn0c8JA0MjkDD1kRWByZNQrrdL/WPc26Mg9aSn4xnDnpGtqcByOdIxT0Pa/BIwxlusyTw8Goro6Pv0eKRnAzynNZPxrsjsRbaF",
    "+RO+qFf19TYnvQV57PU3rPaJIxQHy3IRC2HoImalrNb5z9A7lMREPcGkiY6l8vO8JR2gYGVhKd8AXno29JOp5NNP9YKrPsWve9Ux",
    "n+2oOqkOv5HqI4LqY6Gfcjiu1W00T7Q6PxYJwnCG6trwNmQu7IRQ0phniFmCUgTlcvJbuKbydVd76gkdZaKr7U8HYWaApRGb0G2T",
    "ulGy4WKrJ6RZxCqpTFqEgCptEcaJLbyX1tNdcfIqmDpLuYVx+qb2uUVrgMuB1HfVVWh4BnKYM0Yztqq+KUEozzJQ3nrWctcAf4M4",
    "MqBPqR+vsTxHvOajWAHK01SInUuGV9261022CiJhcsz69DMWCFkormblqacs7zuFTjQHceA9ulXWksG++kKJtaUKHU935KFYxzMx",
    "HuZ+0KS3y7NGn3QLVNcVW0e6yp6iHM5QACOCZiKNPnnmR/M3HsVLv5z6VBnkrNDu1/fsDbFHTNry+GnMWerIZE4cg1kN3dKkS4rx",
    "rINJuqnFDiKdKK5Jde473R7a8cysy5FZsLypCeahDQybqlHiNaVipC2tcSBp3L53QsSABa51O33VUif8bsQgCmmsBZ5j4EL4ad7v",
    "Rx9tjxht4mERlI+6i6oOWYSlUNN/Q8yG3BB5EXA/oyHHTFxG3XfaiUb7k9z+ox/ddKA3nv3y5vp4I3FDxwwjn+JtodkvvtPz4QRy",
    "AHGksfi+q9Sj3fM88ICVdy6tXjmjWcUwYEAkViSOQCdHC14xpWe5cXz9EyRyJvKcAz2x3X9qFHTShJacbsclwmbICAHP47t2gvbn",
    "LdYYd1Gzu03Ec150S81s69RZjJsUURde0x1lkjxGJscTMDf6YEn7JDnyFtX7lbMjjlvPaLxpPDhLbkdgfDvClrl6mUEH32nR3Qw3",
    "7ts80jOgivmJePPB38qFNhSylBPMTEQzX1ffKmGWtNBbuHHhezHsVcJgG2b2uyE15HCtzqAobhEzVISi5hnUWFQr7TndicrczaqS",
    "133N+xLQzgDoOwjBKK2gxDSqBfNcRLVhvPa2oo63cJS+BBuUDQiTb3ACcvPYy4SjnbhRnOM/2h+/61Zxv6paY56D5klYWJLgeTEk",
    "CQ6P7o9aqIocGCMPy/3mxkVsECdXo/uhBG5cegcVhEdReFSkgmIA9GhQBdG0Eqy829ypVoWo6duSN1qnTrY/vigR+zrlnEaXMA5D",
    "M02g59Kw92VjLJwDsQthRjHPfgthLYT2uWZNvaryRAngsOvFWbGr7cEuW136pT1/1dO0J6M06pPeHS1uKoCRfCni1TAR7A3AOSbP",
    "oh/zJ5lChLw9vse3I8iR3+5yb45+SA2zizbXet5GuzimrfUSQyhhkgL9TO0xZvQaiFsqjRR3npLSd7uTReTBesz5T/fsff2Nl/b9",
    "+0uYBRV3FuDMC5gSNq5Sws6kQlqyQ7xfT15zEtZP9HKgzuA9qHTkX6Q8aUIy0zLxRq3paoGc4kXmeEwDr1ww0laKxVs+3FCSMYqS",
    "AjrJlZrtvFDO2IU99XLVniTpZlfdKYbVmMgBNDTXCEXI6dg46ZCKigDMN4+62V/tGUcfpuiS0VzN21zUK+3IOYwEnbNInFUb6hRi",
    "7uJi6/hHdLRxmw6d8JSVTmGsx4yBg3ELExMceryXsKA6LEcNmGBiywh9tit5lUiSUWfXay+8/h+If2SpCo2o1Lx7/kRYadem1Evk",
    "/tIBr6hc8mfowgB+Nv8DmRI/Qg1Pon++SEUmbhdNb5JJ5tKuSV9G65jvAEHoBl9lFUA6QUDS1uhYlB/3UJ5B7qEQ9+krorhjF7kk",
    "uqW8XjKAa6nXMUpV5HtRKbNXPryWpnteKKFP69C11geXPKm+rT5LpKYjoYxSpd5qvwu4towJox9nDJQQa8qF13PSc4PkJU1W9Yi8",
    "SlSFSiOb5AUgNx7t3g/Kub+s3fxxC/si8lZjom6S6A1HBS78crn6It3SEYbyHveEAudd806AkBNoDmrYe9LTRHWZjJJ/sgbHt3RE",
    "CF68Vq7Ww2EbNCNOn2ZrsUOYMDU8ob/Qj5IKmsPtc/QLs5KC7iAPDRtyFfgaKuovrWqYmvIOWLuWRS1gvvYqu5gZtZw4KBMg+6zj",
    "hSaLxsk8JI7I8rX8RMHhJmsKqrQ+8ms5pRl27I7rN3yQz5zoFInRAjAduL/ADiQMc9yXKH7LnGhHnM7D1KPm0yUlOmWUJ6Rb+kSI",
    "vOLqgQWR4v3iD+2j8+GV83dQTMHkHz9H0NrNx93vt967zxkd5eZyqjNO9oVZurURxX3VbdzhssfEUKbKtXpwj8fcKcaSiL3xcjU/",
    "mS+paabib5TLdTUbYbNpoa1ozUdGPEls0VnHTeyqOD9yccZjTpkfEbTb5+ij+kDhXqE+KCbyTBAWO3g7QQfIlHkfMUx9AwnB+I32",
    "ik4N65WiZhXVsF5V5pYUCO52R+WZlN5THdHEuBoS8OIbkiX43gbqBZ4qAruWvgQU4+/1mqF6OD+bPAf9FegPLZtYD9ePSa6215fJ",
    "O/cVvhdoDmgBaDcgYpXKsRpILDDLDdMTgT1NAD+8viO6L0KQzMSJ6huPWyYeilvtU6dWPrxHt4gKXvfHSL1bkFNxKFQ5M13Eg3YQ",
    "Hl8qOPiILIvt3G529nDdBrUeY2XY6YzPIoWZXOccDmoWCihjnYCLMHyxwfsxySWGWQr+6wjeS00p2yRuHtf+AIRxhv0J8d6PCLYM",
    "eCyVGSy7nzcXXTII29YpxOnxNZv8nme4oNqW++N0mlz7S74+FQ6hvwFVsbPZl2agP+jN6JSABu8XRxWUmTOiAYHCsJeehy7nJ6bR",
    "vh0VHaQrnAQBmgmKQM3g0NVxQ65g1zFEg9iodOlFYpBhKxkPF7tWqTilbDgTLwEhQdc6aCTjmmQyBvd0iEFqWe/tyRdxNjz5rAX5",
    "NW7YGMUibk7pUB1PrDsXlMnSS3wgpI9zCgfKDeLXcAnTOicBWmbKTJwfsXbs2AG13f5zq2Go8qQ1xFcrmAOCqcs61b32pAxHek0N",
    "zI3jMTJ56+W07Ld0bw8iSBwzYbOBQ6yAePWsEorMS3607gIK4Q3ITINwntPWOEy5tWVOwAd84CfECrUYM3G2ljTG1SVi44E2KLRs",
    "aP0nFU9lZQ6hdwubfWbiaKqH1gI6FMJPFFPCpSTJw9/SaMN8gPPE4kVDMnNsc/70q3078cqCeTacvCfouX4XkLBkLQfZuY5irop7",
    "X9JNmRTD515cIeLw8c5TETWirSLJmyxoayEl0kitIv0bcrE5FYBhRtRqYAi6LCmumNAtbvqlADasFqKFagJPWKC6W4Tvyd2up7sP",
    "8cyFyLOSRh5yy+dhgGQoyGBAIloBOPc+PhWcGVSbEpwKQa4L3hmeZgoQtabs2k6Vu/+JJ9yhq4Tw3OeIYUPARqOixRLffyda5a66",
    "SKRnYsZJUheKCLBa4gfWRsVNIdpnoQlINQBaw1lTb9SNeRGai7jwHBzfMkdTiX5bCJqt9YpQl6xnUVUQrIINumEelpzKAhtYeWA6",
    "uFipASi5+uOhtYV3FXQ12ykhHGhNYT/XaaxWJhOstzG+m8PfSNLfiEtPtNvHHqlRMmNe2zJHw1yv7XWnHHun0ArIHyVskMwYa4vt",
    "M86ojW52jAJUUB6yUEnEXNxoWGGHpQNFbHjCxQ/9jcIPz6UVCFGSptUr11Xe+4Vb9Gv+Ct0ni5rz12wcVmRL5dwnayvmMiPP6hN8",
    "Z4ShH6NyiCJjzU+DdFdQ1/8hq0I2RL4OdSCg4syi1uS0Xc0KTwkKbeIXz1pJeEPPzzxjOrZWONF7XYKpmXFh6BA6XapN5XP1cAUo",
    "jkb0Korg8TIDonCYmDzpoS5XaGUF8F1Zz1ST56fOZmlEb1YLyrfMCGXoqDVBz3gQ7jXm0J+OqtBzpibkiuKiW9Tcc4i2+BQUOdEw",
    "jibHNSOBV2R4ESZ9Y3wmyxF6fj6lpZqYsvO4NbxYpMsZBYkwNJ2EKbSsQn4C3J8EdaSmXTjjoadsVjG8oOtOpdazzUaC0N2chcut",
    "QLoOpqu4FkCmdRNkjGx+xhAx5Fe8+bZMd6JOVsvTFTyysqt5O0ZUJ8T3trZPnjXSl8BQXGsbwObrvkN6sApeFg6V1Zds1Z6ctCeo",
    "IWKTWuir6FJN2JeeVUMFNg3zg3YgK20Ey3IXK9h/+KgEaxW46JkWzc1Oym48Kow+2jInTmvdEKRxt3y5lAGlYn/aIqvhnIVQy5Xd",
    "1XLFniSDB8YykPFAHpZ720aMK006bPVS2BS16OOIFkMTlTMgvCUamwypFQ+GMgVHzbKYtdFQBrZJiPLAxImb0AykcPLytRgxXJ49",
    "sc/ZNMxxshK1sTC/57JjMghDHRNzL/VVROUJGZ09kYfNehBv80XkASZlx/K4KGqom9wlk1hF9E58R9ZmiIGajB2iY7nrnJQCrwb/",
    "6dra+cMWWp45QewS3YZ4ldPHEYaICQ1AeZyoGKyehstBwjcTXPeyYKIYckL+NX/XwvOaqHitzJ5h4/cOXgDkeFSDZjVC+hSWYkU1",
    "lop4wFKpqPKQkXrTBg61SYeLqCmY6jeGpoJJG9HOQjjxpEj3WcyVy/V1prE0XaR2kJySlmPT56mqk0tbZIpieRSK7psA6WM/UiK6",
    "iqlURtcip0rVDUwZj1hp7xstgRWLPcEqFX4iRRXLlTkbV4jkdrE4Ls71rClx2L8LD2++E71oCNUMJNrmwjJyOflFKXOd524c+RjD",
    "AqGSdEaqTgsjBizpt2YSvNJc+H7t4uG07/Ytee8WX7fF94+QbCbURz7udo9nuIR2IlGu1v/dmfXzYp/mvlFM/T0qYrDi101hlP7M",
    "wlqgJZ3btm0b2oDovURMeM0PWrawtAVCRb6Ur89GFX0bM69dm5VGB3GW4s7WfhuZt5hLGxBu/4T2YiJiSq2u1+5+23XaRSGUjGL2",
    "aH6M+M3+CXhSqiS/f5bfwghiSehzUht8IkjSojN147ycLl6FLmwB7o6PIW3iaxmQGApkaMSX9D1OoVJ7nAKsUbn6fKEQDqE0A/wD",
    "RvSSnZniM5Q5UXk0E0dGAbIklkKn+owJgavH0EsPYHClveXKiNCTpO9zZppS7ehGTRsGNiONmoh8wV9k+zBH3QvoB1ku4vPpESob",
    "oLozYxWeqj0mhgpM2sWA8EQ44s5srT5bcOKT1Xx2r1OsIEN3D63GQcB27Hp4y5x5nhWOCJRpUM48TDODmcNz1Uhk3IUspHPltI8h",
    "4l4wlIkIxdIdhjybrzuU7k2UN8YqZPOIPH6kAw9B7fiYUbz0GBuQi6rzxwkttDxO51AOOrUCbw7bRqqstLblDIEZKu1nNypoTZzc",
    "vV4qzFLeCu3ozjh1QGrsZITzlm6QKyjhBp/TclxecRlfEx8xmCPHTXshxvC1kWEHi+LlAWjBV5AixncfYwPCSHwIy8OzVlpMQDA/",
    "xI+ujBPi69flpc8nZDpeFVR8jtpQxW41Fx6EvJzM6mDLnC6xxEE4I33LItr0+EQMufP1udFrw5j4J2KnqyxihwBcxQAGe6Y+y70X",
    "1wDQrd6egNyQFLojkY3TtN5oF9L6QOIHbCshCRuln5Bkzb1tl8yXAZ0Kj8dRHhsVUvf2zVvmVO3G5rFxoZw4BTqXoE9huvFWipd7",
    "potFuzobFvs40HTvLeMexSpyRTuZHGVMtbdU3qlSvArqRq4nZsY0ndm7YqhK+2rEym7BlCjUn1DER8C6iKOZqXyF5D+9FwqbQhbZ",
    "7YSYjrjSvnBdpc5HFVfsSn9tA5M7NNuIGlbcj1uHvjLBuvOkXOWZIJnZOZlBdSC7o6F6OVsmMkXWA+10XlJkPecm2urotJZg0k7S",
    "DScR3XxOVmSqIFs8iC0e1BVOfZmEnFCmrCDd6yX99YRJMqgefvJXwANiGHEv7IiNmTqI9RGqKzrR5CACuZp2RFtvtmibi40lNR2t",
    "C6riBAYg57jyxtDM0g26lv6r1uFD4ybGljGjYA+tKaVIa01jED4FCNkE34NN2fUpW6TKBCkd2zWtQnAQsy7rR+b80CKv22PapEeP",
    "08Whl0wAAqXN/bnO7iT3+9avh3zABHLR3tFpY9HBe3jx9FkIzkKCkL5I9LkG8g4oDkXEw6Ip5RWl5cWsYKX5etW0XkzPR0WvRP5n",
    "PDcyq48Fn71OmN6wJQ81NnZDHUp32goUCeqOm6hGsZMV0GsDFHZGgB+KqiWgX5t0s16NeJtu1ysGyMeyjjLQCaeZA/l6ZgodtKiW",
    "TC8NUnCcLwcNWoUOIlKRz2BDq0fwamgl7nRDKBgN9N+1ok7ls1mnFJLmMmDyXFcTP7nxR548duWM9TKNHnaNDqw9TKNWDCejdega",
    "XuRqyn7/PQNgeWP9EejlAli7bxEn7OykQySxJL1DQtbfnWqZqW/JRwqEBDpVLZORQHfUnPEfvtAJGvp0hcSGw7e78wUULNHCI3Iy",
    "rXNooy75vEGOppfx7kzKBITdpXbdjEYr53+Ab+7nkMrzG9AFmgVKEVYvT06CSMYnP1ECGlHl2SXtL1W7AnUYzdGjGspoh9OUutR/",
    "GTISGfzlGzAwNqiD9paXAbf+6tiwPxqtn39Q55cYy8LHl1onAoiVjy4alKpcUQqeyBhcZJO8wLi0RiX8TnguNemACAYKEHZbOuly",
    "cReT0dem/B9xy4kxCuOLO8MMD1QGrCoKsXe4VugJeiO+koO6/lHW1JmD1D2oIjvT4cdd+JNTpuuawOiYUCLUWTnCjIhSO+F5gi1K",
    "6kzbsDM99niVoYl4sC86JQpzNdvf7h9NW6vXv6F7i86RQy2m5rL6xPXuqbX5b9fO0AX0fO97n4VCz/FzpDkebi7+gLtu4UO++ofM",
    "rEsUJ3TpD/AC/Muu13a+/pd9O5//6x5YteSA6wq9E2TYF/kYlARcrxuHx64yQvZh6XB/i93ZQQXhI3i2b3P8VOvbr9o3fxC3tM0v",
    "yBzgNzAVh7xNnqzFAhhGNLrJvwFS+9yimXSvXKxgTHn2+XpYJiTh3UGxFnXtCFVzR3sbvdHc4tqXLH2Ji2ThImOY5oWYjcvc4cJR",
    "AdOH025hkYleuqGvXudELZhVO2R9bRpJCMBWKcYjY1ELQxE6lFOpyWWeDM6eypZwsXjwG7V/ygn+RJiAGZ/xDRWIRHie3o67SSQ9",
    "vgA2uwJ4nHUxumWvYxcNcsTk0LxpoROlLKpcF0yfMCgEnQNFto1KPq5nBooYSpd+Rq2HVngtn/hC9UkkTDcNo+qKdd6iiLpa6Ajd",
    "D3dL2K3mFww0Xnwfb9qh4F+ugnEmZii1SrEBYPUsG4j8Iu/9Cd2LjmNUAAjf5sTJOIKvE/ClQArrGzoGiq/vLKOmWAFOrGk/Voih",
    "dHkK+uzlpgYDkBCiOKyHPVbkXQQY86Ll86TDbB2scT6xn88n9lvPys6rQ4r9RmYRf1YRWZ5PQfdHsYIns4ieWIRj24xu10S3kYPr",
    "SbDNKwXsetogQC7eepIxEZZRQIc+/obgcUQYNDfzR+xJB9gNedjfkAEkgC+78EQdt1o2yuITibSUMb6KqUvCYf2ci1Nv4RBisnQf",
    "yBB/VUEYPOE7hRlHZMvuYnHzHKTph2he/RfdGjDNMz4bdEY3+fmxOejwg4HEhQOVx+CF8H6PtYvkTZ8wqqi4ugOkTNcMdd2rWb4h",
    "5/lqFUBo5YgAFsKJCAfN7RInJFSOAtfCcxZvkbTB20GcZJVldMzrf5+nG47QKqjxuCcCaEEwIyO+sc6Gt+sui3rCrgcDws0u0TLs",
    "XqpUFxMY0V37gfYkkDQhZdBnB094oQ+j+8eeeWbEnSH4zXkT82JLNDzeXF3nefrxTTOjmmm+xtMjd/NgF925ynaeKn2j4i1ZhFXu",
    "puxtrqbVVE2vO1O92HKNvI+816SlLG1azFhTRvFBfag62Wmg1eHadDFq5VnBni6iimxaV2lPguZJp84YNNhBDhCuXnjygfOSTOBq",
    "JoSOXqBrEHo0N3MV9r9ez2IsnJjKeJGdQkB+3IvJNdP0qAarziJtGOgE9Q8Xw0U7I6F1DP6zdJUAZIsXX9z9KmUZcHMJkGcGBsfy",
    "z2UQIajqJgqndWvDamKq208xMlaYWaVnv/Wv5fetwBQVAZ4rmKDAjRSgmyJPsAc0qgJHT4KAb6UsofcIeX6R4lgpsQp6XfGZ4NX2",
    "nX/g+/lF0glQRWh9cZZym32uFb7aWj7cvo2ZTvirCBNfuIKdgHV+0hIqA14/SVn55hf894XCWFaufyDyC4DIdvSITOpNsQwSTuvb",
    "Y82FU2KQWtBgLkdRoIiWLkva6XEr8fM9l8bvNmMPAuMOAjmKySaer5MnqV90e87yM3BFV9el2F5RBem/64nLzb9MPhHUBSgd3o1k",
    "Zre1Q3T7OXhOC7o0wrHcK/9cpESIQpOz1JvF46tXjq/+er+JS3QLPskoht3K6+RlALwTt308BWATI1bwf+ilJMz/mLMxLZESl//d",
    "Jv7/c7oW+gGm78D3x9RwXkBOthMoym5BR6XB4gV00VYdCe+mnsCIqUuRoD55NppIJe12TZ1qvL/64zF5Fek7nHdJNKPu7klExXO+",
    "FE7GB4HFvKz1Ef5+QZiIxKK89OeX3tj315deeeX1v8CAiEQl4hhnlYjjDccHR4yCb7y00y3VT6W2cikX2YU71ctAGU3DUyeJp1AO",
    "kHd05hO1pvL+InoJF8vIZ7jW5XZRYq2uFKjLMSbn0GK+A/lqb7tXYCZhwE7AjEKZn3bAmDrwa0rW5rmBC/0LAtzVLL7zByjc2qXP",
    "Qlp7PA1azjbxQiVUG5VZOsUHmelMMXRToUenIi45JhL38OEFOT1w8h4jEsH19Ga3CMWuFbNGVh1MiJBVe49IyRH4uQ1wb9xhxMHh",
    "p+6ooc80JUDYrjlu5GXWuKg1nTaptkrdqKpadKWhMbSDamgH49OicSrjb/tAuUopE3Sfe9pXPmH6YBzFaW82hIn4NOxrOz4dGU0I",
    "mw6GuBz9DpnoF0srH51IW2v33kGdWG7ng3jP9z8v0yuxdw8CWxOO5wsn4KG5OE/Jgr5evfatyA6ER6YubWr/uLz63T3FS5n9ytZb",
    "h66tLV3TyPYVLs7ckY+CoXXJ+G+QYfMG5rvlq/rwzoXb0EPix2eZGcvsojxrf2dNB2d/h0uSwsr1FI8YyH1WL8HUzSw0S6cOkyHD",
    "1YoTUkatmbTpQ0qW9aiFSrSGSVGF5RTDHuUljXIfG+y648thMWdVKVRvlm7tmqRAslE7jnXGYD0DP0/wZ2K34QnMTs4rX3OCrf1M",
    "ed2bkIXxFuatfwBgY46Y1BA8vAIPeBndG2TMjVp78V/4/QKVdEnqQZnS7RW80g7Iffgv0IFX4M8bMCuz8ute3NEoYiv+MxMFXjdI",
    "GxL/gYp/gs974c8LGsUmt8GQyO9w4MCB+IH+eLk62ZdKJBJ9tZlJLQySnI600HKOaosInycu0jGc/LU94RLWwKDyDYWUO/5gbeHF",
    "RLFS6iYlx3N2hL/U9YfOiB4kCcOCAk4hHMIB0rFP3jnwAibDGU+ABrZl7i8YhPAnDDwQx5T54qQ/FKbLWYDc1tf82zdk+KxO2JSu",
    "NzybADSdTYBaMZvEp+QEBX8ySZuZlDHk2OlKuTA7aTokQknYEECnMe/P+JY5kEQijeiWuVmEG8HBHAwn5Zuk/82EeOPWgjfjyvsN",
    "+oiijbGhib573iXxDhncLjEMVuok8t05vnLjttWcv4AkktSZT2QjvhZcKuP+0hpzP7tNz2LT0I4CTk0RYfM3JSGTsGZCo1cMstph",
    "NEz1JWRq5+GdYzA6U+iZQfQehclKIMikOqHwrCsKLcbBs30wj/FYB5Np62B4Brp0MCWfZuHdXvgHXuCufsHlkB6guA1Ml4Q8OXoe",
    "VJAkhGeIDFGFGAhfU+Uq4ngxn80W2PEB8ArpD7CTxpPjkaD8CJ6B0hzCaHvvEpK1IerTLHQOutTv7xGA6dSd9RoqTBS4nTAS078Q",
    "DQX6mFKz0H0CROwbKqNSe2aN2T0nVJovhoNssFNJZj1hJOW0JKJvHXoExLRql2ow/UXY89UyCtXh2LYEwIG97IHSiIyzy6ufHEW8",
    "MnoVV9FlYEq2FzRz0oyjqbuZWsxxolwufKZgqaocVPdWibMkWPQGg69/hO7xvMI7zVJWjSsxlhY50njSMjU1Id54aiGDlhXc3JHw",
    "gWW+56zxt0p0zAua3jfNxQ/WFg6BoJW2/g17RGXieRGFpukX7icjLKrB188oJ01jBjL5qgjQszK03dwhwb7LEJJTf+EXCB5D7h4O",
    "RhgvDFjgbWKvMBg8NsFVrsZFNgkQWXjexdkKINhAJIBQTHoVDvgWJNtoJ/mabIOKgBbLapwbuocCGs8DTfmVsm1cepsk3zWC5IaS",
    "gqwHxSJmzZ0shAbWxIwsr7q10d4R2YCJBq3FO6nE+vZ/2H3lwLLeklrnKS6FMoBtmcvG6T7PUn2KMiElG33iHV+Yx04tMsJ5miSa",
    "cMkVCaYAL7Le+DpLOSlBMURMzUmJEo/8a/4DPXBH5I0TsRs7vKoYBdb5t4JvC8ioxbfo6h8FHSmIOPIxw4PrHPnQ2UGrFnfPftz0",
    "KhiYK97L+NxbyrEDbUZnjjcXTo1rAZ/eGbKFB58BJ9KxuAhYrIk4IG/BRjQoVgExdsKumsGQ3kJAuIHjWcEQ8DSDonNnadgH8tn6",
    "VBoIOu8GoIFi+0QU80PCEeB0Tn3HOvF6+WU0XoBYE5ElCakQJqAb8IUDdrXEwcGe72gvl9/JEbi3aUDbDSBA92mAjlb3izkmSzvZ",
    "NgDL90sczxtB5KKe64XHeVG0e5l5yqac/OQU5qjDkopQAG+HvdEnaQhOXyqFhtJUo3Jw3B8SrpzM5AYX5AG7B+Ky8H7BFB7Ixbgx",
    "3AOwB3FjhXlM8qiGg3kb4+4VicaaKe/suDp9iER6m+op0LLkJE6vM4cyoLQgmCbqiVC2H4X9Z/AE6qmnvPRsf4SpEuZ4Iwd98gk/",
    "sD9kRid3nDUFJiJjYLvP2XSHKcMJI97lkmuHAwNMk6c/zQ+p9aHVKwsgerQeXAgRzwy1v7/WfudUiPT80NrFw6vXH4hMOq6PXEf3",
    "/4CQMNh0TsGvI3ryuGIS2+8XzG2hQrw6FNbxxIxlwttkhef7reN8ArR25BQdFYmbyEECTzTnF0DAWr10gpIz34aiFOl0q3X0u9bp",
    "ZZBmB+j0BI9g0FDFKZ/aH33DZzlQZPXacnN+EQDQRQV6AL64oLW58Cmezdy9G0SST2rJrbWR1DFvgEkVHbvoDX+rU0ycwn1mHVoR",
    "UShoAjFaQX30UXUtVkAv551L/Uomqxs4I7yje8t8sCAiHSIdxxLsgih8lIs2MQkhXBezkjhhyvQL9IIPcxrNpXvJ9tmvku0L/xiP",
    "dG7s4b1jhh4j0mF1aEzCVk3tFE21HyyRbI1GzNblT+B5PBKJmBGLdQqEY3CkZegO9J02Fm/2DZlgdFWh04brtXovW7D7aW2HQ1rY",
    "Fevrkt4jV3kbSOvQsllM2oUpM7c0Qd1+eOc4XZFxTL8O1h0Szawb+qZbMenTelGUvfT/hC+8UpvQ6YIBegY5AYHmnlFMp+Blhbxn",
    "/wdlS8CMmaDLoeWGcyWM/+vsKUskzhrlD2ON8eA4WlKfNLmwU2RH0anbbIboUXnF3bGuwgqFWDEG7jjuY3h046crU2t+CTVp31YO",
    "HEJoxSsLxWNUOFLYJPPRBxb+UOLA1+TI9IwugmB8iuUCTUgQCVkpIXT/3xk0xwOLd4ydU9nD1XYKiqPToPQW5KWD7RA6JmAKDaC3",
    "0LEudNsDlhXUx+//vlXLTauiW3CQJ25jZN7y4T/gggaPqUBECvizlGsJErDImP9ozfVr9gX6u58iKkThCZGuvOi4V/JpEV0ytX0k",
    "4nlB4SnrZCp3wylepLB1b4CKBkAGodj5AkbLBAehhP0tuvq2bmwr5ms1DmEdfcLnIO1eoPNE3p9cJeS9BUdlnnihXC44dknq60Bs",
    "Qr5sB5LC9hTDpYghDFrxZpGtyw3T6rQgHSK15vzrhBBGvCEojah+LVh3Kt2B0isLR2dm4Co0mm+1joZoHZmaKhbN16Afnjr78MGl",
    "8fXYCK+zNGiLnw12QhnvHkvOFlbKpKBMMjJrAYaNqtUM4to6WdCjcoNSIYzJBMUUHwRrPOm8jDcJmQH8wMy67z/pGdeJIqHcJTMy",
    "cGIvdB879O3aPN470zr0VevY+fY/8AasStUBtKebXaEtTGfPAPTstOTT/TLdf8S5f/DEGKvpNInMWtne8gvRXUpohiM5IkreI9Vy",
    "AbNU/W06D8w4ikZ0zNLAsorfrgP1Q5p5ioVYLAL10lyZ064SYJzGhrigyW2kQ2wqfOZ1fdqNS1VdZBmCfbrcSAnPtbmL5Hmn6U8P",
    "78yvXrlK3gDitjomO6vzhygR51duYDfJmyDdqJtNMQR84fDawp32sc9WF7/AOzF+/B6UQO+N5K9XyHLs8gR58ciYCkALziD1hAaA",
    "ab+4kdDI+Oe94At4gF6PnW38JWnRzQYMFmWzTd1kThMioDj0th0yTNZkatQG6gvQ1gfqofRPuLWDIseDrkqDMWqVtCFqxXShkk0k",
    "7AmrshSj2ahUmeZzB0H1xWVofHEm7b9nrJBMUwEfROgkb6m4lltZOjR6vrB5R4VAiw0X3LY4AzHb3qOuoTObJr8ACVbdd0raZYHL",
    "z3kgCVcTU0v0R4WGxCngwh15haB7L5+r0eiIoy7DDIQ344ky3dBldYQAM4JIzMj4U3lHJl/u3H3U8groxzNsDek2Flvb8yWAHBUi",
    "Rlw0R8zJt3tG290Fop+iR2ZqODopcfESb+gjyIhWsNHtgJncCWXcGvCeb3jyac3ii1vUwWvzgtRrfB8r1ibdQHkgNdW6rNngQFq6",
    "PpAzjKmcxtqNgjwSSfx996Tfap/5ZvXKKTRKLJ8OuAbPW3zl1iVk2vMn5b17J1avLCh7hJkx6gZdUHOO/ccwPkzdP0AciY6SJbF3",
    "KaB7fY4hDONZZseYjm0UybFPejZKmZMuHohX7OwePOwL4zF6ImR6EdIR6fauW+S1GbzpwG920jMnimxbWXHlVKYj4meoYMTsRIkv",
    "ueiZ6L02g9cIhCjdfMaZKheyGOkQevjr8bTV/sel9oXP97z559V7xx6SfuAzRpuJIE+fdA/vhUA0I2bEly9zxlu0aO8XPXf1hI4a",
    "wkS9FAPkygsLKKGcmc+Yw+ID5CaQu2MCU1CJprD1NN/VoehWhm7rExk9oF/RjXYr6tdCUKpVQfJ0+yJea0dpw97haFG081ZmjFHU",
    "psoHds+oy43m4LtHZSTRgTBCpNJFlwS8Qm/xKDt8wqq0jp7EeyNwVFy0sW/LnK9iA/ZsIonX32JgNmEk7DfySPC8Risj4SrK0d+c",
    "YtK9dvEwCnduDrQTnDJU5HcbkXd3j7qTO6YynYloGt+lKwqLeSKUrwH9krn1cIUCqtL8Q1WO+QxH9KBPUvR9M4CBUUBHiFp6pjlE",
    "wboU0O8jZDzDqDaQThF4yS6Mn5pTOdJE/i3Pnbu5acp8Ob7+Yo3rF6t2kl6ZGuDlMZRYpvPwxukWYSzF9wjfpsDnw/rFpnh3qr/b",
    "NPfZfA1PX7IKsemtZwJ5kz68c/Nf81dCI3rwrecW2Bl1xxPG0rISbCaAFVeSa4n2+QVJAjl58ZY8xNX1ABZg0ePTJ7jP6FelKmYi",
    "XVo6Cly6uBQIQLJTeWFyPJ/VCgZQBXetcdoAcTqhZEi7v7Vs1+rhcS9u4qLOuDdPY1z5BbmgqLRpVz/LGGRoSb+Yt0PbfQOJ/j54",
    "B43itbJFp1YDThvRjoOe87EH2fxxxe89lgFTZmj98nMLHeBvdBceKNfGIZQcUJI8J67M1TqStsY7dOSE//5uqLtlThuRu80aoLCX",
    "7EJBx1cv8lPm+W7YH/Jcryum3yfMuGyrm7+DcIjQkM0wDj1OfvWE+4udpbUXEQ9lY6722/3jVieaGXINUZgORmWjF5FtQqETAeXi",
    "Wj+STvmD2Bx6kJvvq7JauJozyDxVh/LhMEioIwTo3o8Y0LmShqfdTL1y7t7aie9UgIW4whx4Od0uyEYgpyAtQAYVjxqDDQtZblQb",
    "Da2uvAa9d3YpxioNbfQjzGq6EaiLpiC9CyLctfQiXSoQzuG1L4+jPzk0sMPfmqEV7Ucf3lv7FK05JCng9ZFrS9daH2B4Jt9rjuY5",
    "tCd+3Vw6h6moSBuguya/5xsr6RaXq8ZFp2R/Lh+A1ULV5RV22tihLpwP2EeY+zhlmHXJthYOec5cMduPvFBGJj2/4V6IhcbFr7R7",
    "wPEid23mIj7wPcfYMiDK7u4eswoYjG36skSJj6iCLppHH2EKAi8hC0U9JIub1CmReS2GnE95zoCX2AlrgeitZ1xq6aJSLRUFxqJu",
    "fBILWzdaH51au3RCshMM4CWz41Jz8Z7oNEhm4n7TK0yjmerahXyWtp0i6etyWnnbd55iV0ChlmFiHSUrKDMCW8Mj90lW0dCluCc6",
    "UImIWylfkEu+jripI0TE24ghmnigBy44hdAGmGtUS7qlU29JrnJgU4wO68KWMBRwAcS9wb4hfQwLBTL5CZYhV1WZAh+BILtoqZnL",
    "9qEOLdIx+aZT1tCMTZ7ynklRN0y4lpa0aYzR7qAgk1JakgPBCf/zP7VkidIWhKExxiXrGPzMFJeopueY5gZevn7qZPvji+JePhpD",
    "pVKY3VsWKXWivDlr7n4RFxiImUQJiArIFyNmMd2UpIpqL73FpQHNLSvemLtxxvXZI2mejo4ERxJWPlHfu4gRT4umqRQj4Z4TJpwZ",
    "LUuqUKsadH+jv57ZOcz+opkyO/fNRBdvz3RzJgBU/Spq/Sr6+qXV0jZKIzCHq3sM57uGA0NC+K6GOpUKuWflsiyV8YlRPjvkVF7k",
    "ag+1frpC6Rf4TIhuKxdneOc8eX270YeIoUi7HZbWS/O8LlQ3rpmYnijm650sTvzVFJWtCtAI9EkRgnsurgQlddRM1TwsIBc3iQrq",
    "RnK0SLtZgCQHFen8dJ2+XBVfOHs7R9UUOwqrARqD8kwzL0SCKdVne7yzOxoaR+Vhsu/cmuAFn117P8nz6+b8fOvQEq48MbG0/24m",
    "SXLj8XgujnJcOMSyIF3ed4mMSzdQMDtzBO+WPnFk5fJdum36l9VrH+s3ClDEFMPKxSVz7njtkE2boWaeXXRCXinxC3dV7RxTc1cl",
    "q7dynOXcJ7qA6HVg7U1d0+5U8Byzt44eWzt3GfXZhU8wCcudm3jxtki5clbOyfLu8gGnaj0/XS8XkbZibOmRk6uXj7SWL1N6ihuc",
    "ek7mSTnqVw1B4UW/AnacEASA7ZhulhY69r9uHOjw1ohoiAzzLfcg2+gc10TnkNAK+2enk7OnC/WwnhspF3dlt4iWyd44Wq/RzhMy",
    "gawu9qfPYBW4b8U6GyYr3WDlGqk4VwqlKtSuYBPccmSTbokyE7b6byvImxe9aaxApBqYKvtjo4itmGe567AVthd5qcKWOQT/HDai",
    "MlKEGqTafhCI0HInnA0wKclstYL1BBqY3J3pNUhKyGpD92in8a+wELX/INK8SZpzGtLtLqb+szRr+C1xt5z29ek+cl+hUzMPx2ND",
    "WXPpbHPpJmkwV8lRHr3r+ZZevvv0OmigDzB3Dk7NRR0GfVeeMbTNyT7ffvcLcY6mBABhPAXe/5pzIOy7Elx8BvHVqeYz7FJifkIf",
    "FTM7fS91tCx8pdluNx2pgDzl4qc7Bwl4eg4yhPcc/q3ZhfV7QD2JTB0gQ1VpYa6FtUF5LiKRNmSR+N+rh+iJJGVZw5Q9429ixADC",
    "KdfENkGpSmzTYJ1MiU8iEelCp23ibhJkLuKMmA+8/AppwAThdXmAGnvt2n7DA1MNAx2eTCRSAqI+m2I4IYHxil10Rnc8dPr2Lo1L",
    "+Qa5xmIKHd2nUmi/XYO+wqzIvjDz6jRgnmzqo8jc2REPDB4jUFaocD2RYu1aAcr6Ia8GwPOLXu9i0DN/Ve1cneKQsCpfEK5UXLyI",
    "01AkQ3x3p9AbubQYWlqdT8t1xMstXIaRdofZGAnQBpxsvl6uos6gy9Ve4Zu6C+KB89iEbyWBhXqXivXwtqwMldQCN0yUDGmu2ZVg",
    "P33TrfPxiIShjsLv75VkexYulayXKZRrzku0wuyucwb6/zGfUv9PkuhUKLabVRswki+YC3PCyIieJTtbjigrhUzUjWIgfPgDRETh",
    "GcKKUMC5JouMagP6ZEZKZCZqA7XQEmaJt1raLOWQzuwTk4PJQkhWxLMrTroLHPbIbC+42fX/OMHT7Vuw6PkMaBRS8AwJQXQD8uf/",
    "THkzFCQ2yt2j3Qgpbc6Kyuo3LHADm8RopBlTWpg7MHCx0ubt7YQqrjLCiKNdM+/aeJBx+S94zhqbtQsz9R7TB/HUjTIWadUxGAvG",
    "z4kryX0OdiHnNfwa7Oy0+vUVkEJWr+OJM9/WhOGt84ut85+t3PxQ3Nxk8OHfy8PYOhvq6Wr49a+Xf1Q+2IuxiFUX10z0O+9c1g5P",
    "r3KWBc3JvDvbDcxKMI5Me+kwCcfIwDWrEhNHcoBwu++5WtsDbPXKdXKW8l/LzfdDa93syKbXddcPctiX6CmMKd9L5/llNm+1jl30",
    "OEiI2zRuyAhs1+rF2+D/lxm6ygwZMt0irRWp4tDY+ZJIF+fJHifYsrTUhDnNnOFSpt9JNOcK5IZ50yObd/Cw1QV2vy+xeSWq/1xq",
    "Q17fUd8xVe/u043R/WOeI7kZslzBHIzolw/wehFKes41xRLEJdX2l9HWWyzJfme2FhYVI0oXn/PIM1LX5Bs7/FFIirOHvEcIG5UA",
    "mYw/spFQjsQUtiYc2BuuE3YPyzGiJBx5aCf4o1eipLraXRHb3Vs+IvF6edee14Wn2iNLikW8FmgjfSes4SGbciJDes4KMFT64bCb",
    "mxAZb7TvXDLEQvQD80KR56O/W3pEybBiV+t5GxmjJidiq+Yp7B8mWQpx4v9r7uh6ozqu7/4VFwlld5VlMapQW4MTQYhUq9AiAy91",
    "LFh2L3jlZe92d21qIUu2Q1MTCKFNAQFJk7QoMaVAkFKSKKT9L6U29Im/0DlfM2funbu7BlNViczu3Zm5M2fOnDnfR0sOalolTLiP",
    "6ZDMLs8YxkBtYKmCqxUrlril9WNPBY4vwaS6Kk4avxDYwRFFz8bUmwrI2+ygg+oWp9hKvRokulTOmLnYGlZ7hr/ejDHq4TJUw1uh",
    "1CRsjgLTlBFNrt6QdN7aSvkBqozvgGOiwTiyyoBJ5gal201ZceAuX76RZuBDJpdzI5rQDCIz5yIr7Zp7GpNhH8EHE5B8jXY8hPQ5",
    "hgK1jmHROqCKCxQifhkjiTY45Mw7xzCGR19SE8DNfI7iJCE0A8yVdzdWvwf9jGFn51pjAY9y0v1uahM8DhWuU3MR0QBwUm1YcjZ4",
    "WU6eWy+7k3q7Z3XHbv63XnCbiBDAf1ufWuAnUFnvd8S6O3PG8j+3NJdAoHIZ1FoszmHBxYxA7Gvt6ZGhGtI8ld5yCna2Me0S0VOH",
    "EsUgZa6/UBCazMMTw+sxFJYSSTyd816/JCeNekAfRKWkGlLyzIg6kEXc/F2+b/4aBgZipiFx920kWuDOCp7aK+9j4oel9dtf7v7P",
    "zcvrD28barb+4bX1f1y3zkIQlAWe8pRlgN7pVfSqx+3eDFX1oo97o9388fXXS3nZCoyIJXXkePQUIYBg2Vav5NIeyCPUMthcBQ1M",
    "lLiNIEINulaHoZhMfrXlK0924uos/e5Wl0YOAH23yF15NLVhbdgw7i2bIlOAXWkLcRCZoe3kBWo3AVp67gNY1HZrFNqdU6EvmzcD",
    "BHG/zB4Sl3CdvXQZrDLXgcwthwWOmfeupKyZlAkFit6xx98KubZikAnFd1OZvQfg6w9Eau3JyvLTP67J7YkJipx7wRoZZzcuPMTc",
    "9DCC4gsMnIH4wimGtXrrySa/2Kaqr2gk8tUuhs2qGrG745OGs43ejFW0uBermoZykWUn4obksoSCiIiGQYujaID9stpydLIhmeJd",
    "9cDPikCk/yL4eQj0bAooMST+FXkYCMPX1otnn6+Bt83yA666w16Cwxs+1ewhM4rSB6bvsP+V9XOxz9khbjltBfbLQweubF23NlQT",
    "O1CycMoV0yzrsabdaDmd8B7TdcvT3c3SgPpiYeejjTOY4ZAs4SkPwElocRiSo/GarZlyXGevya0mXTCM1dNHN9DpgEpB9yv+3IlB",
    "tuPiz6X+peEHp4TSSXk7C4eS2uxmIklD0S+p2thSUTvqVufjI/wbcF4nk6Tngl5s4WuDg8/ufIEmvYzIYnbMSLX7FxDgIxQrNeVZ",
    "IwmSYg7/CuMfPgNbOLDcKVv4DZXyT9SmMMZstXWy2jqO+15pLyDzCyWMr2FJb510EUjps79/s37xatCVXH6S3IzAHqAz0Ls3+UAu",
    "P4AS9tDmS8U5hNzcghluG61ZUnry1mXXY9vCGZD0NnlQus8TXvkDKu09WIGKpjQ9QmFhPsxlUZbaPcgZH3xVdSLKHPiDvgkg8akZ",
    "9fBbEBwCAPowb2sxWYqjtBwZowMXnOZ3TaB8OQfEiZ8Br9uL210vuCOdmUlbsjOIs7wW0bPKTO9ME9PjXLkEel1ITXgH0Mng1fLd",
    "pz/c95Nzll7wff0QlQdfX/1k/dafKBwo2nd4wnS6RzlOJSYC8JSw0sdfyC5A5h0//nBTU1Y7dQkneufJirkrH8Gpx3c+vXkeK+J4",
    "6Uo3/vY5ThqrXxtWx4g9xM8YHgk4pevkH/Bs7d6ztVUwRFmGx74O2CGLf7/XEx/uiHmrq3pttHmqzCYd3JP91W6MOcULOwvDGngI",
    "5hvfrmJRNyrG9xH+b2fvp0KVoz+dqksf8CjPpIZOWi3ItpCT/pp/3gHEl1IrgG6nFLSTAnkxgh4SZo9nhsqPlqNpGwrETVxZ+1OJ",
    "9QeDL04doa9Vx97pK8B2BEGHL3ilikOWehXLKX729caFJTGaXcRYp081GWbiwuWjVzVvh7TwU8srB97YibtJc14ZX2rNuNqZMNd7",
    "Z77aLDoGwuptFEdhrkvbMi/e3r9SsVQ6jlEg7X3ey3Ii5ZPZvA2R9yWzAwfGFUNDWy65HP1odHSUs56FcIQufMKNfgDCWKN97UZR",
    "qabemulAcH4pheQpnanNERhSfqpumJ68ApF7R+MzbUhTSV4vXe09sImDBIyjvVy1LoZtG048STFH3k4qMd47Nf7ZchJ3H6zQJj1i",
    "Rjt0Bx4jO7kZXp4cn+s0BS3TkH41cFj01K+KV1YuPpS5EFn0kl4Ga2QQf5yOT4lOU9O6OYkP2klwj9L5OklFA6CY0ujKzrw4KKwg",
    "JfoSEs/s47B+NyRbqdIM5BTppA1eKvyjUgQasYC1ukrNqtbtr3OIiXFtEgHUFus0f1qJNm59vXHtq42PPvj3Dx8/f7yKmZXvOqbu",
    "9gUgz0vL67cfbly9ztLqygWta97qfKqpPSCzI5kAig2qA4/WAKw036onYHMSkmTgOw530SvzHBJ/4niejOc4F19FTimCj2NpSGsW",
    "t0+0g2oL8rWNa185Wdt0KvtiV73tuPjhQkMaTjnBA/CgysMkvuy11/AlXKfSloyTKEU3q3HVDg1pekXWhdeBnlx/sQ+5/co0skPb",
    "t2ZAMZ6diFNI8R5U6/WiZzVRhtyBRqW0m+KmTcrs7dRCn02LbG8yz5BBTcALp9fWtYg9O4+18Gw/ZyG4OMDOg3NAN+x+9h5stZix",
    "ktlqs/6mqulq+Hg7hG38/QmshahIfxPbIANbOm+Jhwa+jSGAC4u+obbaOgRaG/YsIFnAMB1esKi5eM0CWSvMzmmMxPjT+LjuaIt1",
    "JrNjRGzK0a/nGiBi0CKkc9F2Ioaj2m53wDugAPTFjuwel0i5m80BF3pjJ6520Vke7YOQeI6yMiD2fAsi45ffoxBJ6o9PrCgDXPk3",
    "hr++jghD2fF13rpLOiKR64Goulg0CVmoBjVox44m7MYMhyAI7OGpcJba1mZiVJPlbqodAFtWiJ1WD3CbSoy19IjgOCjoQnTqTedP",
    "XCPOlfyJMeVdrYKlkz1s2ePVCENCnfX5NkNBV1+XDm2VShmJBDTEWEomEmCZgGv4Ysqd0OyiTJOGiruR1LF3DkUnBq56mBtXHd0t",
    "Zkp2jYKl9QIqnN59svLV88fv4dd7pHuAWnikQxFlw5ZyH2gA7FRP444R9ZY0faQUdXypuSfxUyCbDIyAxdYgMYSIl55uNa5w6Dv6",
    "lHTRWJZ+Viygc4iKYid3D3dA7Ew5ZwM6gjiHEVLK44OjWDIx7lTiU6fiWm9fs5mcRVedAhzgQqBhF0uyVck9eafhwBugVuL7kV7M",
    "6X7hpU5hDjc2AuA0MOTqKOTSAB4MhVEEqOciY6YKgEhALS9pfGq69m4nSxtqFgg1OI0EvI6hDEhrO0IRaqFp7zBybAPo8h5X44H8",
    "UH4FBsWs5xC06ocIULezrNQMKfTqs2iBYjnCjzuoJlnFm6WFCWUPipsB24XdDbCKykD2i4zUf7FKrvcahN9GbygNBg7PJH1IKFPq",
    "kGcEUMMdEdPVXLQCZGE+3ZkJu+r2Q7yKWpGPgjXUA8ArzdRq/WHBJ6EZxLlhwWUE8fl4K+HFc9+GEyNLb7cI+gtQ09SPYl/wf02a",
    "L7fTSfv/YZc9ZoU6l3FtHrnApYxYKz3jOtF+jfvmarDfhkHv0KTUC/ohBpKigW8T7GDxJDRyGDEHjOxvXhi0sC28HVbi8zgJC+6U",
    "T18eVwF7AK4CyrJi7v63QYsZoZfFXVtujcI+crFP8qtu9U0MGJhtSYbbcgTZ8BVCqtCmnMvaW7TH4YxFerU2yUz0r/euYPg8aNpv",
    "/gVY/NXrIAYsLVswDQCN4T/rydnW1gIH+2JD4YwLOJ+C7o3PiZ8JH4xhAJYNkZZ9KdLLUU27zzC7Zw/Gp3oFNyv3wyTUzPT3Kozh",
    "zMUMYLeoFfj+o3qw2zjZFHV3seQSZdcs6y/DgvcNdKsYySL+jZFJSTINSUwlsHIVFXjVQqI3o13RWLRjl7P5mKHfGI9G0avPfN5L",
    "rxGnnIwAB79OmYbTFiG3krvfBdz9Ksos30H6h50R5YkAUyr4K/+Z7M2vpkQTO+un1K3CypVZ28KsWUCZGDfDqbpxXKzoRQNCLS/8",
    "JMVCOZm9/ZWT2qPNGwhhIFLbU2LDPtLkSphpzub67eM4knEVMR2Z/IMHL45W6cy1rFcIP0IFk+UGcWng7GIrc5PXWNwDE1Iy1yva",
    "JKUyeNmu88ejo6NmkbvJUqXVBlIG4VBSx7yGomhgN5xJsqxUUFrHyAo2tpjRuMlBdMjRLdBFB2DKLjCL6nULrRq8iiMyrfN+vdGB",
    "ZBD4VHO7qekhtcDhGSo4mZ81sDJW3040a4GloZb7e60+ffA00/QNuKYULMoRfgHjs3xGCLjcpuQ5uh0IROgSxLvYCSIyn8m4ayhc",
    "htPPQGwPBUllTCQzyVkOnp1onUo8YzSunWyuYSscJD9JG0b9EmTzbuiMH9cJzw/lwioEQ+7/5b7JA8f3H5s4eAAq+6IejQyeEJzz",
    "ZGkp6NYyFs1vP0d+HfzCRflOqTsMmkD/549XM88XJfV8YfEEV+7zXmuILvWAStIAhewTF+FZeKfF1HD5PtXpHcPa5qn2HOy5MypQ",
    "LZnU2YKb07l+kdEqvU0E33M08ljkIVoTix46FDO0KAE64hAwWpzyNnUaQ1Psz+5UOrkxg09ykMRQanpJLnE7NhtLTbtqu/HzeCHU",
    "xlxX6njloDP75XGfYPjPK4SGCs3xY4n0LuVNUBLujKjfiYjkc7oaA8xrTc8WpcUZ1FGIg3MJPROX/Lw6JItYUeiIm3L+sN5iqXd3",
    "mH6xm43HN3r9S2lY0gxtwNVQXC+9wnKGb3dr1XZcyCQNyMZ7lbJRh9apdltoS7PTJS7Lux+GLxLBTiZzPU58qc4Aih1zvYzbBjxD",
    "zuUXVIMFO+3oUC/6OV1TAv1kQdJij7TraWdF53GRvc8Gulxk/GL6zRAJIjoyAcFMqB67aBqjwOyh6Yjk+j+R49d4N+MQai1X6L4B",
    "kS9kqIskcpOd+yNuoRw8oM1dhpkPKqhNMSLp/vMcQ21X35y2tJL1eLzk+8OeJ9dBf5dS5T0CsWw6qUOQJtukwyhxZOmxioFGvIeh",
    "DA3cBjIO2I76bafZuiDOHZs8iC6dymtyUOESLQ0647CUo7PoRgld2E0VPJ8wIwTMNeQJ03fyyWwhD+1OZHaRMYo32wg7kDThC1zY",
    "I/MX+BdOowUVbiYO0PdGHVmMsEV3IGTzJqcNsu+00o7SXMH+vEUq8uiDGULxPxQTkk7jdKNFUcCLloQJuePg1Swds+lGBuiTJEK7",
    "Hme45D2vAGUda0pShGHSfDT2yVeY3m6a2vbbIl25QVCJXIMNrXoQBY6HX2Ak77DLDqFXByQs5O9lBHY5ksNANuBUGMFIlL29Iokt",
    "sEgADBIcoUJfQcQigGKeqJ82aVltE+UgD88pPQFDIZNqfbNXqQpoOuNSwMvY+U5dLrxV8gZ+vITuEPefvv9o47cXOfJHvPMsLSiU",
    "8hIpDnAJWyTbI81r707KyvGG+XQyqS/Av+D//sbIfwFgjWKh",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
