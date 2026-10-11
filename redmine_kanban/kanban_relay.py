"""設計課タスクボードの中継プログラム。

このPCの中でタスクボードの画面を出し、社外の Redmine との間をつなぐ。
ボードの画面(HTML)はこのファイルに埋め込まれている。チームの設定は同じフォルダの
board_settings.json に書き、ステータスなどそれ以外の設定は起動時に Redmine から自動で読む。

    初回:   kanban_relay.py をダブルクリック（setup.bat でも同じ）→ API キーを入力 → ボードが開く
    2回目〜: ログオン時に自動で起動する。ブラウザで http://127.0.0.1:8765/ を開く
    更新:   共有フォルダの kanban_relay.py / board_settings.json を新しくしておけば、
            次の起動時に自動で入れ替わる。すぐ反映したいときは共有フォルダの kanban_relay.py をダブルクリック
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

VERSION = "4"
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
    ("GET", re.compile(r"^/projects/[\w\-]+/versions\.json$")),
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
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_PUT(self):  # noqa: N802
        self._handle("PUT")

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
        if method == "PUT":
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
            current = running_dir()
            changed = copy_if_changed(HERE, current) if current else []
            if changed and ask_running_to_restart():
                log("新しい版（" + "、".join(changed) + "）に入れ替えて、中継を再起動しました。")
            elif changed:
                log("新しい版を置きましたが、中継を再起動できませんでした。サインインし直すと反映されます。")
            log(f"ボードを開きます（{BOARD_URL}）。")
            webbrowser.open(BOARD_URL)
            if changed:
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
    "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",
    "DynKcIqQ9TenUmJ2VfStHaGyTVVKtKvWIxtn/N4KcjnRJdGCQvHpG7k8amJoEhF5Qzbwcqjbgm5SZOZlvISHslVgd6ldN+vG6oUf",
    "4Z37Gup+zTbIgC4QFiiNTa00OQk6DLtKogQ0ospzDNd/VOwy1GG6wIBfKKN5c0sHAm9Vw1WJ33wDBkkAdTz3ADd/+VE5/PCoBfv7",
    "tE4ErG4fIzGWdqmsdkS0vR2iZYQhbUxxQ9qy8ketucuvDSEYJEDUbelr3aVdMQ5hkXCxSHXES45W1l5uVW91biiVbXrJ0WP4ci9+",
    "5dyJuuo7OkYR6eSeNUwmT/2gww4tzEytO7REnriNQnb58O9wssEzHQIH/oBjzdaBRca8McMTcTe1lG/P7r6KuDeGishj4ALqnLLG",
    "nGWgeCTieUALZ4OgY5cYXqQdqHfpaADk8rBzeVzHwcsj7G/RPWCt73kKuWqVtdHRrT6zj3vyzJtFkd56j4+N+RJDirNJS/dDPsNF",
    "PidUlm6kixJyMGglroTjzRUg7SakjQyZ888TQhj2Lq75qH6e1mojfWu21zgiC0m/gOkB8BVxuaCb6FMnQ/Q88Y3f+uN5q3nq3ONH",
    "l8Y3MLyIeQ4JjVx8nefMDuOdt4WkVbNRRG14pQECNUA1m0FmDJ0tGNeLBlg1xmSsIXE+mONJ52U8gmfuxYuZDdafdDK040h0+Yow",
    "rrCPDu9OOHRnfYFynh+60jx2ofV3PDparjhA9pTuAtrCyHQGoAeakSX1ZTo4yGZ8TDyM1XSeREaDTHeuAjqEiHGNZKaLUkgqqFfo",
    "cPrrdK6CORpY0HktUVQxpPkU2c6HRbKlypAEhGibFycZXaBt1Ep4zfP4jKtSqi5xlAFG9v1jEa+0FTH/nrtC3qf8Xe6ZHUy2fvUa",
    "bb/EsW5mM2sLhyiG5oq7J6MjU62fllV6B9y91Q+v1++2jn2xBvpR/ebaTz/gte2e/D2vlylphSsD5LGdMSVKg50/WzUAzOvNTH/B",
    "J2GB5+v1KJtRQEmaZLMBQyTZfJ2pKYwmxF4g9J4d0k0irPpoA/XtrfSBejj7Vrd20KYv6EwxjFGrpA1RKxbRvA7EUEUWehVgOIVS",
    "rjxdIxoTXF6cGqbU7bzenrVC0sIEL4QSx0soroVFyoxFnjfsmVa7F5XrPqhtlLK+tt9S57XNpin8SYJVOeTJCJ/n8nMeSMLTaDqf",
    "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",
]
# --- BOARD_HTML_END ---

if __name__ == "__main__":
    sys.exit(main())
