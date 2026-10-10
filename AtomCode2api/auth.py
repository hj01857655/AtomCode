# -*- coding: utf-8 -*-
"""atomcode2api 认证模块。

凭据依赖官方 CLI 的当前凭证：~/.atomcode/auth.toml。
- 读：mtime 热加载——官方 CLI 刷新/重登后，网关下一次取 headers() 即自动跟随。
- 写：401 触发 RT 轮换刷新后，原子写回 auth.toml（仅改顶层凭据键，[user] 表原样保留）。
- /login 路由（自建 OAuth）产出的凭据同样写入 auth.toml。

RT 轮换语义：/oauth/refresh 每次返回新 RT、旧 RT 立即作废，因此刷新成功后必须
原子写回 auth.toml；写回后官方 CLI 读到的也是新凭据，两边互不破坏。

auth.toml 不存在时抛 NotLoggedInError（先跑官方 `atomcode login`，或走网关 GET /login）。
"""
import logging
import os
import threading
import time
import tomllib

import requests

log = logging.getLogger("atomcode2api")

REFRESH_URL = "https://acs.atomgit.com/oauth/refresh"
UPSTREAM_UA = "ac2api/0.1.0"       # 绝不能以 atomcode 开头——UA 门按前缀匹配
AUTH_TOML = os.path.join(os.path.expanduser("~"), ".atomcode", "auth.toml")


class NotLoggedInError(Exception):
    """auth.toml 不存在——先跑官方 `atomcode login`，或网关 GET /login。"""


# ── 自建 OAuth 登录（acs.atomgit.com 平台代持流，无需 client_id/PKCE）──
# 流程（源码坐标 crates/atomcode-auth/src/oauth.rs）：
#   1. GET  /auth/login?provider=atomgit → {login_url, state}
#   2. 用户浏览器打开 login_url 授权（可剥掉 force_login=true 免二次确认）
#   3. GET  /auth/check?state=<s> → {valid: true} 表示已授权
#   4. GET  /auth/token?state=<s> → {access_token, refresh_token, expires_in, user{...}}
class OAuthLogin:
    """一次登录会话：发起 → 轮询 → 完成。进程内同时只保留一个活动会话。"""

    def __init__(self):
        self.state = ""
        self.login_url = ""
        self.created_at = 0.0

    def start(self):
        resp = requests.get(
            "https://acs.atomgit.com/auth/login",
            params={"provider": "atomgit"},
            headers={"User-Agent": UPSTREAM_UA},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self.state = data["state"]
        self.login_url = data["login_url"]
        # 剥掉 force_login=true：已登录 atomgit.com 的浏览器可免确认直接授权
        self.login_url = (self.login_url
                          .replace("&force_login=true", "")
                          .replace("?force_login=true&", "?")
                          .replace("?force_login=true", ""))
        self.created_at = time.time()
        log.info("OAuth 会话已发起: state=%s...", self.state[:8])

    def poll(self):
        """返回 (凭据|None, 状态)。已授权时完成交换并返回凭据，否则 (None, 原因)。"""
        if not self.state:
            return None, "login 未发起，先 GET /login"
        if time.time() - self.created_at > 600:
            self.state = ""
            return None, "会话已超时（10 分钟），请重新 /login"
        resp = requests.get(
            "https://acs.atomgit.com/auth/check",
            params={"state": self.state},
            headers={"User-Agent": UPSTREAM_UA},
            timeout=30,
        )
        if not (resp.ok and resp.json().get("valid")):
            return None, "waiting"
        return self._exchange(), "done"

    def _exchange(self):
        resp = requests.get(
            "https://acs.atomgit.com/auth/token",
            params={"state": self.state},
            headers={"User-Agent": UPSTREAM_UA},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self.state = ""            # state 一次性，用完即弃
        return {
            "access_token": data["access_token"],
            "token_type": data.get("token_type", "Bearer"),
            "refresh_token": data.get("refresh_token", ""),
            "expires_in": data.get("expires_in", 604800),
            "created_at": int(time.time()),
            "user": data.get("user", {}),
        }


oauth_session = OAuthLogin()


# ── auth.toml 读写 ───────────────────────────────────────────────────
def _parse_auth_toml():
    """解析 auth.toml；文件缺失抛 NotLoggedInError，读坏返回 None（保留内存态）。"""
    try:
        with open(AUTH_TOML, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise NotLoggedInError(
            "未找到 ~/.atomcode/auth.toml：先跑官方 `atomcode login`，或网关 GET /login"
        )
    except (OSError, ValueError):
        return None


def save_credentials(creds):
    """把一份凭据 dict 原子写入 auth.toml（官方 CLI 与网关共用的当前凭证）。"""
    data = {
        "access_token": creds.get("access_token", ""),
        "token_type": creds.get("token_type", "Bearer"),
        "refresh_token": creds.get("refresh_token", ""),
        "expires_in": int(creds.get("expires_in", 604800)),
        "created_at": int(creds.get("created_at", time.time())),
    }
    user = creds.get("user", {})
    if user.get("id"):
        data["user"] = {"id": str(user["id"]),
                        "username": user.get("username", ""),
                        "name": user.get("name", ""),
                        "email": user.get("email", ""),
                        "avatar_url": user.get("avatar_url", "")}
    _write_auth_toml(data)


def _write_auth_toml(fields):
    """原子写 auth.toml：凭据键逐行替换（或追加），其余内容原样保留。"""
    try:
        with open(AUTH_TOML, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        text = ""

    def fmt(v):
        if isinstance(v, str):
            return '"%s"' % v
        return str(v)

    updates = {k: fmt(v) for k, v in fields.items() if k != "user"}
    seen = set()
    out = []
    in_user_table = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            in_user_table = stripped.lower().startswith("[user")
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip() if "=" in stripped and not in_user_table else None
        if key in updates:
            out.append("%s = %s\n" % (key, updates[key]))
            seen.add(key)
        else:
            out.append(line)
    for key in ("access_token", "token_type", "refresh_token", "expires_in", "created_at"):
        if key in updates and key not in seen:
            out.append("%s = %s\n" % (key, updates[key]))
    if fields.get("user") and "[user]" not in text:
        u = fields["user"]
        out.append("\n[user]\nid = \"%s\"\nusername = \"%s\"\nname = \"%s\"\nemail = \"%s\"\navatar_url = \"%s\"\n"
                   % (u["id"], u.get("username", ""), u.get("name", ""),
                      u.get("email", ""), u.get("avatar_url", "")))

    tmp = AUTH_TOML + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(out))
    os.replace(tmp, AUTH_TOML)
    log.info("凭据已写入 auth.toml (uid: %s)", fields.get("user", {}).get("id", "?"))


# ── 凭证 ──────────────────────────────────────────────────────────────
class Credential:
    """当前凭证：读 ~/.atomcode/auth.toml，mtime 变化自动热加载（跟随官方 CLI 的刷新/重登）。

    401 时调 /oauth/refresh 换新 token 并原子写回 auth.toml。
    进程内加锁串行 + 锁内重读文件：若官方 CLI 已抢先刷新（RT 轮换），
    直接用文件里的新凭据，不再重复刷新，避免并发双刷互杀。
    """

    def __init__(self):
        self.access_token = ""
        self.refresh_token = ""
        self.user_id = ""
        self.username = ""
        self.expires_at = 0
        self._lock = threading.Lock()
        self._mtime = 0.0
        self._load()

    def _load(self):
        data = _parse_auth_toml()
        if data is None:
            log.warning("auth.toml 暂时读坏/占用中，保留当前内存凭据")
            return
        self.access_token = data.get("access_token", "")
        self.refresh_token = data.get("refresh_token", "")
        created = data.get("created_at", 0)
        self.expires_at = created + data.get("expires_in", 604800)
        user = data.get("user", {})
        self.user_id = str(user.get("id", ""))
        self.username = user.get("username", "")
        try:
            self._mtime = os.path.getmtime(AUTH_TOML)
        except OSError:
            self._mtime = 0.0

    def _reload_if_changed(self):
        """文件 mtime 变了就重读——官方 CLI 刷新/重登后网关自动跟随。"""
        try:
            m = os.path.getmtime(AUTH_TOML)
        except OSError:
            return
        if m != self._mtime:
            old = self.access_token
            self._load()
            if self.access_token != old:
                log.info("auth.toml 已被外部更新，凭据已热加载（账号=%s uid=%s）",
                         self.username or "?", self.user_id or "?")

    def is_expired(self):
        return time.time() > self.expires_at - 3600

    def refresh(self):
        """POST /oauth/refresh，RT 轮换并写回 auth.toml（与官方 CLI/并发请求互斥）。"""
        at_before = self.access_token
        with self._lock:
            self._reload_if_changed()
            # 锁等待期间若 auth.toml 已被别人换掉（官方 CLI 抢先刷新，或并发请求已刷），
            # 直接用文件里的新凭据，不再重复刷新（RT 已轮换，旧 RT 刷必失败/互杀）
            if self.access_token != at_before:
                log.info("auth.toml 已被外部刷新，跳过本次重复刷新")
                return
            resp = requests.post(
                REFRESH_URL,
                json={"refresh_token": self.refresh_token},
                headers={"Content-Type": "application/json", "User-Agent": UPSTREAM_UA},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.expires_at = time.time() + data.get("expires_in", 604800)
        save_credentials({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "refresh_token": self.refresh_token,
            "expires_in": data.get("expires_in", 604800),
            "created_at": int(time.time()),
            "user": {"id": self.user_id, "username": self.username},
        })
        log.info("token 已刷新并写回 auth.toml，新过期: %s",
                 time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.expires_at)))

    def headers(self):
        self._reload_if_changed()
        return {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json",
            "User-Agent": UPSTREAM_UA,
        }
