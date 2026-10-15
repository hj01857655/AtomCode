# -*- coding: utf-8 -*-
"""atomcode2api — AtomCode CodingPlan 本地 OpenAI 兼容网关。

把 AtomCode 的 CodingPlan 免费额度包装成标准 OpenAI Chat Completions API。
任意支持自定义 Base URL 的客户端（Cherry Studio / Cline / OpenAI SDK）指向
http://127.0.0.1:8788/v1 即可使用 AtomCode CodingPlan 模型。

启动:
    pip install -r requirements.txt
    python server.py

默认监听 127.0.0.1:8788（避开 zcode2api 的 8787 / codearts2api 的 8787）。
环境变量：HOST / PORT / API_KEY（设置后要求 Bearer 本地鉴权，或在 .env 写 API_KEY=sk-xxx）。

关键约束：数据面 UA 绝不能是 atomcode/* —— 那是签名门的开关（见 docs/atomcode-03-数据面与UA门.md）。
"""
import json
import logging
import os
import re
import threading
import time
import tomllib
from logging.handlers import RotatingFileHandler

import requests
from flask import Flask, Response, jsonify, request
from dotenv import load_dotenv

# 加载 .env（项目根目录），让 API_KEY 等配置可写在文件里
load_dotenv()

# 认证模块（OAuthLogin / Credential / 凭据文件）在 auth.py
from auth import Credential, NotLoggedInError, oauth_session, save_credentials
import responses_bridge as rb
import anthropic_bridge as ab

# ── 日志 ──────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("atomcode2api")
# werkzeug 的访问行在响应*开始*时打（流式会误导），禁掉，统一由 done 日志汇报
logging.getLogger("werkzeug").disabled = True

_req_seq = 0
_seq_lock = threading.Lock()


def _next_req_id():
    global _req_seq
    with _seq_lock:
        _req_seq += 1
        return "r%04d" % _req_seq


# ── 上游伪回复识别 ────────────────────────────────────────────────────────
# 上游把「额度耗尽 / 负载过高」伪装成正常 HTTP 200 的 assistant 文本回复，
# agent 客户端会当成模型真实回答。网关需要识别并转成正规错误。
# 实测无任何可区分的状态码/响应头，只能靠文案，但**不能按裸子串匹配**：
# 用户问「什么是「请求负载过高」」时模型正常解释也会含该短语，会被误判成过载。
# 因此锚定上游固定模板的共现特征（quota 三要素共现、overload 整句前后缀锚定）：
#   quota:    "模型「X」在当前 CodingPlan 用量窗口内已达上限。…约在当日 HH:MM 结束并重置额度…"
#   overload: "模型「X」的请求负载过高，请稍后再试。"
PSEUDO_REPLY_RES = (
    (re.compile(
        r"模型「[^」]{1,64}」在当前\s*CodingPlan\s*用量窗口内已达上限"
        r"(?:.{0,80}?重置额度)?", re.S), "quota_exhausted"),
    (re.compile(
        r"模型「[^」]{1,64}」的请求负载过高，请稍后再试", re.S), "overloaded"),
)


def _detect_pseudo_reply(text):
    """命中返回 (kind, reset_display)，reset_display 形如 "03:13"（当日窗口重置时刻）。"""
    if not text:
        return None
    for pat, kind in PSEUDO_REPLY_RES:
        if pat.search(text):
            m = re.search(r"约在当日\s*(\d{1,2}:\d{2})", text)
            return kind, (m.group(1) if m else None)
    return None


def _retry_after_seconds(reset_display):
    """把 "03:13"（当日窗口重置时刻）换算成 Retry-After 秒数。"""
    if not reset_display:
        return None
    try:
        hh, mm = (int(x) for x in reset_display.split(":"))
    except ValueError:
        return None
    lt = time.localtime()
    delta = (hh * 3600 + mm * 60) - (lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec)
    if delta <= 0:
        delta += 86400
    return delta

# ── 配置 ──────────────────────────────────────────────────────────────
LISTEN_HOST = os.getenv("HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("PORT", "8788"))
API_KEY = os.getenv("API_KEY", "").strip()

LLM_BASE = "https://api-ai.gitcode.com/v1"          # 数据面（免签名，非 atomcode UA）
CONTROL_BASE = "https://api.gitcode.com/api/v5/coding-plan"
UPSTREAM_UA = "ac2api/0.1.0"                        # 绝不能以 atomcode 开头——UA 门按前缀匹配

CONFIG_TOML = os.path.join(os.path.expanduser("~"), ".atomcode", "config.toml")

# ── OpenRouter（免费模型反代，不走 CodingPlan 额度）─────────────────
OPENROUTER_BASE = "https://openrouter.ai/api/v1"

# 从 ~/.atomcode/config.toml 读 OpenRouter API key，或用 OPENROUTER_API_KEY 环境变量覆盖
def _load_openrouter_key():
    key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if key:
        return key
    try:
        with open(CONFIG_TOML, "rb") as f:
            cfg = tomllib.load(f)
        for acct in cfg.get("provider_accounts", {}).values():
            if acct.get("provider") == "openrouter":
                return acct.get("api_key", "")
    except Exception:
        pass
    return ""

OPENROUTER_API_KEY = _load_openrouter_key()

# OpenRouter 免费模型（从用户 config.toml 提取 2026-10-09）
OPENROUTER_MODELS = [
    {"id": "openrouter/stealth/space-bunny-alpha",           "upstream": "stealth/space-bunny-alpha"},
    {"id": "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free", "upstream": "nvidia/nemotron-3-ultra-550b-a55b:free"},
    {"id": "openrouter/nvidia/nemotron-3.5-lightning:free",    "upstream": "nvidia/nemotron-3.5-lightning:free"},
    {"id": "openrouter/thinkingmachines/inkling-small:free",   "upstream": "thinkingmachines/inkling-small:free"},
    {"id": "openrouter/thinkingmachines/inkling:free",         "upstream": "thinkingmachines/inkling:free"},
]


def _is_openrouter_model(model_id):
    return model_id and model_id.startswith("openrouter/")


def _openrouter_upstream_model(model_id):
    """openrouter/stealth/space-bunny-alpha → stealth/space-bunny-alpha"""
    for m in OPENROUTER_MODELS:
        if m["id"] == model_id:
            return m["upstream"]
    return model_id[len("openrouter/"):] if model_id.startswith("openrouter/") else model_id


app = Flask(__name__)

# 认证模块（OAuthLogin / Credential / 凭据文件）在 auth.py


# ── 控制面 ────────────────────────────────────────────────────────────
def claim_plan():
    """领取 CodingPlan Lite-体验版（幂等，启动时调一次）。"""
    try:
        resp = requests.post(
            CONTROL_BASE + "/claim-v2",
            json={"plan_type": "Lite"},
            headers=cred.headers(),
            timeout=30,
        )
        data = resp.json()
        if data.get("success"):
            log.info("[claim] 领取成功: %s（有效期至 %s）", data.get("plan_name"), "7 天后")
        elif data.get("duplicate"):
            log.info("[claim] 已领取: %s", data.get("plan_name"))
        else:
            log.info("[claim] 返回: %s", data)
    except Exception as e:
        log.warning("[claim] 失败: %s", e)


def get_status():
    try:
        resp = requests.get(
            CONTROL_BASE + "/status-v2?plan_type=Lite",
            headers=cred.headers(),
            timeout=30,
        )
        return resp.json()
    except Exception:
        return None


def fetch_models():
    """从控制面 models-v2 拿模型目录。"""
    resp = requests.get(
        CONTROL_BASE + "/models-v2?plan_type=Lite",
        headers=cred.headers(),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ── 本地鉴权 ──────────────────────────────────────────────────────────
def _guard():
    if not API_KEY or request.headers.get("Authorization", "") == "Bearer " + API_KEY:
        return None
    return jsonify({"error": {"message": "invalid api key", "type": "auth_error"}}), 401


def _cred_guard():
    """未登录（无 auth.toml）时返回 401 提示；已登录返回 None。"""
    if cred is None:
        return jsonify({"error": {
            "message": "尚未登录：先跑官方 `atomcode login`，或 GET /login 走网关 OAuth 登录",
            "type": "auth_error",
            "login_url": "/login",
        }}), 401
    return None


# ── OpenAI 兼容面 ─────────────────────────────────────────────────────
@app.route("/v1/models", methods=["GET"])
def list_models():
    denied = _guard() or _cred_guard()
    if denied:
        return denied
    try:
        upstream = fetch_models()
    except Exception as e:
        return jsonify({"error": {"message": str(e), "type": "upstream_error"}}), 502
    data = []
    for m in upstream:
        if not m.get("plan_available", True):
            continue
        data.append({
            "id": m.get("display_model_name", ""),
            "object": "model",
            "owned_by": "atomcode",
        })
    # 追加 OpenRouter 免费模型
    if OPENROUTER_API_KEY:
        for m in OPENROUTER_MODELS:
            data.append({"id": m["id"], "object": "model", "owned_by": "openrouter"})
    return jsonify({"object": "list", "data": data})


# ── 上游发送（chat 与 responses 路由共用）──────────────────────────────
def _send_openrouter(body, req_id):
    """OpenRouter 分支：POST 并返回 (resp, err)。

    成功 err=None，resp 为上游响应（调用方负责 close）；
    失败 resp=None，err 为直接返回客户端的 (jsonify, status)。
    """
    or_headers = {
        "Authorization": "Bearer " + OPENROUTER_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": UPSTREAM_UA,
        # OpenRouter app-attribution（官方 CLI 同款，openai_compat.rs:
        # OPENROUTER_ATTRIBUTION_HEADERS）：免费模型有 agentic harness 门，
        # 缺这两个头会被 403
        "HTTP-Referer": "https://gitcode.com/atomgit_atomcode/atomcode",
        "X-Title": "AtomCode",
    }
    try:
        resp = requests.post(OPENROUTER_BASE + "/chat/completions",
                             json=body, headers=or_headers, stream=True, timeout=120)
    except requests.exceptions.Timeout:
        log.error("OpenRouter 超时 (120s): model=%s", body.get("model"))
        return None, (jsonify({"error": {
            "message": "OpenRouter 上游请求超时 (120s)",
            "type": "upstream_error",
        }}), 504)
    except requests.exceptions.RequestException as e:
        log.error("OpenRouter 连接失败: %s", e)
        return None, (jsonify({"error": {
            "message": "OpenRouter 上游连接失败: %s" % e,
            "type": "upstream_error",
        }}), 502)
    if resp.status_code != 200:
        err = resp.text[:1000]
        resp.close()
        log.error("OpenRouter HTTP %s: model=%s err=%s", resp.status_code, body.get("model"), err)
        return None, (jsonify({"error": {
            "message": "OpenRouter 错误 (HTTP %s): %s" % (resp.status_code, err),
            "type": "upstream_error",
        }}), resp.status_code)
    return resp, None


def _send_codingplan(body, req_id, model_id):
    """CodingPlan 分支：瞬时错误退避重试 + 401 刷新重试一次。

    返回 (resp, err)，约定同 _send_openrouter。
    """
    url = LLM_BASE + "/chat/completions"

    def _post():
        # 每次调用现取 cred.headers()——刷新后拿到的是新 token
        return requests.post(url, json=body, headers=cred.headers(), stream=True, timeout=120)

    # 瞬时错误退避重试：上游 LiteLLM 偶发 502/503（客户端表现为「请求负载过高」），
    # 网关层重试吃掉，退避 0.5/1/2s 共 1+3 次。403 是 UA 门/权限错不重试；
    # 401 只刷新 token 重试一次。
    RETRY_STATUSES = {429, 500, 502, 503, 504}
    resp = None
    refreshed = False
    for attempt in range(4):
        try:
            resp = _post()
        except requests.exceptions.Timeout:
            log.error("[%s] 上游超时 (120s): model=%s (第%d次)", req_id, model_id, attempt + 1)
            return None, (jsonify({"error": {
                "message": "上游请求超时 (120s)，模型响应过慢或服务繁忙",
                "type": "upstream_error",
            }}), 504)
        except requests.exceptions.RequestException as e:
            log.error("[%s] 上游连接失败: %s (第%d次)", req_id, e, attempt + 1)
            return None, (jsonify({"error": {
                "message": "上游连接失败: %s" % e,
                "type": "upstream_error",
            }}), 502)
        if resp.status_code == 401 and not refreshed:
            refreshed = True
            resp.close()
            log.warning("[%s] 上游 401，刷新 token 重试", req_id)
            try:
                cred.refresh()
            except Exception as e:
                log.error("token 刷新失败: %s", e)
                return None, (jsonify({"error": {
                    "message": "token 刷新失败: %s" % e,
                    "type": "auth_error",
                }}), 401)
            continue
        if resp.status_code in RETRY_STATUSES and attempt < 3:
            wait = 0.5 * (2 ** attempt)
            log.warning("[%s] 上游 HTTP %s (第%d次), %.1fs 后重试: model=%s",
                        req_id, resp.status_code, attempt + 1, wait, model_id)
            resp.close()
            time.sleep(wait)
            continue
        break

    if resp.status_code != 200:
        err = resp.text[:1000]
        resp.close()
        log.error("[%s] 上游 HTTP %s: model=%s err=%s", req_id, resp.status_code, model_id, err)
        return None, (jsonify({"error": {
            "message": "上游错误 (HTTP %s): %s" % (resp.status_code, err),
            "type": "upstream_error",
        }}), resp.status_code)
    return resp, None


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    denied = _guard() or _cred_guard()
    if denied:
        return denied

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body.get("messages"):
        return jsonify({"error": {
            "message": "invalid request: 'messages' is required",
            "type": "invalid_request_error",
        }}), 400

    model_id = body.get("model", "")
    req_id = _next_req_id()
    t_in = time.time()
    # UA 是日志里唯一的客户端归因维度（API key 全客户端共用、ip 恒为 127.0.0.1）；
    # 折掉换行防伪造多行日志
    ua = (request.headers.get("User-Agent") or "-").replace("\r", " ").replace("\n", " ")
    log.info("[%s] in: model=%s stream=%s msgs=%d | ua=%s | body=%dB",
             req_id, model_id, bool(body.get("stream")),
             len(body["messages"]), ua, len(request.get_data()))

    # ── OpenRouter 路由：免费模型走 OpenRouter API，不走 CodingPlan 额度 ──
    if _is_openrouter_model(model_id):
        if not OPENROUTER_API_KEY:
            return jsonify({"error": {
                "message": "OpenRouter API key 未配置（在 ~/.atomcode/config.toml 或 OPENROUTER_API_KEY 环境变量）",
                "type": "auth_error",
            }}), 401
        or_body = dict(body)
        or_body["model"] = _openrouter_upstream_model(model_id)
        resp, err = _send_openrouter(or_body, req_id)
        if err is not None:
            return err
        want_stream = bool(body.get("stream"))
        t0 = time.time()
        if not want_stream:
            content = resp.content
            resp.close()
            log.info("[%s] done: openrouter %dB %.1fs", req_id, len(content), time.time() - t0)
            return Response(content, status=200,
                            content_type="application/json; charset=utf-8")
        def or_generate():
            total = 0
            ttft = None
            try:
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk:
                        if ttft is None:
                            ttft = time.time() - t_in
                        total += len(chunk)
                        yield chunk
                log.info("[%s] done: openrouter %dB %.1fs ttft=%s", req_id, total, time.time() - t0,
                         ("%.1fs" % ttft) if ttft is not None else "-")
            except GeneratorExit:
                log.warning("[%s] client 断开: openrouter %dB %.1fs", req_id, total, time.time() - t0)
                raise
            except Exception as e:
                log.error("[%s] 流中断: openrouter %dB %.1fs err=%s", req_id, total, time.time() - t0, e)
            finally:
                resp.close()
        return Response(or_generate(), status=200, mimetype="text/event-stream")

    # ── CodingPlan 路由 ──
    # 对齐官方 CLI（openai_compat.rs:1335）：必带 include_usage，上游才会在
    # 流末尾发 usage 块——这是额度观察与记账的依据。客户端已带则尊重客户端。
    if body.get("stream") and not body.get("stream_options"):
        body = dict(body, stream_options={"include_usage": True})

    resp, err = _send_codingplan(body, req_id, model_id)
    if err is not None:
        return err

    want_stream = bool(body.get("stream"))
    t0 = time.time()

    if not want_stream:
        content = resp.content
        resp.close()
        # 上游把额度耗尽/过载伪装成 200 的正常回复文本，识别后转正规 429
        try:
            _j = json.loads(content.decode("utf-8", "ignore"))
            _txt = (_j.get("choices") or [{}])[0].get("message", {}).get("content")
        except (ValueError, AttributeError, IndexError):
            _j, _txt = None, None
        pseudo = _detect_pseudo_reply(_txt)
        if pseudo:
            kind, reset = pseudo
            wait = _retry_after_seconds(reset)
            log.warning("[%s] quota(%s) model=%s reset=%s —— 200 伪回复转 429",
                        req_id, kind, model_id, reset or "?")
            body_err = {"error": {
                "message": _txt,
                "type": "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error",
                "code": kind,
                "reset_at": reset,
            }}
            headers = {"Retry-After": str(wait)} if wait else {}
            return jsonify(body_err), 429, headers
        log.info("[%s] done: %dB %.1fs", req_id, len(content), time.time() - t0)
        return Response(content, status=200,
                        content_type="application/json; charset=utf-8")

    # SSE 透传（上游已是 OpenAI SSE 格式，含 reasoning_content 字段）
    def generate():
        total = 0
        usage = None
        ttft = None
        text_buf = []      # 累积正文用于后置伪回复检测（上限 4KB）
        text_len = 0
        intercept = True   # 上游伪回复必以首个 content delta 整段出现，只拦那一段
        try:
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                if ttft is None:
                    ttft = time.time() - t_in
                total += len(chunk)
                contents = []
                try:
                    for line in chunk.decode("utf-8", "ignore").splitlines():
                        if not line.startswith("data:"):
                            continue
                        payload = line[5:].strip()
                        if not payload or payload == "[DONE]":
                            continue
                        d = json.loads(payload)
                        u = d.get("usage")
                        if u:
                            usage = u
                        for ch in (d.get("choices") or []):
                            c = (ch.get("delta") or {}).get("content")
                            if c:
                                contents.append(c)
                except ValueError:
                    pass
                if contents:
                    if intercept:
                        pseudo = _detect_pseudo_reply("".join(contents))
                        if pseudo:
                            kind, reset = pseudo
                            log.warning("[%s] quota(%s) model=%s reset=%s —— 流内伪回复替换为 SSE error",
                                        req_id, kind, model_id, reset or "?")
                            err = {"error": {
                                "message": "".join(contents),
                                "type": "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error",
                                "code": kind,
                                "reset_at": reset,
                                "retry_after": _retry_after_seconds(reset),
                            }}
                            yield f"data: {json.dumps(err, ensure_ascii=False)}\n\n"
                            yield "data: [DONE]\n\n"
                            return
                        intercept = False
                    if text_len < 4096:
                        text_buf.extend(contents)
                        text_len += sum(len(c) for c in contents)
                yield chunk
            ttft_s = ("%.1fs" % ttft) if ttft is not None else "-"
            info = "%dB %.1fs ttft=%s" % (total, time.time() - t0, ttft_s)
            if usage:
                info += " tokens=%s/%s" % (
                    usage.get("prompt_tokens"), usage.get("completion_tokens"))
            pseudo = _detect_pseudo_reply("".join(text_buf))
            if pseudo:
                log.warning("[%s] done: %s quota(%s) reset=%s —— 上游 200 伪回复（已透传）",
                            req_id, info, pseudo[0], pseudo[1] or "?")
            else:
                log.info("[%s] done: %s", req_id, info)
        except GeneratorExit:
            log.warning("[%s] client 断开: %dB %.1fs", req_id, total, time.time() - t0)
            raise
        except Exception as e:
            log.error("[%s] 流中断: %dB %.1fs err=%s", req_id, total, time.time() - t0, e)
        finally:
            resp.close()

    return Response(generate(), status=200, mimetype="text/event-stream")


def _first_content_line(line):
    """从 Chat SSE 原始行提取 delta.content（非内容帧返回 None）。"""
    try:
        s = line.decode("utf-8", "ignore") if isinstance(line, (bytes, bytearray)) else str(line)
        s = s.strip()
        if not s.startswith("data:"):
            return None
        payload = s[5:].strip()
        if not payload or payload == "[DONE]":
            return None
        d = json.loads(payload)
        for ch in (d.get("choices") or []):
            c = (ch.get("delta") or {}).get("content")
            if c:
                return c
    except (ValueError, AttributeError, TypeError):
        pass
    return None


# ── OpenAI Responses 端点（grok-build / Codex 等原生 Responses 客户端）──────
# 上游仍是 Chat 协议：请求体经 responses_bridge 转成 Chat，复用两条上游发送
# 分支（_send_openrouter / _send_codingplan）；响应侧包成 Responses SSE
# （每帧带 sequence_number）。额度伪回复识别与 chat 路由同款。
@app.route("/v1/responses", methods=["POST"])
def responses_api():
    denied = _guard() or _cred_guard()
    if denied:
        return denied

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body:
        return jsonify({"error": {"message": "invalid request: JSON object body required",
                                  "type": "invalid_request_error"}}), 400

    chat_body = rb.responses_to_chat(body)
    if not chat_body.get("messages"):
        return jsonify({"error": {"message": "invalid request: 'input' is required",
                                  "type": "invalid_request_error"}}), 400

    model_id = body.get("model", "")
    req_id = _next_req_id()
    want_stream = bool(chat_body.get("stream"))

    # 与 chat 同款：流式必带 include_usage，上游才会在流末发 usage 块
    if want_stream and not chat_body.get("stream_options"):
        chat_body = dict(chat_body, stream_options={"include_usage": True})

    if _is_openrouter_model(model_id):
        if not OPENROUTER_API_KEY:
            return jsonify({"error": {
                "message": "OpenRouter API key 未配置（在 ~/.atomcode/config.toml 或 OPENROUTER_API_KEY 环境变量）",
                "type": "auth_error",
            }}), 401
        or_body = dict(chat_body)
        or_body["model"] = _openrouter_upstream_model(model_id)
        resp, err = _send_openrouter(or_body, req_id)
    else:
        resp, err = _send_codingplan(chat_body, req_id, model_id)
    if err is not None:
        return err

    t0 = time.time()

    if want_stream:
        def chat_lines():
            """上游 Chat SSE 行流 + 额度伪回复拦截（首个内容命中即转错误帧）。"""
            intercept = True
            for line in resp.iter_lines(decode_unicode=False):
                if intercept:
                    c = _first_content_line(line)
                    if c:
                        pseudo = _detect_pseudo_reply(c)
                        if pseudo:
                            kind, reset = pseudo
                            log.warning("[%s] quota(%s) model=%s reset=%s —— 流内伪回复替换为 SSE error",
                                        req_id, kind, model_id, reset or "?")
                            err = {"error": {
                                "message": c,
                                "type": "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error",
                                "code": kind,
                                "reset_at": reset,
                                "retry_after": _retry_after_seconds(reset),
                            }}
                            yield b"data: " + json.dumps(err, ensure_ascii=False,
                                                         separators=(",", ":")).encode("utf-8") + b"\n\n"
                            return
                        intercept = False
                yield line

        def generate():
            total = 0
            try:
                for frame in rb.chat_sse_to_responses(chat_lines(), model_id):
                    total += len(frame)
                    yield frame
                log.info("[%s] done: responses %dB %.1fs", req_id, total, time.time() - t0)
            except GeneratorExit:
                log.warning("[%s] client 断开: responses %dB %.1fs", req_id, total, time.time() - t0)
                raise
            except Exception as e:
                log.error("[%s] 流中断: responses %dB %.1fs err=%s", req_id, total, time.time() - t0, e)
            finally:
                resp.close()

        return Response(generate(), status=200, mimetype="text/event-stream")

    # 非流式：上游返回普通 Chat JSON（body 里 stream=false）
    content = resp.content
    resp.close()
    try:
        chat_json = json.loads(content.decode("utf-8", "ignore"))
        _txt = (chat_json.get("choices") or [{}])[0].get("message", {}).get("content")
    except (ValueError, AttributeError, IndexError, TypeError):
        chat_json, _txt = None, None
    # 上游把额度耗尽/过载伪装成 200 的正常回复文本，识别后转正规 429（与 chat 同款）
    pseudo = _detect_pseudo_reply(_txt)
    if pseudo:
        kind, reset = pseudo
        wait = _retry_after_seconds(reset)
        log.warning("[%s] quota(%s) model=%s reset=%s —— 200 伪回复转 429",
                    req_id, kind, model_id, reset or "?")
        body_err = {"error": {
            "message": _txt,
            "type": "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error",
            "code": kind,
            "reset_at": reset,
        }}
        headers = {"Retry-After": str(wait)} if wait else {}
        return jsonify(body_err), 429, headers
    if not isinstance(chat_json, dict):
        return jsonify({"error": {"message": "upstream returned non-JSON body",
                                  "type": "upstream_error"}}), 502
    out = rb.chat_json_to_responses(chat_json, model_id)
    payload = json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    log.info("[%s] done: responses %dB %.1fs", req_id, len(payload), time.time() - t0)
    return Response(payload, status=200,
                    content_type="application/json; charset=utf-8")


# ── Anthropic Messages 端点（Claude Code / Kiro 等原生 Anthropic 客户端）──────
# 与 /v1/responses 同构：anthropic_bridge 把 Anthropic ⇄ Chat 翻掉，复用两条
# 上游发送分支；额度伪回复识别与 chat/responses 同款。
@app.route("/v1/messages", methods=["POST"])
def messages_api():
    denied = _guard() or _cred_guard()
    if denied:
        return denied

    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not body.get("messages"):
        return jsonify(ab.error_body("invalid_request_error",
            "invalid request: 'messages' is required")), 400

    chat_body = ab.anthropic_to_chat(body)
    if not chat_body.get("messages"):
        return jsonify(ab.error_body("invalid_request_error",
            "invalid request: 'messages' is required")), 400

    model_id = body.get("model", "")
    req_id = _next_req_id()
    want_stream = bool(chat_body.get("stream"))

    if want_stream and not chat_body.get("stream_options"):
        chat_body = dict(chat_body, stream_options={"include_usage": True})

    if _is_openrouter_model(model_id):
        if not OPENROUTER_API_KEY:
            return jsonify(ab.error_body("authentication_error",
                "OpenRouter API key 未配置")), 401
        or_body = dict(chat_body)
        or_body["model"] = _openrouter_upstream_model(model_id)
        resp, err = _send_openrouter(or_body, req_id)
    else:
        resp, err = _send_codingplan(chat_body, req_id, model_id)
    if err is not None:
        return err

    t0 = time.time()

    if want_stream:
        def chat_lines():
            intercept = True
            for line in resp.iter_lines(decode_unicode=False):
                if intercept:
                    c = _first_content_line(line)
                    if c:
                        pseudo = _detect_pseudo_reply(c)
                        if pseudo:
                            kind, reset = pseudo
                            log.warning("[%s] quota(%s) model=%s reset=%s —— 流内伪回复替换为 SSE error",
                                        req_id, kind, model_id, reset or "?")
                            err = {"error": {
                                "message": c,
                                "type": "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error",
                                "code": kind,
                                "reset_at": reset,
                                "retry_after": _retry_after_seconds(reset),
                            }}
                            yield b"data: " + json.dumps(err, ensure_ascii=False,
                                                         separators=(",", ":")).encode("utf-8") + b"\n\n"
                            return
                        intercept = False
                yield line

        def generate():
            total = 0
            try:
                for frame in ab.chat_sse_to_anthropic(chat_lines(), model_id):
                    total += len(frame)
                    yield frame
                log.info("[%s] done: messages %dB %.1fs", req_id, total, time.time() - t0)
            except GeneratorExit:
                log.warning("[%s] client 断开: messages %dB %.1fs", req_id, total, time.time() - t0)
                raise
            except Exception as e:
                log.error("[%s] 流中断: messages %dB %.1fs err=%s", req_id, total, time.time() - t0, e)
            finally:
                resp.close()

        return Response(generate(), status=200, mimetype="text/event-stream")

    content = resp.content
    resp.close()
    try:
        chat_json = json.loads(content.decode("utf-8", "ignore"))
        _txt = (chat_json.get("choices") or [{}])[0].get("message", {}).get("content")
    except (ValueError, AttributeError, IndexError, TypeError):
        chat_json, _txt = None, None
    pseudo = _detect_pseudo_reply(_txt)
    if pseudo:
        kind, reset = pseudo
        wait = _retry_after_seconds(reset)
        log.warning("[%s] quota(%s) model=%s reset=%s —— 200 伪回复转 429",
                    req_id, kind, model_id, reset or "?")
        et = "rate_limit_error" if kind == "quota_exhausted" else "overloaded_error"
        body_err = ab.error_body(et, _txt)
        headers = {"Retry-After": str(wait)} if wait else {}
        return jsonify(body_err), 429, headers
    if not isinstance(chat_json, dict):
        return jsonify(ab.error_body("api_error", "upstream returned non-JSON body")), 502
    out = ab.chat_json_to_anthropic(chat_json, model_id)
    payload = json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    log.info("[%s] done: messages %dB %.1fs", req_id, len(payload), time.time() - t0)
    return Response(payload, status=200,
                    content_type="application/json; charset=utf-8")


@app.route("/login", methods=["GET"])
def login_start():
    """发起 OAuth 登录：返回 atomgit 授权 URL，用户在浏览器打开并确认。"""
    try:
        oauth_session.start()
    except Exception as e:
        log.error("OAuth 发起失败: %s", e)
        return jsonify({"error": {"message": "OAuth 发起失败: %s" % e, "type": "auth_error"}}), 502
    return jsonify({
        "message": "在浏览器打开以下 URL 完成授权，然后 GET /login/poll 轮询",
        "login_url": oauth_session.login_url,
        "expires_in": 600,
    })


@app.route("/login/poll", methods=["GET"])
def login_poll():
    """轮询登录状态：waiting / done（完成交换并启用新凭据）。"""
    global cred
    try:
        creds, state = oauth_session.poll()
    except Exception as e:
        log.error("OAuth 轮询失败: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 502
    if creds is None:
        return jsonify({"status": state})
    save_credentials(creds)
    cred = Credential()          # 用新凭据重建（_load 读 auth.toml）
    user = creds.get("user", {})
    return jsonify({
        "status": "done",
        "username": user.get("username", ""),
        "uid": user.get("id", ""),
        "message": "登录成功，凭据已写入 ~/.atomcode/auth.toml，网关已切换到新凭据",
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "atomcode2api"})


@app.route("/status", methods=["GET"])
def status():
    """额度状态（5h 窗口水位 + 套餐到期）。"""
    denied = _guard() or _cred_guard()
    if denied:
        return denied
    s = get_status()
    if not s:
        return jsonify({"error": "无法获取状态"}), 502
    free = s.get("codingplan_free", {})
    usage = s.get("current_usage", {})
    return jsonify({
        "plan": free.get("plan_name"),
        "status": free.get("status"),
        "claimed_at": free.get("claimed_at"),
        "expires_at": free.get("expires_at"),
        "remaining_days": free.get("remaining_days"),
        "window_used": usage.get("window_tokens_used"),
        "window_limit": usage.get("window_token_limit"),
        "window_reset": usage.get("reset_at"),
        "seconds_until_reset": usage.get("seconds_until_reset"),
    })


# ── 启动 ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        cred = Credential()
        log.info("凭证账号: %s (uid: %s)", cred.username or "未命名", cred.user_id)
        if cred.is_expired():
            log.info("token 已过期，尝试刷新...")
            try:
                cred.refresh()
            except Exception as e:
                log.error("token 刷新失败: %s", e)
        claim_plan()
    except NotLoggedInError:
        cred = None
        log.warning("尚未登录，CodingPlan 路由不可用——GET /login 开始 OAuth 登录（OpenRouter 路由不受影响）")

    s = get_status()
    if s:
        free = s.get("codingplan_free", {})
        usage = s.get("current_usage", {})
        print("套餐: %s | 到期: %s | 剩余天数: %s" % (
            free.get("plan_name"), free.get("expires_at"), free.get("remaining_days")))
        print("窗口: %s/%s | 重置: %s" % (
            usage.get("window_tokens_used"), usage.get("window_token_limit"),
            usage.get("reset_at")))

    print("atomcode2api 已启动: http://%s:%s" % (LISTEN_HOST, LISTEN_PORT))
    print("OpenAI Base URL: http://%s:%s/v1" % (LISTEN_HOST, LISTEN_PORT))
    print("CodingPlan 模型: qwen3.8-27b, glm5.3-flash")
    if OPENROUTER_API_KEY:
        print("OpenRouter 模型: %d 个免费模型已接入" % len(OPENROUTER_MODELS))
    else:
        print("OpenRouter: 未配置 API key（跳过免费模型）")
    print("本地鉴权: %s" % ("已开启（API_KEY）" if API_KEY else "未开启（仅回环）"))
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, threaded=True)
