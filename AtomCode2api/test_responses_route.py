# -*- coding: utf-8 -*-
"""/v1/responses 路由端到端验证（Flask test_client + mock 上游，不连真实 CodingPlan/OpenRouter）。

monkeypatch 掉 requests.post / cred / API_KEY / OPENROUTER_API_KEY，覆盖：
  1. /v1/responses 流式（CodingPlan 模型）：Responses SSE 合法
  2. /v1/responses 非流式（CodingPlan 模型）：Responses JSON 合法
  3. /v1/responses 流式（OpenRouter 模型）：模型映射后走 OpenRouter 分支
  4. /v1/chat/completions 流式回归：_send_* 抽取不破坏老路由
  5. /v1/responses 流式额度伪回复拦截：首个内容命中即 response.failed
"""
import json

import server


class FakeCred:
    def headers(self):
        return {"Authorization": "Bearer fake"}

    def refresh(self):
        pass


class FakeUpstream:
    def __init__(self, raw=b"", status=200, content_type="text/event-stream"):
        self._raw = raw
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        self.closed = False

    @property
    def content(self):
        return self._raw

    @property
    def text(self):
        return self._raw.decode("utf-8", "replace")

    def close(self):
        self.closed = True

    def iter_lines(self, decode_unicode=False):
        for block in self._raw.split(b"\n\n"):
            yield block

    def iter_content(self, chunk_size=4096):
        yield self._raw


def sse(*objs):
    parts = []
    for o in objs:
        parts.append(o if isinstance(o, bytes)
                     else b"data: " + json.dumps(o, ensure_ascii=False).encode())
    return b"\n\n".join(parts) + b"\n\n"


def parse_frames(raw):
    events = []
    for block in raw.split(b"\n\n"):
        block = block.strip()
        if not block.startswith(b"data:"):
            continue
        payload = block[5:].decode("utf-8").strip()
        if not payload or payload == "[DONE]":
            continue
        events.append(json.loads(payload))
    return events


USAGE = {"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17,
         "completion_tokens_details": {"reasoning_tokens": 3},
         "prompt_tokens_details": {"cached_tokens": 0}}

CHAT_STREAM = sse(
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {"role": "assistant", "reasoning_content": "think "},
                  "finish_reason": None}]},
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {"reasoning_content": "ok"}, "finish_reason": None}]},
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {"content": "Hi!"}, "finish_reason": None}]},
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {"tool_calls": [
         {"index": 0, "id": "call_1", "type": "function",
          "function": {"name": "get_weather", "arguments": '{"city": "BJ"}'}}]},
         "finish_reason": None}]},
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
    {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": [],
     "usage": USAGE},
    b"data: [DONE]",
)

CHAT_JSON = {"id": "c2", "object": "chat.completion", "created": 1, "model": "m",
             "choices": [{"index": 0,
                          "message": {"role": "assistant", "content": "Hi!",
                                      "reasoning_content": "think ok"},
                          "finish_reason": "stop"}],
             "usage": USAGE}
CHAT_JSON_BYTES = json.dumps(CHAT_JSON).encode()

# 命中 PSEUDO_REPLY_RES 的 overload 模板
PSEUDO_STREAM = sse(
    {"id": "c3", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0,
                  "delta": {"role": "assistant",
                            "content": "模型「qwen3.8-27b」的请求负载过高，请稍后再试。"},
                  "finish_reason": None}]},
    {"id": "c3", "object": "chat.completion.chunk", "created": 1, "model": "m",
     "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    b"data: [DONE]",
)

captured = {}


def install_fake(mode="stream"):
    server.cred = FakeCred()
    server.API_KEY = ""
    server.OPENROUTER_API_KEY = "fake-or-key"

    def fake_post(url, json=None, headers=None, stream=None, timeout=None):
        captured["url"] = url
        captured["payload"] = json
        if mode == "json":
            return FakeUpstream(CHAT_JSON_BYTES, content_type="application/json")
        if mode == "pseudo":
            return FakeUpstream(PSEUDO_STREAM)
        return FakeUpstream(CHAT_STREAM)

    server.requests.post = fake_post


def main():
    client = server.app.test_client()
    resp_req = {
        "model": "qwen3.8-27b",
        "stream": True,
        "instructions": "sys prompt",
        "input": [{"type": "message", "role": "user", "content": "hello"}],
        "tools": [{"type": "function", "name": "get_weather", "description": "w",
                   "parameters": {"type": "object",
                                  "properties": {"city": {"type": "string"}}}}],
    }

    # ---------- 1) /v1/responses 流式（CodingPlan） ----------
    install_fake("stream")
    r = client.post("/v1/responses", json=resp_req)
    assert r.status_code == 200, (r.status_code, r.data[:500])
    assert "text/event-stream" in r.headers.get("Content-Type", "")

    cb = captured["payload"]
    assert captured["url"].startswith("https://api-ai.gitcode.com"), captured["url"]
    assert cb["messages"][0] == {"role": "system", "content": "sys prompt"}
    assert cb["messages"][1] == {"role": "user", "content": "hello"}
    assert cb["stream"] is True
    assert cb["stream_options"] == {"include_usage": True}
    assert cb["tools"][0]["function"]["name"] == "get_weather"

    events = parse_frames(r.data)
    seqs = [e["sequence_number"] for e in events]
    assert seqs == list(range(len(events))), seqs
    types = [e["type"] for e in events]
    print("responses 流事件序列（%d 帧）:" % len(events))
    for i, e in enumerate(events):
        print("  %2d %s" % (i, e["type"]))
    assert types[0] == "response.created"
    assert types[-1] == "response.completed"
    final = events[-1]["response"]
    for k in ("id", "object", "created_at", "model", "status", "output"):
        assert k in final, k
    assert final["status"] == "completed"
    assert [o["type"] for o in final["output"]] == \
        ["reasoning", "message", "function_call"], final["output"]
    assert final["usage"]["total_tokens"] == 17
    fn = final["output"][2]
    assert fn["call_id"] == "call_1" and fn["arguments"] == '{"city": "BJ"}'

    # ---------- 2) /v1/responses 非流式（CodingPlan） ----------
    install_fake("json")
    r = client.post("/v1/responses", json=dict(resp_req, stream=False))
    assert r.status_code == 200, (r.status_code, r.data[:500])
    out = r.get_json()
    assert out["object"] == "response" and out["status"] == "completed"
    assert [o["type"] for o in out["output"]] == ["reasoning", "message"]
    assert out["usage"]["total_tokens"] == 17

    # ---------- 3) /v1/responses 流式（OpenRouter 模型） ----------
    install_fake("stream")
    r = client.post("/v1/responses",
                    json=dict(resp_req, model="openrouter/thinkingmachines/inkling:free"))
    assert r.status_code == 200, (r.status_code, r.data[:500])
    assert captured["url"].startswith("https://openrouter.ai"), captured["url"]
    assert captured["payload"]["model"] == "thinkingmachines/inkling:free"
    events = parse_frames(r.data)
    assert events[-1]["type"] == "response.completed"

    # ---------- 4) /v1/chat/completions 回归（CodingPlan 流式） ----------
    install_fake("stream")
    r = client.post("/v1/chat/completions",
                    json={"model": "qwen3.8-27b", "stream": True,
                          "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200, (r.status_code, r.data[:300])
    assert b"data: " in r.data and b"[DONE]" in r.data
    assert r.data == CHAT_STREAM  # 透传行为不变

    # ---------- 5) 流内额度伪回复拦截 -> response.failed ----------
    install_fake("pseudo")
    r = client.post("/v1/responses", json=resp_req)
    assert r.status_code == 200, (r.status_code, r.data[:500])
    events = parse_frames(r.data)
    assert events[-1]["type"] == "response.failed", events[-1]
    err = events[-1]["response"]["error"]
    assert err["code"] == "overloaded"

    print("ALL PASS")


if __name__ == "__main__":
    main()
