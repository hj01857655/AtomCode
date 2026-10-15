# 控制面日志转发代理：127.0.0.1:18888 -> https://api.gitcode.com/api/v5
# 目的：抓 coding-plan claim/status/models 响应体，搜 D1 及其派生种子（base64/b64url/hex/原始）
# 用法：python mitm_reverse.py 1>mitm_reverse.out 2>&1 &  后台跑；随后
#   $env:ATOMCODE_CODINGPLAN_API_BASE="http://127.0.0.1:18888/api/v5"; atomcode status
import json, threading, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request

TARGET = "https://api.gitcode.com/api/v5"
LOG = pathlib.Path(r"E:\VSCodeSpace\Agent\AtomCode\AtomCode2api\tools\crypto\indep\mitm_log.jsonl")
seen = []

D1 = bytes.fromhex("01ac078b42a8a21e3572cb0c91e79d0f84f14c9c26e8008dfe68013d9712bfa2")

class H(BaseHTTPRequestHandler):
    def _proxy(self):
        body = b""
        ln = int(self.headers.get("Content-Length") or 0)
        if ln: body = self.rfile.read(ln)
        req = urllib.request.Request(TARGET + self.path[len("/api/v5"):] if self.path.startswith("/api/v5") else self.path,
                                     data=body or None, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "connection"):
                req.add_header(k, v)
        rec = {"t": self.path, "method": self.command, "req_body": body.decode("utf-8", "replace")[:2000]}
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                rb = r.read()
                rec["status"] = r.status
        except urllib.error.HTTPError as e:
            rb = e.read(); rec["status"] = e.code
        except Exception as e:
            rec["status"] = "ERR"; rec["err"] = repr(e)[:200]; rb = b""
        text = rb.decode("utf-8", "replace")
        rec["resp_head"] = text[:3000]
        # D1 形态检测
        import base64
        forms = {"hexL": D1.hex(), "hexU": D1.hex().upper(),
                 "b64": base64.b64encode(D1).decode(),
                 "b64url": base64.urlsafe_b64encode(D1).decode().rstrip("="),
                 "b64c": base64.b64encode(D1).decode().rstrip("=")}
        low = text.lower()
        rec["d1_forms"] = [n for n, f in forms.items() if f.lower() in low]
        with LOG.open("a", encoding="utf-8") as f: f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.send_response(rec["status"] if isinstance(rec["status"], int) else 502)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(rb)
    do_GET = do_POST = do_PUT = do_DELETE = _proxy
    def log_message(self, *a): pass

ThreadingHTTPServer(("127.0.0.1", 18888), H).serve_forever()
