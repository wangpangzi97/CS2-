#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""客机 → 主机 的单向文件回传口（仅 VMnet8 内网用，跑完即关）。

背景：这台机器的 VMware Tools 文件传输组件坏了 ——
`vmrun copyFileFromGuestToHost` / `copyFileFromHostToGuest` 一律报
"The file name is not valid"（而 runProgramInGuest / listProcessesInGuest 正常）。
所以改成让客机自己 POST 上来。

用法：
    python vm_pull_server.py <监听地址> <落盘目录>
    POST /up/<相对路径>   body = 原始字节，按相对路径落盘
    GET  /               返回已收到的清单
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

ROOT = ""
LOCK = threading.Lock()
RECEIVED = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静音，别刷屏
        pass

    def _reply(self, code, body=b"OK"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with LOCK:
            body = "\n".join(RECEIVED).encode("utf-8")
        self._reply(200, body or b"(empty)")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n) if n else b""
        if not self.path.startswith("/up/"):
            self._reply(404, b"bad path")
            return
        rel = unquote(self.path[4:]).replace("\\", "/").lstrip("/")
        # 防目录穿越
        rel = "/".join(p for p in rel.split("/") if p not in ("", ".", ".."))
        if not rel:
            self._reply(400, b"bad name")
            return
        dst = os.path.join(ROOT, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        with LOCK:
            RECEIVED.append("%s\t%d" % (rel, len(data)))
        self._reply(200, b"stored")


def main():
    global ROOT
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    ROOT = os.path.abspath(sys.argv[2])
    os.makedirs(ROOT, exist_ok=True)
    addr = sys.argv[1]
    host, port = addr.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    print("listening %s -> %s" % (addr, ROOT), flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
