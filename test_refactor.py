#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重构回归测试（FastAPI 版）: 校验 MVC 重构后的行为与协议不变量。

覆盖:
- 5 个路由的响应状态、Content-Type、字段顺序
- cdkeyLogin: token 存在、boss/group/tally/finaltime 字段与 7 天有效期
- userBind: UUID1 格式的 nonce + 服务器时间戳 + "绑定成功"
- setAppMessage / logOut: 仅回显 nonce/timestamp
- 签名缺失/错误 -> 403；data 非法 -> 500；路由不存在 -> 404
- appInit 代理: 请求体与 Host 头透传到上游，上游响应字节原样返回（含上游 404 透传）
- appInit 上游不可达 -> 500 上游服务器连接失败（不降级造假数据）
- uvicorn 启动参数组装（端口/主机/热重载优先级）

用法:
    uv run test_refactor.py
"""

import hashlib
import json
import os
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

APPID = "2876"
SIGN_KEY = "jcpNWyTTzwg"
CLIENT_ENCRYPT_MKEY = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST = 104
SERVER_ENCRYPT_MKEY = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST = 8

EXPECTED_CONTENT_TYPE = "text/html; charset=utf-8"


# ============== 客户端侧协议实现（独立于服务端代码，避免“自己验自己”）==============
def encrypt_request(plain_text: str) -> str:
    """客户端请求加密: (byte - 104) XOR CLIENT_ENCRYPT_MKEY[i]"""
    data = plain_text.encode("utf-8")
    kl = len(CLIENT_ENCRYPT_MKEY)
    return "".join(f"{((b - CLIENT_ENCRYPT_CONST) ^ CLIENT_ENCRYPT_MKEY[i % kl]) & 255:02X}"
                   for i, b in enumerate(data))


def decrypt_response(encrypted_hex: str) -> str:
    """客户端响应解密: ((byte XOR SERVER_ENCRYPT_MKEY[i]) + 8)"""
    kl = len(SERVER_ENCRYPT_MKEY)
    out = bytearray()
    for i in range(0, len(encrypted_hex), 2):
        b = int(encrypted_hex[i:i + 2], 16)
        out.append(((b ^ SERVER_ENCRYPT_MKEY[(i // 2) % kl]) + SERVER_ENCRYPT_CONST) & 255)
    return out.decode("utf-8")


def build_request(inner: Optional[Dict[str, Any]] = None, sign_override: Optional[str] = None,
                  data_override: Optional[str] = None) -> Dict[str, Any]:
    """构造签名请求体；inner 为 None 时 data 为空串"""
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    timestamp = int(time.time())
    if data_override is not None:
        encrypted_data = data_override
    elif inner is None:
        encrypted_data = ""
    else:
        encrypted_data = encrypt_request(json.dumps(inner, ensure_ascii=False, separators=(",", ":")))
    sign_str = APPID + nonce + SIGN_KEY + str(timestamp) + encrypted_data
    sign = sign_override or hashlib.md5(sign_str.encode()).hexdigest()
    return {"appid": APPID, "nonce": nonce, "timestamp": timestamp, "sign": sign, "data": encrypted_data}


# ============== 断言工具 ==============
_FAILURES: List[str] = []
_CHECKS = 0


def check(condition: bool, label: str, detail: str = "") -> None:
    """记录断言结果"""
    global _CHECKS
    _CHECKS += 1
    if condition:
        print(f"  [PASS] {label}")
    else:
        print(f"  [FAIL] {label} {detail}")
        _FAILURES.append(f"{label} {detail}".strip())


def free_port() -> int:
    """获取一个空闲端口"""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ============== 假上游服务器（验证 appInit 代理透传）==============
class _UpstreamHandler(BaseHTTPRequestHandler):
    captured: Dict[str, Any] = {}
    payload: bytes = b'{"status":200,"msg":"OK","data":"FROM_UPSTREAM"}'
    status: int = 200

    def do_POST(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler 约定)
        length = int(self.headers.get("Content-Length", 0))
        _UpstreamHandler.captured = {
            "path": self.path,
            "host_header": self.headers.get("Host"),
            "content_type": self.headers.get("Content-Type"),
            "body": self.rfile.read(length),
        }
        body = _UpstreamHandler.payload
        self.send_response(_UpstreamHandler.status)
        self.send_header("Content-Type", EXPECTED_CONTENT_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """静默处理访问日志"""


def start_fake_upstream(port: int) -> HTTPServer:
    """在后台线程启动假上游服务器"""
    server = HTTPServer(("127.0.0.1", port), _UpstreamHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ============== 用例 ==============
def assert_envelope(body: bytes, label: str, expected_ct: str = EXPECTED_CONTENT_TYPE) -> Dict[str, Any]:
    """校验统一响应外层结构与字段顺序"""
    text = body.decode("utf-8")
    check(text.startswith('{"status":'), f"{label}: body 以 status 开头", text[:60])
    check(not text.endswith("\n"), f"{label}: body 无尾随换行", repr(text[-5:]))
    keys = list(json.loads(text).keys())
    check(keys == ["status", "msg", "data"], f"{label}: 字段顺序 status/msg/data", str(keys))
    return json.loads(text)


def case_ok_routes(client: Any) -> None:
    """验证 4 个本地路由的响应内容"""
    print("\n[1] 本地路由响应")

    # cdkeyLogin
    r = client.post("/v1/cdkeyLogin", json=build_request({"cdkey": "TEST-CARD", "mac": "AA:BB:CC"}))
    check(r.status_code == 200, "cdkeyLogin: HTTP 200", str(r.status_code))
    check(r.headers["content-type"] == EXPECTED_CONTENT_TYPE, "cdkeyLogin: Content-Type",
          r.headers["content-type"])
    outer = assert_envelope(r.content, "cdkeyLogin")
    check(outer["status"] == 200 and outer["msg"] == "OK", "cdkeyLogin: status/msg", str(outer)[:80])
    inner = json.loads(decrypt_response(outer["data"]))
    check(set(inner) == {"nonce", "timestamp", "token", "boss", "group", "finaltime", "tally"},
          "cdkeyLogin: 内层字段集合", str(list(inner)))
    check(inner["boss"] == "ms" and inner["group"] == "普通" and inner["tally"] == 0.0,
          "cdkeyLogin: boss/group/tally", str(inner))
    check(len(inner["token"]) == 36 and inner["token"] == inner["token"].upper(),
          "cdkeyLogin: token 为 36 位大写 UUID", inner["token"])
    finaltime = datetime.strptime(inner["finaltime"], "%Y-%m-%d %H:%M:%S")
    delta = finaltime - datetime.now()
    check(timedelta(days=6, hours=23) < delta < timedelta(days=7, minutes=1),
          "cdkeyLogin: 有效期 7 天", str(delta))

    # setAppMessage
    req = build_request({"msg": "hello"})
    r = client.post("/v1/setAppMessage", json=req)
    outer = assert_envelope(r.content, "setAppMessage")
    inner = json.loads(decrypt_response(outer["data"]))
    check(inner == {"nonce": req["nonce"], "timestamp": req["timestamp"]},
          "setAppMessage: 仅回显 nonce/timestamp", str(inner))

    # logOut
    req = build_request({"token": "T"})
    r = client.post("/v1/logOut", json=req)
    outer = assert_envelope(r.content, "logOut")
    inner = json.loads(decrypt_response(outer["data"]))
    check(inner == {"nonce": req["nonce"], "timestamp": req["timestamp"]},
          "logOut: 仅回显 nonce/timestamp", str(inner))

    # userBind
    before = int(time.time())
    r = client.post("/v1/userBind", json=build_request(None))
    after = int(time.time())
    outer = assert_envelope(r.content, "userBind")
    inner = json.loads(decrypt_response(outer["data"]))
    check(inner.get("msg") == "绑定成功", "userBind: msg=绑定成功", str(inner))
    nonce = inner.get("nonce", "")
    check(nonce.startswith("{") and nonce.endswith("}"), "userBind: nonce 带花括号", nonce)
    check(len(nonce) == 38, "userBind: nonce 长度 38 (UUID1 大写加括号)", nonce)
    check(isinstance(inner.get("timestamp"), int), "userBind: timestamp 为整数", str(type(inner.get("timestamp"))))
    check(before <= inner["timestamp"] <= after, "userBind: timestamp 为服务器当前时间", str(inner["timestamp"]))

    # getAppCode (本地合成, 值须使客户端 stof 门控通过: float32 == 0x477B548E / 64340.555)
    req = build_request({"appkey": "K", "token": "T", "uname": "U", "func": "XGdun", "param": "1, 2, 3, 4"})
    r = client.post("/v1/getAppCode", json=req)
    outer = assert_envelope(r.content, "getAppCode")
    inner = json.loads(decrypt_response(outer["data"]))
    check(set(inner) == {"nonce", "timestamp", "value"}, "getAppCode: 内层字段集合", str(list(inner)))
    check(inner["nonce"] == req["nonce"] and inner["timestamp"] == req["timestamp"],
          "getAppCode: 回显 nonce/timestamp", str(inner))
    import struct as _st
    _gate = _st.unpack('<f', _st.pack('<I', 0x477B548E))[0]
    _got = _st.unpack('<f', _st.pack('<f', float(inner["value"])))
    check(_got[0] == _gate, f"getAppCode: value float32 == 门控魔数 {_gate} (0x477B548E)",
          f"stof({inner['value']!r}) -> {_got[0]}")

    # getVerCore (本地合成, 镜像真实上游快照; 可 env 覆盖)
    req = build_request({"appkey": "K", "token": "T", "uname": "U", "version": "41234"})
    r = client.post("/v1/getVerCore", json=req)
    outer = assert_envelope(r.content, "getVerCore")
    inner = json.loads(decrypt_response(outer["data"]))
    check(set(inner) == {"nonce", "timestamp", "state", "md5", "data", "url", "update"},
          "getVerCore: 内层字段集合", str(list(inner)))
    check(inner["state"] == 1, "getVerCore: state=1 (正式版)", str(inner["state"]))
    check(isinstance(inner["md5"], str) and len(inner["md5"]) == 32, "getVerCore: md5 为 32 位 hex",
          inner["md5"])
    check(len(inner["data"]) == 6 * 33, "getVerCore: data 为 6 段 字母+32hex 版本清单", str(len(inner["data"])))
    check("netbios.vmp.dll" in inner["update"], "getVerCore: update 含 vmp blob URL", inner["update"][:80])
    # 业务字段类型回显（非字符串 nonce/timestamp 必须原样保留）
    r = client.post("/v1/setAppMessage", json=build_request({"a": 1}))
    inner = json.loads(decrypt_response(json.loads(r.content)["data"]))
    check(isinstance(inner["timestamp"], int), "回显: timestamp 保持 int 类型", str(type(inner["timestamp"])))


def case_sign_failures(client: Any) -> None:
    """验证签名与解密异常分支"""
    print("\n[2] 异常分支")

    bad = build_request({"cdkey": "X"})
    bad["sign"] = "0" * 32
    r = client.post("/v1/cdkeyLogin", json=bad)
    outer = assert_envelope(r.content, "签名错误")
    check(r.status_code == 200, "签名错误: HTTP 仍为 200（业务码在 body）", str(r.status_code))
    check(outer == {"status": 403, "msg": "签名验证失败", "data": ""},
          "签名错误 -> 403 签名验证失败", str(outer))

    no_sign = build_request({"cdkey": "X"})
    del no_sign["sign"]
    r = client.post("/v1/cdkeyLogin", json=no_sign)
    check(json.loads(r.content)["status"] == 403, "签名缺失 -> 403", r.content.decode())

    raw = b"not json at all"
    r = client.post("/v1/cdkeyLogin", content=raw,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    check(r.headers["content-type"] == EXPECTED_CONTENT_TYPE, "非法 JSON: Content-Type 不变",
          r.headers["content-type"])
    check(json.loads(r.content)["status"] == 500, "非法 JSON -> 500 且为 JSON 信封", r.content.decode()[:80])

    # 非法 hex 解密失败 -> 500（签名按非法 data 正确计算，确保走到解密分支）
    broken = build_request(data_override="ZZZZ")
    r = client.post("/v1/cdkeyLogin", json=broken)
    outer = json.loads(r.content)
    check(outer["status"] == 500 and outer["msg"], "非法 data -> 500 且带 msg", str(outer)[:80])

    # 空 data 可正常解密（不抛异常）
    r = client.post("/v1/setAppMessage", json=build_request(None))
    check(json.loads(r.content)["status"] == 200, "空 data -> 200", r.content.decode())

    # 未知路由走 Starlette 默认 404（非协议信封）
    r = client.post("/v1/nope", json=build_request(None))
    check(r.status_code == 404, "未知路由 -> HTTP 404", str(r.status_code))


def case_app_init_proxy(client: Any) -> None:
    """验证 appInit 代理透传与上游响应原样返回"""
    print("\n[3] appInit 代理")

    req = build_request({"appkey": "K", "version": "41234"})
    body = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    r = client.post("/v1/appInit", content=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"})

    check(r.content == _UpstreamHandler.payload, "appInit: 上游响应字节原样返回", r.content.decode()[:80])
    check(r.status_code == 200, "appInit: 透传上游 HTTP 状态", str(r.status_code))
    check(r.headers["content-type"] == EXPECTED_CONTENT_TYPE, "appInit: Content-Type",
          r.headers["content-type"])
    cap = _UpstreamHandler.captured
    check(cap.get("path") == "/v1/appInit", "appInit: 转发路径 /v1/appInit", str(cap.get("path")))
    check(cap.get("host_header") == "bgp.tyserve.net", "appInit: Host 头为真实域名", str(cap.get("host_header")))
    check(cap.get("body") == body, "appInit: 请求体原样透传", str(cap.get("body"))[:60])
    check(cap.get("content_type") == "application/x-www-form-urlencoded",
          "appInit: 上游 Content-Type", str(cap.get("content_type")))

    # 上游非 200 时同样透传字节与状态码
    _UpstreamHandler.status = 404
    _UpstreamHandler.payload = b'{"status":404,"msg":"NOT FOUND","data":""}'
    try:
        r = client.post("/v1/appInit", content=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        check(r.status_code == 404 and r.content == _UpstreamHandler.payload,
              "appInit: 上游 404 透传", f"{r.status_code} {r.content.decode()}")
    finally:
        _UpstreamHandler.status = 200
        _UpstreamHandler.payload = b'{"status":200,"msg":"OK","data":"FROM_UPSTREAM"}'


def case_app_init_upstream_down(client: Any) -> None:
    """验证上游不可达时的降级错误（不造假数据）"""
    print("\n[4] appInit 上游不可达")

    import config.settings as settings_module

    original_host = settings_module.settings.real_host
    object.__setattr__(settings_module.settings, "real_host", "127.0.0.1:1")
    try:
        req = build_request({"appkey": "K", "version": "1"})
        r = client.post("/v1/appInit", json=req,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        outer = json.loads(r.content)
        check(outer == {"status": 500, "msg": "上游服务器连接失败", "data": ""},
              "上游不可达 -> 500 上游服务器连接失败", str(outer))
    finally:
        object.__setattr__(settings_module.settings, "real_host", original_host)


def case_server_config() -> None:
    """验证 uvicorn 启动参数组装"""
    print("\n[5] 启动参数")

    import app as app_module

    cfg = app_module.build_server_config()
    check(cfg["host"] == "0.0.0.0" and cfg["port"] == 8123,
          "默认取自 settings (FAKER_PORT=8123)", f"{cfg['host']}:{cfg['port']}")
    cfg = app_module.build_server_config(port=9000)
    check(cfg["port"] == 9000, "port 参数覆盖 settings", str(cfg["port"]))
    cfg = app_module.build_server_config(host="127.0.0.1")
    check(cfg["host"] == "127.0.0.1", "host 参数覆盖 settings", str(cfg["host"]))
    cfg = app_module.build_server_config(reload=True)
    check(cfg["reload"] is True, "reload 参数生效", str(cfg["reload"]))
    cfg = app_module.build_server_config(reload=False)
    check(cfg["reload"] is False, "reload=False 生效", str(cfg["reload"]))
    check(cfg["log_config"]["loggers"]["uvicorn.access"]["level"] == "WARNING",
          "uvicorn 访问日志压到 WARNING（请求日志交给 loguru）",
          str(cfg["log_config"]["loggers"]["uvicorn.access"]))
    check(app_module.app is not None, "uvicorn app:app 可用（模块级 app 存在）", "")


def app_paths_and_methods(app: Any) -> List[Tuple[str, str]]:
    """
    收集应用实际暴露的 (path, method) 列表。

    FastAPI 0.142 起 app.routes 中是 _IncludedRouter 包装对象，
    真实路由在 original_router.routes 里，这里做一次展开。
    """
    found: List[Tuple[str, str]] = []

    def walk(routes: Any) -> None:
        for route in routes:
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(inner.routes)
                continue
            path = getattr(route, "path", None)
            if path is None:
                continue
            for method in sorted(getattr(route, "methods", None) or []):
                if method not in ("HEAD", "OPTIONS"):
                    found.append((path, method))

    walk(app.routes)
    return sorted(found)


def main() -> int:
    """执行全部回归用例"""
    upstream_port = free_port()
    server = start_fake_upstream(upstream_port)

    # 必须在导入 app 之前设置，settings 在导入期读取环境变量
    os.environ["FAKER_REAL_HOST"] = f"127.0.0.1:{upstream_port}"
    os.environ["FAKER_PORT"] = "8123"

    from fastapi.testclient import TestClient  # noqa: E402
    from app import app  # noqa: E402  延迟导入以应用环境变量

    exposed = app_paths_and_methods(app)
    print(f"已注册路由: {exposed}")
    check(exposed == [
        ("/v1/appInit", "POST"),
        ("/v1/cdkeyLogin", "POST"),
        ("/v1/getAppCode", "POST"),
        ("/v1/getVerCore", "POST"),
        ("/v1/logOut", "POST"),
        ("/v1/setAppMessage", "POST"),
        ("/v1/userBind", "POST"),
    ], "路由集合与客户端 7 个接口一致", str(exposed))
    check(not any(path in ("/docs", "/openapi.json", "/redoc") for path, _ in exposed),
          "内置文档接口已关闭", str(exposed))

    with TestClient(app) as client:
        case_ok_routes(client)
        case_sign_failures(client)
        case_app_init_proxy(client)
        case_app_init_upstream_down(client)

    case_server_config()
    server.shutdown()

    print("\n" + "=" * 60)
    if _FAILURES:
        print(f"FAILED: {len(_FAILURES)}/{_CHECKS} 项断言未通过")
        for item in _FAILURES:
            print(f"  - {item}")
        return 1
    print(f"ALL PASSED: {_CHECKS}/{_CHECKS} 项断言通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
