#!/usr/bin/env python3
"""单独测试 /v1/appInit 接口 — 从 fake_server_hijack.py 摘出"""
import json
import time
import hashlib
import uuid
import httpx
import asyncio

# ============== 加密参数（来自 fake_server_hijack.py）==============
CLIENT_ENCRYPT_MKEY = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST = 104

SERVER_ENCRYPT_MKEY = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST = 8

# ============== 配置 ==============
REAL_HOST = "183.131.62.35"
REAL_DOMAIN = "bgp.tyserve.net"

appid = "2876"
appkey = "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013"
signKey = "jcpNWyTTzwg"

# ============== 加解密（来自 fake_server_hijack.py）==============
def encrypt_request(plain_text):
    """加密客户端请求: (byte - 104) XOR mKey11[i]"""
    bytedata = plain_text.encode('utf-8')
    key = CLIENT_ENCRYPT_MKEY
    kl = len(key)
    parts = []
    for i, b in enumerate(bytedata):
        v = ((b - CLIENT_ENCRYPT_CONST) ^ key[i % kl]) & 255
        parts.append(f"{v:02X}")
    return "".join(parts)


def decrypt_response(encrypted_hex):
    """解密服务器响应: ((byte XOR mKey13[i]) + 8)"""
    key = SERVER_ENCRYPT_MKEY
    const = SERVER_ENCRYPT_CONST
    result = bytearray()
    kl = len(key)
    for i in range(0, len(encrypted_hex), 2):
        b = int(encrypted_hex[i:i+2], 16)
        result.append(((b ^ key[(i // 2) % kl]) + const) & 255)
    return result.decode('utf-8')


# ============== 构造请求（签名逻辑来自 fake_server_hijack.py verify_sign）==============
def build_init_request(version="123144"):
    """构造 /v1/appInit 的加密签名请求体"""
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    timestamp = int(time.time())

    # 内层 data
    inner = {"appkey": appkey, "version": version}
    inner_json = json.dumps(inner, ensure_ascii=False, separators=(',', ':'))
    encrypted_data = encrypt_request(inner_json)

    # 签名: MD5(appid + nonce + signKey + timestamp + data)
    sign_str = appid + nonce + signKey + str(timestamp) + encrypted_data
    sign = hashlib.md5(sign_str.encode()).hexdigest()

    return {
        "appid": appid,
        "nonce": nonce,
        "timestamp": timestamp,
        "sign": sign,
        "data": encrypted_data
    }


# ============== 发送请求 ==============
async def call_app_init(host="127.0.0.1", port=80, version="41234", real_mode=False):
    req = build_init_request(version)
    url = f"http://{host}:{port}/v1/appInit"

    print("=" * 60)
    print(f"POST {url}")
    print(f"内层明文: {json.dumps({'appkey': appkey, 'version': version}, ensure_ascii=False)}")
    print(f"加密后 data: {req['data']}")
    print(f"签名: {req['sign']}")
    print(f"完整请求: {json.dumps(req, ensure_ascii=False)}")
    print("=" * 60)

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if real_mode:
        headers["Host"] = REAL_DOMAIN

    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(url, content=json.dumps(req, ensure_ascii=False, separators=(',', ':')),
                              headers=headers)

    resp_json = r.json()
    print(f"HTTP {r.status_code}")
    print(f"status: {resp_json.get('status')}, msg: {resp_json.get('msg')}")

    encrypted_data = resp_json.get("data", "")
    if encrypted_data:
        try:
            decrypted = json.loads(decrypt_response(encrypted_data))
            print(f"解密后 data: {json.dumps(decrypted, ensure_ascii=False, indent=2)}")
        except Exception as e:
            print(f"解密失败: {e}")
            print(f"原始 data: {encrypted_data}")
    else:
        print(f"响应: {json.dumps(resp_json, ensure_ascii=False)}")

    return resp_json


if __name__ == "__main__":
    import sys
    # 加上 --real 就走真实服务器（带 Host header）
    real_mode = "--real" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    host = args[0] if len(args) > 0 else ("127.0.0.1" if not real_mode else REAL_HOST)
    port = int(args[1]) if len(args) > 1 else 80
    version = args[2] if len(args) > 2 else "41234"
    if real_mode:
        print(f"[真实模式] target={host}:{port}, Host header={REAL_DOMAIN}")
    asyncio.run(call_app_init(host, port, version, real_mode=real_mode))
