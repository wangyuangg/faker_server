#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fake Server - URL Hijack Version (FastAPI)
"""

import json
import time
import hashlib
import uuid
import functools
import httpx
from datetime import datetime, timedelta
from fastapi import FastAPI, Request
from starlette.responses import Response
from loguru import logger

app = FastAPI()

REAL_HOST = "183.131.62.35"
REAL_DOMAIN = "bgp.tyserve.net"
client = httpx.AsyncClient(timeout=10.0)


def compact_json(data):
    ordered = {"status": data.get("status", 200), "msg": data.get("msg", "OK"), "data": data.get("data", "")}
    return json.dumps(ordered, ensure_ascii=False, separators=(',', ':'))


def json_response(data):
    return Response(compact_json(data), media_type='text/html; charset=utf-8')


# ============== 配置 ==============
appid = "2876"
appkey = "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013"
signKey = "jcpNWyTTzwg"
version = "41234"

# ============== 加密算法参数 ==============
CLIENT_ENCRYPT_MKEY = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST = 104

SERVER_ENCRYPT_MKEY = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST = 8


# ============== 加解密算法 ==============
def _crypt(hex_str, key, const):
    """通用解密: ((byte XOR key[i]) + const)"""
    result = bytearray()
    kl = len(key)
    for i in range(0, len(hex_str), 2):
        b = int(hex_str[i:i+2], 16)
        result.append(((b ^ key[(i // 2) % kl]) + const) & 255)
    return result.decode('utf-8')


def decrypt_request(encrypted_hex):
    """解密客户端请求: ((byte XOR mKey11[i]) + 104)"""
    return _crypt(encrypted_hex, CLIENT_ENCRYPT_MKEY, CLIENT_ENCRYPT_CONST)


def decrypt_response(encrypted_hex):
    """解密服务器响应: ((byte XOR mKey13[i]) + 8)"""
    return _crypt(encrypted_hex, SERVER_ENCRYPT_MKEY, SERVER_ENCRYPT_CONST)


def encrypt_response(plain_text):
    """加密服务器响应: (byte - 8) XOR mKey13[i]"""
    bytedata = plain_text.encode('utf-8')
    key = SERVER_ENCRYPT_MKEY
    kl = len(key)
    parts = []
    for i, b in enumerate(bytedata):
        v = ((b - SERVER_ENCRYPT_CONST) ^ key[i % kl]) & 255
        parts.append(f"{v:02X}")
    return "".join(parts)


# ============== 签名验证 ==============
def verify_sign(data_json):
    """验证客户端签名: MD5(appid + nonce + signKey + timestamp + data)"""
    try:
        sign = data_json.get("sign", "")
        received_appid = data_json.get("appid", "")
        nonce = data_json.get("nonce", "")
        timestamp = data_json.get("timestamp", 0)
        encrypted_data = data_json.get("data", "")

        sign_str = str(received_appid) + nonce + signKey + str(timestamp) + encrypted_data
        expected_sign = hashlib.md5(sign_str.encode()).hexdigest()

        return sign.lower() == expected_sign.lower()
    except Exception as e:
        logger.error(f"签名验证失败: {e}")
        return False


# ============== 打印工具 ==============
def show(outer_json, label):
    """解密 data 字段后完整打印，带颜色"""
    d = dict(outer_json)
    encrypted = d.get("data", "")
    if encrypted:
        try:
            d["data"] = json.loads(decrypt_response(encrypted) if "status" in d else decrypt_request(encrypted))
        except Exception:
            pass
    if ">>>" in label:
        logger.opt(colors=True).info(f"<cyan>{label}</cyan> {json.dumps(d, ensure_ascii=False)}")
    else:
        logger.opt(colors=True).info(f"<green>{label}</green> {json.dumps(d, ensure_ascii=False)}")


# ============== 生成响应数据 ==============
def make_response_data(nonce, timestamp, extra_data):
    response = {"nonce": nonce, "timestamp": timestamp, **extra_data}
    return encrypt_response(json.dumps(response, ensure_ascii=False, separators=(',', ':')))


# ============== 路由装饰器 ==============
def api_post(path):
    """带统一错误处理的 POST 路由装饰器"""
    def decorator(f):
        @app.post(path)
        @functools.wraps(f)
        async def wrapper(request: Request):
            try:
                return await f(request)
            except Exception as e:
                logger.opt(colors=True).error(f"<red>{path}</red> {e}")
                logger.exception("")
                return json_response({"status": 500, "msg": str(e)})
        return wrapper
    return decorator


async def parse_request(request: Request):
    """解析并验证请求，返回 (原始 JSON, 解密后的 data dict)"""
    data_json = json.loads(await request.body())
    if not verify_sign(data_json):
        return None, json_response({"status": 403, "msg": "签名验证失败"})
    encrypted = data_json.get("data", "")
    decrypted = json.loads(decrypt_request(encrypted)) if encrypted else {}
    return data_json, decrypted


# ============== API 路由 ==============

@api_post('/v1/appInit')
async def app_init(request: Request):
    body = await request.body()
    data_json = json.loads(body)
    show(data_json, "appInit >>>")

    try:
        r = await client.post(
            f"http://{REAL_HOST}/v1/appInit",
            content=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Host": REAL_DOMAIN}
        )
        resp_json = json.loads(r.content)
        show(resp_json, "appInit <<<")
        return Response(r.content, media_type='text/html; charset=utf-8', status_code=r.status_code)
    except Exception as e:
        logger.warning(f"[appInit] proxy failed: {e}, falling back")
        if not verify_sign(data_json):
            return json_response({"status": 403, "msg": "签名验证失败"})
        encrypted = data_json.get("data", "")
        decrypted = json.loads(decrypt_request(encrypted)) if encrypted else {}
        extra_data = {
            "notic": "欢迎使用假服务器",
            "md5": "",
            "lastVersion": version,
            "updata": 0,
            "url": "",
            "update": ""
        }
        response_data = make_response_data(data_json.get("nonce", ""), data_json.get("timestamp", 0), extra_data)
        return json_response({"status": 200, "msg": "OK", "data": response_data})


@api_post('/v1/cdkeyLogin')
async def cdkey_login(request: Request):
    data_json, decrypted = await parse_request(request)
    if isinstance(decrypted, Response):
        return decrypted

    show(data_json, "cdkeyLogin >>>")

    expire_time = datetime.now() + timedelta(days=365)
    extra_data = {
        "token": str(uuid.uuid4()).upper(),
        "boss": "ms",
        "group": "普通",
        "finaltime": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
        "tally": 0.0
    }
    response_data = make_response_data(data_json.get("nonce", ""), data_json.get("timestamp", 0), extra_data)
    resp = {"status": 200, "msg": "OK", "data": response_data}
    show(resp, "cdkeyLogin <<<")
    return json_response(resp)


@api_post('/v1/setAppMessage')
async def set_app_message(request: Request):
    data_json, decrypted = await parse_request(request)
    if isinstance(decrypted, Response):
        return decrypted

    show(data_json, "setAppMessage >>>")

    response_data = make_response_data(data_json.get("nonce", ""), data_json.get("timestamp", 0), {})
    resp = {"status": 200, "msg": "OK", "data": response_data}
    show(resp, "setAppMessage <<<")
    return json_response(resp)


@api_post('/v1/userBind')
async def user_bind(request: Request):
    data_json, decrypted = await parse_request(request)
    if isinstance(decrypted, Response):
        return decrypted

    show(data_json, "userBind >>>")

    extra_data = {"msg": "绑定成功"}
    response_data = make_response_data(
        "{" + str(uuid.uuid1()).upper() + "}",
        int(time.time()),
        extra_data
    )
    resp = {"status": 200, "msg": "OK", "data": response_data}
    show(resp, "userBind <<<")
    return json_response(resp)


@api_post('/v1/logOut')
async def log_out(request: Request):
    data_json, decrypted = await parse_request(request)
    if isinstance(decrypted, Response):
        return decrypted
    show(data_json, "logOut >>>")
    response_data = make_response_data(data_json.get("nonce", ""), data_json.get("timestamp", 0), {})
    resp = {"status": 200, "msg": "OK", "data": response_data}
    show(resp, "logOut <<<")
    return json_response(resp)


if __name__ == '__main__':
    import uvicorn
    logger.info(f"Fake Server v{version} | http://0.0.0.0:80")
    uvicorn.run(app, host='0.0.0.0', port=80, log_level='warning')
