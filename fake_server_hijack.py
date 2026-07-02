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
from typing import Any, Callable, Dict, List, Tuple, Union
import httpx
from datetime import datetime, timedelta
from fastapi import FastAPI, Request
from starlette.responses import Response
from loguru import logger

app = FastAPI()

REAL_HOST: str = "183.131.62.35"
REAL_DOMAIN: str = "bgp.tyserve.net"
client = httpx.AsyncClient(timeout=10.0)


def compact_json(data: Dict[str, Any]) -> str:
    """
    将响应 dict 压缩为固定顺序的 JSON 字符串。

    @param {Dict[str, Any]} data - 包含 status/msg/data 的响应字典
    @returns {str} 紧凑 JSON 字符串，不含空格和 ASCII 转义
    """
    ordered = {"status": data.get("status", 200), "msg": data.get("msg", "OK"), "data": data.get("data", "")}
    return json.dumps(ordered, ensure_ascii=False, separators=(',', ':'))


def json_response(data: Dict[str, Any]) -> Response:
    """
    构造 text/html 媒介类型的 HTTP 响应，body 为紧凑 JSON。

    @param {Dict[str, Any]} data - 响应数据，需包含 status/msg/data 字段
    @returns {Response} Starlette Response 对象，Content-Type 为 text/html
    """
    return Response(compact_json(data), media_type='text/html; charset=utf-8')


# ============== 配置 ==============
appid: str = "2876"
appkey: str = "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013"
signKey: str = "jcpNWyTTzwg"
version: str = "41234"

# ============== 加密算法参数 ==============
CLIENT_ENCRYPT_MKEY: List[int] = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST: int = 104

SERVER_ENCRYPT_MKEY: List[int] = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST: int = 8


# ============== 加解密算法 ==============
def _crypt(hex_str: str, key: List[int], const: int) -> str:
    """
    通用解密算法: ((byte XOR key[i]) + const) & 0xFF。

    每两个十六进制字符为一组，先与 key 循环异或，再加常量，取低 8 位。

    @param {string} hex_str - 十六进制密文字符串
    @param {number[]} key - 加解密密钥数组，循环使用
    @param {number} const - 加解密常量
    @returns {string} 解密后的明文字符串
    """
    result = bytearray()
    kl = len(key)
    for i in range(0, len(hex_str), 2):
        b = int(hex_str[i:i+2], 16)
        result.append(((b ^ key[(i // 2) % kl]) + const) & 255)
    return result.decode('utf-8')


def decrypt_request(encrypted_hex: str) -> str:
    """
    解密客户端请求: ((byte XOR CLIENT_ENCRYPT_MKEY[i]) + CLIENT_ENCRYPT_CONST)。

    @param {string} encrypted_hex - 客户端发来的加密数据（十六进制）
    @returns {string} 解密后的 JSON 字符串
    """
    return _crypt(encrypted_hex, CLIENT_ENCRYPT_MKEY, CLIENT_ENCRYPT_CONST)


def decrypt_response(encrypted_hex: str) -> str:
    """
    解密服务器响应: ((byte XOR SERVER_ENCRYPT_MKEY[i]) + SERVER_ENCRYPT_CONST)。

    @param {string} encrypted_hex - 服务器返回的加密数据（十六进制）
    @returns {string} 解密后的 JSON 字符串
    """
    return _crypt(encrypted_hex, SERVER_ENCRYPT_MKEY, SERVER_ENCRYPT_CONST)


def encrypt_response(plain_text: str) -> str:
    """
    加密响应数据: (byte - SERVER_ENCRYPT_CONST) XOR SERVER_ENCRYPT_MKEY[i]。

    与客户端解密算法互为逆运算，用于构造返回给客户端的数据。

    @param {string} plain_text - 待加密的明文字符串
    @returns {string} 十六进制密文字符串
    """
    bytedata = plain_text.encode('utf-8')
    key = SERVER_ENCRYPT_MKEY
    kl = len(key)
    parts: List[str] = []
    for i, b in enumerate(bytedata):
        v = ((b - SERVER_ENCRYPT_CONST) ^ key[i % kl]) & 255
        parts.append(f"{v:02X}")
    return "".join(parts)


# ============== 签名验证 ==============
def verify_sign(data_json: Dict[str, Any]) -> bool:
    """
    验证客户端签名: MD5(appid + nonce + signKey + timestamp + encrypted_data)。

    拼接规则与客户端约定一致，比较时忽略大小写。

    @param {Dict<string, any>} data_json - 客户端请求体，需含 appid/nonce/timestamp/sign/data 字段
    @returns {boolean} 签名是否匹配
    """
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
def show(outer_json: Dict[str, Any], label: str) -> None:
    """
    解密并打印请求/响应数据，带颜色区分方向。

    - 传入方向（label 含 ">>>"）：用 cyan 色，对 data 字段执行 decrypt_request
    - 传出方向（label 含 "<<<"）：用 green 色，对 data 字段执行 decrypt_response
    - 解密失败时静默跳过，保留原始 data

    @param {Dict<string, any>} outer_json - 请求或响应的原始 JSON
    @param {string} label - 日志标签，含 ">>>" 表示请求方向，否则为响应方向
    """
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
def make_response_data(nonce: str, timestamp: int, extra_data: Dict[str, Any]) -> str:
    """
    构造加密后的响应 data 字段。

    将 nonce + timestamp + 业务字段组装为 JSON，再经 encrypt_response 加密。

    @param {string} nonce - 客户端请求中的 nonce，原样返回
    @param {number} timestamp - 客户端请求中的时间戳，原样返回
    @param {Dict<string, any>} extra_data - 业务层返回的额外字段
    @returns {string} 加密后的十六进制字符串
    """
    response = {"nonce": nonce, "timestamp": timestamp, **extra_data}
    return encrypt_response(json.dumps(response, ensure_ascii=False, separators=(',', ':')))


# ============== 路由装饰器 ==============
def api_post(path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    POST 路由装饰器工厂，自动注册到 FastAPI app 并提供统一异常捕获。

    被装饰函数抛出任何异常时，自动返回 status=500 的 JSON 响应并记录日志。

    @param {string} path - API 路径，如 "/v1/appInit"
    @returns {Function} 装饰器函数，接受 handler 并返回包装后的 handler
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
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


async def parse_request(request: Request) -> Tuple[Union[Dict[str, Any], None], Union[Dict[str, Any], Response]]:
    """
    解析并验证客户端请求。

    流程：读取 body JSON → 验证签名 → 解密 data 字段 → 返回结构化结果。

    @param {Request} request - FastAPI Request 对象
    @returns {[Dict|null, Dict|Response]} 元组 — 第一个元素是原始 JSON（签名失败时为 null），
             第二个元素是解密后的 data dict（签名失败时为 403 Response）
    """
    data_json = json.loads(await request.body())
    if not verify_sign(data_json):
        return None, json_response({"status": 403, "msg": "签名验证失败"})
    encrypted = data_json.get("data", "")
    decrypted = json.loads(decrypt_request(encrypted)) if encrypted else {}
    return data_json, decrypted


# ============== API 路由 ==============

@api_post('/v1/appInit')
async def app_init(request: Request) -> Response:
    """
    应用初始化接口（代理模式）。

    优先转发到 REAL_HOST 真实服务器；转发失败时降级为本地假数据响应，
    返回 fake server 的版本信息和欢迎语。

    @param {Request} request - FastAPI Request 对象
    @returns {Response} 真实服务器或假服务器的 JSON 响应
    """
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
async def cdkey_login(request: Request) -> Response:
    """
    CDKey 登录接口。

    接收客户端提交的 cdkey，返回一个 365 天有效期的 token 及用户分组信息。

    @param {Request} request - FastAPI Request 对象
    @returns {Response} 包含 token/boss/group/finaltime/tally 的加密响应
    """
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
async def set_app_message(request: Request) -> Response:
    """
    应用消息上报接口。

    接收客户端上传的消息，返回空加密响应以确认接收。

    @param {Request} request - FastAPI Request 对象
    @returns {Response} 仅含 nonce/timestamp 的加密确认响应
    """
    data_json, decrypted = await parse_request(request)
    if isinstance(decrypted, Response):
        return decrypted

    show(data_json, "setAppMessage >>>")

    response_data = make_response_data(data_json.get("nonce", ""), data_json.get("timestamp", 0), {})
    resp = {"status": 200, "msg": "OK", "data": response_data}
    show(resp, "setAppMessage <<<")
    return json_response(resp)


@api_post('/v1/userBind')
async def user_bind(request: Request) -> Response:
    """
    用户绑定接口。

    绑定成功后返回 "绑定成功" 消息，使用 UUID1 作为新 nonce。

    @param {Request} request - FastAPI Request 对象
    @returns {Response} 包含 {"msg": "绑定成功"} 的加密响应
    """
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
async def log_out(request: Request) -> Response:
    """
    登出接口。

    接收客户端提交的 token，返回空加密响应以确认登出。

    @param {Request} request - FastAPI Request 对象
    @returns {Response} 仅含 nonce/timestamp 的加密确认响应
    """
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
