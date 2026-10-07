# -*- coding: utf-8 -*-
"""
请求解析 (原 Flask 版 parse_request)。

FastAPI 中请求体需异步读取，因此本模块为 async；
路由已读取的原始 body 可通过 body 参数复用，避免重复 await。
"""

import json
from typing import Any, Dict, Optional

from common.errors import SignError
from util.crypto import decrypt_request
from util.signature import verify_sign


async def read_body(request: Any, body: Optional[bytes] = None) -> bytes:
    """
    读取请求原始 body。

    @param {Request} request - Starlette/FastAPI Request 对象
    @param {bytes|None} body - 已读取的 body，传入时直接复用
    @returns {bytes} 原始请求体字节
    """
    if body is not None:
        return body
    return await request.body()


def parse_body(raw_body: bytes) -> Dict[str, Any]:
    """
    解析并验证已读取的请求体。

    流程：JSON 反序列化 → 验证签名 → 解密 data 字段。

    签名失败时抛出 SignError（由异常中间件转换为 403 响应）；
    data 解密失败时异常原样上抛（中间件转换为 500 响应）。

    @param {bytes} raw_body - 请求原始字节
    @returns {Dict} 原始请求 JSON
    """
    data_json = json.loads(raw_body)
    if not verify_sign(data_json):
        raise SignError
    encrypted = data_json.get("data", "")
    if encrypted:
        json.loads(decrypt_request(encrypted))
    return data_json


async def parse_request(request: Any, body: Optional[bytes] = None) -> Dict[str, Any]:
    """
    解析并验证客户端请求（异步读取 + 校验）。

    @param {Request} request - Starlette/FastAPI Request 对象
    @param {bytes|None} body - 已读取的 body，传入时直接复用
    @returns {Dict} 原始请求 JSON
    """
    return parse_body(await read_body(request, body))


__all__ = ["parse_request", "parse_body", "read_body"]
