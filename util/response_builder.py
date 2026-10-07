# -*- coding: utf-8 -*-
"""
响应 data 字段构造 (原 make_response_data)。

协议不变量: 内层明文为 {"nonce":..., "timestamp":..., ...extra_data}，
nonce/timestamp 原样回显客户端值（保留其原始 JSON 类型），
JSON 不做 ASCII 转义，最后经 encrypt_response 加密为十六进制。
"""

import json
from typing import Any, Dict, Union

from util.crypto import encrypt_response

NonceValue = Union[str, int]


def make_response_data(nonce: NonceValue, timestamp: NonceValue, extra_data: Dict[str, Any]) -> str:
    """
    构造加密后的响应 data 字段。

    @param {string|number} nonce - 回显给客户端的 nonce
    @param {string|number} timestamp - 回显给客户端的时间戳
    @param {Dict<string, any>} extra_data - 业务层返回的额外字段
    @returns {string} 加密后的十六进制字符串
    """
    response = {"nonce": nonce, "timestamp": timestamp, **extra_data}
    return encrypt_response(json.dumps(response, ensure_ascii=False, separators=(",", ":")))


__all__ = ["make_response_data"]
