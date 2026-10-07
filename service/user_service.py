# -*- coding: utf-8 -*-
"""
userBind 业务逻辑 (原 user_bind 路由内的业务段)。

业务规则: 直接返回绑定成功；与其它接口不同，此处用 UUID1（带花括号、
大写）作为新 nonce、服务器当前时间作为 timestamp，而非回显请求值。
"""

import time
import uuid
from typing import Optional

from util.response_builder import make_response_data

BIND_SUCCESS_MESSAGE: str = "绑定成功"


def build_bind_data() -> str:
    """
    构造 userBind 的加密响应 data。

    @returns {string} 含 {"msg": "绑定成功"} 的加密十六进制响应 data
    """
    nonce = "{" + str(uuid.uuid1()).upper() + "}"
    return make_response_data(nonce, int(time.time()), {"msg": BIND_SUCCESS_MESSAGE})


def extract_token(data_json: dict) -> Optional[str]:
    """
    从已解析的请求体中提取加密 data（供日志/调试使用，不做校验）。

    @param {Dict<string, any>} data_json - 客户端请求 JSON
    @returns {string|None} 加密的 data 字段，缺失时为 None
    """
    encrypted = data_json.get("data", "")
    return encrypted or None


__all__ = ["build_bind_data", "extract_token", "BIND_SUCCESS_MESSAGE"]
