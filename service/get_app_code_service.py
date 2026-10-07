# -*- coding: utf-8 -*-
"""
getAppCode 业务逻辑 —— 只做协议组装, func 分派交给 service/remote_funcs 注册表。

响应契约: data = encrypt({"nonce":…, "timestamp":…, **handler 字段})。
本模块不再包含任何 func 相关的 if/else: 新增接口只需在 remote_funcs/ 下注册。
"""

from typing import Any, Optional

from service.remote_funcs import dispatch
from service.remote_funcs.xgdun2 import (  # noqa: F401  (向后兼容的再导出)
    get_xgdun2_value,
    parse_xgdun2_param,
)
from util.response_builder import make_response_data


def build_app_code_data(nonce: Any, timestamp: Any, request_data: Optional[dict] = None) -> str:
    """
    构造 getAppCode 响应 data (nonce/timestamp 回显 + handler 字段)。

    @param {string|number} nonce - 客户端请求中的 nonce，原样回显
    @param {string|number} timestamp - 客户端请求中的时间戳，原样回显
    @param {Dict|None} request_data - 解密后的请求内层数据 (含 func/param)
    @returns {string} 加密后的十六进制响应 data
    """
    return make_response_data(nonce, timestamp, dispatch(request_data or {}))


__all__ = ["build_app_code_data", "parse_xgdun2_param", "get_xgdun2_value"]
