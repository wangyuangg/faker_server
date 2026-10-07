# -*- coding: utf-8 -*-
"""
logOut 业务逻辑 (原 log_out 路由内的业务段)。

业务规则: 无服务端会话状态，仅回显 nonce/timestamp 确认登出。
"""

from typing import Any

from util.response_builder import make_response_data


def build_logout_data(nonce: Any, timestamp: Any) -> str:
    """
    构造 logOut 的加密响应 data。

    @param {string|number} nonce - 客户端请求中的 nonce，原样返回
    @param {string|number} timestamp - 客户端请求中的时间戳，原样返回
    @returns {string} 加密后的十六进制响应 data
    """
    return make_response_data(nonce, timestamp, {})


__all__ = ["build_logout_data"]
