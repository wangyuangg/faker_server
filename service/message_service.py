# -*- coding: utf-8 -*-
"""
setAppMessage 业务逻辑 (原 set_app_message 路由内的业务段)。

业务规则: 仅确认接收客户端上报的消息，不回传任何业务字段。
"""

from typing import Any

from util.response_builder import make_response_data


def build_ack_data(nonce: Any, timestamp: Any) -> str:
    """
    构造空业务字段的确认响应 data（仅含 nonce/timestamp）。

    @param {string|number} nonce - 客户端请求中的 nonce，原样返回
    @param {string|number} timestamp - 客户端请求中的时间戳，原样返回
    @returns {string} 加密后的十六进制响应 data
    """
    return make_response_data(nonce, timestamp, {})


__all__ = ["build_ack_data"]
