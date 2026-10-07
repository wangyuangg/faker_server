# -*- coding: utf-8 -*-
"""
响应状态/消息常量。

注意: status / msg 均为业务字段而非 HTTP 状态码，
HTTP 层除 appInit 代理外一律返回 200。
"""


class ApiStatus:
    """响应 status 与 msg 字面量集合。"""

    SUCCESS: int = 200
    SIGN_FAILED: int = 403
    SERVER_ERROR: int = 500

    MSG_OK: str = "OK"
    MSG_SIGN_FAILED: str = "签名验证失败"
    MSG_UPSTREAM_FAILED: str = "上游服务器连接失败"


__all__ = ["ApiStatus"]
