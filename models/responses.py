# -*- coding: utf-8 -*-
"""
响应模型: 协议统一响应体 {"status":int, "msg":str, "data":str}。

data 为加密后的十六进制字符串；appInit 代理模式不走该模型，
由上游响应字节原样透传（见 service/upstream_proxy_service.py）。
"""

from dataclasses import dataclass
from typing import Any

from models.api_status import ApiStatus


@dataclass
class ApiResponse:
    """
    统一 API 响应模型。

    @field status {number} - 业务状态码，默认 200
    @field msg {string} - 业务提示信息，默认 "OK"
    @field data {any} - 加密后的 data 字段，默认空字符串
    """

    status: int = ApiStatus.SUCCESS
    msg: str = ApiStatus.MSG_OK
    data: Any = ""

    @classmethod
    def success(cls, data: Any = "") -> "ApiResponse":
        """
        构造成功响应。

        @param {any} data - 加密后的 data 字段
        @returns {ApiResponse} status=200 / msg="OK" 的响应模型
        """
        return cls(status=ApiStatus.SUCCESS, msg=ApiStatus.MSG_OK, data=data)

    @classmethod
    def error(cls, status: int, msg: str) -> "ApiResponse":
        """
        构造错误响应。

        @param {number} status - 业务错误码，如 403 / 500
        @param {string} msg - 错误提示信息
        @returns {ApiResponse} data 为空的错误响应模型
        """
        return cls(status=status, msg=msg, data="")

    def to_dict(self) -> dict:
        """
        转换为 compact_json / json_response 所需的字典。

        @returns {dict} 含 status/msg/data 三个键的字典
        """
        return {"status": self.status, "msg": self.msg, "data": self.data}


__all__ = ["ApiResponse"]
