# -*- coding: utf-8 -*-
"""
请求模型与响应 data 字段构造器。

ClientRequest 描述客户端请求体和其中的加密业务数据；
make_response_data 负责组装内层明文 {"nonce","timestamp",...extra} 并加密，
供 service 层返回给 controller。
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from util.response_builder import make_response_data

NonceValue = Union[str, int]


@dataclass
class ClientRequest:
    """
    客户端请求模型（签名外层）。

    @field appid {string} - 应用 ID，参与签名
    @field nonce {string} - 随机串，需原样回显
    @field timestamp {number} - 客户端时间戳，需原样回显
    @field sign {string} - MD5 签名
    @field data {string} - 加密后的业务数据（十六进制）
    """

    appid: str = ""
    nonce: str = ""
    timestamp: int = 0
    sign: str = ""
    data: str = ""

    @classmethod
    def from_dict(cls, data_json: Dict[str, Any]) -> "ClientRequest":
        """
        从解析后的请求 JSON 构造模型。

        @param {Dict<string, any>} data_json - 已通过签名校验的请求体
        @returns {ClientRequest} 请求模型实例
        """
        return cls(
            appid=str(data_json.get("appid", "")),
            nonce=data_json.get("nonce", ""),
            timestamp=data_json.get("timestamp", 0),
            sign=data_json.get("sign", ""),
            data=data_json.get("data", ""),
        )


@dataclass
class LoginPayload:
    """
    cdkeyLogin 内层业务数据模型（非严格校验，缺字段取默认值）。

    @field appkey {string} - 应用密钥
    @field version {string} - 客户端版本号
    @field cdkey {string} - 卡密
    @field mac {string} - 设备 MAC
    """

    appkey: str = ""
    version: str = ""
    cdkey: str = ""
    mac: str = ""

    @classmethod
    def from_dict(cls, inner: Optional[Dict[str, Any]]) -> "LoginPayload":
        """
        从解密后的内层 JSON 构造模型；解密失败或非对象时退化为全默认值。

        @param {Dict<string, any>|None} inner - 解密后的内层数据
        @returns {LoginPayload} 登录业务数据模型
        """
        if not isinstance(inner, dict):
            return cls()
        return cls(
            appkey=str(inner.get("appkey", "")),
            version=str(inner.get("version", "")),
            cdkey=str(inner.get("cdkey", "")),
            mac=str(inner.get("mac", "")),
        )


__all__ = ["ClientRequest", "LoginPayload", "make_response_data"]
