# -*- coding: utf-8 -*-
"""
加解密算法参数 (原 fake_server_hijack.py 的 "加密算法参数" 段)。

协议: 每字节先与密钥循环异或，再加/减常量并取低 8 位。
请求用 CLIENT_* 参数解密，响应用 SERVER_* 参数加解密。
"""

from typing import List

# 客户端请求解密参数: plain = (byte ^ key[i]) + const
CLIENT_ENCRYPT_MKEY: List[int] = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST: int = 104

# 服务器响应加解密参数: byte = (plain - const) ^ key[i]
SERVER_ENCRYPT_MKEY: List[int] = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST: int = 8

__all__ = [
    "CLIENT_ENCRYPT_MKEY",
    "CLIENT_ENCRYPT_CONST",
    "SERVER_ENCRYPT_MKEY",
    "SERVER_ENCRYPT_CONST",
]
