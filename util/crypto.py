# -*- coding: utf-8 -*-
"""
协议加解密算法 (原 _crypt / decrypt_request / decrypt_response / encrypt_response)。

协议不变量（不可破坏）:
- 客户端请求: plain = ((byte ^ CLIENT_ENCRYPT_MKEY[i]) + CLIENT_ENCRYPT_CONST) & 0xFF
- 服务器响应: plain = ((byte ^ SERVER_ENCRYPT_MKEY[i]) + SERVER_ENCRYPT_CONST) & 0xFF
- 响应加密为服务器解密的逆运算: byte = ((plain - const) ^ key[i]) & 0xFF
- 密文为十六进制字符串，密文每个字节对应 key 的循环下标（按字节计数，非字符计数）
"""

from typing import List

from config.crypto import (
    CLIENT_ENCRYPT_CONST,
    CLIENT_ENCRYPT_MKEY,
    SERVER_ENCRYPT_CONST,
    SERVER_ENCRYPT_MKEY,
)


def _crypt(hex_str: str, key: List[int], const: int) -> str:
    """
    通用解密算法: ((byte XOR key[i]) + const) & 0xFF。

    每两个十六进制字符为一组，先与 key 循环异或，再加常量，取低 8 位。

    @param {string} hex_str - 十六进制密文字符串
    @param {number[]} key - 加解密密钥数组，循环使用
    @param {number} const - 加解密常量
    @returns {string} 解密后的明文字符串
    """
    result = bytearray()
    kl = len(key)
    for i in range(0, len(hex_str), 2):
        b = int(hex_str[i : i + 2], 16)
        result.append(((b ^ key[(i // 2) % kl]) + const) & 255)
    return result.decode("utf-8")


def decrypt_request(encrypted_hex: str) -> str:
    """
    解密客户端请求: ((byte XOR CLIENT_ENCRYPT_MKEY[i]) + CLIENT_ENCRYPT_CONST)。

    @param {string} encrypted_hex - 客户端发来的加密数据（十六进制）
    @returns {string} 解密后的 JSON 字符串
    """
    return _crypt(encrypted_hex, CLIENT_ENCRYPT_MKEY, CLIENT_ENCRYPT_CONST)


def encrypt_request(plain_text: str) -> str:
    """
    加密客户端请求数据: (byte - CLIENT_ENCRYPT_CONST) XOR CLIENT_ENCRYPT_MKEY[i]。

    与客户端解密算法互为逆运算，用于服务端主动向上游发起合法请求
    (如 XGdun2 目标推导时的 appInit 探测)。

    @param {string} plain_text - 待加密的 JSON 明文
    @returns {string} 十六进制密文字符串
    """
    bytedata = plain_text.encode("utf-8")
    key = CLIENT_ENCRYPT_MKEY
    kl = len(key)
    parts: List[str] = []
    for i, b in enumerate(bytedata):
        v = ((b - CLIENT_ENCRYPT_CONST) ^ key[i % kl]) & 255
        parts.append(f"{v:02X}")
    return "".join(parts)


def decrypt_response(encrypted_hex: str) -> str:
    """
    解密服务器响应: ((byte XOR SERVER_ENCRYPT_MKEY[i]) + SERVER_ENCRYPT_CONST)。

    @param {string} encrypted_hex - 服务器返回的加密数据（十六进制）
    @returns {string} 解密后的 JSON 字符串
    """
    return _crypt(encrypted_hex, SERVER_ENCRYPT_MKEY, SERVER_ENCRYPT_CONST)


def encrypt_response(plain_text: str) -> str:
    """
    加密响应数据: (byte - SERVER_ENCRYPT_CONST) XOR SERVER_ENCRYPT_MKEY[i]。

    与客户端解密算法互为逆运算，用于构造返回给客户端的数据。

    @param {string} plain_text - 待加密的明文字符串
    @returns {string} 十六进制密文字符串
    """
    bytedata = plain_text.encode("utf-8")
    key = SERVER_ENCRYPT_MKEY
    kl = len(key)
    parts: List[str] = []
    for i, b in enumerate(bytedata):
        v = ((b - SERVER_ENCRYPT_CONST) ^ key[i % kl]) & 255
        parts.append(f"{v:02X}")
    return "".join(parts)


__all__ = ["decrypt_request", "decrypt_response", "encrypt_response"]
