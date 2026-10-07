# -*- coding: utf-8 -*-
"""
签名验证 (原 verify_sign)。

协议不变量: sign = MD5(appid + nonce + signKey + timestamp + data)，
比较时忽略大小写；timestamp 以 str() 形式参与拼接。
"""

import hashlib
from typing import Any, Dict

from loguru import logger

from config.settings import SIGN_KEY


def verify_sign(data_json: Dict[str, Any]) -> bool:
    """
    验证客户端签名: MD5(appid + nonce + signKey + timestamp + encrypted_data)。

    @param {Dict<string, any>} data_json - 客户端请求体，需含 appid/nonce/timestamp/sign/data 字段
    @returns {boolean} 签名是否匹配
    """
    try:
        sign = data_json.get("sign", "")
        received_appid = data_json.get("appid", "")
        nonce = data_json.get("nonce", "")
        timestamp = data_json.get("timestamp", 0)
        encrypted_data = data_json.get("data", "")

        sign_str = str(received_appid) + nonce + SIGN_KEY + str(timestamp) + encrypted_data
        expected_sign = hashlib.md5(sign_str.encode()).hexdigest()

        return sign.lower() == expected_sign.lower()
    except (AttributeError, TypeError, ValueError) as e:
        logger.error(f"签名验证失败: {e}")
        return False


__all__ = ["verify_sign"]
