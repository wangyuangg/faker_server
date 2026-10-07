# -*- coding: utf-8 -*-
"""
cdkeyLogin 业务逻辑 (原 cdkey_login 路由内的业务段)。

业务规则: 任意 cdkey 均登录成功，签发 7 天有效期的 token，
返回 ms / 普通 / tally=0.0 的固定分组信息。
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict

from util.response_builder import make_response_data

TOKEN_VALID_DAYS: int = 7
TOKEN_TIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"


def build_login_data(nonce: Any, timestamp: Any) -> str:
    """
    构造 cdkeyLogin 的加密响应 data。

    @param {string|number} nonce - 客户端请求中的 nonce，原样返回
    @param {string|number} timestamp - 客户端请求中的时间戳，原样返回
    @returns {string} 加密后的十六进制响应 data
    """
    expire_time = datetime.now() + timedelta(days=TOKEN_VALID_DAYS)
    extra_data: Dict[str, Any] = {
        "token": str(uuid.uuid4()).upper(),
        "boss": "ms",
        "group": "普通",
        "finaltime": expire_time.strftime(TOKEN_TIME_FORMAT),
        "tally": 0.0,
    }
    return make_response_data(nonce, timestamp, extra_data)


__all__ = ["build_login_data", "TOKEN_VALID_DAYS"]
