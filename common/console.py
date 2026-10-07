# -*- coding: utf-8 -*-
"""
控制台打印工具 (原 show 函数)。

解密并打印请求/响应数据，用颜色区分方向:
- 传入方向（label 含 ">>>"）: cyan，对 data 字段执行 decrypt_request
- 传出方向（label 含 "<<<"）: green，对 data 字段执行 decrypt_response
- 解密失败时静默跳过，保留原始 data
"""

import json
from typing import Any, Dict

from loguru import logger

from util.crypto import decrypt_request, decrypt_response


def show(outer_json: Dict[str, Any], label: str) -> None:
    """
    解密并打印请求/响应数据，带颜色区分方向。

    @param {Dict[string, any]} outer_json - 请求或响应的原始 JSON
    @param {string} label - 日志标签，含 ">>>" 表示请求方向，否则为响应方向
    """
    d = dict(outer_json)
    encrypted = d.get("data", "")
    if encrypted:
        try:
            d["data"] = json.loads(
                decrypt_response(encrypted) if "status" in d else decrypt_request(encrypted)
            )
        except (TypeError, ValueError):
            pass
    if ">>>" in label:
        logger.opt(colors=True).info(f"<cyan>{label}</cyan> {json.dumps(d, ensure_ascii=False)}")
    else:
        logger.opt(colors=True).info(f"<green>{label}</green> {json.dumps(d, ensure_ascii=False)}")


__all__ = ["show"]
