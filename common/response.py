# -*- coding: utf-8 -*-
"""
统一响应构造 (原 Flask 版 json_response / compact_json)。

响应契约（不可破坏）:
- body 为紧凑 JSON，字段顺序固定为 status / msg / data
- ensure_ascii=False: 中文与特殊字符不做 \\uXXXX 转义，否则加密载荷不一致
- Content-Type 固定为 text/html; charset=utf-8
- 业务状态码（403/500）放在 body 的 status 字段，HTTP 状态码仍为 200；
  只有 appInit 代理会透传上游的 HTTP 状态码

FastAPI 注意: 默认的 JSONResponse 会输出 application/json 并剥离 charset，
因此这里直接返回 Starlette Response，并在路由上声明 response_class=RawJsonResponse
（避免 FastAPI 生成错误的 OpenAPI 响应模型）。
"""

import json
from typing import Any, Dict

from starlette.responses import Response

CONTENT_TYPE: str = "text/html; charset=utf-8"


class RawJsonResponse(Response):
    """
    纯文本 JSON 响应类型: Content-Type 固定为 text/html; charset=utf-8。

    仅用于路由装饰器声明 response_class，实际由 json_response / raw_response 构造。
    """

    media_type = CONTENT_TYPE


def compact_json(data: Dict[str, Any]) -> str:
    """
    将响应 dict 压缩为固定顺序的 JSON 字符串。

    @param {Dict[str, Any]} data - 包含 status/msg/data 的响应字典
    @returns {string} 紧凑 JSON 字符串，不含空格和 ASCII 转义
    """
    ordered = {
        "status": data.get("status", 200),
        "msg": data.get("msg", "OK"),
        "data": data.get("data", ""),
    }
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def json_response(data: Dict[str, Any]) -> Response:
    """
    构造 text/html 媒介类型的 HTTP 响应，body 为紧凑 JSON。

    @param {Dict[str, Any]} data - 响应数据，需包含 status/msg/data 字段
    @returns {Response} Starlette Response 对象，Content-Type 为 text/html
    """
    return Response(compact_json(data), media_type=CONTENT_TYPE)


def raw_response(content: bytes, status_code: int) -> Response:
    """
    原样透传上游响应（appInit 代理模式使用，保持上游字节不变）。

    @param {bytes} content - 上游返回的原始响应体
    @param {number} status_code - 上游 HTTP 状态码
    @returns {Response} Starlette Response 对象
    """
    return Response(content, status_code=status_code, media_type=CONTENT_TYPE)


__all__ = ["compact_json", "json_response", "raw_response", "RawJsonResponse", "CONTENT_TYPE"]
