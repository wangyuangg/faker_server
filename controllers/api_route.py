# -*- coding: utf-8 -*-
"""
POST 路由装饰器 (原 Flask 版 api_post 的注册部分)。

统一的异常捕获已上移到 common/exception_middleware.ApiExceptionMiddleware，
因此这里只负责把 async handler 注册到 APIRouter 上。

response_class=RawJsonResponse: 声明响应媒介类型为 text/html; charset=utf-8，
避免 FastAPI 默认按 application/json 生成 OpenAPI 响应模型。
"""

import functools
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter

from common.response import CONTENT_TYPE, RawJsonResponse


def api_post(router: APIRouter, path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    POST 路由装饰器工厂，注册到指定 APIRouter。

    @param {APIRouter} router - 目标路由器
    @param {string} path - API 路径，如 "/v1/appInit"
    @returns {Function} 装饰器函数，接受 handler 并返回注册后的 handler
    """

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @router.post(
            path,
            response_class=RawJsonResponse,
            responses={200: {"content": {CONTENT_TYPE: {}}}},
        )
        @functools.wraps(f)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await f(*args, **kwargs)

        return wrapper

    return decorator


__all__ = ["api_post"]
