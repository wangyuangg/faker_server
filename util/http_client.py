# -*- coding: utf-8 -*-
"""
共享的上游 HTTP 客户端 (原 fake_server_hijack.py 的模块级 httpx.Client)。

FastAPI 运行在事件循环里，因此使用 httpx.AsyncClient 避免阻塞请求处理；
惰性创建单例，连接池在整个事件循环内复用。
"""

from typing import Optional

import httpx

from config.settings import settings

_client: Optional[httpx.AsyncClient] = None


def get_client() -> httpx.AsyncClient:
    """
    获取全局共享的上游异步 HTTP 客户端（首次调用时创建）。

    @returns {httpx.AsyncClient} 异步客户端，超时取 settings.upstream_timeout
    """
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=settings.upstream_timeout)
    return _client


async def close_client() -> None:
    """
    关闭共享客户端并释放连接池（应用 shutdown 时调用）。
    """
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


__all__ = ["get_client", "close_client"]
