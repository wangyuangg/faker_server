# -*- coding: utf-8 -*-
"""
上游真实服务器代理 (原 app_init 路由内的转发段)。

仅 /v1/appInit 走代理: 客户端需要从真实响应里的链接下载文件，
假服务器无法提供这些文件，因此失败时由异常中间件返回 500，不降级造假数据。

上游只提供 IP + 80 端口的明文 HTTP，无 https 可用（HttpUrlsUsage 告警属预期）。
"""

from typing import Tuple

from config.settings import settings
from util.http_client import get_client

UPSTREAM_CONTENT_TYPE: str = "application/x-www-form-urlencoded"


async def forward_app_init(body: bytes) -> Tuple[bytes, int]:
    """
    将 appInit 原始请求体转发到真实服务器（异步，不阻塞事件循环）。

    以 REAL_DOMAIN 作为 Host 头，Content-Type 保持客户端使用的表单类型。

    @param {bytes} body - 客户端原始请求体（原样透传，不解密）
    @returns {Tuple[bytes, number]} (上游响应体字节, 上游 HTTP 状态码)
    @raises httpx.HTTPError - 上游不可达/超时等异常由异常中间件转为 500
    """
    response = await get_client().post(
        f"{settings.upstream_base_url}/v1/appInit",
        content=body,
        headers={"Content-Type": UPSTREAM_CONTENT_TYPE, "Host": settings.real_domain},
    )
    return response.content, response.status_code


__all__ = ["forward_app_init", "UPSTREAM_CONTENT_TYPE"]
