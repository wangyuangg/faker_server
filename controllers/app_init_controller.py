# -*- coding: utf-8 -*-
"""
/v1/appInit 接口（代理模式）。

与其它接口不同，appInit 不做签名校验也不解密：请求体原样转发给上游真实服务器，
上游响应体原样返回（客户端需要从响应里拿文件下载链接）。
上游不可用时返回 {"status":500,"msg":"上游服务器连接失败"}，不降级造假数据。
"""

import json

from fastapi import APIRouter, Request
from loguru import logger
from starlette.responses import Response

from common.console import show
from common.response import json_response, raw_response
from controllers.api_route import api_post
from models.api_status import ApiStatus
from service import upstream_proxy_service

router = APIRouter()


@api_post(router, "/v1/appInit")
async def app_init(request: Request) -> Response:
    """
    应用初始化接口（代理模式）。

    优先转发到真实服务器；转发失败时返回 500 错误提示。

    @param {Request} request - 请求对象，body 将被原样转发
    @returns {Response} 真实服务器的原始响应，或 500 错误响应
    """
    body = await request.body()
    data_json = json.loads(body)
    show(data_json, "appInit >>>")

    # noinspection PyBroadException
    try:
        content, status_code = await upstream_proxy_service.forward_app_init(body)
        show(json.loads(content), "appInit <<<")
        return raw_response(content, status_code)
    except Exception as e:
        logger.warning(f"[appInit] proxy failed: {e}")
        # 不降级返回假数据：客户端需要从响应里的链接下载文件，
        # 假服务器提供不了这些文件，直接返回错误
        return json_response({"status": ApiStatus.SERVER_ERROR, "msg": ApiStatus.MSG_UPSTREAM_FAILED})


__all__ = ["router", "app_init"]
