# -*- coding: utf-8 -*-
"""
/v1/cdkeyLogin 接口。

接收客户端提交的 cdkey，返回 7 天有效期的 token 及用户分组信息。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import login_service
from util.parser import parse_request

router = APIRouter()


@api_post(router, "/v1/cdkeyLogin")
async def cdkey_login(request: Request) -> Response:
    """
    CDKey 登录接口。

    @param {Request} request - 请求对象
    @returns {Response} 包含 token/boss/group/finaltime/tally 的加密响应
    """
    data_json = await parse_request(request)
    show(data_json, "cdkeyLogin >>>")

    resp = ApiResponse.success(
        login_service.build_login_data(data_json.get("nonce", ""), data_json.get("timestamp", 0))
    )
    show(resp.to_dict(), "cdkeyLogin <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "cdkey_login"]
