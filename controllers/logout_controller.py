# -*- coding: utf-8 -*-
"""
/v1/logOut 接口。

接收客户端提交的 token，返回空加密响应以确认登出。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import logout_service
from util.parser import parse_request

router = APIRouter()


@api_post(router, "/v1/logOut")
async def log_out(request: Request) -> Response:
    """
    登出接口。

    @param {Request} request - 请求对象
    @returns {Response} 仅含 nonce/timestamp 的加密确认响应
    """
    data_json = await parse_request(request)
    show(data_json, "logOut >>>")

    resp = ApiResponse.success(
        logout_service.build_logout_data(data_json.get("nonce", ""), data_json.get("timestamp", 0))
    )
    show(resp.to_dict(), "logOut <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "log_out"]
