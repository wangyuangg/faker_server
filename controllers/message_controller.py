# -*- coding: utf-8 -*-
"""
/v1/setAppMessage 接口。

接收客户端上报的消息，返回空加密响应以确认接收。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import message_service
from util.parser import parse_request

router = APIRouter()


@api_post(router, "/v1/setAppMessage")
async def set_app_message(request: Request) -> Response:
    """
    应用消息上报接口。

    @param {Request} request - 请求对象
    @returns {Response} 仅含 nonce/timestamp 的加密确认响应
    """
    data_json = await parse_request(request)
    show(data_json, "setAppMessage >>>")

    resp = ApiResponse.success(
        message_service.build_ack_data(data_json.get("nonce", ""), data_json.get("timestamp", 0))
    )
    show(resp.to_dict(), "setAppMessage <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "set_app_message"]
