# -*- coding: utf-8 -*-
"""
/v1/userBind 接口。

绑定成功后返回 "绑定成功"，使用 UUID1 作为新 nonce。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import user_service
from util.parser import parse_request

router = APIRouter()


@api_post(router, "/v1/userBind")
async def user_bind(request: Request) -> Response:
    """
    用户绑定接口。

    @param {Request} request - 请求对象
    @returns {Response} 包含 {"msg": "绑定成功"} 的加密响应
    """
    data_json = await parse_request(request)
    show(data_json, "userBind >>>")

    resp = ApiResponse.success(user_service.build_bind_data())
    show(resp.to_dict(), "userBind <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "user_bind"]
