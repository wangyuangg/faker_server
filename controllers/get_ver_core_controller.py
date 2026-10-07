# -*- coding: utf-8 -*-
"""
/v1/getVerCore 接口 (本地合成)。

客户端进游戏第二层新验证: 请求 data 携带 version, 响应 data 返回
state/md5/data/url/update。客户端据此判断版本状态并以 data 版本清单 / update
多 blob 链接校验、分发各 build。字段取 config.settings 快照 (env 可覆盖)。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import get_ver_core_service
from util.parser import parse_request

router = APIRouter()


@api_post(router, "/v1/getVerCore")
async def get_ver_core(request: Request) -> Response:
    """
    核心版本校验接口 (本地合成)。

    @param {Request} request - 请求对象
    @returns {Response} 含 state/md5/data/url/update 的加密响应
    """
    data_json = await parse_request(request)
    show(data_json, "getVerCore >>>")

    resp = ApiResponse.success(
        get_ver_core_service.build_ver_core_data(
            data_json.get("nonce", ""), data_json.get("timestamp", 0)
        )
    )
    show(resp.to_dict(), "getVerCore <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "get_ver_core"]
