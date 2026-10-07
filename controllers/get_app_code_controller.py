# -*- coding: utf-8 -*-
"""
/v1/getAppCode 接口 (本地合成)。

客户端防山寨层: 请求 data 携带 func="XGdun" / param="1, 2, 3, 4" (客户端硬编码),
响应 data 返回 value, 客户端 stof(value) 须等于内置魔数 64340.555, 否则验证链终止。
value 取 config.settings.appcode_value (env FAKER_APPCODE_VALUE 可覆盖)。
"""

from fastapi import APIRouter, Request
from starlette.responses import Response

from common.console import show
from common.response import json_response
from controllers.api_route import api_post
from models.responses import ApiResponse
from service import get_app_code_service
from util.parser import parse_request
from util.crypto import decrypt_request
import json

router = APIRouter()


@api_post(router, "/v1/getAppCode")
async def get_app_code(request: Request) -> Response:
    """
    远程函数执行接口 (本地合成)。

    @param {Request} request - 请求对象
    @returns {Response} 含 value 的加密响应 (value 须使客户端 stof 门控通过)
    """
    data_json = await parse_request(request)
    show(data_json, "getAppCode >>>")
    # 中文注释：解析已验签请求的内层 JSON，XGdun2 的 func/param 位于 data 内。
    inner = {}
    if data_json.get("data"):
        inner = json.loads(decrypt_request(data_json["data"]))

    resp = ApiResponse.success(
        get_app_code_service.build_app_code_data(
            data_json.get("nonce", ""), data_json.get("timestamp", 0), inner
        )
    )
    show(resp.to_dict(), "getAppCode <<<")
    return json_response(resp.to_dict())


__all__ = ["router", "get_app_code"]
