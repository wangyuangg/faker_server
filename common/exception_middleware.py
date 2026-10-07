# -*- coding: utf-8 -*-
"""
全局异常处理中间件 (FastAPI 版，替代原 Flask 的 api_post try/except)。

行为与简化前的 Flask 版一致:
- SignError            → {"status":403,"msg":"签名验证失败"}
- 其它任何异常          → {"status":500,"msg":str(e)}，并记录完整堆栈
两种情况的 HTTP 状态码都是 200（业务状态码在 body 的 status 字段里）。

之所以用纯 ASGI 中间件而不是 @app.exception_handler：路由层、依赖注入层
与其它中间件抛出的异常都能被兜住，不会漏成 Starlette 默认的 500 纯文本响应。
"""

from loguru import logger
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from common.errors import SignError
from common.response import json_response
from models.api_status import ApiStatus


class ApiExceptionMiddleware:
    """
    纯 ASGI 异常兜底中间件（无 BaseHTTPMiddleware 开销）。

    捕获下游应用抛出的所有异常，转换为统一 JSON 错误响应；
    响应已经开始发送时无法再改写，此时原样上抛交由 ServerErrorMiddleware 处理。
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        ASGI 调用入口。

        @param {Scope} scope - ASGI 作用域
        @param {Receive} receive - 接收消息的可等待对象
        @param {Send} send - 发送消息的可等待对象
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except SignError:
            if not response_started:
                await json_response(
                    {"status": ApiStatus.SIGN_FAILED, "msg": ApiStatus.MSG_SIGN_FAILED}
                )(scope, receive, send)
        except Exception as e:
            path = scope.get("path", "?")
            logger.opt(colors=True).error(f"<red>{path}</red> {e}")
            logger.exception("")
            if not response_started:
                await json_response({"status": ApiStatus.SERVER_ERROR, "msg": str(e)})(
                    scope, receive, send
                )
            else:
                raise


def install_exception_middleware(app: object) -> None:
    """
    为 FastAPI 应用安装异常兜底中间件。

    @param {FastAPI} app - 目标应用实例
    """
    app.add_middleware(ApiExceptionMiddleware)  # type: ignore[attr-defined]


__all__ = ["ApiExceptionMiddleware", "install_exception_middleware"]
