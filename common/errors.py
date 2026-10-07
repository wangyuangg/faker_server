# -*- coding: utf-8 -*-
"""
全局异常定义。
"""


class SignError(Exception):
    """
    签名验证失败异常。

    由 common.exception_middleware.ApiExceptionMiddleware 统一转换为
    {"status":403,"msg":"签名验证失败"}，业务代码只需 raise SignError 即可。
    """

    def __init__(self, message: str = "签名验证失败") -> None:
        super().__init__(message)
        self.message = message


__all__ = ["SignError"]
