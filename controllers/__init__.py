# -*- coding: utf-8 -*-
"""
controllers 包: 路由/控制器层。每个模块对应一组 API，暴露 router（APIRouter）供 app 注册。
"""

from controllers import (  # noqa: F401
    app_init_controller,
    cdkey_login_controller,
    get_app_code_controller,
    get_ver_core_controller,
    logout_controller,
    message_controller,
    user_bind_controller,
)

#: 全部待注册路由的路由器列表
ALL_ROUTERS = [
    app_init_controller.router,
    cdkey_login_controller.router,
    get_app_code_controller.router,
    get_ver_core_controller.router,
    message_controller.router,
    user_bind_controller.router,
    logout_controller.router,
]

__all__ = ["ALL_ROUTERS"]
