#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fake Server 应用装配与启动入口（FastAPI + uvicorn）。

MVC 分层:
    controllers/  —— 路由/控制器，仅做参数解析、调用 service、组装 Response
    service/      —— 业务逻辑（登录、绑定、登出、上游代理）
    models/       —— 数据模型（请求/响应结构、状态码）
    util/         —— 纯函数工具（加解密、签名、请求解析、响应体构造、异步 HTTP 客户端）
    config/       —— 配置与协议常量
    common/       —— 响应格式、异常、异常中间件、日志打印等基建

启动:
    python app.py                     # 默认 0.0.0.0:80（Windows 需管理员权限）
    python app.py 8080                # 指定端口（等价于设置 FAKER_PORT）
    uvicorn app:app --port 8080       # 直接用 ASGI 服务器启动
    FAKER_RELOAD=1 python app.py 8080 # 开发热重载

环境变量: FAKER_REAL_HOST / FAKER_REAL_DOMAIN / FAKER_BIND_HOST / FAKER_PORT / FAKER_RELOAD
"""

import asyncio
import contextlib
import copy
import logging
import os
import sys
from typing import Any, AsyncIterator, Dict, Optional

# 支持 `python app.py` 直接运行（脚本目录不在 sys.path 时会找不到顶层包）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from loguru import logger  # noqa: E402
from uvicorn.config import LOGGING_CONFIG  # noqa: E402

from common.exception_middleware import install_exception_middleware  # noqa: E402
from config.settings import settings  # noqa: E402
from controllers import ALL_ROUTERS  # noqa: E402
from util.http_client import close_client  # noqa: E402


def create_app() -> FastAPI:
    """
    应用工厂: 创建 FastAPI 实例、安装异常中间件、注册全部路由。

    关闭内置文档（/docs、/redoc、/openapi.json）——这些接口只服务于定制客户端协议。

    @returns {FastAPI} 已完成路由注册的应用实例
    """
    app = FastAPI(
        title="Fake Server",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )
    install_exception_middleware(app)
    for router in ALL_ROUTERS:
        app.include_router(router)
    return app


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """
    应用生命周期: 启动时从上游推导 XGdun2 "1" 目标 (预埋下一版 MD5),
    退出时关闭共享的上游 httpx 连接池。

    @param {FastAPI} _app - 应用实例（未使用）
    """
    from service.build_registry import registry
    from service.gate_model import run_startup_self_test

    # 中文注释：台账载入 + 门控自检 (离线可用; 失败只告警不阻断)。
    registry.load()
    run_startup_self_test()
    # 中文注释：增量发现作者新发布的构建, 后台跑, 不阻塞启动。
    refresh_task = asyncio.create_task(registry.refresh())
    yield
    refresh_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await refresh_task
    await close_client()


app = create_app()


def build_server_config(
    port: Optional[int] = None,
    host: Optional[str] = None,
    reload: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    组装 uvicorn 启动参数（抽出来便于测试，不实际启动服务）。

    访问日志（uvicorn.access）压到 WARNING，请求日志统一由 loguru 的 show() 输出。

    @param {number|None} port - 覆盖监听端口；None 时用 settings.bind_port
    @param {string|None} host - 覆盖监听地址；None 时用 settings.bind_host
    @param {boolean|None} reload - 是否启用热重载；None 时读 FAKER_RELOAD
    @returns {Dict} 可直接展开给 uvicorn.run 的参数
    """
    if reload is None:
        reload = os.environ.get("FAKER_RELOAD", "") not in ("", "0", "false", "False")
    log_config = copy.deepcopy(LOGGING_CONFIG)
    log_config["loggers"]["uvicorn.access"]["level"] = "WARNING"
    return {
        "app": app,
        "host": settings.bind_host if host is None else host,
        "port": settings.bind_port if port is None else port,
        "reload": reload,
        "log_config": log_config,
    }


def run(port: Optional[int] = None, host: Optional[str] = None, reload: Optional[bool] = None) -> None:
    """
    启动服务（原 Flask app.run 的对应实现）。

    @param {number|None} port - 监听端口；None 时用 settings.bind_port
    @param {string|None} host - 监听地址；None 时用 settings.bind_host
    @param {boolean|None} reload - 是否启用热重载
    """
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    config = build_server_config(port, host, reload)
    logger.info(f"Fake Server | http://{config['host']}:{config['port']}")
    uvicorn.run(**config)


if __name__ == "__main__":
    cli_port = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run(cli_port)
