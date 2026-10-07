#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fake Server - URL Hijack Version (FastAPI)

历史入口，保留以兼容 `run.bat` / 既有启动脚本。
实际实现已按 MVC 架构重构，见:
    app.py          —— 应用装配与启动入口（推荐入口）
    controllers/    —— 路由/控制器（FastAPI APIRouter）
    service/        —— 业务逻辑
    models/         —— 数据模型
    util/ config/ common/ —— 工具、配置、基建

用法（与原脚本完全一致，默认 80 端口）:
    python fake_server_hijack.py [port]
"""

import os
import sys

# 兼容 `python fake_server_hijack.py`: 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, run  # noqa: E402,F401

__all__ = ["app", "run"]

if __name__ == "__main__":
    cli_port = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run(cli_port)
