# -*- coding: utf-8 -*-
"""
/v1/getAppCode 的"远程函数"注册表。

真实协议里 getAppCode 是"把 func 名 + param 交给服务器执行、返回结果"的通用入口
(见 getAppCode.txt 官方文档)。客户端现在用到两个:

    XGdun   param = "1, 2, 3, 4"                        -> value = 浮点门控常量
    XGdun2  param = "\"<machine>\",\"<selector>\""      -> value = 逆变换出的构建指纹

所以这里不做 if/else, 而是注册表: 每个 func 一个 handler, 声明自己的 param 正则
与响应字段构造。**未注册的 func 一律返回 value="" 并告警** —— 绝不复用别的 func
的返回值 (否则作者新增接口时, 假服务器会"静默通过", 反而更难排查)。

新增接口步骤: 本目录加一个模块, 写 @remote_func("<name>", param_re=...) 的 build(),
在 _BUILTIN_MODULES 里登记; 若该 func 还有客户端门控, 在 service/gate_model.py 补断言。
"""

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Pattern

from loguru import logger

#: (请求内层字典) -> 追加到响应 data 的字段; 返回 None 表示"无法合成"
Builder = Callable[[dict], Optional[dict]]


@dataclass(frozen=True)
class RemoteFunc:
    """一个远程函数的定义。"""

    name: str
    build: Builder
    param_re: Optional[Pattern] = None
    description: str = ""

    def parse_param(self, param) -> Optional[re.Match]:
        """按声明的正则解析 param 字符串; 未声明正则时返回 None。"""
        if self.param_re is None or not isinstance(param, str):
            return None
        return self.param_re.match(param)


REGISTRY: Dict[str, RemoteFunc] = {}
_BUILTIN_MODULES: List[str] = ["service.remote_funcs.xgdun", "service.remote_funcs.xgdun2"]
_builtin_loaded = False


def remote_func(name: str, param_re: Optional[str] = None, description: str = ""):
    """注册一个远程函数 handler。"""

    def decorator(fn: Builder) -> Builder:
        REGISTRY[name] = RemoteFunc(
            name=name,
            build=fn,
            param_re=re.compile(param_re) if param_re else None,
            description=description,
        )
        return fn

    return decorator


def load_builtin() -> None:
    """导入内置 handler 模块以触发注册 (幂等)。"""
    global _builtin_loaded
    if _builtin_loaded:
        return
    _builtin_loaded = True
    import importlib

    for module in _BUILTIN_MODULES:
        importlib.import_module(module)
    logger.info(f"[remote-func] 已注册 {len(REGISTRY)} 个: {sorted(REGISTRY)}")


def get(name: str) -> Optional[RemoteFunc]:
    """按 func 名取 handler (未注册返回 None)。"""
    load_builtin()
    return REGISTRY.get(name)


def names() -> List[str]:
    """中文注释：已注册的 func 名列表 (调试/自检用)。"""
    load_builtin()
    return sorted(REGISTRY)


def dispatch(request_data: dict) -> dict:
    """按 request_data['func'] 分派, 返回要并入响应 data 的字段。"""
    load_builtin()
    func = str(request_data.get("func") or "")
    entry = REGISTRY.get(func)
    if entry is None:
        logger.warning(f"[remote-func] 未注册的 func={func!r}, 返回空 value (已注册: {sorted(REGISTRY)})")
        return {"value": ""}
    try:
        extra = entry.build(request_data)
    except Exception as e:  # 单个 handler 异常不应打断协议
        logger.warning(f"[remote-func] func={func!r} 合成失败: {e}")
        return {"value": ""}
    return extra if extra else {"value": ""}


__all__ = ["RemoteFunc", "REGISTRY", "remote_func", "load_builtin", "get", "names", "dispatch"]
