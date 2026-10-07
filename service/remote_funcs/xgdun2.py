# -*- coding: utf-8 -*-
"""
func = "XGdun2" —— 按 (机器码, selector) 合成构建指纹。

请求 param 形如 `"BFEBFBFF000B0671","M"` (是字符串, 不是 JSON 数组)。
客户端把返回的 value 用机器码派生 (util/xgdun2.transform), 与本机 .\\netbios.dll
的 MD5 比较。因此这里对 selector 对应的目标 MD5 做逆变换 (RE/14)。

目标 MD5 来自 service/build_registry.py 的台账 (滚动窗口 M/1/2/3 + 诱饵 4/5),
而非硬编码常量 —— 作者更新发布时台账自动跟随。
"""

import json
import re
from typing import Optional, Tuple

from loguru import logger

from service.build_registry import registry
from service.remote_funcs import remote_func
from util.xgdun2 import inverse_transform

#: `"machine","selector"` (允许空白), 与 DLL 的拼接格式一致
XGDUN2_PARAM_RE = re.compile(r'^\s*"(?P<machine>[^"]+)"\s*,\s*"(?P<selector>[^"]+)"\s*$')
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def parse_xgdun2_param(param) -> Optional[Tuple[str, str]]:
    """解析 DLL 发送的 `"machine","selector"` 字符串。"""
    if not isinstance(param, str):
        return None
    match = XGDUN2_PARAM_RE.match(param)
    if match:
        return match.group("machine"), match.group("selector")
    # 兼容转义/空白差异: 优先用 JSON 解析而非手工切分
    try:
        values = json.loads("[" + param + "]")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if isinstance(values, list) and len(values) == 2 and all(isinstance(v, str) for v in values):
        return values[0], values[1]
    return None


def get_xgdun2_value(machine: str, selector: str) -> Optional[str]:
    """按 (机器码, selector) 合成 32 位 hex value。"""
    target = registry.target_for(selector)
    if not isinstance(target, str) or not _MD5_RE.fullmatch(target):
        logger.warning(f"[xgdun2] selector={selector!r} 无可用目标 MD5, 返回空 value")
        return None
    return inverse_transform(target.lower(), machine)


@remote_func("XGdun2", param_re=XGDUN2_PARAM_RE.pattern, description="构建指纹逆变换 (滚动窗口)")
def build(request_data: dict) -> dict:
    """解析 param -> 取目标 MD5 -> 逆变换出 value。"""
    parsed = parse_xgdun2_param(request_data.get("param"))
    if not parsed:
        logger.warning(f"[xgdun2] param 无法解析: {request_data.get('param')!r}")
        return {"value": ""}
    machine, selector = parsed
    value = get_xgdun2_value(machine, selector)
    # 未知 selector 也返回协议格式 (空值), 便于客户端走进明确失败分支
    return {"value": value or ""}


__all__ = ["build", "parse_xgdun2_param", "get_xgdun2_value", "XGDUN2_PARAM_RE"]
