# -*- coding: utf-8 -*-
"""
func = "XGdun" —— 旧的浮点门控。

客户端 (DLL) 请求 func="XGdun", param="1, 2, 3, 4" (两者都硬编码), 拿到 value 后
做 stof() 并与门控常量比较; 门控模型见 service/gate_model.py (含 2026-10-07 起
的等价混淆式)。

本 handler 只负责返回值: 取 settings.appcode_value (env FAKER_APPCODE_VALUE 可覆盖),
默认 "64340.5555555556" = float32 0x477B548E。
"""

from config.settings import settings

from service.remote_funcs import remote_func

#: DLL 里硬编码的 param (Str::one_two_three_four)
XGDUN_PARAM: str = "1, 2, 3, 4"


@remote_func("XGdun", param_re=r"^1,\s*2,\s*3,\s*4\s*$", description="浮点门控 (stof == 0x477B548E)")
def build(request_data: dict) -> dict:
    """返回浮点门控常量。"""
    return {"value": settings.appcode_value}


__all__ = ["build", "XGDUN_PARAM"]
