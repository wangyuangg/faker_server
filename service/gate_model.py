# -*- coding: utf-8 -*-
"""
客户端门控模型 —— 把"客户端会不会接受我们合成的响应"写成可执行断言。

来源: IDA 反汇编 (RE/14、RE/17)。

1) XGdun (getAppCode func="XGdun")
   客户端: stof(value) 的 float32 位模式 == 0x477B548E (64340.5546875)。
   2026-10-07 起的新构建把它改写成等价混淆式 (不再有 float 字面量):
       ((bits ^ 0x12345678) + 0x9E3779B9) & 0xFFFFFFFF == 0x0F3867CAF
   两式对同一 bits 恒等, 故本模块同时接受两种形态。

2) XGdun2 (getAppCode func="XGdun2")
   客户端把服务端 value 用机器码派生 (util/xgdun2.transform), 与本机
   .\\netbios.dll 的 MD5 逐字节比较; M/1/2/3/4/5 六次短路 OR。
   因此"能不能过"取决于 transform(value, machine) 是否 ∈ 已知构建 MD5 集合。

启动/CI 调 run_startup_self_test(): 作者再改常量或换混淆式时这里立刻失败,
不必等真机跑到那一步。
"""

import struct
from typing import Iterable, List, Tuple

from loguru import logger

M32: int = 0xFFFFFFFF

# XGdun 门控: 旧形态 (float 位模式) 与 新形态 (等价混淆) 的常量
XGDUN_FLOAT_BITS: int = 0x477B548E
XGDUN_OBF_XOR: int = 0x12345678
XGDUN_OBF_ADD: int = 0x9E3779B9
XGDUN_OBF_TARGET: int = 0x0F3867CAF

#: 自检用的机器码 (与真实日志一致)
SAMPLE_MACHINE: str = "BFEBFBFF000B0671"


def float_bits(value: float) -> int:
    """取 float32 的位模式 (与客户端 `movd eax, xmm0` 等价)。"""
    return struct.unpack("<I", struct.pack("<f", value))[0]


def xgdun_gate_bits(bits: int) -> bool:
    """旧/新两种门控形态任一成立即通过。"""
    legacy = bits == XGDUN_FLOAT_BITS
    obfuscated = (((bits ^ XGDUN_OBF_XOR) + XGDUN_OBF_ADD) & M32) == XGDUN_OBF_TARGET
    return legacy or obfuscated


def xgdun_gate_ok(value: str) -> bool:
    """value 字符串经 stof 后是否能让客户端 XGdun 门控通过。"""
    try:
        return xgdun_gate_bits(float_bits(float(value)))
    except (TypeError, ValueError, OverflowError):
        return False


def xgdun2_gate_ok(value: str, machine: str, known_md5s: Iterable[str]) -> bool:
    """value 经客户端派生算法后是否命中任一已知构建 MD5。"""
    from util.xgdun2 import transform

    if not value or not machine:
        return False
    try:
        derived = transform(value, machine)
    except (TypeError, ValueError):
        return False
    return derived.lower() in {m.lower() for m in known_md5s}


def check_xgdun(appcode_value: str) -> List[Tuple[str, bool, str]]:
    """校验 appcode_value 对两种门控形态都成立, 且错误值被拒。"""
    try:
        bits = float_bits(float(appcode_value))
    except (TypeError, ValueError, OverflowError):
        return [("xgdun 可解析", False, f"{appcode_value!r} 不是数值")]
    results: List[Tuple[str, bool, str]] = [
        ("xgdun 旧形态 float32==0x477B548E", bits == XGDUN_FLOAT_BITS, f"bits=0x{bits:08X}"),
    ]
    obf = ((bits ^ XGDUN_OBF_XOR) + XGDUN_OBF_ADD) & M32
    results.append(("xgdun 新形态等价混淆式", obf == XGDUN_OBF_TARGET,
                    f"0x{obf:08X} vs 0x{XGDUN_OBF_TARGET:08X}"))
    results.append(("xgdun 错误值被拒绝", not xgdun_gate_ok("1.0"), "value='1.0'"))
    return results


def check_xgdun2(sample_machine: str, targets: dict, known_md5s: Iterable[str]) -> List[Tuple[str, bool, str]]:
    """校验每个 selector 的目标 MD5 逆变换闭环, 且真值在台账内 / 诱饵不在。"""
    from util.xgdun2 import inverse_transform, transform

    known = {m.lower() for m in known_md5s}
    results: List[Tuple[str, bool, str]] = []
    for selector in ("M", "1", "2", "3"):
        target = targets.get(selector)
        if not isinstance(target, str) or len(target) != 32:
            results.append((f"xgdun2[{selector}] 目标存在", False, f"{target!r}"))
            continue
        value = inverse_transform(target.lower(), sample_machine)
        results.append((f"xgdun2[{selector}] 逆变换闭环",
                        transform(value, sample_machine) == target.lower(),
                        f"target={target[:8]}…"))
        results.append((f"xgdun2[{selector}] 目标 ∈ 台账", target.lower() in known, f"target={target[:8]}…"))
    for selector in ("4", "5"):
        target = targets.get(selector)
        ok = isinstance(target, str) and len(target) == 32 and target.lower() not in known
        results.append((f"xgdun2[{selector}] 诱饵 (不在台账)", ok, f"target={str(target)[:8]}…"))
    return results


def log_checks(checks: Iterable[Tuple[str, bool, str]]) -> bool:
    """打印自检结果, 返回是否全通过。"""
    all_ok = True
    for name, ok, detail in checks:
        if ok:
            logger.info(f"[self-test] PASS  {name}  ({detail})")
        else:
            all_ok = False
            logger.error(f"[self-test] FAIL  {name}  ({detail})")
    return all_ok


def run_startup_self_test() -> bool:
    """启动自检: 门控常量 + selector 目标闭环。失败只告警, 不阻断启动。"""
    from config.settings import settings
    from service.build_registry import registry

    registry.load()
    checks = check_xgdun(settings.appcode_value)
    checks += check_xgdun2(SAMPLE_MACHINE, registry.targets(), registry.known_md5s())
    ok = log_checks(checks)
    if not ok:
        logger.error("[self-test] 响应可能不再被客户端接受 —— 核对 RE/17 门控常量与构建台账")
    return ok


__all__ = [
    "M32", "XGDUN_FLOAT_BITS", "XGDUN_OBF_XOR", "XGDUN_OBF_ADD", "XGDUN_OBF_TARGET", "SAMPLE_MACHINE",
    "float_bits", "xgdun_gate_bits", "xgdun_gate_ok", "xgdun2_gate_ok",
    "check_xgdun", "check_xgdun2", "log_checks", "run_startup_self_test",
]
