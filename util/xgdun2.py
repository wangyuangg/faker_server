# -*- coding: utf-8 -*-
"""
XGdun2 本地校验算法 (正向 + 逆向)。

来源: 又更新了.dll IDA 反汇编 (RE/14-xgdun2-local-validation.md, RE/tools/xgdun2_algo.py):
  0x1805E62B0  machine -> FNV-1a 32 (offset 0x811C9DC5, prime 0x01000193)
  0x1805E2CB0  seed -> 4 derived words:
                 x = seed + 0x9E3779B9*i
                 x ^= x>>16; x *= 0x7FEB352D
                 x ^= x>>15; x *= 0x846CA68B
                 x ^= x>>16
  0x1805E2690  32-hex value -> 4 big-endian dwords (越界补'0', 非hex记0)
  0x1805DCDA0  y_i = derived_i ^ ror32(ror32(x_i,7) - 0x9E3779B9, 13)
  0x1805DC340  4 dwords -> 小写大端 hex
  0x1805DC6B0  客户端逐字节比较 hex(结果) == MD5hex(".\netbios.dll")

DLL 语义: 六个 selector (M/1..5) 依序短路尝试, 任一 transform(value) 等于
本机 netbios.dll 的 MD5 即通过。因此服务端应对每个 selector 返回
inverse_transform(候选 DLL 的 MD5, machine) —— 与真实上游一致:
真实服务器 M = 版本清单 (vercore M 段) 登记的构建 (49381119...),
1 = vmp 下载 URL 当前分发的构建 (2c7be32c...), 2..5 = C 段附近的诱饵
(dae29fa5...f172/3/4/75)。
"""

M32 = 0xFFFFFFFF

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193
GOLDEN = 0x9E3779B9
MUL1 = 0x7FEB352D
MUL2 = 0x846CA68B


def fnv1a32(s: str) -> int:
    """0x1805E62B0: 机器码字符串 -> FNV-1a 32 位种子。"""
    h = FNV_OFFSET
    for b in s.encode("ascii"):
        h = ((b ^ h) * FNV_PRIME) & M32
    return h


def derive_words(seed: int) -> list:
    """0x1805E2CB0: 种子 -> 4 个 32 位派生字。"""
    out = []
    for i in range(4):
        x = (seed + GOLDEN * i) & M32
        x = (x ^ (x >> 16)) & M32
        x = (x * MUL1) & M32
        x = (x ^ (x >> 15)) & M32
        x = (x * MUL2) & M32
        x = (x ^ (x >> 16)) & M32
        out.append(x)
    return out


def ror32(x: int, n: int) -> int:
    """0x1805E44A0: ror eax, cl。"""
    n &= 31
    if n == 0:
        return x & M32
    return ((x >> n) | (x << (32 - n))) & M32


def rol32(x: int, n: int) -> int:
    """ror32 的逆。"""
    n &= 31
    if n == 0:
        return x & M32
    return ((x << n) | (x >> (32 - n))) & M32


_HEX_DIGIT = {c: int(c, 16) for c in "0123456789abcdefABCDEF"}


def parse_hex32(value_hex: str) -> list:
    """0x1805E2690: 32 位 hex -> 4 个大端 dword。

    与 DLL 一致: 索引越界按 '0' 处理, 非 hex 字符按 0 处理。
    """
    out = []
    for i in range(4):
        v = 0
        for j in range(8):
            idx = i * 8 + j
            c = value_hex[idx] if idx < len(value_hex) else "0"
            v = (v * 16 + _HEX_DIGIT.get(c, 0)) & M32
        out.append(v)
    return out


def transform_elem(x: int, d: int) -> int:
    """0x1805DCDA0: d ^ ror32(ror32(x,7) - 0x9E3779B9, 13)。"""
    v = ror32(x, 7)
    v = (v - GOLDEN) & M32
    v = ror32(v, 13)
    return v ^ d


def inverse_elem(y: int, d: int) -> int:
    """transform_elem 的逆: x = rol32(rol32(y^d,13) + 0x9E3779B9, 7)。"""
    t = (y ^ d) & M32
    s = rol32(t, 13)
    u = (s + GOLDEN) & M32
    return rol32(u, 7)


def transform(value_hex: str, machine: str) -> str:
    """0x1805DCED0 正向: 服务端 value + 机器码 -> 派生 hex (客户端本地计算)。"""
    seed = fnv1a32(machine)
    d = derive_words(seed)
    xs = parse_hex32(value_hex)
    ys = [transform_elem(x, d[i]) for i, x in enumerate(xs)]
    return "".join("{:08x}".format(y) for y in ys)


def inverse_transform(target_hex: str, machine: str) -> str:
    """逆向: 给定客户端期望的派生结果 (netbios.dll 的 MD5hex),
    反推服务端应返回的 32 位 hex value。"""
    seed = fnv1a32(machine)
    d = derive_words(seed)
    ys = parse_hex32(target_hex)
    xs = [inverse_elem(y, d[i]) for i, y in enumerate(ys)]
    return "".join("{:08x}".format(x) for x in xs)


__all__ = [
    "fnv1a32", "derive_words", "ror32", "rol32", "parse_hex32",
    "transform_elem", "inverse_elem", "transform", "inverse_transform",
]
