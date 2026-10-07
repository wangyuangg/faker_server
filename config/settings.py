# -*- coding: utf-8 -*-
"""
服务配置 (原 fake_server_hijack.py 顶部的常量与 REAL_HOST/REAL_DOMAIN)。

上游地址支持 FAKER_REAL_HOST / FAKER_REAL_DOMAIN 环境变量覆盖，
与 C++ / Go 两个实现保持一致的联调方式。
"""

import json
import os
import re
from dataclasses import dataclass, field

# 默认绑定端口 80（Windows 下需管理员权限），可用 FAKER_PORT 覆盖
DEFAULT_PORT: int = 80
DEFAULT_HOST: str = "0.0.0.0"

# 签名密钥: MD5(appid + nonce + signKey + timestamp + data)
SIGN_KEY: str = "jcpNWyTTzwg"


# XGdun2 客户端校验目标 (RE/14): 客户端把服务端 value 做 ror/xor 派生后与本机
# .\netbios.dll 的 MD5 逐字节比较, 六个 selector (M/1..5) 依序短路尝试,
# 任一命中即通过。校验是自引用的 —— 与手里的对照样本无关, 服务端只需编码
# "客户端实际在跑的那个 netbios.dll" 的 MD5:
#   M 及 2..5 -> 版本清单 (getVerCore 广播的 vercore M 段) 登记的构建, 动态提取
#   1 -> vmp 下载 URL 当前实际分发的构建 (启动期由 xgdun2_target_service 推导)
# 真实上游行为 (2026-10-07 双卡冒烟反推验证): M=清单登记版, 1=URL 分发版
# (两者短暂不一致时双值兼容), 2..5=vercore C 段附近的诱饵 (不命中任何文件)。
XGDUN2_NEXT_TARGET = "2c7be32cd4b2f181bb2374285b4d6083"

# getVerCore 版本清单默认快照 (与 vercore_data 字段同源, 供 XGdun2 目标提取)
_VERCORE_DATA_DEFAULT = (
    "Xd2c40635803c235768e7b07e13c5a2d2J5d8ddbffe0760ddb1111e91cb615194e"
    "D0235b9529fd94c36c4b80fddb8bcdc58Gfe5eb1535380196a6485972819128a62"
    "M4938111943e61071affd2f8cb34951e2Cdae29fa55cfa063f0c8a812f1cd0f179"
)


def _vercore_data_value() -> str:
    """中文注释：vercore 清单的唯一取值来源 (字段默认值与 XGdun2 目标共用)。"""
    return os.environ.get("FAKER_VERCORE_DATA", _VERCORE_DATA_DEFAULT)


_VERCORE_SEGMENT_RE = re.compile(r"([A-Z])([0-9a-fA-F]{32})")


def vercore_segments(vercore_data: str) -> dict:
    """中文注释：解析 getVerCore data 字段的 "字母+32hex" 六段清单。"""
    return {tag: h.lower() for tag, h in _VERCORE_SEGMENT_RE.findall(vercore_data or "")}


def current_netbios_md5() -> str | None:
    """当前部署 netbios.dll 的 MD5 = vercore M 段 (与本服务版本广播自洽)。"""
    return vercore_segments(_vercore_data_value()).get("M")


def _load_xgdun2_values() -> dict:
    """中文注释：读取 XGdun2 快照表覆盖 (仅环境变量注入时生效, 默认走算法)。"""
    raw = os.environ.get("FAKER_XGDUN2_VALUES", "").strip()
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _load_xgdun2_targets() -> dict:
    """中文注释：组装 selector -> 目标 MD5 映射。

    默认: M/2..5 -> vercore M 段 (当前部署版, 随版本广播自动跟随),
    1 -> 预埋下一版。FAKER_XGDUN2_TARGETS 传 JSON {"selector": "md5"} 覆盖。
    """
    targets = {}
    current = current_netbios_md5()
    if current:
        for selector in ("M", "2", "3", "4", "5"):
            targets[selector] = current
    # 中文注释：FAKER_XGDUN2_NEXT_TARGET 固定值优先; 否则启动期由
    # xgdun2_target_service 从上游 appInit 的 update URL 自动推导。
    fixed_next = os.environ.get("FAKER_XGDUN2_NEXT_TARGET", "").strip()
    targets["1"] = fixed_next or XGDUN2_NEXT_TARGET
    raw = os.environ.get("FAKER_XGDUN2_TARGETS", "").strip()
    if raw:
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                targets.update(loaded)
        except json.JSONDecodeError:
            pass
    return targets


@dataclass(frozen=True)
class ServerSettings:
    """
    上游真实服务器与本地监听配置，以及新接口的本地合成响应快照。

    @field real_host {string} - 上游真实服务器 IP（明文 HTTP:80）
    @field real_domain {string} - 上游 Host 头使用的域名
    @field bind_host {string} - 本地监听地址
    @field bind_port {number} - 本地监听端口
    @field upstream_timeout {number} - 上游请求超时秒数
    @field appcode_value {string} - /v1/getAppCode 响应的 value 字段（客户端 stof 后须等于
        内置魔数 64340.555，即 float 0x477B548E；默认 "64340.5555555556" 为 2026-10-05
        真实上游快照，float32 解析后与魔数逐位相等）
    @field vercore_state {number} - /v1/getVerCore 的版本状态（0 测试/1 正式/2 停用/3 强制更新）
    @field vercore_md5 {string} - /v1/getVerCore 的版本 MD5（与 appInit 上游返回的 md5 一致）
    @field vercore_data {string} - /v1/getVerCore 的版本数据（6 段 "字母+32hex" 版本清单）
    @field vercore_url {string} - /v1/getVerCore 的更新地址（可为空串）
    @field vercore_update {string} - /v1/getVerCore 的更新内容（4 个 gitcode blob URL 拼接）
    """

    real_host: str = field(default_factory=lambda: os.environ.get("FAKER_REAL_HOST", "183.131.62.35"))
    real_domain: str = field(default_factory=lambda: os.environ.get("FAKER_REAL_DOMAIN", "bgp.tyserve.net"))
    bind_host: str = field(default_factory=lambda: os.environ.get("FAKER_BIND_HOST", DEFAULT_HOST))
    bind_port: int = field(default_factory=lambda: int(os.environ.get("FAKER_PORT", DEFAULT_PORT)))
    upstream_timeout: float = 10.0

    # 新接口本地合成值: 镜像 2026-10-05 真卡探测到的真实上游响应
    # (探测脚本 D:/faker_server/test_new_endpoints.py); 作者轮换版本时用环境变量覆盖
    appcode_value: str = field(default_factory=lambda: os.environ.get("FAKER_APPCODE_VALUE", "64340.5555555556"))
    # XGdun2 快照表覆盖 (机器码/selector -> 32 位 value); 默认为空, 走算法合成。
    xgdun2_values: dict = field(default_factory=lambda: _load_xgdun2_values())
    # XGdun2 selector -> 候选 netbios.dll MD5 (客户端本地校验目标)。
    xgdun2_targets: dict = field(default_factory=lambda: _load_xgdun2_targets())
    vercore_state: int = field(default_factory=lambda: int(os.environ.get("FAKER_VERCORE_STATE", "1")))
    vercore_md5: str = field(default_factory=lambda: os.environ.get("FAKER_VERCORE_MD5", "a33b08f1c418d34fd96d2f61001e971a"))
    vercore_data: str = field(default_factory=_vercore_data_value)
    vercore_url: str = field(default_factory=lambda: os.environ.get("FAKER_VERCORE_URL", ""))
    vercore_update: str = field(
        default_factory=lambda: os.environ.get(
            "FAKER_VERCORE_UPDATE",
            "https://raw.gitcode.com/w355755/KK/blobs/5f0c03b4a643685711ad733270d032d59f4f4412/netbios.dll"
            "https://raw.gitcode.com/w355755/KK/blobs/1cd87b811e8eb40bcd746a4495a7cc743c091b0d/netbios.vmp.dll"
            "https://raw.gitcode.com/w355755/KK/blobs/db809e505fc77d5d83f839a41e3432a1057e01fd/netbioscs.dll"
            "https://raw.gitcode.com/w355755/KK/blobs/ee3298994773444e3ce5af8d8293c62294609fa4/netbiosgj.dll",
        )
    )

    @property
    def upstream_base_url(self) -> str:
        """
        上游真实服务器的 HTTP 基地址。

        @returns {string} 形如 "http://183.131.62.35" 的基地址
        """
        return f"http://{self.real_host}"


settings = ServerSettings()

__all__ = ["settings", "ServerSettings", "SIGN_KEY", "DEFAULT_PORT", "DEFAULT_HOST"]
