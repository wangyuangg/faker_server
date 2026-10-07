# -*- coding: utf-8 -*-
"""
getVerCore 业务逻辑 (本地合成)。

客户端进游戏后的第二层新验证: 请求 data 携带 version, 响应 data 返回
state/md5/data/url/update。客户端据此判断版本状态(0 测试/1 正式/2 停用/3 强制
更新), 并以 data 字段(6 段 "字母+32hex" 版本清单)与 update(4 个 gitcode blob
URL 拼接)校验/分发各 build。不走上游代理: fake 签发的 token 真实上游不认,
因此全部字段取 config.settings 快照(镜像 2026-10-05 真实上游), 支持 env 覆盖。
"""

from typing import Any

from config.settings import settings
from loguru import logger

from service.build_registry import registry
from util.response_builder import make_response_data


def build_update_field() -> str:
    """由构建台账拼出 update 字段 (4 条 blob URL, 顺序同仓库 files 列表)。

    真实上游的 update = 每个模块"当前分发"的 blob URL 拼接; 台账里每个文件的
    最后一条即当前分发版, 因此这里生成的串与上游逐字节一致 (RE/17)。
    台账不可用时退回 settings.vercore_update 快照。
    """
    registry.load()
    raw = registry.repo.get("raw", "")
    if not raw:
        return settings.vercore_update
    parts = []
    for name in registry.files:
        builds = registry.builds(name)
        if builds:
            parts.append(f"{raw}/{builds[-1].blob}/{name}")
    if len(parts) != len(registry.files):
        logger.warning("[vercore] 台账不完整, update 退回 settings 快照")
        return settings.vercore_update
    return "".join(parts)


def build_ver_core_data(nonce: Any, timestamp: Any) -> str:
    """
    构造 getVerCore 响应 data（nonce/timestamp 回显 + state/md5/data/url/update）。

    @param {string|number} nonce - 客户端请求中的 nonce，原样回显
    @param {string|number} timestamp - 客户端请求中的时间戳，原样回显
    @returns {string} 加密后的十六进制响应 data
    """
    return make_response_data(
        nonce,
        timestamp,
        {
            "state": settings.vercore_state,
            "md5": settings.vercore_md5,
            "data": settings.vercore_data,
            "url": settings.vercore_url,
            "update": build_update_field(),
        },
    )


__all__ = ["build_ver_core_data", "build_update_field"]
