# -*- coding: utf-8 -*-
"""
XGdun2 "1" selector 目标 (下载 URL 当前分发的 netbios.vmp.dll 构建 MD5) 自动推导。

[已弃用] 2026-10-07 起由 service/build_registry.py 取代: 台账直接按"最近 4 个发布构建"
映射 M/1/2/3 (RE/17), 不再需要在启动期下载 7MB blob 猜"下一个目标"。app.py 已不再调用
本模块; 保留仅为兼容旧脚本 (test_refactor.py 等)。

多功能模块架构 (2026-10-07 appInit/getVerCore 实测, RE/14):
  - update 字段的 4 条 URL = 4 个不同功能模块 (D/M/C/G 段一一对应);
  - XGdun2 校验部署为 .\netbios.dll 的 vmp 主模块;
  - "M" 值锚定版本清单 (vercore M 段) 登记的构建;
  - "1" 值锚定 vmp URL 当前实际分发的构建 —— 两者短暂不一致时双值兼容
    (登记版客户端走 M, 已取新构建客户端走 1)。

因此 "1" 的目标 = 当前 update URL 里 netbios.vmp.dll blob 的 MD5,
可直接从上游 appInit 推导, 作者更新分发构建时无需改配置。

优先级: FAKER_XGDUN2_TARGETS (显式覆盖) > FAKER_XGDUN2_NEXT_TARGET (固定值)
        > 上游自动推导 > 硬编码默认值。
"""

import hashlib
import json
import re
import time
import uuid

import httpx
from loguru import logger

from config.settings import settings, SIGN_KEY
from util.crypto import decrypt_response, encrypt_request
from util.http_client import get_client

# 硬编码默认: 又更新了.dll (2026-10-07 实测 = blob afe125c0 的内容)
XGDUN2_NEXT_DEFAULT = "2c7be32cd4b2f181bb2374285b4d6083"

APPID = "2876"
_MD5_RE = re.compile(r"[0-9a-f]{32}")
VMP_DLL_NAME = "netbios.vmp.dll"


def _split_update_urls(update: str) -> list:
    """中文注释：update 字段是若干 URL 无分隔符拼接, 按 https:// 切分还原。"""
    return ["https://" + part for part in update.split("https://") if part]

_next_target_cache = None


def _build_app_init_request() -> dict:
    """中文注释：构造合法的 appInit 请求信封 (appid/nonce/sign/data)。"""
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    timestamp = int(time.time())
    inner = json.dumps({"appkey": "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013", "version": "41234"},
                       ensure_ascii=False, separators=(",", ":"))
    data = encrypt_request(inner)
    sign = hashlib.md5((APPID + nonce + SIGN_KEY + str(timestamp) + data).encode()).hexdigest()
    return {"appid": APPID, "nonce": nonce, "timestamp": timestamp, "sign": sign, "data": data}


async def _fetch_upstream_app_init_update() -> str | None:
    """请求真实上游 appInit, 返回解密后 data 的 update 字段 (拼接的 blob URL 串)。"""
    resp = await get_client().post(
        f"{settings.upstream_base_url}/v1/appInit",
        content=json.dumps(_build_app_init_request(), ensure_ascii=False, separators=(",", ":")),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Host": settings.real_domain},
    )
    env = resp.json()
    if env.get("status") != 200 or not env.get("data"):
        logger.warning(f"[xgdun2-target] appInit status={env.get('status')} 无 data, 放弃推导")
        return None
    data = json.loads(decrypt_response(env["data"]))
    update = data.get("update", "")
    return update if isinstance(update, str) else None


async def _download_md5(url: str) -> str | None:
    """中文注释：流式下载 blob 并计算 MD5 (大文件不进内存)。"""
    md5 = hashlib.md5()
    async with httpx.AsyncClient(timeout=180.0, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes(1024 * 1024):
                md5.update(chunk)
    digest = md5.hexdigest()
    return digest if _MD5_RE.fullmatch(digest) else None


async def refresh_xgdun2_next_target() -> str | None:
    """从上游 update URL 推导并更新 "1" selector 的目标 MD5, 返回新值。

    显式环境变量覆盖 (FAKER_XGDUN2_TARGETS / FAKER_XGDUN2_NEXT_TARGET) 时不动作。
    失败时保留现有值, 不抛异常 (启动期调用, 非致命)。
    """
    global _next_target_cache
    import os
    if os.environ.get("FAKER_XGDUN2_TARGETS", "").strip() or os.environ.get(
            "FAKER_XGDUN2_NEXT_TARGET", "").strip():
        return settings.xgdun2_targets.get("1")
    try:
        update = await _fetch_upstream_app_init_update()
        if not update:
            return settings.xgdun2_targets.get("1")
        vmp_url = next(
            (u for u in _split_update_urls(update) if u.rstrip("/").endswith(VMP_DLL_NAME)),
            None)
        if not vmp_url:
            logger.warning("[xgdun2-target] appInit update 里没找到 netbios.vmp.dll URL")
            return settings.xgdun2_targets.get("1")
        digest = await _download_md5(vmp_url)
        if not digest:
            return settings.xgdun2_targets.get("1")
        old = settings.xgdun2_targets.get("1")
        settings.xgdun2_targets["1"] = digest
        _next_target_cache = digest
        if digest != old:
            logger.info(f"[xgdun2-target] '1' 目标已跟随 update URL: {old} -> {digest}")
        return digest
    except Exception as e:
        logger.warning(f"[xgdun2-target] 推导失败, 保留现有值: {e}")
        return settings.xgdun2_targets.get("1")


__all__ = ["refresh_xgdun2_next_target", "XGDUN2_NEXT_DEFAULT"]
