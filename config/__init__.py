# -*- coding: utf-8 -*-
"""
配置包: 集中存放协议密钥、上游地址与加密算法参数。

分模块导入可避免循环依赖:
    from config.settings import settings
    from config.crypto import CLIENT_ENCRYPT_MKEY
"""

from config import crypto, settings  # noqa: F401  显式导出子模块，便于 from config import settings

__all__ = ["settings", "crypto"]
