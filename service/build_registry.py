# -*- coding: utf-8 -*-
"""
构建台账 —— XGdun2 六个 selector 的唯一取值来源。

背景 (RE/17): 作者在 gitcode 仓库 w355755/KK 上发布 4 个模块, 每次改动先
`delete: 删除文件 netbios.vmp.dll` 再重传 (raw blob 按内容寻址, 必须换 hash)。
真实上游把 XGdun2 的六个 selector 映射为:

    M, 1, 2, 3 -> 最近 4 个"不同"的 netbios.vmp.dll 构建 (按发布时间升序)
    4, 5       -> 诱饵: netbioscs.dll 的 MD5 末字节 -5 / -4 (永不命中任何构建)

客户端六个 selector 是短路 OR, 只要客户端在跑近 4 个构建之一就通过 ——
这正是作者吸收"清单登记版 / URL 分发版"不一致窗口的办法。

本模块:
  * 台账落盘 config/build_ledger.json, 内容寻址、离线可用、不重复下载;
  * refresh() 增量发现新 blob (只算 MD5, 默认不落原始文件);
  * target_for(selector) 按声明式规则给出目标 MD5。

优先级: FAKER_XGDUN2_TARGETS (显式覆盖) > 台账 > settings.xgdun2_targets (兜底)。
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from loguru import logger

#: 最近的 vmp 构建按时间升序映射到 selector (RE/17 实测)
WINDOW_SELECTORS: Dict[str, int] = {"M": 0, "1": 1, "2": 2, "3": 3}
#: 诱饵 selector -> (基准文件, MD5 末字节偏移)
DECOY_SELECTORS: Dict[str, tuple] = {"4": ("netbioscs.dll", -5), "5": ("netbioscs.dll", -4)}

VMP_FILE: str = "netbios.vmp.dll"
LEDGER_PATH: Path = Path(__file__).resolve().parent.parent / "config" / "build_ledger.json"
API_TIMEOUT: float = 20.0
BLOB_TIMEOUT: float = 300.0
COMMIT_SCAN: int = 20


@dataclass(frozen=True)
class BuildEntry:
    """一条构建记录: blob 为 gitcode blob sha, md5 为文件内容摘要。"""

    file: str
    blob: str
    md5: str
    size: int
    first_seen: str = ""

    def to_dict(self) -> dict:
        """序列化为台账 JSON 行。"""
        return {"file": self.file, "blob": self.blob, "md5": self.md5,
                "size": self.size, "first_seen": self.first_seen}


def decoy_md5(base_md5: str, delta: int) -> str:
    """把 32hex 的末字节按 delta 平移 (诱饵构造, 与真实上游一致)。"""
    last = (int(base_md5[-2:], 16) + delta) & 0xFF
    return f"{base_md5[:-2]}{last:02x}"


class BuildRegistry:
    """构建台账 + selector 规则 (进程内单例 registry)。"""

    def __init__(self, ledger_path: Path = LEDGER_PATH) -> None:
        self.ledger_path = ledger_path
        self.repo: dict = {}
        self.files: List[str] = []
        self.entries: List[BuildEntry] = []
        self._loaded = False
        self._overrides: Optional[Dict[str, str]] = None

    # ---------- 台账读写 ----------
    def load(self) -> None:
        """从磁盘载入台账 (幂等)。缺文件时保持空台账, 由 settings 兜底。"""
        if self._loaded:
            return
        self._loaded = True
        try:
            raw = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[registry] 台账不可用 ({e}); 退化到 settings 兜底值")
            return
        self.repo = raw.get("repo", {})
        self.files = list(raw.get("files", []))
        self.entries = [BuildEntry(**row) for row in raw.get("entries", []) if row.get("blob")]
        logger.info(f"[registry] 台账载入 {len(self.entries)} 条")

    def save(self) -> None:
        """台账落盘 (原子写, 避免半截文件)。"""
        payload = {
            "schema": 1,
            "note": "netbios 构建台账; service/build_registry.py 维护, 手工可读可改",
            "repo": self.repo,
            "files": self.files,
            "entries": [e.to_dict() for e in self.entries],
        }
        tmp = self.ledger_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.ledger_path)

    # ---------- 查询 ----------
    def builds(self, file: str = VMP_FILE) -> List[BuildEntry]:
        """按 first_seen 升序返回某文件的全部构建。"""
        rows = [e for e in self.entries if e.file == file]
        return sorted(rows, key=lambda e: e.first_seen or "")

    def known_md5s(self, file: Optional[str] = None) -> List[str]:
        """台账里出现过的全部 MD5 (默认全部文件)。"""
        return [e.md5 for e in self.entries if file is None or e.file == file]

    def overrides(self) -> Dict[str, str]:
        """FAKER_XGDUN2_TARGETS 显式覆盖表 (最高优先级)。"""
        if self._overrides is None:
            self._overrides = {}
            raw = os.environ.get("FAKER_XGDUN2_TARGETS", "").strip()
            if raw:
                try:
                    loaded = json.loads(raw)
                    if isinstance(loaded, dict):
                        self._overrides = {str(k): str(v).lower() for k, v in loaded.items()}
                except json.JSONDecodeError:
                    logger.warning("[registry] FAKER_XGDUN2_TARGETS 不是合法 JSON, 忽略")
        return self._overrides

    def selector_target(self, selector: str) -> Optional[str]:
        """按规则给出 selector 目标 MD5; 台账不足时返回 None。"""
        self.load()
        index = WINDOW_SELECTORS.get(selector)
        if index is not None:
            recent = self.builds(VMP_FILE)[-len(WINDOW_SELECTORS):]  # 最近 4 个, 时间升序
            if len(recent) > index:
                return recent[index].md5
            return None
        decoy = DECOY_SELECTORS.get(selector)
        if decoy:
            base_file, delta = decoy
            base = self.builds(base_file)
            if base:
                return decoy_md5(base[-1].md5, delta)
        return None

    def targets(self) -> Dict[str, str]:
        """全部 selector 的目标 MD5 (供门控自检与响应合成)。"""
        out: Dict[str, str] = {}
        for selector in list(WINDOW_SELECTORS) + list(DECOY_SELECTORS):
            value = self.overrides().get(selector) or self.selector_target(selector)
            if value:
                out[selector] = value
        return out

    def target_for(self, selector: str) -> Optional[str]:
        """合成 XGdun2 响应时使用: 覆盖 > 台账 > settings 兜底。"""
        override = self.overrides().get(selector)
        if override:
            return override
        value = self.selector_target(selector)
        if value:
            return value
        from config.settings import settings

        return settings.xgdun2_targets.get(selector) or settings.xgdun2_targets.get("M")

    # ---------- 增量刷新 ----------
    async def refresh(self) -> int:
        """从 gitcode 仓库增量发现新 blob 并入账, 返回新增条数 (失败非致命)。"""
        self.load()
        if os.environ.get("FAKER_REGISTRY_REFRESH", "1").strip() in ("0", "false", "False"):
            return 0
        if not self.repo.get("api"):
            return 0
        known_blobs = {e.blob for e in self.entries}
        added = 0
        try:
            async with httpx.AsyncClient(timeout=API_TIMEOUT, follow_redirects=True) as api:
                commits = await self._commits(api)
                for commit in commits:
                    tree = await self._tree(api, commit.get("sha", ""))
                    if not tree:
                        continue
                    date = commit.get("commit", {}).get("committer", {}).get("date", "")
                    for path, blob in tree.items():
                        if path not in self.files or blob in known_blobs:
                            continue
                        digest = await self._blob_md5(blob, path)
                        if not digest:
                            continue
                        self.entries.append(BuildEntry(path, blob, digest, 0, date))
                        known_blobs.add(blob)
                        added += 1
                        logger.info(f"[registry] 新构建入账 {path} blob={blob[:12]}… md5={digest}")
                        self.save()
        except Exception as e:  # 网络/解析异常一律不致命
            logger.warning(f"[registry] 刷新失败, 保留现有台账: {e}")
            return added
        logger.info(f"[registry] 刷新完成, 新增 {added} 条, 台账共 {len(self.entries)} 条")
        return added

    async def _commits(self, api: httpx.AsyncClient) -> List[dict]:
        url = f"{self.repo['api']}/commits?per_page={COMMIT_SCAN}"
        resp = await api.get(url, headers={"User-Agent": "fake-server/1.0"})
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []

    async def _tree(self, api: httpx.AsyncClient, sha: str) -> Dict[str, str]:
        if not sha:
            return {}
        url = f"{self.repo['api']}/git/trees/{sha}?recursive=1"
        resp = await api.get(url, headers={"User-Agent": "fake-server/1.0"})
        resp.raise_for_status()
        payload = resp.json()
        return {x["path"]: x["sha"] for x in payload.get("tree", []) if x.get("type") == "blob"}

    def _blob_url(self, blob: str, path: str) -> str:
        return f"{self.repo['raw']}/{blob}/{path}"

    async def _blob_md5(self, blob: str, path: str) -> Optional[str]:
        """流式下载 blob 计算 MD5 (不进内存); FAKER_BLOB_CACHE 可落盘留档。"""
        cache_dir = os.environ.get("FAKER_BLOB_CACHE", "").strip()
        digest = hashlib.md5()
        async with httpx.AsyncClient(timeout=BLOB_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("GET", self._blob_url(blob, path)) as resp:
                resp.raise_for_status()
                handle = None
                if cache_dir:
                    Path(cache_dir).mkdir(parents=True, exist_ok=True)
                    handle = open(Path(cache_dir) / f"{blob}_{path}", "wb")
                try:
                    async for chunk in resp.aiter_bytes(1024 * 1024):
                        digest.update(chunk)
                        if handle:
                            handle.write(chunk)
                finally:
                    if handle:
                        handle.close()
        return digest.hexdigest()


#: 进程内单例
registry = BuildRegistry()

__all__ = [
    "BuildEntry", "BuildRegistry", "registry",
    "WINDOW_SELECTORS", "DECOY_SELECTORS", "VMP_FILE", "decoy_md5",
]
