# -*- coding: utf-8 -*-
"""一次性核对: 本地 fake server 的业务字段 vs 2026-10-07 真实上游快照。

用法: uv run python _verify_vs_upstream.py _local_xgdun2.json _local_full.json
"""

import json
import sys

REAL_XGDUN2 = {
    "M": "6e7bd6c9302a349276d019df158268fd",
    "1": "8da58a94272109dcfd0f4d440b97e8be",
    "2": "bd55c2787817cf5c660843ea70227fe5",
    "3": "6a0a960b415ee4987d86e01dc0535e87",
    "4": "d534a4218c498651cce5e6b90c6c5207",
    "5": "d534a4218c498651cce5e6b90c7c5207",
}
REAL_XGDUN = "64340.5555555556"
REAL_UPDATE = (
    "https://raw.gitcode.com/w355755/KK/blobs/5f0c03b4a643685711ad733270d032d59f4f4412/netbios.dll"
    "https://raw.gitcode.com/w355755/KK/blobs/61f439ecd443c5a5058fdaf3f04bec9ab508a85b/netbios.vmp.dll"
    "https://raw.gitcode.com/w355755/KK/blobs/db809e505fc77d5d83f839a41e3432a1057e01fd/netbioscs.dll"
    "https://raw.gitcode.com/w355755/KK/blobs/ee3298994773444e3ce5af8d8293c62294609fa4/netbiosgj.dll"
)
REAL_DATA = (
    "Xd2c40635803c235768e7b07e13c5a2d2J5d8ddbffe0760ddb1111e91cb615194e"
    "D0235b9529fd94c36c4b80fddb8bcdc58Gfe5eb1535380196a6485972819128a62"
    "M4938111943e61071affd2f8cb34951e2Cdae29fa55cfa063f0c8a812f1cd0f179"
)


def main() -> int:
    xgdun2_run = json.load(open(sys.argv[1], encoding="utf-8"))["results"][0]
    full_run = json.load(open(sys.argv[2], encoding="utf-8"))["results"][0]

    ok = True
    for item in xgdun2_run["xgdun2"]:
        selector = item["selector"]
        got = item["data"]["value"]
        match = got == REAL_XGDUN2[selector]
        ok &= match
        print(f"XGdun2[{selector}] {'一致' if match else '不一致: ' + REAL_XGDUN2[selector]}  {got}")

    value = full_run["getAppCode"]["data"]["value"]
    gate = value == REAL_XGDUN
    ok &= gate
    print(f"XGdun      {'一致' if gate else '不一致'}  {value}")

    vc = full_run["getVerCore"]["data"]
    checks = [
        ("vercore.state == 1", vc["state"] == 1),
        ("vercore.md5", vc["md5"] == "a33b08f1c418d34fd96d2f61001e971a"),
        ("vercore.data", vc["data"] == REAL_DATA),
        ("vercore.update", vc["update"] == REAL_UPDATE),
        ("vercore.url == ''", vc["url"] == ""),
    ]
    for name, passed in checks:
        ok &= passed
        print(f"{name:24s} {'一致' if passed else '不一致'}")

    print()
    print("与真实上游快照完全一致:" , bool(ok))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
