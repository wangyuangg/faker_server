#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RE dossier: 测 /v1/getAppCode 与 /v1/getVerCore 两个新接口 (完整链路)。

链路: cdkeyLogin(拿 token) -> getAppCode(func=XGdun,param='1, 2, 3, 4') / getVerCore
加密/签名/密钥常量与 test_init.py 保持一致 (来源 fake_server_hijack.py)。
可打真实上游 (Host: bgp.tyserve.net) 或本地 fake server (127.0.0.1:port)。

批量测试用法:
    uv run python test_new_endpoints.py 127.0.0.1 8888 --n 5          # 本地连跑 5 轮
    uv run python test_new_endpoints.py --json --out run1.json       # 真实上游, 存结构化结果
    uv run python test_new_endpoints.py 127.0.0.1 8888 --json --out run2.json
    uv run python test_new_endpoints.py 127.0.0.1 8888 --expect run1.json
                                                                     # 与上一次结果逐字段 diff
    uv run python test_new_endpoints.py --xgdun2 --cdkey TOKEN       # 六次 XGdun2 冒烟测试
"""
import json
import time
import hashlib
import struct
import uuid
import sys
import asyncio

import httpx

# ============== 加密参数 (来自 fake_server_hijack.py / test_init.py) ==============
CLIENT_ENCRYPT_MKEY = [21, 7, 127, 20, 63, 128, 88, 133, 33, 246, 244]
CLIENT_ENCRYPT_CONST = 104
SERVER_ENCRYPT_MKEY = [1, 112, 219, 26, 87, 199, 249, 59, 228, 69, 66, 220, 45]
SERVER_ENCRYPT_CONST = 8

# ============== 配置 ==============
REAL_HOST = "183.131.62.35"
REAL_DOMAIN = "bgp.tyserve.net"

appid = "2876"
appkey = "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013"
signKey = "jcpNWyTTzwg"

VERSION = "41234"
MAC = "BFEBFBFF000B0671"          # CPUID 机器码, 从真实日志取
CDKEY = "TOKEN"                   # 默认占位符；真实卡只从 --cdkey 或环境变量传入

# 以下两项在 DLL 里硬编码 (Str::XGdun / Str::one_two_three_four)
FUNC = "XGdun"
PARAM = "1, 2, 3, 4"
XGDUN2_SELECTORS = ("M", "1", "2", "3", "4", "5")

# DLL 门控魔数 (dword_18067B0D4, float32)
GATE_CONST = struct.unpack("<f", struct.pack("<I", 0x477B548E))[0]

# XGdun2 客户端本地校验: DLL 把 value 做 ror/xor 派生后与本机 .\netbios.dll
# 的 MD5 逐字节比较 (RE/14)。下列为已知客户端 netbios.dll 候选 MD5:
#   49381119... 版本清单登记的构建 (vercore M 段 = netbios(新).dll)
#   2c7be32c... URL 当前分发的构建 (又更新了.dll = 当前 vmp blob)
#   0235b952... 未加壳 netbios.dll blob (vercore D 段)
#   85068720... 旧版 netbios(旧).dll
XGDUN2_CLIENT_MD5S = {
    # 六个 selector = 最近发布的 4 个构建的滚动窗口（RE/17），逐个对应 blob 仓库历史：
    "4938111943e61071affd2f8cb34951e2": "vmp-2026-10-06T21:16",    # = vercore M 段
    "2c7be32cd4b2f181bb2374285b4d6083": "vmp-2026-10-06T21:18",    # 本地 又更新了.dll / 最新.dll
    "28c52e2b394af4f22a5d9e99b1baeb38": "vmp-2026-10-07T18:10",    # 第 5 个 selector
    "7d0470d6b6e6b36d3c10cc2183a80437": "vmp-2026-10-07T19:46",    # 第 6 个 selector，当前分发
    "0235b9529fd94c36c4b80fddb8bcdc58": "plain-blob",
    "850687206167b5a6a480db47537fcd78": "old",
}

try:
    from util.xgdun2 import transform as _xgdun2_transform
except ImportError:  # 从其他目录运行时退化为不做客户端门控模拟
    _xgdun2_transform = None

# diff 时忽略的易变字段
IGNORED_DIFF_KEYS = {"nonce", "timestamp", "sign", "token", "finaltime", "msg"}


def mask_secret(value):
    """中文注释：日志只保留首尾少量字符，避免泄露卡号或会话 token。"""
    if not value:
        return value
    text = str(value)
    if len(text) <= 8:
        return "REDACTED"
    return text[:4] + "..." + text[-4:]


def encrypt_request(plain_text):
    """加密客户端请求: (byte - 104) XOR mKey11[i]"""
    data = plain_text.encode("utf-8")
    key, kl = CLIENT_ENCRYPT_MKEY, len(CLIENT_ENCRYPT_MKEY)
    return "".join(f"{(((b - CLIENT_ENCRYPT_CONST) ^ key[i % kl]) & 255):02X}"
                   for i, b in enumerate(data))


def decrypt_response(encrypted_hex):
    """解密服务器响应: ((byte XOR mKey13[i]) + 8)"""
    key, kl, const = SERVER_ENCRYPT_MKEY, len(SERVER_ENCRYPT_MKEY), SERVER_ENCRYPT_CONST
    out = bytearray()
    for i in range(0, len(encrypted_hex), 2):
        b = int(encrypted_hex[i:i + 2], 16)
        out.append(((b ^ key[(i // 2) % kl]) + const) & 255)
    return out.decode("utf-8")


def _envelope(inner_dict, nonce, timestamp):
    """加密 inner + 计算 MD5 签名, 组装公共请求体。"""
    inner_json = json.dumps(inner_dict, ensure_ascii=False, separators=(",", ":"))
    enc = encrypt_request(inner_json)
    sign = hashlib.md5((appid + nonce + signKey + str(timestamp) + enc).encode()).hexdigest()
    return {
        "appid": appid, "nonce": nonce, "timestamp": timestamp,
        "sign": sign, "data": enc,
    }, inner_json


def build_cdkey_login(cdkey, mac, version):
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    ts = int(time.time())
    inner = {"appkey": appkey, "cdkey": cdkey, "mac": mac, "version": version}
    return _envelope(inner, nonce, ts)


def build_get_app_code(token, uname, func=FUNC, param=PARAM):
    """中文注释：构造 getAppCode，可切换旧 XGdun 与新 XGdun2。"""
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    ts = int(time.time())
    inner = {"appkey": appkey, "token": token, "uname": uname, "func": func, "param": param}
    return _envelope(inner, nonce, ts)


def build_xgdun2(token, uname, mac, selector):
    """中文注释：构造单次 XGdun2 请求；param 是带引号的字符串而非数组。"""
    param = f'"{mac}","{selector}"'
    return build_get_app_code(token, uname, "XGdun2", param)


def build_get_ver_core(token, uname, version):
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    ts = int(time.time())
    inner = {"appkey": appkey, "token": token, "uname": uname, "version": version}
    return _envelope(inner, nonce, ts)

def build_logout(token, uname):
    """logOut: 释放服务端在线名额 (DLL Api::logOut 请求键: appkey, token, uname)。"""
    nonce = "{" + str(uuid.uuid4()).upper() + "}"
    ts = int(time.time())
    inner = {"appkey": appkey, "token": token, "uname": uname}
    return _envelope(inner, nonce, ts)


async def post(client, path, req, host, port, with_real_domain=True):
    url = f"http://{host}:{port}{path}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if with_real_domain:
        headers["Host"] = REAL_DOMAIN
    return await client.post(
        url,
        content=json.dumps(req, ensure_ascii=False, separators=(",", ":")),
        headers=headers,
        timeout=20.0,
    )


def parse_resp(resp, label, verbose=True):
    """打印信封 (verbose 时); 返回 (inner_data_dict_or_None, envelope_dict)。"""
    try:
        j = resp.json()
    except Exception as e:
        if verbose:
            print(f"[{label}] HTTP {resp.status_code} 非JSON: {resp.text[:200]!r} ({e})")
        return None, None
    if verbose:
        print(f"[{label}] HTTP {resp.status_code}  信封 status={j.get('status')} msg={j.get('msg')!r}")
    enc = j.get("data", "")
    if enc:
        try:
            d = json.loads(decrypt_response(enc))
            if verbose:
                shown = dict(d) if isinstance(d, dict) else d
                if isinstance(shown, dict) and "token" in shown:
                    shown["token"] = mask_secret(shown["token"])
                print(f"[{label}] data(明文) = {json.dumps(shown, ensure_ascii=False)}")
            return d, j
        except Exception as e:
            if verbose:
                print(f"[{label}] data(解密失败:{e}) 原始 = {enc[:120]!r}")
            return None, j
    if verbose:
        print(f"[{label}] 完整响应 = {json.dumps(j, ensure_ascii=False)}")
    return j, j


def gate_check(value):
    """客户端门控判定: stof(value) 的 float32 是否逐位等于 DLL 魔数 0x477B548E (64340.555)。"""
    try:
        f32 = struct.unpack("<f", struct.pack("<f", float(value)))[0]
    except (TypeError, ValueError, OverflowError):
        return False, f"非数值 {value!r}"
    return f32 == GATE_CONST, f"{f32} == {GATE_CONST}"


async def one_round(client, host, port, verbose=True, do_logout=True,
                    cdkey=None, mac=None, xgdun2=False):
    """跑完整链路一轮, 返回结构化结果 dict; 轮末 logOut 释放在线名额 (防 -213)。"""
    cdkey = cdkey or CDKEY
    mac = mac or MAC
    out = {"target": f"{host}:{port}", "cdkey": mask_secret(cdkey), "version": VERSION}

    # 1) cdkeyLogin -> token
    req, inner = build_cdkey_login(cdkey, mac, VERSION)
    r = await post(client, "/v1/cdkeyLogin", req, host, port)
    d, env = parse_resp(r, "cdkeyLogin", verbose)
    out["cdkeyLogin"] = {"envelope": env, "data": d}
    status = (env or {}).get("status")
    token = (d or {}).get("token")
    if verbose:
        print(f"   [cdkeyLogin] 信封 status={status} token={mask_secret(token)}")
    if status != 200 or not token:
        out["fatal"] = f"cdkeyLogin 信封 status={status} msg={(env or {}).get('msg')!r} 终止"
        if verbose:
            print("!! " + out["fatal"])
        return out
    uname = cdkey

    if xgdun2:
        # 中文注释：最新 DLL 登录后按固定顺序发送六次 XGdun2。
        out["xgdun2"] = []
        for selector in XGDUN2_SELECTORS:
            req, inner = build_xgdun2(token, uname, mac, selector)
            r = await post(client, "/v1/getAppCode", req, host, port)
            d, env = parse_resp(r, f"XGdun2[{selector}]", verbose)
            item = {"selector": selector, "envelope": env, "data": d}
            if env and env.get("status") == 200 and d and "value" in d:
                # 中文注释：XGdun2 返回 selector 派生字符串，不适用旧 XGdun 的浮点魔数门控。
                ok = isinstance(d["value"], str) and bool(d["value"])
                item["accepted"] = ok
                item["value"] = d["value"]
                # 中文注释：模拟客户端本地校验 —— transform(value, mac) 应命中已知
                # netbios.dll 的 MD5, 否则真实 DLL 六次比较全部失败 (RE/14)。
                if ok and _xgdun2_transform is not None:
                    derived = _xgdun2_transform(d["value"], mac)
                    hit = XGDUN2_CLIENT_MD5S.get(derived)
                    item["client_gate"] = hit
                    if verbose:
                        mark = f"CLIENT-GATE PASS ({hit})" if hit else "CLIENT-GATE FAIL"
                        print(f"   [XGdun2/{selector}] {mark}: derived={derived}")
                if verbose:
                    mark = "ACCEPTED" if ok else "EMPTY"
                    print(f"   [XGdun2/{selector}] {mark}: value={d['value']!r}")
            out["xgdun2"].append(item)

        if do_logout:
            # 中文注释：冒烟测试结束释放服务端在线会话，避免下一轮命中在线数限制。
            req, inner = build_logout(token, uname)
            r = await post(client, "/v1/logOut", req, host, port)
            d, env = parse_resp(r, "logOut", verbose)
            out["logOut"] = {"envelope": env, "data": d}
        return out

    # 2) getAppCode (DLL 硬编码 func=XGdun, param='1, 2, 3, 4')
    req, inner = build_get_app_code(token, uname)
    r = await post(client, "/v1/getAppCode", req, host, port)
    d, env = parse_resp(r, "getAppCode", verbose)
    out["getAppCode"] = {"envelope": env, "data": d}
    if env and env.get("status") == 200 and d and "value" in d:
        ok, why = gate_check(d["value"])
        out["getAppCode"]["gate"] = {"value": d["value"], "pass": ok, "detail": why}
        if verbose:
            mark = "GATE PASS" if ok else "GATE FAIL"
            print(f"   [getAppCode] {mark}: value={d['value']!r}  ({why})")

    # 3) getVerCore
    req, inner = build_get_ver_core(token, uname, VERSION)
    r = await post(client, "/v1/getVerCore", req, host, port)
    d, env = parse_resp(r, "getVerCore", verbose)
    out["getVerCore"] = {"envelope": env, "data": d}
    if verbose and env and env.get("status") == 200 and d:
        for k in ("state", "md5", "url", "update", "data"):
            if k in d:
                print(f"   [getVerCore] {k}={str(d[k])[:70]!r}")

    # 4) logOut: 释放服务端在线名额, 避免下一轮撞 -213 "账号在线数量已达到最大"
    if do_logout:
        req, inner = build_logout(token, uname)
        r = await post(client, "/v1/logOut", req, host, port)
        d, env = parse_resp(r, "logOut", verbose)
        out["logOut"] = {"envelope": env, "data": d}
    return out


def diff_results(a, b, path="$"):
    """逐字段 diff 两次运行结果; 返回差异列表 (忽略易变字段)。"""
    diffs = []
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a) | set(b)
        for k in keys:
            p = f"{path}.{k}"
            if k in IGNORED_DIFF_KEYS:
                continue
            if k not in a:
                diffs.append(f"{p}: 仅B有 = {b[k]!r}")
            elif k not in b:
                diffs.append(f"{p}: 仅A有 = {a[k]!r}")
            else:
                diffs.extend(diff_results(a[k], b[k], p))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append(f"{path}: 长度 {len(a)} vs {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diffs.extend(diff_results(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            diffs.append(f"{path}: {a!r} -> {b!r}")
    return diffs


async def main_coro(args):
    host = args["host"]
    port = args["port"]
    n = args["n"]
    verbose = not args.get("json", False)

    with_real_domain = host == REAL_HOST or host in ("127.0.0.1", "localhost")
    results = []
    async with httpx.AsyncClient() as client:
        # --release TOKEN: 先登出旧会话, 释放上游在线名额
        if args.get("release"):
            req, inner = build_logout(args["release"], CDKEY)
            r = await post(client, "/v1/logOut", req, host, port)
            d, env = parse_resp(r, "logOut(release)", True)
            print(f"   [logOut] 信封 status={(env or {}).get('status')} msg={(env or {}).get('msg')!r}")
        for i in range(1, n + 1):
            print("=" * 64)
            print(f"第 {i}/{n} 轮  target={host}:{port}" + ("  (真实上游)" if with_real_domain and host == REAL_HOST else ""))
            print("=" * 64)
            results.append(await one_round(
                client, host, port, verbose,
                cdkey=args.get("cdkey"), mac=args.get("mac"),
                xgdun2=args.get("xgdun2", False)))

    # 汇总判定
    print("\n" + "=" * 64)
    print("汇总")
    print("=" * 64)
    gate_pass = 0  # 中文注释：仅非 xgdun2 路径会累加, 预置 0 避免未定义。
    if args.get("xgdun2"):
        accepted = sum(
            1 for x in results for item in x.get("xgdun2", [])
            if item.get("accepted"))
        total_gates = n * len(XGDUN2_SELECTORS)
        all_ok = bool(results) and all(
            item.get("envelope", {}).get("status") == 200
            and item.get("accepted")
            for x in results for item in x.get("xgdun2", []))
        print(f"  轮数 {n} | XGdun2 接受 {accepted}/{total_gates} | status=200 {all_ok}")
        for x in results:
            summary = ", ".join(
                f"{item.get('selector')}={'PASS' if item.get('accepted') else 'FAIL'}"
                for item in x.get("xgdun2", []))
            print(f"  - {summary}")
    else:
        gate_pass = sum(1 for x in results if (x.get("getAppCode") or {}).get("gate", {}).get("pass"))
        all_ok = all(x.get("getVerCore", {}).get("envelope", {}).get("status") == 200 for x in results)
        print(f"  轮数 {n} | getAppCode 门控通过 {gate_pass}/{n} | getVerCore status=200 {all_ok}")
        for x in results:
            g = (x.get("getAppCode") or {}).get("gate")
            vc = x.get("getVerCore", {}).get("data")
            print(f"  - gate={'PASS' if g and g.get('pass') else 'FAIL'}  "
                  f"value={g.get('value') if g else None!r}  vercore.state={vc.get('state') if vc else None}")

    if args.get("json", False):
        results[0]["_meta"] = {"gate_const": GATE_CONST, "runs": len(results)}
        payload = {"results": results,
                   "summary": {"gate_pass": gate_pass, "n": n}}
        s = json.dumps(payload, ensure_ascii=False, indent=2)
        print(s)
        if args.get("out"):
            with open(args["out"], "w", encoding="utf-8") as f:
                f.write(s)
            print(f"[saved -> {args['out']}]")

    # --expect diff
    if args.get("expect"):
        try:
            prev = json.load(open(args["expect"], encoding="utf-8"))
            prev = prev["results"][0] if "results" in prev else prev
        except Exception as e:
            print(f"--expect 读取失败: {e}")
            return 1
        cur = results[0]
        diffs = diff_results(prev, cur)
        print(f"\n== diff vs {args['expect']} (忽略 {sorted(IGNORED_DIFF_KEYS)}) ==")
        if diffs:
            for d in diffs:
                print("  DIFF " + d)
        else:
            print("  无差异 (业务字段一致)")
    return 0


def main():
    argv = sys.argv[1:]
    flags = {}
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--json":
            flags["json"] = True
        elif a == "--n":
            i += 1; flags["n"] = int(argv[i])
        elif a == "--out":
            i += 1; flags["out"] = argv[i]
        elif a == "--expect":
            i += 1; flags["expect"] = argv[i]
        elif a == "--release":
            i += 1; flags["release"] = argv[i]
        elif a == "--cdkey":
            i += 1; flags["cdkey"] = argv[i]
        elif a == "--mac":
            i += 1; flags["mac"] = argv[i]
        elif a == "--xgdun2":
            flags["xgdun2"] = True
        else:
            args.append(a)
        i += 1
    host = args[0] if len(args) > 0 else REAL_HOST
    port = int(args[1]) if len(args) > 1 else 80
    flags["host"] = host
    flags["port"] = port
    flags["n"] = flags.get("n", 1)
    sys.exit(asyncio.run(main_coro(flags)))


if __name__ == "__main__":
    main()
