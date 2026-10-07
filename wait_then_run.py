#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""等上游在线名额释放: 每 60s 试 cdkeyLogin, 成功后自动跑 5 轮并 dump JSON。"""
import asyncio, sys, time
sys.path.insert(0, r"D:\faker_server")
import httpx
import test_new_endpoints as t

HOST, PORT = t.REAL_HOST, 80

async def try_login(client):
    req, _ = t.build_cdkey_login(t.CDKEY, t.MAC, t.VERSION)
    r = await t.post(client, "/v1/cdkeyLogin", req, HOST, PORT)
    j = r.json()
    st = j.get("status")
    token = None
    if st == 200:
        inner = t.json.loads(t.decrypt_response(j.get("data", "")))
    deadline = time.time() + 900   # 最多等 15 分钟
    return st, token, j.get("msg")

async def main():
    deadline = time.time() + 600   # 最多等 10 分钟
    last = None
    while time.time() < deadline:
        async with httpx.AsyncClient() as client:
            st, token, msg = await try_login(client)
        print(f"[{time.strftime('%H:%M:%S')}] cdkeyLogin -> {st} {msg!r}" + (f" token={token}" if token else ""))
        if st == 200:
            # 登录成功(占了一个名额), 登出释放, 然后正式跑 5 轮
            req, _ = t.build_logout(token, t.CDKEY)
            r = await client.post(f"http://{HOST}:{PORT}/v1/logOut",
                                  content=t.json.dumps(req, ensure_ascii=False, separators=(",", ":")),
                                  headers={"Content-Type": "application/x-www-form-urlencoded", "Host": t.REAL_DOMAIN})
            print("   释放登录后开始 5 轮对比 ...")
            break
        await asyncio.sleep(60)
    else:
        print("!! 10 分钟内名额未释放, 中止")
        return 1

    # 5 轮对比
    await t.main_coro({"host": HOST, "port": PORT, "n": 5, "json": True, "out": r"D:\faker_server\real5.json"})
    return 0

if __name__ == "__main__":
    asyncio.run(main())
