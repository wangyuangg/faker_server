# AGENTS.md

Fake game API server (hijacks requests for `bgp.tyserve.net`) with an XOR+counter
encryption protocol and MD5 signature. Three implementations exist (Python, C++,
Go); the C++ one is the active focus.

## Layout

- `app.py` — Python entrypoint: FastAPI app factory + router registration + `run()` (port 80)
- `fake_server_hijack.py` — legacy entrypoint, now a thin wrapper around `app.py`
- Python MVC packages (see "Python layout (MVC)" below)
- `cpp/` — C++ reimplementation (VS2026/MSVC, CMake)
- `go-faker/` — Go reimplementation (gin + zerolog + goccy/go-json)
- `test_init.py` — appInit test client (uses `.venv` via `uv`); `--real` flag
  targets the real server with `Host` header
- `cpp/build/release/faker_server.exe` — build output (xmake)

## Python layout (MVC)

Stack: FastAPI + uvicorn + httpx(AsyncClient) + loguru.

```bat
uv run app.py            :: 入口（默认 0.0.0.0:80，可传端口参数）
uv run app.py 8080       :: 指定端口（等价 FAKER_PORT=8080）
uvicorn app:app --port 8080   :: 直接用 ASGI 服务器启动
uv run test_refactor.py  :: 重构回归测试（56 项断言，含 appInit 代理透传）
uv run test_init.py [host] [port] [version] [--real]
```

```
app.py                create_app() 创建 FastAPI 实例 + install_exception_middleware
                      + include_router，模块级 app 供 `uvicorn app:app` 使用
controllers/          路由层，每个 API 一个 APIRouter，只做解析/调用 service/组装响应
  api_route.py        api_post(router, path) 装饰器：注册 POST 路由 + 声明响应媒介类型
  *_controller.py     app_init / cdkey_login / message / user_bind / logout
service/              业务逻辑层（token 签发、绑定、登出、上游代理）
models/               数据模型层（ApiResponse / ClientRequest / LoginPayload / ApiStatus）
util/                 纯函数工具（crypto 加解密、signature 签名、parser 异步请求解析、
                      response_builder 响应体构造、http_client 共享 httpx.AsyncClient）
config/               settings（上游地址/监听配置）、crypto（协议密钥常量）
common/               response（紧凑 JSON 与 text/html 响应）、errors（SignError）、
                      exception_middleware（ASGI 异常兜底）、console（show 彩色日志）
```

- 依赖方向单向: `controllers → service → {models, util} → config`；`common` 只被
  controller/util 引用，不反向依赖业务层。
- 统一异常处理在 `common/exception_middleware.py` 的纯 ASGI 中间件里（不是路由内
  try/except，也不是 `@app.exception_handler`）：`SignError → 403 信封`，其它异常
  `→ 500 信封`，两者 HTTP 状态码都是 200。
- 路由 handler 必须 `async def`；请求体用 `await request.body()` 读原始字节，
  `util.parser.parse_request(request, body)` 支持复用已读 body。
- 响应绝不使用 FastAPI 的 `JSONResponse`（会变成 `application/json` 并丢掉 charset）：
  统一返回 `common.response.json_response()` / `raw_response()`，并在 `api_post`
  里声明 `response_class=RawJsonResponse`。
- `app_init` 控制器不做签名校验也不解密（原实现即如此），其余 4 个路由统一走
  `util.parser.parse_request`。
- 上游代理用 `httpx.AsyncClient`（`util/http_client.get_client()` 懒加载单例，
  应用 shutdown 时 `close_client()` 释放连接池），不要在请求路径里用同步 httpx。
- 新增接口: 建 `controllers/xxx_controller.py` → `router = APIRouter()` →
  `@api_post(router, "/v1/xxx")` → 在 `controllers/__init__.py` 的 `ALL_ROUTERS` 注册。
- `settings` 为 frozen dataclass，在导入时读取环境变量 `FAKER_REAL_HOST` /
  `FAKER_REAL_DOMAIN` / `FAKER_BIND_HOST` / `FAKER_PORT` / `FAKER_RELOAD`
  （测试里要换上游地址，必须在 `import app` 之前设置）。

## C++ build (cpp/)

```bat
build.bat            # xmake f -m release && xmake
```

- MSVC REQUIRES the `/utf-8` flag — already set in `xmake.lua` via
  `add_cxflags("/utf-8", {force = true})`. Without it, UTF-8 Chinese string
  literals are misread as GBK and the file won't compile.
- Deps are vendored headers in `cpp/third_party/` (nlohmann/json, cpp-httplib).
  Note: this httplib version has the new API — `Result::error()`, not
  `error_message()`; `Response` is unique_ptr-based.
- Links `ws2_32`, `rpcrt4` (UuidCreate for UUIDs), and `bcrypt` (MD5 via
  Windows BCrypt API — `md5.cpp` is a thin wrapper, not hand-rolled crypto).
- Output: `cpp/build/release/faker_server.exe`.

## Go build (go-faker/)

```bat
cd go-faker
go build -o faker_server.exe .
go test ./...
```

- Stack: `gin-gonic/gin` (routing), `rs/zerolog` (logging), `goccy/go-json`
  (JSON). MD5 via `crypto/md5`; UUID v1/v4 hand-rolled on `crypto/rand`.
- JSON parity technique: response payloads are structs (field order = JSON
  order) marshaled with `json.MarshalNoEscape` — no HTML/ASCII escaping;
  `nonce`/`timestamp` are `json.RawMessage` echoes; `tally` is a
  `json.RawMessage("0.0")` literal.
- Output: `go-faker/faker_server.exe`; default port 80, first CLI argument
  overrides (e.g. `faker_server.exe 8080`).
- `FAKER_REAL_HOST` overrides the real upstream host, same as the other versions.

## Protocol invariants (don't break these)

- Sign: `MD5(appid + nonce + signKey + timestamp + data)`, case-insensitive compare.
- Client-decrypt: `(byte ^ CLIENT_ENCRYPT_MKEY[i]) + 104`; server-decrypt:
  `(byte ^ SERVER_ENCRYPT_MKEY[i]) + 8`; response-encrypt is the inverse.
- Response body is compact JSON `{"status":200,"msg":"OK","data":"<hex>"}` with
  `Content-Type: text/html; charset=utf-8`; clients send JSON with
  `Content-Type: application/x-www-form-urlencoded`.
- JSON must be dumped without ASCII escaping — C++: `dump(-1, ' ', false)`;
  Python: `ensure_ascii=False`. Escaped `\uXXXX` changes the encrypted payload
  and breaks parity.
- `make_response_data` echoes the client's `nonce`/`timestamp` back
  (preserving their original JSON types). `userBind` is the exception: it sends
  a fresh `{UUID1}` nonce and the server's current time instead.
- appInit is a byte-for-byte proxy and deliberately skips signature
  verification/decryption; the other 4 routes verify the sign first.

## Runtime

- Default port 80 — binds only as Administrator; pass a port arg to override.
- `FAKER_REAL_HOST` env var overrides the real upstream host (for testing the
  appInit fallback). Use `127.0.0.1:1` (dead port) to force fallback — a bare
  `127.0.0.1` loops the proxy back into the server itself.
- FastAPI serves the same raw HTTP envelope as the old Flask app: business status
  codes (403/500) live in the body, HTTP is 200; only appInit passes an upstream
  HTTP status through. `text/html; charset=utf-8` and the compact body were
  verified byte-identical against the Flask implementation.
- appInit proxies to the real host; on failure it returns
  `{"status":500,"msg":"上游服务器连接失败"}` with NO fake data (the client
  downloads files from the response's `update` URLs, which a fake server can't
  serve). The other 4 routes (`/v1/cdkeyLogin`, `/v1/setAppMessage`,
  `/v1/userBind`, `/v1/logOut`) always answer locally. cdkeyLogin token is
  valid 7 days.
- Built-in docs are disabled (`docs_url`/`openapi_url`/`redoc_url=None`) — the
  protocol is consumed by a game client, not by browsers.
- `FAKER_RELOAD=1` enables uvicorn auto-reload for development.
- When testing from a shell, start the server and run the test client in the
  same invocation — detached processes get killed when the shell exits.
  Killing the wrapping shell may leave the uvicorn child alive; check the port
  before concluding the server is gone.
- Protocol was verified against the real client module `netbios.dll` (IDA):
  keys/sign-format/paths match byte-for-byte. Client strings are obfuscated as
  `{u32 len; data[len]; u8 pad; u8 xor_key; u8 sub_key}`, decoded by
  `plain[i] = xor_key ^ (data[i] - sub_key)` (signed chars). This module only
  calls appInit/cdkeyLogin/logOut (not setAppMessage/userBind); cdkeyLogin
  inner payload is `{appkey, version, cdkey, mac}`; client checks response
  `nonce` echo, requires `status==200`, and flags |server_ts - local_ts| > 500
  (echoing the request timestamp back always passes).

## Conventions

- Keep the C++, Go and Python implementations behaviorally in sync (protocol,
  routes, expiry, response fields).
- Python: `uv run test_refactor.py` must stay green after touching the protocol
  path — it asserts the envelope byte format, 7-day token expiry, UUID1 bind
  nonce, 403/500 branches, unknown-route 404 and appInit passthrough
  (body + `Host` header + upstream status).
- C++ sources contain Chinese comments/strings; always compile with `/utf-8`.

