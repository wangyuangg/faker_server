# `test_new_endpoints.py` 流程输入输出记录

## 1. 运行目标

本文件总结 `test_new_endpoints.py` 的一轮完整链路：

```text
cdkeyLogin -> getAppCode -> getVerCore -> logOut
```

本次实际运行目标：

```text
HOST = 183.131.62.35
PORT = 80
DOMAIN = bgp.tyserve.net
轮数 = 1
```

本次卡号：

```text
MSTK6DEB5ADEFD6A4C699369B387F78A5DE4
```

执行命令：

```powershell
.\.venv\Scripts\python.exe .\test_new_endpoints.py 183.131.62.35 80 --n 1
```

## 2. 固定配置与协议封装

脚本中的固定配置：

| 名称 | 值 |
|---|---|
| `appid` | `2876` |
| `appkey` | `BDD09ED5-82E5-424C-A6A7-C8AC7F66A013` |
| `signKey` | `jcpNWyTTzwg` |
| `VERSION` | `41234` |
| `MAC` | `BFEBFBFF000B0671` |
| `FUNC` | `XGdun` |
| `PARAM` | `1, 2, 3, 4` |
| `GATE_CONST` | `float32(0x477B548E) = 64340.5546875` |

每个请求的外层 JSON 结构：

```json
{
  "appid": "2876",
  "nonce": "{随机大写 UUID}",
  "timestamp": 1791259696,
  "sign": "MD5(appid + nonce + signKey + timestamp + data)",
  "data": "UTF-8 内层 JSON 的十六进制加密串"
}
```

请求加密算法（`encrypt_request`）：

```text
encrypted_byte[i] = ((plain_byte[i] - 104) XOR CLIENT_ENCRYPT_MKEY[i % 11]) & 0xff
```

响应 `data` 解密算法（`decrypt_response`）：

```text
plain_byte[i] = ((encrypted_byte[i] XOR SERVER_ENCRYPT_MKEY[i % 13]) + 8) & 0xff
```

响应信封通常为：

```json
{
  "status": 200,
  "msg": "OK",
  "data": "响应内层 JSON 的十六进制加密串"
}
```

HTTP 请求使用：

```text
Content-Type: application/x-www-form-urlencoded
Host: bgp.tyserve.net
```

## 3. 流程一：`cdkeyLogin`

### 输入

脚本调用路径：

```text
POST /v1/cdkeyLogin
```

内层明文 JSON：

```json
{
  "appkey": "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013",
  "cdkey": "MSTK6DEB5ADEFD6A4C699369B387F78A5DE4",
  "mac": "BFEBFBFF000B0671",
  "version": "41234"
}
```

外层请求的 `nonce` 为随机 UUID，`timestamp` 为发送时 Unix 时间戳，`data` 为上述内层 JSON 加密后的十六进制字符串，`sign` 使用 MD5 计算。

### 本次输出

HTTP 与响应信封：

```text
HTTP 200
status = 200
msg = "OK"
```

解密后的业务数据：

```json
{
  "nonce": "{A8B8A9E6-A394-4F44-930A-61088E79B86E}",
  "timestamp": 1791259696,
  "token": "55A318BE-0758-44D9-B5BC-83D5616F1AD5",
  "boss": "ms",
  "group": "普通",
  "finaltime": "2026-10-06 21:47:18",
  "tally": 0.0
}
```

脚本提取的关键输出：

```text
status = 200
token = 55A318BE-0758-44D9-B5BC-83D5616F1AD5
uname = MSTK6DEB5ADEFD6A4C699369B387F78A5DE4
```

后续流程以 `token` 作为认证输入；`uname` 被设置为当前卡号。

## 4. 流程二：`getAppCode`

### 输入

脚本调用路径：

```text
POST /v1/getAppCode
```

内层明文 JSON：

```json
{
  "appkey": "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013",
  "token": "55A318BE-0758-44D9-B5BC-83D5616F1AD5",
  "uname": "MSTK6DEB5ADEFD6A4C699369B387F78A5DE4",
  "func": "XGdun",
  "param": "1, 2, 3, 4"
}
```

其中 `token` 是 `cdkeyLogin` 的动态输出，`func` 与 `param` 是脚本硬编码值。

### 本次输出

HTTP 与响应信封：

```text
HTTP 200
status = 200
msg = "OK"
```

解密后的业务数据：

```json
{
  "nonce": "{588B8641-6BF9-4110-BB7D-3CF11DC26C95}",
  "timestamp": 1791259696,
  "value": "64340.5555555556"
}
```

### 门控判定

脚本把 `value` 转换为 float32，再与 DLL 魔数比较：

```text
输入字符串: 64340.5555555556
float32(value): 64340.5546875
GATE_CONST:     64340.5546875
判定: PASS
```

结构化结果等价于：

```json
{
  "value": "64340.5555555556",
  "pass": true,
  "detail": "64340.5546875 == 64340.5546875"
}
```

## 5. 流程三：`getVerCore`

### 输入

脚本调用路径：

```text
POST /v1/getVerCore
```

内层明文 JSON：

```json
{
  "appkey": "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013",
  "token": "55A318BE-0758-44D9-B5BC-83D5616F1AD5",
  "uname": "MSTK6DEB5ADEFD6A4C699369B387F78A5DE4",
  "version": "41234"
}
```

### 本次输出

HTTP 与响应信封：

```text
HTTP 200
status = 200
msg = "OK"
```

解密后的业务数据：

```json
{
  "nonce": "{17C35553-3995-41CD-8101-ABC2B6F64B3C}",
  "timestamp": 1791259696,
  "state": 1,
  "md5": "a33b08f1c418d34fd96d2f61001e971a",
  "data": "Xd2c40635803c235768e7b07e13c5a2d2J5d8ddbffe0760ddb1111e91cb615194eD0235b9529fd94c36c4b80fddb8bcdc58Gfe5eb1535380196a6485972819128a62M4938111943e61071affd2f8cb34951e2Cdae29fa55cfa063f0c8a812f1cd0f179",
  "url": "",
  "update": "https://raw.gitcode.com/w355755/KK/blobs/5f0c03b4a643685711ad733270d032d59f4f4412/netbios.dllhttps://raw.gitcode.com/w355755/KK/blobs/1cd87b811e8eb40bcd746a4495a7cc743c091b0d/netbios.vmp.dllhttps://raw.gitcode.com/w355755/KK/blobs/db809e505fc77d5d83f839a41e3432a1057e01fd/netbioscs.dllhttps://raw.gitcode.com/w355755/KK/blobs/ee3298994773444e3ce5af8d8293c62294609fa4/netbiosgj.dll"
}
```

脚本汇总时读取的字段：

```text
state = 1
md5   = a33b08f1c418d34fd96d2f61001e971a
url   = ""
update = 多个组件更新地址拼接字符串
data  = 版本/核心数据字符串
```

## 6. 流程四：`logOut`

### 输入

脚本调用路径：

```text
POST /v1/logOut
```

内层明文 JSON：

```json
{
  "appkey": "BDD09ED5-82E5-424C-A6A7-C8AC7F66A013",
  "token": "55A318BE-0758-44D9-B5BC-83D5616F1AD5",
  "uname": "MSTK6DEB5ADEFD6A4C699369B387F78A5DE4"
}
```

该请求用于释放服务端在线名额，避免下一轮登录触发在线数量限制。

### 本次输出

HTTP 与响应信封：

```text
HTTP 200
status = 200
msg = "OK"
```

解密后的业务数据：

```json
{
  "nonce": "{83688119-C367-4ABE-A315-ACBD66119015}",
  "timestamp": 1791259697
}
```

## 7. 单轮最终汇总

本次运行的终端汇总：

```text
轮数 1
getAppCode 门控通过 1/1
getVerCore status=200 True
gate=PASS
value='64340.5555555556'
vercore.state=1
```

结论：本次卡号完成登录、应用门控值校验、版本核心查询和登出；四个步骤均收到 HTTP 200，业务信封状态均为 `200`。

## 8. 失败与提前终止条件

### `cdkeyLogin` 失败

若响应信封不是 `status=200` 或解密数据没有 `token`，脚本立即终止后续流程，并记录：

```text
fatal = cdkeyLogin 信封 status=<值> msg=<值> 终止
```

### `getAppCode` 门控失败

接口仍可能返回 HTTP 200，但 `value` 转换为 float32 后不等于 `GATE_CONST`，此时记录 `GATE FAIL`。

### `getVerCore` 非 200

最终汇总中的 `getVerCore status=200` 会为 `False`。

### 动态字段

以下字段每轮可能变化，不应作为固定值比较：

```text
nonce, timestamp, sign, token, finaltime, msg
```

