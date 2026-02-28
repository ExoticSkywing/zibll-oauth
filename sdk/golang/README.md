# Zibll OAuth Go SDK

Go 语言 SDK，用于对接 Zibll OAuth2 服务（基于 WordPress 插件 `zibll-oauth`）。

## 特性

- ✅ 完整的 OAuth2 Authorization Code Grant 流程
- ✅ 财务扣款（异步模型）
- ✅ 回调签名验证（Sign2）
- ✅ 自动重试机制
- ✅ 可自定义 HTTP 客户端和日志
- ✅ 完整的错误处理

## 兼容的 OAuth2 流程

- **授权**：`GET /authorize?response_type=code&client_id=...&redirect_uri=...&state=...&scope=...`
- **换取 Token**：`POST /token`（`grant_type=authorization_code`）
- **刷新 Token**：`POST /token`（`grant_type=refresh_token`，refresh_token 会轮换）
- **吊销**：`POST /revoke`
- **获取用户信息**：`GET /userinfo`
- **获取 UnionID**：`GET /unionid`
- **健康检查**：`GET /health`

## 安装

```bash
go get cnb.cool/yungnet/zibll-oauth/sdk/golang
```

## 快速开始

### 1) 创建客户端

```go
package main

import (
    "fmt"
    "cnb.cool/yungnet/zibll-oauth/sdk/golang"
)

func main() {
    config := &ziblloauth.Config{
        BaseURL:     "https://www.example.com/wp-json/zibll-oauth/v1",
        AppID:       "zo_xxxxxxxx",
        RedirectURI: "https://your-app.example.com/oauth/callback",
        AppKey:      "your_appkey_here",
    }
    client, err := ziblloauth.NewClient(config)
    if err != nil {
        panic(err)
    }
    // 使用 client...
}
```

### 2) 发起授权（获取 code）

```go
// 生成随机 state
state, _ := ziblloauth.GenerateState(16)

// 构建授权 URL
authorizeURL := client.BuildAuthorizeURL(state, "basic email profile")

// 重定向用户到授权页面
http.Redirect(w, r, authorizeURL, http.StatusFound)
```

### 3) 回调处理（code 换 token）

```go
func callbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")

    // 使用 code 换取 access_token
    tokenResp, err := client.TokenByCode(code, state)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 保存 token
    accessToken := tokenResp.AccessToken
    refreshToken := tokenResp.RefreshToken

    fmt.Fprintf(w, "Access Token: %s\n", accessToken)
}
```

### 4) 使用 Token 调用接口

```go
// 获取用户信息
userInfo, err := client.GetUserInfo(accessToken)
if err != nil {
    panic(err)
}
fmt.Printf("用户: %s (%s)\n", userInfo.Name, userInfo.OpenID)
if userInfo.RefreshToken != "" {
    fmt.Printf("UserInfo RefreshToken: %s (expires_in=%d)\n", userInfo.RefreshToken, userInfo.RefreshTokenExpiresIn)
}

// 获取 UnionID
unionIDResp, err := client.GetUnionID(accessToken)
if err != nil {
    panic(err)
}
fmt.Printf("UnionID: %s\n", unionIDResp.UnionID)
```

### 5) 刷新和吊销 Token

```go
// 刷新 Token（会轮换 refresh_token）
newToken, err := client.RefreshToken(refreshToken)
if err != nil {
    panic(err)
}
// 使用新的 newToken.RefreshToken

// 刷新 Token（不轮换 refresh_token，适用于无法保存轮换 refresh_token 的场景）
stableToken, err := client.RefreshTokenNoRotate(refreshToken)
if err != nil {
    panic(err)
}
// stableToken.RefreshToken == refreshToken

// 吊销 Token
err = client.RevokeToken(newToken.RefreshToken, "refresh_token")
if err != nil {
    panic(err)
}
```

## 财务扣款（异步模型）

### 财务权限判断

财务相关接口（如扣款）通常要求用户完成财务授权。

SDK 提供 `HasFinancePermission(accessToken)` 用于判断当前 `accessToken` 是否具备财务权限：

- 判断依据：调用 `GET /userinfo`，检查返回的 `userinfo` 对象中是否**存在** `balance` 字段
- `balance` 字段存在：说明已授予财务权限
- `balance` 字段不存在：说明未授予财务权限

> 注意：不能通过 `UserInfo.Balance == 0` 判断是否有权限。因为在 Go 反序列化中，字段不存在时数值类型会是 `0`，无法区分“没返回 balance”和“返回 balance=0”。

示例：

```go
ok, err := client.HasFinancePermission(accessToken)
if err != nil {
    panic(err)
}
if !ok {
    // 引导用户进行财务授权（/authorize_finance -> 回调 code -> /token）
    // authorizeFinanceURL := client.BuildAuthorizeFinanceURL(state)
    panic("no finance permission")
}

// 有财务权限后再进行扣款/查询
```

### 发起扣款

```go
req := ziblloauth.FinanceDeductRequest{
    ProductName: "示例商品",
    Amount:      10.00,
    OrderNo:     "ORD_" + time.Now().Format("20060102150405"),
}

resp, err := client.FinanceDeduct(accessToken, req)
if err != nil {
    panic(err)
}

// resp.Status 可能是 "processing", "success", "failed"
fmt.Printf("交易号: %s, 状态: %s\n", resp.TradeNo, resp.Status)
```

### 查询扣款结果

```go
// 使用 trade_no 查询
verifyResp, err := client.FinanceVerify(accessToken, resp.TradeNo, "")
if err != nil {
    panic(err)
}

// 或使用 order_no 查询
verifyResp, err := client.FinanceVerify(accessToken, "", req.OrderNo)

fmt.Printf("状态: %s, 余额: %.2f\n", verifyResp.Status, verifyResp.Balance)
```

### 获取用户签约状态

```go
// 获取用户签约状态
signStatus, err := client.FinanceSignStatus(accessToken)
if err != nil {
    panic(err)
}

fmt.Printf("用户OpenID: %s\n", signStatus.OpenID)
fmt.Printf("是否已签约: %v\n", signStatus.IsSigned)
fmt.Printf("财务授权状态: %d\n", signStatus.FinanceScope)
fmt.Printf("授权时间: %s\n", signStatus.AuthorizedAt)
```

## 回调处理（签名验证）

### 扣款结果回调

```go
func financeDeductCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // 解析回调 payload
    payload, err := ziblloauth.ParseFinanceDeductCallbackPayload(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 验证签名
    if !payload.VerifySign(appKey) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }

    // 使用 event_id 做幂等处理
    eventID := payload.EventID
    // TODO: 检查 event_id 是否已处理过

    // 处理业务逻辑
    if payload.Status == "success" {
        // 扣款成功，更新订单状态
        fmt.Printf("扣款成功: 订单号=%s, 金额=%.2f\n", payload.OrderNo, payload.Amount)
    } else if payload.Status == "failed" {
        // 扣款失败
        fmt.Printf("扣款失败: 订单号=%s\n", payload.OrderNo)
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"code": 0, "message": "success"}`))
}
```

### 撤销授权回调

```go
func revokeCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // 解析回调 payload
    payload, err := ziblloauth.ParseRevokeCallbackPayload(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 验证签名
    if !payload.VerifySign(appKey) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }

    // 使用 event_id 做幂等处理
    eventID := payload.EventID
    // TODO: 检查 event_id 是否已处理过

    // 处理业务逻辑
    fmt.Printf("撤销授权: OpenID=%s, UserID=%d\n", payload.OpenID, payload.UserID)

    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"code": 0, "message": "success"}`))
}
```

## 高级功能

### 自定义 HTTP 客户端

```go
httpClient := &http.Client{
    Timeout: 30 * time.Second,
}
client, _ := ziblloauth.NewClient(config, ziblloauth.WithHTTPClient(httpClient))
```

### 自定义日志

```go
type MyLogger struct{}

func (l *MyLogger) Debug(format string, args ...interface{}) {
    log.Printf("[DEBUG] "+format, args...)
}

func (l *MyLogger) Info(format string, args ...interface{}) {
    log.Printf("[INFO] "+format, args...)
}

func (l *MyLogger) Warn(format string, args ...interface{}) {
    log.Printf("[WARN] "+format, args...)
}

func (l *MyLogger) Error(format string, args ...interface{}) {
    log.Printf("[ERROR] "+format, args...)
}

client, _ := ziblloauth.NewClient(config, ziblloauth.WithLogger(&MyLogger{}))
```

### 配置重试

```go
// 最多重试 3 次
client, _ := ziblloauth.NewClient(config, ziblloauth.WithRetry(3))
```

### 配置超时

```go
// 请求超时 30 秒
client, _ := ziblloauth.NewClient(config, ziblloauth.WithTimeout(30))
```

## 错误处理

SDK 使用标准的 `error` 返回错误。常见的错误类型：

- `ziblloauth.ErrInvalidConfig` - 配置无效
- `ziblloauth.ErrMissingAppID` - AppID 为空
- `ziblloauth.ErrMissingAppKey` - AppKey 为空
- `ziblloauth.ErrMissingRedirectURI` - RedirectURI 为空
- `ziblloauth.ErrInvalidState` - state 参数无效
- `ziblloauth.ErrMissingAccessToken` - accessToken 为空
- `ziblloauth.ErrInvalidAmount` - 扣款金额无效
- `ziblloauth.ErrMissingOrderNo` - 订单号为空
- `ziblloauth.ErrMissingProductName` - 商品名称为空
- `ziblloauth.ErrMissingTradeNoAndOrderNo` - tradeNo 和 orderNo 至少需要一个

API 错误会返回 `*ziblloauth.APIError`，包含 HTTP 状态码和错误消息。

## 完整示例

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "cnb.cool/yungnet/zibll-oauth/sdk/golang"
)

var (
    config = &ziblloauth.Config{
        BaseURL:     "https://www.example.com/wp-json/zibll-oauth/v1",
        AppID:       "zo_xxxxxxxx",
        RedirectURI: "https://your-app.example.com/oauth/callback",
        AppKey:      "your_appkey_here",
    }
    client, _ = ziblloauth.NewClient(config)
)

func main() {
    http.HandleFunc("/oauth/login", loginHandler)
    http.HandleFunc("/oauth/callback", callbackHandler)
    http.HandleFunc("/oauth/userinfo", userinfoHandler)
    http.HandleFunc("/oauth/deduct", deductHandler)
    http.HandleFunc("/oauth/sign_status", signStatusHandler)
    http.HandleFunc("/oauth/callback/finance", financeCallbackHandler)
    
    log.Println("Server started on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    state, _ := ziblloauth.GenerateState(16)
    authorizeURL := client.BuildAuthorizeURL(state, "basic email profile")
    http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    tokenResp, err := client.TokenByCode(code, state)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // 保存 token 到 session 或数据库
    fmt.Fprintf(w, "Access Token: %s\n", tokenResp.AccessToken)
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
    // 从 session 或数据库获取 accessToken
    accessToken := "your_access_token"
    
    userInfo, err := client.GetUserInfo(accessToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    fmt.Fprintf(w, "用户: %s (%s)\n", userInfo.Name, userInfo.OpenID)
    if userInfo.RefreshToken != "" {
        fmt.Fprintf(w, "UserInfo RefreshToken: %s (expires_in=%d)\n", userInfo.RefreshToken, userInfo.RefreshTokenExpiresIn)
    }
}

func deductHandler(w http.ResponseWriter, r *http.Request) {
    accessToken := "your_access_token"
    
    req := ziblloauth.FinanceDeductRequest{
        ProductName: "示例商品",
        Amount:      10.00,
        OrderNo:     "ORD_" + time.Now().Format("20060102150405"),
    }
    
    resp, err := client.FinanceDeduct(accessToken, req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    fmt.Fprintf(w, "交易号: %s, 状态: %s\n", resp.TradeNo, resp.Status)
}

func financeCallbackHandler(w http.ResponseWriter, r *http.Request) {
    payload, err := ziblloauth.ParseFinanceDeductCallbackPayload(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    if !payload.VerifySign(config.AppKey) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }
    
    // 处理业务逻辑...
    w.WriteHeader(http.StatusOK)
}

func signStatusHandler(w http.ResponseWriter, r *http.Request) {
    accessToken := "your_access_token"
    
    signStatus, err := client.FinanceSignStatus(accessToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    
    fmt.Fprintf(w, "用户OpenID: %s\n", signStatus.OpenID)
    fmt.Fprintf(w, "是否已签约: %v\n", signStatus.IsSigned)
    fmt.Fprintf(w, "财务授权状态: %d\n", signStatus.FinanceScope)
    fmt.Fprintf(w, "授权时间: %s\n", signStatus.AuthorizedAt)
}
```

## 相关链接

- [开发文档](../../docs/开发文档.md)
- [PHP 示例](../../examples/)
- [完整 API 文档](https://pkg.go.dev/cnb.cool/yungnet/zibll-oauth/sdk/golang)

## License

MIT
