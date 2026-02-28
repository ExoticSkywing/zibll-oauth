package ziblloauth

// 响应类型定义

// TokenResponse Token 响应
type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in,omitempty"`
}

// UserInfo 用户信息
type UserInfo struct {
	OpenID                string  `json:"openid"`
	Name                  string  `json:"name"`
	Avatar                string  `json:"avatar"`
	Email                 string  `json:"email,omitempty"`
	Description           string  `json:"description,omitempty"`
	Phone                 string  `json:"phone,omitempty"`
	Balance               float64 `json:"balance,omitempty"`
	RefreshToken          string  `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int64   `json:"refresh_token_expires_in,omitempty"`
}

// UserInfoResponse 用户信息响应
type UserInfoResponse struct {
	UserInfo *UserInfo `json:"userinfo"`
}

// UnionIDResponse UnionID 响应
type UnionIDResponse struct {
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
}

// HealthResponse 健康检查响应
type HealthResponse struct {
	OK bool `json:"ok"`
}

// FinanceDeductRequest 扣款请求参数
type FinanceDeductRequest struct {
	// ProductName 商品名称
	ProductName string
	// Amount 扣款金额（必须 > 0）
	Amount float64
	// OrderNo 外部订单号（用于幂等）
	OrderNo string
}

// FinanceDeductReguest is a backward-compatible alias for FinanceDeductRequest.
//
// Note: "Reguest" is a historical misspelling kept for compatibility.
type FinanceDeductReguest = FinanceDeductRequest

// Validate 验证扣款请求
func (r *FinanceDeductRequest) Validate() error {
	if r.ProductName == "" {
		return ErrMissingProductName
	}
	if r.Amount <= 0 {
		return ErrInvalidAmount
	}
	if r.OrderNo == "" {
		return ErrMissingOrderNo
	}
	return nil
}

// FinanceDeductResponse 扣款响应
type FinanceDeductResponse struct {
	TradeNo string  `json:"trade_no"`
	OrderNo string  `json:"order_no"`
	Status  string  `json:"status"` // processing/success/failed
	Message string  `json:"message"`
	Amount  float64 `json:"amount,omitempty"`
	Balance float64 `json:"balance,omitempty"`
}

// FinanceVerifyResponse 扣款校验响应
type FinanceVerifyResponse struct {
	TradeNo     string  `json:"trade_no"`
	OrderNo     string  `json:"order_no"`
	ProductName string  `json:"product_name"`
	Amount      float64 `json:"amount"`
	Status      string  `json:"status"` // processing/success/failed/unknown
	ErrorMsg    string  `json:"error_msg"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// FinanceSignStatusResponse 用户签约状态响应
type FinanceSignStatusResponse struct {
	OpenID        string `json:"openid"`
	IsSigned      bool   `json:"is_signed"`
	Scope         string `json:"scope"`
	FinanceScope  int    `json:"finance_scope"`  // 1=已签约财务权限, 0=未签约
	Status        int    `json:"status"`         // 1=有效, 0=已撤销
	CreatedAt     string `json:"created_at"`
	AuthorizedAt  string `json:"authorized_at,omitempty"` // 财务授权时间
}

// FinanceDeductCallbackPayload 扣款结果回调 payload（Provider -> Third-party）
//
// Content-Type: application/json
//
// 兼容：历史版本可能使用 application/x-www-form-urlencoded
//
// 签名规则：HMAC-SHA256(canonical_query_string(payload), key=appkey)
type FinanceDeductCallbackPayload struct {
	AppID     string  `json:"appid"`
	OpenID    string  `json:"openid"`
	OrderNo   string  `json:"order_no"`
	TradeNo   string  `json:"trade_no"`
	Amount    float64 `json:"amount"`
	Status    string  `json:"status"`
	Balance   float64 `json:"balance"`
	Timestamp int64   `json:"timestamp"`
	Nonce     string  `json:"nonce"`
	EventID   string  `json:"event_id"`
	Sign2     string  `json:"sign2"`
}

// RevokeCallbackPayload 取消授权回调 payload（Provider -> Third-party）
//
// Content-Type: application/json
//
// 兼容：历史版本可能使用 application/x-www-form-urlencoded
//
// 签名规则：HMAC-SHA256(canonical_query_string(payload), key=appkey)
type RevokeCallbackPayload struct {
	AppID          string `json:"appid"`
	OpenID         string `json:"openid"`
	UserID         int64  `json:"user_id"`
	FinanceGranted int    `json:"finance_granted"`
	Status         string `json:"status"`
	RevokedAt      int64  `json:"revoked_at"`
	Timestamp      int64  `json:"timestamp"`
	Nonce          string `json:"nonce"`
	EventID        string `json:"event_id"`
	Sign2          string `json:"sign2"`
}
