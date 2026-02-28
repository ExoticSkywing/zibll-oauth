package ziblloauth

import "errors"

var (
	// ErrInvalidConfig 配置无效
	ErrInvalidConfig = errors.New("invalid configuration")
	// ErrMissingAppID AppID 为空
	ErrMissingAppID = errors.New("appid is required")
	// ErrMissingAppKey AppKey 为空
	ErrMissingAppKey = errors.New("appkey is required")
	// ErrMissingRedirectURI RedirectURI 为空
	ErrMissingRedirectURI = errors.New("redirect uri is required")
	// ErrMissingBaseURL BaseURL 为空
	ErrMissingBaseURL = errors.New("baseurl is required")
	// ErrInvalidState state 参数无效
	ErrInvalidState = errors.New("state parameter is invalid")
	// ErrMissingOpenID openid 为空
	ErrMissingOpenID = errors.New("openid is required")
	// ErrMissingAccessToken accessToken 为空
	ErrMissingAccessToken = errors.New("access token is required")
	// ErrInvalidAmount 扣款金额无效
	ErrInvalidAmount = errors.New("amount must be greater than 0")
	// ErrMissingOrderNo 订单号为空
	ErrMissingOrderNo = errors.New("order no is required")
	// ErrMissingProductName 商品名称为空
	ErrMissingProductName = errors.New("product name is required")
	// ErrMissingTradeNoAndOrderNo tradeNo 和 orderNo 至少需要一个
	ErrMissingTradeNoAndOrderNo = errors.New("trade no or order no is required")
)

// APIError API 错误
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError 创建 API 错误
func NewAPIError(statusCode int, message string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
	}
}
