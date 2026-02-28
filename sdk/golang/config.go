package ziblloauth

import (
	"net/http"
	"time"
)

// Config SDK 配置
type Config struct {
	// BaseURL OAuth 服务端基础地址，例如: https://example.com/wp-json/zibll-oauth/v1
	BaseURL string
	// AppID 应用标识
	AppID string
	// RedirectURI 回调地址（必须与服务端配置严格一致）
	RedirectURI string
	// AppKey 应用密钥（用于签名）
	AppKey string
	// Timeout 请求超时时间（秒），0 表示不设置超时
	Timeout int
	// MaxRetries 最大重试次数，0 表示不重试
	MaxRetries int
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.AppID == "" {
		return ErrMissingAppID
	}
	if c.RedirectURI == "" {
		return ErrMissingRedirectURI
	}
	if c.AppKey == "" {
		return ErrMissingAppKey
	}
	if c.BaseURL == "" {
		return ErrMissingBaseURL
	}
	return nil
}

// ClientOption 客户端选项
type ClientOption func(*Client)

// WithHTTPClient 设置自定义 HTTP 客户端
func WithHTTPClient(client HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithTimeout 设置请求超时时间
func WithTimeout(timeout int) ClientOption {
	return func(c *Client) {
		c.config.Timeout = timeout
		if hc, ok := c.httpClient.(*http.Client); ok {
			if timeout > 0 {
				hc.Timeout = time.Duration(timeout) * time.Second
			} else {
				hc.Timeout = 0
			}
		}
	}
}

// WithLogger 设置日志记录器
func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithRetry 设置重试次数
func WithRetry(maxRetries int) ClientOption {
	return func(c *Client) {
		c.config.MaxRetries = maxRetries
	}
}
