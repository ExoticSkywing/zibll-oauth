package ziblloauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client Zibll OAuth 客户端
type Client struct {
	config     *Config
	httpClient HTTPClient
	logger     Logger
}

// NewClient 创建新的 OAuth 客户端
func NewClient(config *Config, opts ...ClientOption) (*Client, error) {
	// 验证配置
	if err := config.Validate(); err != nil {
		return nil, err
	}

	client := &Client{
		config:     config,
		httpClient: &http.Client{},
		logger:     &DefaultLogger{},
	}

	// 应用选项
	for _, opt := range opts {
		opt(client)
	}

	if hc, ok := client.httpClient.(*http.Client); ok {
		if client.config.Timeout > 0 {
			hc.Timeout = time.Duration(client.config.Timeout) * time.Second
		}
	}

	return client, nil
}

// SetHTTPClient 设置自定义 HTTP 客户端（已废弃，请使用 WithHTTPClient 选项）
func (c *Client) SetHTTPClient(client *http.Client) {
	c.httpClient = client
}

func (c *Client) normalizeAccessToken(accessToken string) string {
	token := strings.TrimSpace(accessToken)
	if token == "" {
		return ""
	}

	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "authorization:") {
		token = strings.TrimSpace(token[len("authorization:"):])
		lower = strings.ToLower(token)
	}

	if strings.HasPrefix(lower, "bearer ") {
		return strings.TrimSpace(token[len("bearer "):])
	}

	if strings.ContainsAny(token, " \t\r\n") {
		if i := strings.Index(lower, "bearer "); i >= 0 {
			return strings.TrimSpace(token[i+len("bearer "):])
		}
	}

	return token
}

// buildURL 构建 URL
func (c *Client) buildURL(endpoint string, params map[string]interface{}) string {
	u, _ := url.Parse(c.config.BaseURL + endpoint)
	q := u.Query()
	for k, v := range params {
		q.Set(k, fmt.Sprintf("%v", v))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// get 发送 GET 请求
func (c *Client) get(endpoint string, params map[string]string, headers map[string]string, result interface{}) error {
	// 构建 URL
	urlStr := c.config.BaseURL + endpoint
	if params != nil && len(params) > 0 {
		u, _ := url.Parse(urlStr)
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		urlStr = u.String()
	}

	// 创建请求
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.doRequestAndParse(req, result)
}

// postForm 发送 POST 表单请求
func (c *Client) postForm(endpoint string, formData map[string]string, result interface{}) error {
	return c.postFormWithHeaders(endpoint, formData, nil, result)
}

// postFormWithHeaders 发送带请求头的 POST 表单请求
func (c *Client) postFormWithHeaders(endpoint string, formData map[string]string, headers map[string]string, result interface{}) error {
	// 构建表单数据
	form := url.Values{}
	for k, v := range formData {
		form.Set(k, v)
	}
	encoded := form.Encode()

	// 创建请求
	urlStr := c.config.BaseURL + endpoint
	req, err := http.NewRequest("POST", urlStr, strings.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}
	if req.GetBody == nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(encoded)), nil
		}
	}

	// 使用表单编码
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// 设置额外的请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.doRequestAndParse(req, result)
}

// doRequestAndParse 执行请求并解析响应
func (c *Client) doRequestAndParse(req *http.Request, result interface{}) error {
	// 执行请求
	resp, err := c.doRequest(nil, req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	// 检查状态码
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = strings.TrimSpace(resp.Status)
			if msg == "" {
				msg = "request failed"
			}
		}
		return NewAPIError(resp.StatusCode, msg)
	}

	ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if ct != "" && !strings.Contains(ct, "application/json") {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 600 {
			snippet = snippet[:600]
		}
		if snippet == "" {
			snippet = "<empty body>"
		}
		return fmt.Errorf("响应不是 JSON: status=%s content-type=%s body=%s", resp.Status, ct, snippet)
	}

	// 解析响应
	if result != nil {
		if len(body) == 0 {
			return fmt.Errorf("解析响应失败: empty response body")
		}
		if err := json.Unmarshal(body, result); err != nil {
			snippet := strings.TrimSpace(string(body))
			if len(snippet) > 600 {
				snippet = snippet[:600]
			}
			return fmt.Errorf("解析响应失败: %w, body=%s", err, snippet)
		}
	}

	return nil
}

// doRequest 执行 HTTP 请求
func (c *Client) doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	if ctx != nil {
		req = req.WithContext(ctx)
	}

	var resp *http.Response
	var err error

	// 重试逻辑
	maxRetries := c.config.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}

	for i := 0; i <= maxRetries; i++ {
		if i > 0 && req.GetBody != nil {
			rc, e := req.GetBody()
			if e == nil {
				req.Body = rc
			}
		}
		resp, err = c.httpClient.Do(req)
		if err == nil {
			break
		}

		// 最后一次重试或非临时性错误，直接返回
		if i == maxRetries || !isTemporaryError(err) {
			return nil, err
		}

		c.logger.Warn("请求失败，进行第 %d 次重试: %v", i+1, err)
	}

	return resp, err
}

// readBody 读取响应体
func (c *Client) readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
