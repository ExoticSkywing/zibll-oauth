package ziblloauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

func GenerateState(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// BuildAuthorizeURL 构建授权 URL
//
// 参数:
//   - state: 接入方自定义状态，服务端会原样返回（建议必填）
//   - scope: 授权范围，可选，默认 basic
//
// 返回完整的授权 URL
func (c *Client) BuildAuthorizeURL(state string, scope string) string {
	if state == "" {
		c.logger.Error("state is required")
		return ""
	}

	params := map[string]interface{}{
		"response_type": "code",
		"client_id":     c.config.AppID,
		"redirect_uri":  c.config.RedirectURI,
		"state":         state,
	}
	if scope != "" {
		params["scope"] = scope
	}
	return c.buildURL(EndpointAuthorize, params)
}

func (c *Client) BuildAuthorizeFinanceURL(state string) string {
	if state == "" {
		c.logger.Error("state is required")
		return ""
	}

	params := map[string]interface{}{
		"response_type": "code",
		"client_id":     c.config.AppID,
		"redirect_uri":  c.config.RedirectURI,
		"state":         state,
	}

	return c.buildURL(EndpointAuthorizeFinance, params)
}

// TokenByCode 使用 code 换取 access_token（推荐）
//
// 参数:
//   - code: 授权回调收到的 code
//   - state: 状态参数（接入方应自行校验）
func (c *Client) TokenByCode(code string, state string) (*TokenResponse, error) {
	c.logger.Debug("开始换取 Token: code=%s", code)

	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("code is required")
	}
	if state == "" {
		return nil, ErrInvalidState
	}

	formData := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.config.AppID,
		"client_secret": c.config.AppKey,
		"code":          code,
		"redirect_uri":  c.config.RedirectURI,
	}

	var result TokenResponse
	if err := c.postForm(EndpointToken, formData, &result); err != nil {
		c.logger.Error("换取 Token 失败: %v", err)
		return nil, err
	}

	c.logger.Info("换取 Token 成功: token_type=%s, expires_in=%d", result.TokenType, result.ExpiresIn)
	return &result, nil
}

// RefreshToken 使用 refresh_token 换取新的 access_token（并轮换 refresh_token）
func (c *Client) RefreshToken(refreshToken string) (*TokenResponse, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}

	formData := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     c.config.AppID,
		"client_secret": c.config.AppKey,
		"refresh_token": refreshToken,
	}

	var result TokenResponse
	if err := c.postForm(EndpointToken, formData, &result); err != nil {
		c.logger.Error("刷新 Token 失败: %v", err)
		return nil, err
	}

	c.logger.Info("刷新 Token 成功: token_type=%s, expires_in=%d", result.TokenType, result.ExpiresIn)
	return &result, nil
}

// RefreshTokenNoRotate 使用 refresh_token 换取新的 access_token，但不轮换 refresh_token。
//
// 该模式适用于接入方无法持久化保存轮换后的 refresh_token 的场景。
// 服务端会续期原 refresh_token（滑动过期）并返回同一个 refresh_token。
func (c *Client) RefreshTokenNoRotate(refreshToken string) (*TokenResponse, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}

	formData := map[string]string{
		"grant_type":           "refresh_token",
		"client_id":            c.config.AppID,
		"client_secret":        c.config.AppKey,
		"refresh_token":        refreshToken,
		"rotate_refresh_token": "0",
	}

	var result TokenResponse
	if err := c.postForm(EndpointToken, formData, &result); err != nil {
		c.logger.Error("刷新 Token(不轮换) 失败: %v", err)
		return nil, err
	}

	c.logger.Info("刷新 Token(不轮换) 成功: token_type=%s, expires_in=%d", result.TokenType, result.ExpiresIn)
	return &result, nil
}

// RevokeToken 吊销 access_token / refresh_token
//
// tokenTypeHint 建议传 "refresh_token" 或 "access_token"。
func (c *Client) RevokeToken(token string, tokenTypeHint string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("token is required")
	}

	formData := map[string]string{
		"client_id":     c.config.AppID,
		"client_secret": c.config.AppKey,
		"token":         token,
	}
	if strings.TrimSpace(tokenTypeHint) != "" {
		formData["token_type_hint"] = strings.TrimSpace(tokenTypeHint)
	}

	var result map[string]interface{}
	if err := c.postForm(EndpointRevoke, formData, &result); err != nil {
		c.logger.Error("吊销 Token 失败: %v", err)
		return err
	}
	return nil
}

// GetUserInfo 获取用户信息
//
// 使用 Bearer Token 认证
//
// 参数:
//   - accessToken: 访问令牌
func (c *Client) GetUserInfo(accessToken string) (*UserInfo, error) {
	c.logger.Debug("开始获取用户信息")

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return nil, ErrMissingAccessToken
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	var result UserInfoResponse
	if err := c.get(EndpointUserInfo, nil, headers, &result); err != nil {
		c.logger.Error("获取用户信息失败: %v", err)
		return nil, err
	}

	c.logger.Info("获取用户信息成功: openid=%s, name=%s", result.UserInfo.OpenID, result.UserInfo.Name)
	return result.UserInfo, nil
}

// GetUnionID 获取 UnionID（跨应用用户标识）
//
// 使用 Bearer Token 认证
//
// 参数:
//   - accessToken: 访问令牌
func (c *Client) GetUnionID(accessToken string) (*UnionIDResponse, error) {
	c.logger.Debug("开始获取 UnionID")

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return nil, ErrMissingAccessToken
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	var result UnionIDResponse
	if err := c.get(EndpointUnionID, nil, headers, &result); err != nil {
		c.logger.Error("获取 UnionID 失败: %v", err)
		return nil, err
	}

	c.logger.Info("获取 UnionID 成功: openid=%s, unionid=%s", result.OpenID, result.UnionID)
	return &result, nil
}

// Health 健康检查
func (c *Client) Health() (bool, error) {
	c.logger.Debug("开始健康检查")

	var result HealthResponse
	if err := c.get(EndpointHealth, nil, nil, &result); err != nil {
		c.logger.Error("健康检查失败: %v", err)
		return false, err
	}

	c.logger.Info("健康检查成功: ok=%v", result.OK)
	return result.OK, nil
}
