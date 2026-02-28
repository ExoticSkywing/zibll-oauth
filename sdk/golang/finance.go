package ziblloauth

import (
	"encoding/json"
	"fmt"
)

type rawUserInfoResponse struct {
	UserInfo json.RawMessage `json:"userinfo"`
}

// FinanceDeduct 调用财务扣款接口
//
// - 依赖用户已经完成财务授权（/authorize_finance -> 回调 code -> /token）
// - 使用 accessToken 调用
func (c *Client) FinanceDeduct(accessToken string, req FinanceDeductRequest) (*FinanceDeductResponse, error) {
	c.logger.Debug("开始财务扣款: product_name=%s, amount=%.2f, order_no=%s", req.ProductName, req.Amount, req.OrderNo)

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return nil, ErrMissingAccessToken
	}
	if err := req.Validate(); err != nil {
		c.logger.Error("扣款请求参数无效: %v", err)
		return nil, err
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	formData := map[string]string{
		"product_name": req.ProductName,
		"order_no":     req.OrderNo,
		"amount":       formatAmount(req.Amount),
	}

	var result FinanceDeductResponse
	err := c.postFormWithHeaders(EndpointFinanceDeduct, formData, headers, &result)
	if err != nil {
		c.logger.Error("财务扣款失败: %v", err)
		// 返回nil和错误，让调用方正确处理错误情况
		return nil, err
	}

	c.logger.Info("财务扣款成功: trade_no=%s, status=%s, amount=%.2f", result.TradeNo, result.Status, result.Amount)
	return &result, nil
}

// FinanceVerify 查询扣款结果
//
// tradeNo 与 orderNo 至少传一个；若都传，以 tradeNo 优先。
func (c *Client) FinanceVerify(accessToken string, tradeNo, orderNo string) (*FinanceVerifyResponse, error) {
	c.logger.Debug("开始查询扣款结果: trade_no=%s, order_no=%s", tradeNo, orderNo)

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return nil, ErrMissingAccessToken
	}
	if tradeNo == "" && orderNo == "" {
		return nil, ErrMissingTradeNoAndOrderNo
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	params := map[string]string{}
	if tradeNo != "" {
		params["trade_no"] = tradeNo
	} else {
		params["order_no"] = orderNo
	}

	var result FinanceVerifyResponse
	if err := c.get(EndpointFinanceVerify, params, headers, &result); err != nil {
		c.logger.Error("查询扣款结果失败: %v", err)
		return nil, err
	}

	c.logger.Info("查询扣款结果成功: trade_no=%s, status=%s", result.TradeNo, result.Status)
	return &result, nil
}

func (c *Client) HasFinancePermission(accessToken string) (bool, error) {
	c.logger.Debug("开始判断财务权限")

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return false, ErrMissingAccessToken
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	var rawResp rawUserInfoResponse
	if err := c.get(EndpointUserInfo, nil, headers, &rawResp); err != nil {
		c.logger.Error("获取用户信息失败(用于判断财务权限): %v", err)
		return false, err
	}

	if len(rawResp.UserInfo) == 0 {
		return false, fmt.Errorf("用户信息响应无效: 缺少 userinfo")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawResp.UserInfo, &fields); err != nil {
		return false, fmt.Errorf("解析用户信息失败: %w", err)
	}

	_, ok := fields["balance"]
	return ok, nil
}

// FinanceSignStatus 获取用户签约状态
//
// 返回用户的财务签约状态详情，包括是否已签约、授权范围等信息。
func (c *Client) FinanceSignStatus(accessToken string) (*FinanceSignStatusResponse, error) {
	c.logger.Debug("开始获取用户签约状态")

	accessToken = c.normalizeAccessToken(accessToken)
	if accessToken == "" {
		return nil, ErrMissingAccessToken
	}

	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}

	var result FinanceSignStatusResponse
	if err := c.get(EndpointFinanceSignStatus, nil, headers, &result); err != nil {
		c.logger.Error("获取用户签约状态失败: %v", err)
		return nil, err
	}

	c.logger.Info("获取用户签约状态成功: openid=%s, is_signed=%v", result.OpenID, result.IsSigned)
	return &result, nil
}

// formatAmount 格式化金额（保留两位小数）
func formatAmount(amount float64) string {
	return fmt.Sprintf("%.2f", amount)
}
