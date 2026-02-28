package ziblloauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ParseFinanceDeductCallbackPayload 从 HTTP 请求中解析扣款结果回调 payload。
func ParseFinanceDeductCallbackPayload(r *http.Request) (*FinanceDeductCallbackPayload, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}

	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.Contains(ct, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read json body failed: %w", err)
		}
		// 回填，尽量不影响调用方后续读取
		r.Body = io.NopCloser(bytes.NewReader(body))

		var p FinanceDeductCallbackPayload
		if err := json.Unmarshal(body, &p); err == nil {
			p.AppID = strings.TrimSpace(p.AppID)
			p.OpenID = strings.TrimSpace(p.OpenID)
			p.OrderNo = strings.TrimSpace(p.OrderNo)
			p.TradeNo = strings.TrimSpace(p.TradeNo)
			p.Status = strings.TrimSpace(p.Status)
			p.Nonce = strings.TrimSpace(p.Nonce)
			p.EventID = strings.TrimSpace(p.EventID)
			p.Sign2 = strings.ToLower(strings.TrimSpace(p.Sign2))
			return &p, nil
		}
		// JSON 解析失败时，回退表单解析
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form failed: %w", err)
	}

	getInt64 := func(key string) int64 {
		v := strings.TrimSpace(r.Form.Get(key))
		if v == "" {
			return 0
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	getFloat64 := func(key string) float64 {
		v := strings.TrimSpace(r.Form.Get(key))
		if v == "" {
			return 0
		}
		n, _ := strconv.ParseFloat(v, 64)
		return n
	}

	p := &FinanceDeductCallbackPayload{
		AppID:     strings.TrimSpace(r.Form.Get("appid")),
		OpenID:    strings.TrimSpace(r.Form.Get("openid")),
		OrderNo:   strings.TrimSpace(r.Form.Get("order_no")),
		TradeNo:   strings.TrimSpace(r.Form.Get("trade_no")),
		Amount:    getFloat64("amount"),
		Status:    strings.TrimSpace(r.Form.Get("status")),
		Balance:   getFloat64("balance"),
		Timestamp: getInt64("timestamp"),
		Nonce:     strings.TrimSpace(r.Form.Get("nonce")),
		EventID:   strings.TrimSpace(r.Form.Get("event_id")),
		Sign2:     strings.ToLower(strings.TrimSpace(r.Form.Get("sign2"))),
	}

	return p, nil
}

func (p *FinanceDeductCallbackPayload) ExpectedSign2(appKey string) string {
	appKey = strings.TrimSpace(appKey)
	if appKey == "" {
		return ""
	}
	if p == nil {
		return ""
	}

	params := map[string]interface{}{
		"appid":     p.AppID,
		"openid":    p.OpenID,
		"order_no":  p.OrderNo,
		"trade_no":  p.TradeNo,
		"amount":    fmt.Sprintf("%v", p.Amount),
		"status":    p.Status,
		"balance":   fmt.Sprintf("%v", p.Balance),
		"timestamp": fmt.Sprintf("%d", p.Timestamp),
		"nonce":     p.Nonce,
		"event_id":  p.EventID,
	}

	expected := NewDefaultSigner(appKey).Sign(params)
	return strings.ToLower(strings.TrimSpace(expected))
}

// VerifySign 验证扣款结果回调签名。
func (p *FinanceDeductCallbackPayload) VerifySign(appKey string) bool {
	if p == nil {
		return false
	}

	sign2 := strings.ToLower(strings.TrimSpace(p.Sign2))
	if sign2 == "" {
		return false
	}
	expected2 := p.ExpectedSign2(appKey)
	if expected2 == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected2), []byte(sign2)) == 1
}

// ParseRevokeCallbackPayload 从 HTTP 请求中解析取消授权回调 payload。
func ParseRevokeCallbackPayload(r *http.Request) (*RevokeCallbackPayload, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}

	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.Contains(ct, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("read json body failed: %w", err)
		}
		// 回填，尽量不影响调用方后续读取
		r.Body = io.NopCloser(bytes.NewReader(body))

		var p RevokeCallbackPayload
		if err := json.Unmarshal(body, &p); err == nil {
			p.AppID = strings.TrimSpace(p.AppID)
			p.OpenID = strings.TrimSpace(p.OpenID)
			p.Status = strings.TrimSpace(p.Status)
			p.Nonce = strings.TrimSpace(p.Nonce)
			p.EventID = strings.TrimSpace(p.EventID)
			p.Sign2 = strings.ToLower(strings.TrimSpace(p.Sign2))
			return &p, nil
		}
		// JSON 解析失败时，回退表单解析
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form failed: %w", err)
	}

	getInt64 := func(key string) int64 {
		v := strings.TrimSpace(r.Form.Get(key))
		if v == "" {
			return 0
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	getInt := func(key string) int {
		v := strings.TrimSpace(r.Form.Get(key))
		if v == "" {
			return 0
		}
		n, _ := strconv.Atoi(v)
		return n
	}

	p := &RevokeCallbackPayload{
		AppID:          strings.TrimSpace(r.Form.Get("appid")),
		OpenID:         strings.TrimSpace(r.Form.Get("openid")),
		UserID:         getInt64("user_id"),
		FinanceGranted: getInt("finance_granted"),
		Status:         strings.TrimSpace(r.Form.Get("status")),
		RevokedAt:      getInt64("revoked_at"),
		Timestamp:      getInt64("timestamp"),
		Nonce:          strings.TrimSpace(r.Form.Get("nonce")),
		EventID:        strings.TrimSpace(r.Form.Get("event_id")),
		Sign2:          strings.ToLower(strings.TrimSpace(r.Form.Get("sign2"))),
	}

	return p, nil
}

func (p *RevokeCallbackPayload) ExpectedSign2(appKey string) string {
	appKey = strings.TrimSpace(appKey)
	if appKey == "" {
		return ""
	}
	if p == nil {
		return ""
	}

	params := map[string]interface{}{
		"appid":           p.AppID,
		"openid":          p.OpenID,
		"user_id":         fmt.Sprintf("%d", p.UserID),
		"finance_granted": fmt.Sprintf("%d", p.FinanceGranted),
		"status":          p.Status,
		"revoked_at":      fmt.Sprintf("%d", p.RevokedAt),
		"timestamp":       fmt.Sprintf("%d", p.Timestamp),
		"nonce":           p.Nonce,
		"event_id":        p.EventID,
	}

	expected := NewDefaultSigner(appKey).Sign(params)
	return strings.ToLower(strings.TrimSpace(expected))
}

func (p *RevokeCallbackPayload) VerifySignDebug(appKey string, logf func(format string, args ...interface{})) bool {
	if logf == nil {
		logf = func(format string, args ...interface{}) {}
	}

	appKeyNorm := strings.TrimSpace(appKey)
	if appKeyNorm == "" {
		logf("[zibll-oauth] revoke verify: empty appKey")
		return false
	}

	appKeySum := sha256.Sum256([]byte(appKeyNorm))
	appKeyFP := hex.EncodeToString(appKeySum[:])
	if len(appKeyFP) > 12 {
		appKeyFP = appKeyFP[:12]
	}

	if p == nil {
		logf("[zibll-oauth] revoke verify: nil payload appKey_fp=%s", appKeyFP)
		return false
	}

	signNorm := strings.ToLower(strings.TrimSpace(p.Sign2))

	logf("[zibll-oauth] revoke verify: appKey_fp=%s appid=%s openid=%s user_id=%d status=%s finance_granted=%d revoked_at=%d timestamp=%d sign_len=%d", appKeyFP, p.AppID, p.OpenID, p.UserID, p.Status, p.FinanceGranted, p.RevokedAt, p.Timestamp, len(signNorm))

	if strings.Contains(signNorm, "sign=") {
		logf("[zibll-oauth] revoke verify: sign contains 'sign=' prefix, looks like you passed a whole query/form string")
	}

	isHex := false
	if len(signNorm) == 64 {
		if _, err := hex.DecodeString(signNorm); err == nil {
			isHex = true
		}
	}
	logf("[zibll-oauth] revoke verify: sign2=%q sign2_is_hex64=%v", signNorm, isHex)

	expected := p.ExpectedSign2(appKeyNorm)
	logf("[zibll-oauth] revoke verify: expected2=%q", expected)

	if expected == "" {
		logf("[zibll-oauth] revoke verify: expected2 is empty")
		return false
	}
	if signNorm == "" {
		logf("[zibll-oauth] revoke verify: sign is empty")
		return false
	}

	match := subtle.ConstantTimeCompare([]byte(expected), []byte(signNorm)) == 1
	logf("[zibll-oauth] revoke verify: match=%v", match)
	return match
}

// VerifySign 验证回调签名。
func (p *RevokeCallbackPayload) VerifySign(appKey string) bool {
	if p == nil {
		return false
	}

	sign2 := strings.ToLower(strings.TrimSpace(p.Sign2))
	if sign2 == "" {
		return false
	}
	expected2 := p.ExpectedSign2(appKey)
	if expected2 == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected2), []byte(sign2)) == 1
}
