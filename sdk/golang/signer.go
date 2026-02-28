package ziblloauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Signer 签名器接口
type Signer interface {
	Sign(params map[string]interface{}) string
}

// DefaultSigner 默认签名器（V2）
//
// 签名算法：HMAC-SHA256(canonical_query_string(params), key=appKey)
//
// - 需要 params 中包含 timestamp + nonce
// - canonical_query_string 会按 key 排序，排除 sign/sign2
type DefaultSigner struct {
	appKey string
}

// NewDefaultSigner 创建默认签名器
func NewDefaultSigner(appKey string) *DefaultSigner {
	return &DefaultSigner{
		appKey: appKey,
	}
}

func canonicalQueryString(params map[string]interface{}) string {
	if params == nil {
		return ""
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "sign" || k == "sign2" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		v := params[k]
		// PHP rawurlencode uses %20 for spaces; Go url.QueryEscape uses '+'
		ek := strings.ReplaceAll(url.QueryEscape(k), "+", "%20")
		ev := strings.ReplaceAll(url.QueryEscape(fmt.Sprintf("%v", v)), "+", "%20")
		pairs = append(pairs, ek+"="+ev)
	}
	return strings.Join(pairs, "&")
}

// Sign 计算签名（HMAC-SHA256）
func (s *DefaultSigner) Sign(params map[string]interface{}) string {
	if s == nil {
		return ""
	}
	if strings.TrimSpace(s.appKey) == "" {
		return ""
	}

	// V2 强制 timestamp + nonce
	if params == nil {
		return ""
	}
	if strings.TrimSpace(fmt.Sprintf("%v", params["timestamp"])) == "" {
		return ""
	}
	if strings.TrimSpace(fmt.Sprintf("%v", params["nonce"])) == "" {
		return ""
	}

	canonical := canonicalQueryString(params)
	if canonical == "" {
		return ""
	}

	h := hmac.New(sha256.New, []byte(s.appKey))
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}
