package ziblloauth

// API 端点定义
const (
	// 授权相关端点
	EndpointAuthorize        = "/authorize"
	EndpointToken            = "/token"
	EndpointRevoke           = "/revoke"
	EndpointUserInfo         = "/userinfo"
	EndpointUnionID          = "/unionid"
	EndpointHealth           = "/health"
	EndpointAuthorizeFinance = "/authorize_finance"

	// 财务相关端点
	EndpointFinanceDeduct     = "/finance/deduct"
	EndpointFinanceVerify     = "/finance/verify"
	EndpointFinanceSignStatus = "/finance/sign_status"
)

// Scope 授权范围
const (
	ScopeBasic   = "basic"
	ScopeEmail   = "email"
	ScopeProfile = "profile"
	ScopePhone   = "phone"
)
