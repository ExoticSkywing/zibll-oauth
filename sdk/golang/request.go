package ziblloauth

import (
	"errors"
	"net"
	"net/http"
)

// HTTPClient HTTP 客户端接口
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Logger 日志接口
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// DefaultLogger 默认日志记录器（空实现）
type DefaultLogger struct{}

func (l *DefaultLogger) Debug(format string, args ...interface{}) {}
func (l *DefaultLogger) Info(format string, args ...interface{})  {}
func (l *DefaultLogger) Warn(format string, args ...interface{})  {}
func (l *DefaultLogger) Error(format string, args ...interface{}) {}

// isTemporaryError 判断是否为临时性错误
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// 网络超时错误
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() || netErr.Temporary() {
			return true
		}
	}

	// 连接被拒绝等网络错误
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// 检查是否是操作超时或连接重置
	errStr := err.Error()
	return errStr == "connection reset by peer" ||
		errStr == "EOF" ||
		errStr == "i/o timeout"
}
