//go:build !windows

package system

// CloseForegroundWeChatView 非 Windows 平台无操作
func CloseForegroundWeChatView() bool { return false }