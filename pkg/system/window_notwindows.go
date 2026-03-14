//go:build !windows

package system

// SendCloseWindow 非 Windows 平台无操作
func SendCloseWindow() {}
