//go:build windows

package system

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	user32      = syscall.NewLazyDLL("user32.dll")
	keybd_event = user32.NewProc("keybd_event")
)

const (
	vkControl      = 0x11
	vkW            = 0x57
	keyeventfKeyup = 0x0002
)

// SendCloseWindow 模拟 Ctrl+W 关闭当前前台窗口
func SendCloseWindow() {
	// 短暂延迟，确保按键发送到正确的窗口
	time.Sleep(200 * time.Millisecond)
	keybd_event.Call(uintptr(vkControl), 0, 0, 0)
	keybd_event.Call(uintptr(vkW), 0, 0, 0)
	time.Sleep(50 * time.Millisecond)
	keybd_event.Call(uintptr(vkW), 0, uintptr(keyeventfKeyup), 0)
	keybd_event.Call(uintptr(vkControl), 0, uintptr(keyeventfKeyup), 0)
}

// 确保 unsafe 包被使用（keybd_event 内部需要）
var _ unsafe.Pointer
