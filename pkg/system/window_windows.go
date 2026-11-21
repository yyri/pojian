//go:build windows

package system

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	user32              = syscall.NewLazyDLL("user32.dll")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	getForegroundWindow = user32.NewProc("GetForegroundWindow")
	getWindowThreadPid  = user32.NewProc("GetWindowThreadProcessId")
	postMessage         = user32.NewProc("PostMessageW")
	openProcess         = kernel32.NewProc("OpenProcess")
	queryProcImageName  = kernel32.NewProc("QueryFullProcessImageNameW")
	closeProcessHandle  = kernel32.NewProc("CloseHandle")
)

const (
	processQueryLimitedInfo = 0x1000
	wmClose                 = 0x0010
)

// CloseForegroundWeChatView 关闭当前前台的微信内置浏览器窗口。
// 仅当前台窗口属于 WeChatAppEx.exe 进程时才发送 WM_CLOSE，避免误伤其它窗口。
// 返回是否执行了关闭。应在打开系统浏览器之前调用（此时前台还是微信文章页）。
func CloseForegroundWeChatView() bool {
	hwnd, _, _ := getForegroundWindow.Call()
	if hwnd == 0 {
		return false
	}
	var pid uint32
	getWindowThreadPid.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return false
	}
	handle, _, _ := openProcess.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	defer closeProcessHandle.Call(handle)
	var size uint32 = 1024
	buf := make([]uint16, size)
	ok, _, _ := queryProcImageName.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return false
	}
	image_name := syscall.UTF16ToString(buf)
	if !strings.EqualFold(filepath.Base(image_name), "WeChatAppEx.exe") {
		return false
	}
	postMessage.Call(hwnd, wmClose, 0, 0)
	return true
}