//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
)

type Rules struct {
	BlockedProcesses []string `yaml:"blocked_processes"`
}

var (
	ntdll                = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProcess  = ntdll.NewProc("NtResumeProcess")

	user32          = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")

	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessName = kernel32.NewProc("QueryFullProcessImageNameW")

	seen = struct {
		sync.Mutex
		m map[uint32]bool
	}{
		m: make(map[uint32]bool),
	}
)

const (
	PROCESS_SUSPEND_RESUME = 0x0800

	MB_OKCANCEL      = 0x00000001
	MB_ICONWARNING   = 0x00000030
	MB_TOPMOST       = 0x00040000
	MB_SETFOREGROUND = 0x00010000

	IDOK = 1
)

func main() {
	rules, err := loadRules("rules.yaml")
	if err != nil {
		fmt.Println("Failed to load rules.yaml:", err)
		return
	}

	fmt.Println("Thinkmay Process Guard")
	fmt.Printf("Loaded %d blocked process patterns\n", len(rules.BlockedProcesses))

	// Mark toàn bộ process hiện tại là đã biết.
	initial, err := listProcesses()
	if err == nil {
		seen.Lock()
		for _, p := range initial {
			seen.m[p.PID] = true
		}
		seen.Unlock()
	}

	for {
		processes, err := listProcesses()
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		current := make(map[uint32]bool, len(processes))

		for _, proc := range processes {
			current[proc.PID] = true

			if proc.PID <= 4 || proc.PID == uint32(os.Getpid()) {
				continue
			}

			seen.Lock()
			alreadySeen := seen.m[proc.PID]

			if !alreadySeen {
				seen.m[proc.PID] = true
			}

			seen.Unlock()

			if alreadySeen {
				continue
			}

			if !isBlocked(proc.Name, rules) {
				continue
			}

			go handleBlockedProcess(proc)
		}

		// Dọn PID đã exit để tránh map lớn dần mãi.
		seen.Lock()

		for pid := range seen.m {
			if !current[pid] {
				delete(seen.m, pid)
			}
		}

		seen.Unlock()

		// 100ms = phản ứng nhanh, vẫn rất nhẹ vì chỉ enumerate process.
		time.Sleep(100 * time.Millisecond)
	}
}

type ProcessInfo struct {
	PID  uint32
	Name string
}

func loadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rules Rules

	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	return &rules, nil
}

func listProcesses() ([]ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS,
		0,
	)

	if err != nil {
		return nil, err
	}

	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])

		processes = append(processes, ProcessInfo{
			PID:  entry.ProcessID,
			Name: name,
		})

		err = windows.Process32Next(snapshot, &entry)

		if err != nil {
			break
		}
	}

	return processes, nil
}

func isBlocked(processName string, rules *Rules) bool {
	name := strings.ToLower(processName)

	for _, pattern := range rules.BlockedProcesses {
		pattern = strings.ToLower(strings.TrimSpace(pattern))

		if pattern == "" {
			continue
		}

		ok, err := filepath.Match(pattern, name)
		if err != nil {
			continue
		}

		if ok {
			return true
		}
	}

	return false
}

func handleBlockedProcess(proc ProcessInfo) {
	handle, err := windows.OpenProcess(
		PROCESS_SUSPEND_RESUME|
			windows.PROCESS_QUERY_LIMITED_INFORMATION|
			windows.PROCESS_TERMINATE,
		false,
		proc.PID,
	)

	if err != nil {
		return
	}

	defer windows.CloseHandle(handle)

	// Suspend càng sớm càng tốt.
	if err := suspendProcess(handle); err != nil {
		return
	}

	path, _ := getProcessPath(proc.PID)

	if path == "" {
		path = proc.Name
	}

	fmt.Printf(
		"[BLOCKED]\nPID: %d\nName: %s\nPath: %s\n",
		proc.PID,
		proc.Name,
		path,
	)

	message := fmt.Sprintf(
		`Hệ thống phát hiện một chương trình có khả năng gây xung đột với CloudPC.

Tên chương trình:
%s

Đường dẫn:
%s

Một số chương trình antivirus hoặc phần mềm bảo mật có thể làm gián đoạn kết nối từ xa và khiến CloudPC không thể hoạt động bình thường.

Nếu đây là ứng dụng thông thường và bạn cho rằng hệ thống nhận diện nhầm, hãy chọn OK để tiếp tục chạy.

Nếu đây là antivirus, phần mềm bảo mật hoặc bạn không chắc chắn, hãy chọn Cancel để hủy chương trình.

Khuyến nghị: Chọn Cancel nếu bạn không chắc chắn.`,
		proc.Name,
		path,
	)

	result := messageBox(
		"Thinkmay Daemon",
		message,
		MB_OKCANCEL|
			MB_ICONWARNING|
			MB_TOPMOST|
			MB_SETFOREGROUND,
	)

	if result == IDOK {
		confirmMessage := fmt.Sprintf(
			`XÁC NHẬN LẦN CUỐI: Bạn có thực sự chắc chắn muốn cho phép chương trình này hoạt động không?

Chương trình:
%s

Đường dẫn:
%s

Nếu đây là phần mềm bảo mật/antivirus, việc cho phép chạy có thể làm ngắt kết nối CloudPC vĩnh viễn.`,
			proc.Name,
			path,
		)

		confirmResult := messageBox(
			"Thinkmay Daemon - Xác nhận",
			confirmMessage,
			MB_OKCANCEL|
				MB_ICONWARNING|
				MB_TOPMOST|
				MB_SETFOREGROUND,
		)

		if confirmResult == IDOK {
			fmt.Printf("[USER ALLOW] %s\n", path)
			_ = resumeProcess(handle)
			return
		}
	}

	fmt.Printf("[USER CANCEL] %s\n", path)

	// Process đang suspended nên kill khá sạch.
	if err := windows.TerminateProcess(handle, 0); err != nil {
		// Nếu kill thất bại thì không để process bị treo mãi.
		_ = resumeProcess(handle)
	} else {
		// Tự động xóa file sau khi kill để đảm bảo an toàn.
		// Windows cần thời gian giải phóng handle nên thực hiện bất đồng bộ với cơ chế retry.
		if path != "" && filepath.IsAbs(path) {
			go func(filePath string) {
				for i := 0; i < 10; i++ {
					time.Sleep(100 * time.Millisecond)
					err := os.Remove(filePath)
					if err == nil {
						fmt.Printf("[DELETED] %s\n", filePath)
						return
					}
				}
				fmt.Printf("[ERROR] Failed to delete file: %s\n", filePath)
			}(path)
		}
	}
}

func suspendProcess(handle windows.Handle) error {
	status, _, _ := procNtSuspendProcess.Call(uintptr(handle))

	if int32(status) < 0 {
		return fmt.Errorf(
			"NtSuspendProcess failed: 0x%08X",
			uint32(status),
		)
	}

	return nil
}

func resumeProcess(handle windows.Handle) error {
	status, _, _ := procNtResumeProcess.Call(uintptr(handle))

	if int32(status) < 0 {
		return fmt.Errorf(
			"NtResumeProcess failed: 0x%08X",
			uint32(status),
		)
	}

	return nil
}

func getProcessPath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)

	if err != nil {
		return "", err
	}

	defer windows.CloseHandle(handle)

	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))

	r1, _, e1 := procQueryFullProcessName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return "", e1
		}

		return "", fmt.Errorf("QueryFullProcessImageNameW failed")
	}

	return windows.UTF16ToString(buffer[:size]), nil
}

func messageBox(title string, text string, flags uintptr) int {
	titlePtr, _ := windows.UTF16PtrFromString(title)
	textPtr, _ := windows.UTF16PtrFromString(text)

	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags,
	)

	return int(ret)
}
