package sandbox

// The write-restricted, low-integrity token has a fresh restricting SID. Only
// the workspace and private temporary directory receive its write grant. A job
// contains the command tree; held handles keep ACL writes off reparse points.
import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var winSecurity = syscall.NewLazyDLL("advapi32.dll")
var winKernel = syscall.NewLazyDLL("kernel32.dll")
var winCreateRestricted = winSecurity.NewProc("CreateRestrictedToken")
var winSetToken = winSecurity.NewProc("SetTokenInformation")
var winGetSecurity = winSecurity.NewProc("GetSecurityInfo")
var winSDString = winSecurity.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
var winStringSD = winSecurity.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var winSetSecurity = winSecurity.NewProc("SetKernelObjectSecurity")
var winCreateJob = winKernel.NewProc("CreateJobObjectW")
var winSetJob = winKernel.NewProc("SetInformationJobObject")
var winAssignJob = winKernel.NewProc("AssignProcessToJobObject")
var winTerminateJob = winKernel.NewProc("TerminateJobObject")
var winQueryJob = winKernel.NewProc("QueryInformationJobObject")
var winCreateEvent = winKernel.NewProc("CreateEventW")
var winUser = syscall.NewLazyDLL("user32.dll")
var winCreateStation = winUser.NewProc("CreateWindowStationW")
var winSetStation = winUser.NewProc("SetProcessWindowStation")
var winCreateDesktop = winUser.NewProc("CreateDesktopW")
var winSetDesktop = winUser.NewProc("SetThreadDesktop")
var winIsRestricted = winSecurity.NewProc("IsTokenRestricted")

const winHelperArg = "_gateway_windows_sandbox_exec_v1"
const winSecurityParts = 0x4 | 0x10 // DACL and mandatory label, not audit SACL
func winBool(proc *syscall.LazyProc, args ...uintptr) error {
	ok, _, err := proc.Call(args...)
	if ok == 0 {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}
	return nil
}
func winFree(p uintptr) {
	if p != 0 {
		_, _ = syscall.LocalFree(syscall.Handle(p))
	}
}

// Join before any caller code; the inherited job handle never reaches it.
func init() {
	if len(os.Args) < 2 || os.Args[1] != winHelperArg {
		return
	}
	fail := func(err error) { fmt.Fprintln(os.Stderr, "sandbox-not-enforced:", err); os.Exit(125) }
	if len(os.Args) < 6 {
		fail(errors.New("invalid restricted launcher"))
	}
	handle, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fail(err)
	}
	job := syscall.Handle(handle)
	tokenValue, err := strconv.ParseUint(os.Args[3], 10, 64)
	if err != nil {
		fail(err)
	}
	token := syscall.Token(tokenValue)
	if err = winBool(winIsRestricted, uintptr(token)); err != nil {
		fail(err)
	}
	if err = syscall.SetHandleInformation(syscall.Handle(token), 1, 0); err != nil {
		fail(err)
	}
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		fail(err)
	}
	if err = winBool(winAssignJob, uintptr(job), uintptr(self)); err != nil {
		fail(err)
	}
	if err = syscall.CloseHandle(job); err != nil {
		fail(err)
	}
	// The trusted launcher prepares a private desktop before starting the
	// restricted child. The operator's interactive desktop is never granted to
	// the restricting SID. Startup with a nil Desktop inherits this association.
	runtime.LockOSThread()
	if err = privateWindowsDesktop(os.Args[4], token); err != nil {
		fail(err)
	}
	cmd := exec.Command(os.Args[5], os.Args[6:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: token, CreationFlags: 0x08000000}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Start()
	token.Close()
	if err == nil {
		err = cmd.Wait()
	}
	if err == nil {
		os.Exit(0)
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		os.Exit(exited.ExitCode())
	}
	fmt.Fprintln(os.Stderr, "server-exec-failed:", err)
	os.Exit(126)
}

func privateWindowsDesktop(sid string, token syscall.Token) error {
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	userSID, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	raw, err := syscall.UTF16PtrFromString("D:(A;;GA;;;SY)(A;;GA;;;" + userSID + ")(A;;GA;;;" + sid + ")S:(ML;;NW;;;LW)")
	if err != nil {
		return err
	}
	var sd uintptr
	if err = winBool(winStringSD, uintptr(unsafe.Pointer(raw)), 1, uintptr(unsafe.Pointer(&sd)), 0); err != nil {
		return err
	}
	defer winFree(sd)
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := syscall.UTF16PtrFromString("gateway-" + sid)
	if err != nil {
		return err
	}
	station, _, callErr := winCreateStation.Call(uintptr(unsafe.Pointer(name)), 1, 0xf037f, uintptr(unsafe.Pointer(&sa)))
	if station == 0 {
		return fmt.Errorf("private window station: %w", callErr)
	}
	if err = winBool(winSetStation, station); err != nil {
		return err
	}
	name, _ = syscall.UTF16PtrFromString("source")
	desktop, _, callErr := winCreateDesktop.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, 0xf01ff, uintptr(unsafe.Pointer(&sa)))
	if desktop == 0 {
		return fmt.Errorf("private desktop: %w", callErr)
	}
	// Both handles stay private to the trusted launcher and close on exit.
	return winBool(winSetDesktop, desktop)
}

type winACL struct {
	handle   syscall.Handle
	original uintptr
	changed  bool
}
type winResources struct {
	token syscall.Token
	job   syscall.Handle
	lock  syscall.Handle
	acls  []winACL
	once  sync.Once
	clean bool
}

// Restore only after the job is empty; retain temporary files on cleanup error.
func (r *winResources) cleanup() error {
	r.once.Do(func() {
		r.clean = true
		if r.job != 0 {
			if err := winBool(winTerminateJob, uintptr(r.job), 1); err != nil {
				r.clean = false
			}
			deadline := time.Now().Add(3 * time.Second)
			for r.clean {
				var info struct {
					UserTime, KernelTime, PeriodUser, PeriodKernel int64
					PageFaults, Total, Active, Terminated          uint32
				}
				if err := winBool(winQueryJob, uintptr(r.job), 1, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0); err != nil {
					r.clean = false
					break
				}
				if info.Active == 0 {
					break
				}
				if time.Now().After(deadline) {
					r.clean = false
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			syscall.CloseHandle(r.job)
		}
		if r.token != 0 {
			r.token.Close()
		}
		stopped := r.clean
		for i := len(r.acls) - 1; i >= 0; i-- {
			a := r.acls[i]
			if a.changed && stopped {
				if err := winBool(winSetSecurity, uintptr(a.handle), winSecurityParts, a.original); err != nil {
					r.clean = false
				}
			}
			winFree(a.original)
			syscall.CloseHandle(a.handle)
		}
		if r.lock != 0 {
			syscall.CloseHandle(r.lock)
		}
		if !r.clean {
			fmt.Fprintln(os.Stderr, "sandbox-cleanup-failed: job termination or ACL restoration failed; temporary files retained")
		}
	})
	if !r.clean {
		return errors.New("sandbox-cleanup-failed: job termination or ACL restoration failed")
	}
	return nil
}
func platformCommand(ctx context.Context, executable string, args []string, mode, workspace, tmp string) (_ *exec.Cmd, report Report, result error) {
	report = Report{Mode: mode, Backend: "windows-restricted-token", State: "not-enforced"}
	resources := &winResources{}
	report.cleanup = resources.cleanup
	defer func() {
		if result != nil {
			resources.cleanup()
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, report, err
	}
	sidText := fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", binary.LittleEndian.Uint32(random[0:4]), binary.LittleEndian.Uint32(random[4:8]), binary.LittleEndian.Uint32(random[8:12]), binary.LittleEndian.Uint32(random[12:16]))
	sid, err := syscall.StringToSid(sidText)
	if err != nil {
		return nil, report, err
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, report, err
	}
	var original syscall.Token
	if err = syscall.OpenProcessToken(current, syscall.TOKEN_ALL_ACCESS, &original); err != nil {
		return nil, report, err
	}
	defer original.Close()
	restricted := syscall.SIDAndAttributes{Sid: sid}
	if err = winBool(winCreateRestricted, uintptr(original), 0x9, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restricted)), uintptr(unsafe.Pointer(&resources.token))); err != nil {
		return nil, report, err
	}
	low, err := syscall.StringToSid("S-1-16-4096")
	if err != nil {
		return nil, report, err
	}
	label := syscall.SIDAndAttributes{Sid: low, Attributes: 0x20}
	if err = winBool(winSetToken, uintptr(resources.token), 25, uintptr(unsafe.Pointer(&label)), unsafe.Sizeof(label)+uintptr(low.Len())); err != nil {
		return nil, report, err
	}
	if mode == WorkspaceWrite {
		// Validate the complete tree before changing any ACL. No delete sharing;
		// reparse points and multiply-linked files are refused, not followed.
		for _, root := range []string{workspace, tmp} {
			err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if len(resources.acls) >= 10000 {
					return errors.New("sandbox-policy-invalid: workspace exceeds 10000 existing objects")
				}
				a, err := holdWindowsFile(path)
				if err != nil {
					return err
				}
				resources.acls = append(resources.acls, a)
				if path == workspace {
					resources.lock, err = lockWindowsWorkspace(a.handle)
					if err != nil {
						return err
					}
				}
				return snapshotWindowsACL(&resources.acls[len(resources.acls)-1])
			})
			if err != nil {
				return nil, report, err
			}
		}
		for i := range resources.acls {
			if err = grantWindowsACL(&resources.acls[i], sidText); err != nil {
				return nil, report, err
			}
		}
	}
	// No breakaway. Once joined, only the parent retains the job handle, so loss
	// of the parent ends the tree even without normal cleanup.
	sa := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), InheritHandle: 1}
	job, _, callErr := winCreateJob.Call(uintptr(unsafe.Pointer(&sa)), 0)
	if job == 0 {
		return nil, report, callErr
	}
	resources.job = syscall.Handle(job)
	var limits struct {
		PerProcess, PerJob                                         int64
		Flags                                                      uint32
		MinWorking, MaxWorking                                     uintptr
		Active                                                     uint32
		Affinity                                                   uintptr
		Priority, Scheduling                                       uint32
		IO                                                         [6]uint64
		ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
	}
	limits.Flags = 0x2000
	if err = winBool(winSetJob, job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); err != nil {
		return nil, report, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, report, err
	}
	if err = syscall.SetHandleInformation(syscall.Handle(resources.token), 1, 1); err != nil {
		return nil, report, err
	}
	argv := append([]string{winHelperArg, strconv.FormatUint(uint64(job), 10), strconv.FormatUint(uint64(resources.token), 10), sidText, executable}, args...)
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000, AdditionalInheritedHandles: []syscall.Handle{resources.job, syscall.Handle(resources.token)}}
	report.State = "partial"
	report.Reason = "low-integrity write-restricted token and per-run ACLs restrict writes on access-controlled filesystems; network access and objects without usable access controls are not confined"
	report.cleanup = resources.cleanup
	return cmd, report, nil
}

// Exclusion is acquired using physical identity before reading any ACL. The
// global namespace covers separate logon sessions sharing the workspace.
var lockWindowsWorkspace = func(handle syscall.Handle) (syscall.Handle, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, err
	}
	name, _ := syscall.UTF16PtrFromString(fmt.Sprintf("Global\\gateway-sandbox-%08x-%08x-%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow))
	h, _, err := winCreateEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		return 0, err
	}
	if err == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(syscall.Handle(h))
		return 0, errors.New("sandbox-policy-invalid: workspace already in use")
	}
	return syscall.Handle(h), nil
}

func holdWindowsFile(path string) (winACL, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return winACL{}, err
	}
	// READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES; open the
	// reparse point itself and keep this exact object from being renamed.
	handle, err := syscall.CreateFile(name, 0xe0080, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0x02000000|0x00200000, 0)
	if err != nil {
		return winACL{}, fmt.Errorf("sandbox-policy-invalid: workspace ACL handle: %w", err)
	}
	fail := func(err error) (winACL, error) { syscall.CloseHandle(handle); return winACL{}, err }
	var info syscall.ByHandleFileInformation
	if err = syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1) {
		return fail(errors.New("sandbox-policy-invalid: workspace contains a reparse point or multiply-linked file"))
	}
	return winACL{handle: handle}, nil
}

func snapshotWindowsACL(a *winACL) error {
	status, _, _ := winGetSecurity.Call(uintptr(a.handle), 1, winSecurityParts, 0, 0, 0, 0, uintptr(unsafe.Pointer(&a.original)))
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func holdWindowsACL(path string) (winACL, error) {
	a, err := holdWindowsFile(path)
	if err != nil {
		return a, err
	}
	if err = snapshotWindowsACL(&a); err != nil {
		syscall.CloseHandle(a.handle)
		return winACL{}, err
	}
	return a, nil
}

func grantWindowsACL(a *winACL, sid string) error {
	var text *uint16
	if err := winBool(winSDString, a.original, 1, winSecurityParts, uintptr(unsafe.Pointer(&text)), 0); err != nil {
		return err
	}
	defer winFree(uintptr(unsafe.Pointer(text)))
	var units []uint16
	for i := uintptr(0); i < 65536; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(text)) + 2*i))
		if c == 0 {
			break
		}
		units = append(units, c)
	}
	sddl := syscall.UTF16ToString(units)
	dacl, _, _ := strings.Cut(sddl, "S:")
	if !strings.HasPrefix(dacl, "D:") || strings.Contains(dacl, "NO_ACCESS_CONTROL") {
		return errors.New("sandbox-policy-invalid: workspace requires a non-null DACL")
	}
	// No WRITE_DAC/WRITE_OWNER grant. This API changes the held object only;
	// existing descendants were checked and are each changed through a handle.
	sddl = dacl + "(A;OICI;0x1301bf;;;" + sid + ")S:(ML;OICI;NW;;;LW)"
	raw, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var sd uintptr
	if err = winBool(winStringSD, uintptr(unsafe.Pointer(raw)), 1, uintptr(unsafe.Pointer(&sd)), 0); err != nil {
		return err
	}
	defer winFree(sd)
	if err = winBool(winSetSecurity, uintptr(a.handle), winSecurityParts, sd); err != nil {
		return err
	}
	a.changed = true
	return nil
}
