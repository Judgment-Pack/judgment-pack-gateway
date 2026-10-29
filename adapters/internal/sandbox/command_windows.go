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
var winSetSecurity = winSecurity.NewProc("SetSecurityInfo")
var winGetDACL = winSecurity.NewProc("GetSecurityDescriptorDacl")
var winGetSACL = winSecurity.NewProc("GetSecurityDescriptorSacl")
var winGetControl = winSecurity.NewProc("GetSecurityDescriptorControl")
var winCreateJob = winKernel.NewProc("CreateJobObjectW")
var winSetJob = winKernel.NewProc("SetInformationJobObject")
var winAssignJob = winKernel.NewProc("AssignProcessToJobObject")
var winTerminateJob = winKernel.NewProc("TerminateJobObject")
var winQueryJob = winKernel.NewProc("QueryInformationJobObject")
var winReopenFile = winKernel.NewProc("ReOpenFile")
var winCreateEvent = winKernel.NewProc("CreateEventW")
var winUser = syscall.NewLazyDLL("user32.dll")
var winCreateStation = winUser.NewProc("CreateWindowStationW")
var winSetStation = winUser.NewProc("SetProcessWindowStation")
var winCreateDesktop = winUser.NewProc("CreateDesktopW")
var winSetDesktop = winUser.NewProc("SetThreadDesktop")

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
	if len(os.Args) < 5 {
		fail(errors.New("invalid restricted launcher"))
	}
	handle, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fail(err)
	}
	job := syscall.Handle(handle)
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
	// the restricting SID. The child explicitly names this private desktop.
	runtime.LockOSThread()
	// Create the restricted token from this launcher's primary token. The
	// CreateProcessAsUser exception is specific to the caller's primary token,
	// not a restricted token made by its parent before this process existed.
	token, err := restrictedWindowsToken(os.Args[3])
	if err != nil {
		fail(err)
	}
	if err = privateWindowsDesktop(os.Args[3], token); err != nil {
		fail(err)
	}
	code, err := runWindowsChild(token, "gateway-"+os.Args[3]+`\source`, os.Args[4:])
	token.Close()
	if err == nil {
		os.Exit(int(code))
	}
	fmt.Fprintln(os.Stderr, "server-exec-failed:", err)
	os.Exit(126)
}

// Go's SysProcAttr has no Desktop field. Use an explicit standard-handle
// allowlist and private desktop. The job, token and ACL handles stay private.
func runWindowsChild(token syscall.Token, desktop string, argv []string) (uint32, error) {
	executable, err := syscall.UTF16PtrFromString(argv[0])
	if err != nil {
		return 0, err
	}
	words := make([]string, len(argv))
	for i, arg := range argv {
		words[i] = syscall.EscapeArg(arg)
	}
	line, err := syscall.UTF16PtrFromString(strings.Join(words, " "))
	if err != nil {
		return 0, err
	}
	name, err := syscall.UTF16PtrFromString(desktop)
	if err != nil {
		return 0, err
	}
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var handles [3]syscall.Handle
	for i, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if err = syscall.DuplicateHandle(self, syscall.Handle(file.Fd()), self, &handles[i], 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return 0, err
		}
		defer syscall.CloseHandle(handles[i])
	}
	initialize := winKernel.NewProc("InitializeProcThreadAttributeList")
	var size uintptr
	initialize.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 1<<20 {
		return 0, errors.New("invalid process attribute size")
	}
	attributes := make([]byte, size)
	list := uintptr(unsafe.Pointer(&attributes[0]))
	if err = winBool(initialize, list, 1, 0, uintptr(unsafe.Pointer(&size))); err != nil {
		return 0, err
	}
	defer func() {
		winKernel.NewProc("DeleteProcThreadAttributeList").Call(list)
		runtime.KeepAlive(attributes)
		runtime.KeepAlive(handles)
	}()
	if err = winBool(winKernel.NewProc("UpdateProcThreadAttribute"), list, 0, 0x20002, uintptr(unsafe.Pointer(&handles[0])), unsafe.Sizeof(handles), 0, 0); err != nil {
		return 0, err
	}
	startup := struct {
		syscall.StartupInfo
		attributes *byte
	}{attributes: &attributes[0]}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Desktop = name
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = handles[0], handles[1], handles[2]
	var process syscall.ProcessInformation
	// Null environment and directory inherit the trusted launcher's selected
	// source environment and workspace. CREATE_NO_WINDOW; extended startup info.
	err = syscall.CreateProcessAsUser(token, executable, line, nil, nil, true, 0x08080000, nil, nil, &startup.StartupInfo, &process)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(handles)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(process.Process)
	syscall.CloseHandle(process.Thread)
	if _, err = syscall.WaitForSingleObject(process.Process, syscall.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	err = syscall.GetExitCodeProcess(process.Process, &code)
	return code, err
}

func restrictedWindowsToken(sidText string) (syscall.Token, error) {
	sid, err := syscall.StringToSid(sidText)
	if err != nil {
		return 0, err
	}
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var original syscall.Token
	if err = syscall.OpenProcessToken(current, syscall.TOKEN_ALL_ACCESS, &original); err != nil {
		return 0, err
	}
	defer original.Close()
	var token syscall.Token
	restricted := syscall.SIDAndAttributes{Sid: sid}
	if err = winBool(winCreateRestricted, uintptr(original), 0x9, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restricted)), uintptr(unsafe.Pointer(&token))); err != nil {
		return 0, err
	}
	low, err := syscall.StringToSid("S-1-16-4096")
	if err != nil {
		token.Close()
		return 0, err
	}
	label := syscall.SIDAndAttributes{Sid: low, Attributes: 0x20}
	if err = winBool(winSetToken, uintptr(token), 25, uintptr(unsafe.Pointer(&label)), unsafe.Sizeof(label)+uintptr(low.Len())); err != nil {
		token.Close()
		return 0, err
	}
	// New private objects must be accessible to the same restricting SID.
	// This changes only the new token's default DACL, never an existing host
	// object's ACL and never the set of restricting SIDs.
	user, err := token.GetTokenUser()
	if err != nil {
		token.Close()
		return 0, err
	}
	userSID, err := user.User.Sid.String()
	if err != nil {
		token.Close()
		return 0, err
	}
	raw, err := syscall.UTF16PtrFromString("D:(A;;GA;;;SY)(A;;GA;;;" + userSID + ")(A;;GA;;;" + sidText + ")")
	if err != nil {
		token.Close()
		return 0, err
	}
	var sd uintptr
	if err = winBool(winStringSD, uintptr(unsafe.Pointer(raw)), 1, uintptr(unsafe.Pointer(&sd)), 0); err != nil {
		token.Close()
		return 0, err
	}
	defer winFree(sd)
	var dacl uintptr
	var present, defaulted uint32
	if err = winBool(winGetDACL, sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); err != nil {
		token.Close()
		return 0, err
	}
	if err = winBool(winSetToken, uintptr(token), 6, uintptr(unsafe.Pointer(&dacl)), unsafe.Sizeof(dacl)); err != nil {
		token.Close()
		return 0, err
	}
	return token, nil
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
		stopped := r.clean
		for i := len(r.acls) - 1; i >= 0; i-- {
			a := r.acls[i]
			if a.changed && stopped {
				if err := restoreWindowsACL(a); err != nil {
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
	var err error
	if mode == WorkspaceWrite {
		// Validate the complete tree before changing any ACL. Reparse points
		// and multiply-linked files are refused, not followed. Global exclusion
		// prevents a second restricted writer from changing nested workspaces.
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
	argv := append([]string{winHelperArg, strconv.FormatUint(uint64(job), 10), sidText, executable}, args...)
	cmd := exec.CommandContext(ctx, self, argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000, AdditionalInheritedHandles: []syscall.Handle{resources.job}}
	report.State = "partial"
	report.Reason = "low-integrity write-restricted token and per-run ACLs restrict writes on access-controlled filesystems; network access and objects without usable access controls are not confined"
	report.cleanup = resources.cleanup
	return cmd, report, nil
}

// Exclude all restricted workspace writers before reading any ACL, including
// nested or aliased workspaces and separate logon sessions. File handles allow
// delete sharing but never request DELETE, so ordinary file I/O remains possible;
// they keep restoration bound to the original object if the child renames it.
// The fresh SID cannot move an object outside its writable parent directories.
var lockWindowsWorkspace = func(_ syscall.Handle) (syscall.Handle, error) {
	name, _ := syscall.UTF16PtrFromString("Global\\gateway-sandbox-workspace-write-v1")
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
	handle, err := syscall.CreateFile(name, 0xe0080, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0x02000000|0x00200000, 0)
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
	if err = setWindowsFileSecurity(a.handle, sd); err != nil {
		return err
	}
	a.changed = true
	return nil
}

// ReOpenFile binds a short-lived mutation handle to the held physical object,
// even after a rename. MAXIMUM_ALLOWED suppresses SetSecurityInfo propagation,
// but its DELETE access would conflict with normal Go opens while it remained
// open. Close this handle before ordinary I/O; the retained handle lacks DELETE.
// Only DACL and mandatory-label components are set, preserving audit SACL ACEs.
func setWindowsFileSecurity(handle syscall.Handle, sd uintptr) error {
	mutation, _, reopenErr := winReopenFile.Call(uintptr(handle), 0x020e0080, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, 0x02000000|0x00200000)
	if syscall.Handle(mutation) == syscall.InvalidHandle {
		return fmt.Errorf("reopen held security object: %w", reopenErr)
	}
	defer syscall.CloseHandle(syscall.Handle(mutation))
	var dacl, sacl uintptr
	var present, defaulted uint32
	if err := winBool(winGetDACL, sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); err != nil {
		return err
	}
	if present == 0 || dacl == 0 {
		return errors.New("sandbox-policy-invalid: missing or null DACL")
	}
	if err := winBool(winGetSACL, sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&sacl)), uintptr(unsafe.Pointer(&defaulted))); err != nil {
		return err
	}
	var control uint16
	var revision uint32
	if err := winBool(winGetControl, sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision))); err != nil {
		return err
	}
	flags := uintptr(winSecurityParts | 0x20000000) // unprotected DACL
	if control&0x1000 != 0 {
		flags = winSecurityParts | 0x80000000
	}
	status, _, _ := winSetSecurity.Call(mutation, 1, flags, 0, 0, dacl, sacl)
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func windowsSecurityState(sd uintptr) (string, error) {
	var control uint16
	var revision uint32
	if err := winBool(winGetControl, sd, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision))); err != nil {
		return "", err
	}
	var text *uint16
	if err := winBool(winSDString, sd, 1, winSecurityParts, uintptr(unsafe.Pointer(&text)), 0); err != nil {
		return "", err
	}
	defer winFree(uintptr(unsafe.Pointer(text)))
	var units []uint16
	for i := uintptr(0); i < 65536; i++ {
		u := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(text)) + 2*i))
		if u == 0 {
			// GetSecurityInfo may represent no mandatory label with either an
			// absent or null label-only SACL. Both contain no label ACE. Keep
			// every DACL ACE flag and its control state, including inheritance.
			s := strings.TrimSuffix(syscall.UTF16ToString(units), "S:NO_ACCESS_CONTROL")
			return fmt.Sprintf("%04x:%s", control&0x150c, s), nil
		}
		units = append(units, u)
	}
	return "", errors.New("sandbox-cleanup-failed: security descriptor exceeds bound")
}

func restoreWindowsACL(a winACL) error {
	before, err := windowsSecurityState(a.original)
	if err != nil {
		return err
	}
	if err = setWindowsFileSecurity(a.handle, a.original); err != nil {
		return err
	}
	current := winACL{handle: a.handle}
	if err = snapshotWindowsACL(&current); err != nil {
		return err
	}
	defer winFree(current.original)
	after, err := windowsSecurityState(current.original)
	if err != nil {
		return err
	}
	if before != after {
		return errors.New("sandbox-cleanup-failed: restored DACL or mandatory label differs")
	}
	return nil
}
