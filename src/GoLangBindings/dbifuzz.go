package dbifuzz
//package main

/*

#include "../Common/Golang/GoHeaders.h"

//ctest
HANDLE gethandle()
{
    return (HANDLE)(0x666);
}

*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
    "log"
)

var (
	dbifuzz, _                   = syscall.LoadLibrary("InAppFuzzDbiModule.dll")
	Init, _                      = syscall.GetProcAddress(dbifuzz, "Init")
	SmartTrace, _                = syscall.GetProcAddress(dbifuzz, "SmartTrace")
	GetNextFuzzThread, _         = syscall.GetProcAddress(dbifuzz, "GetNextFuzzThread")
	DbiSetHook, _                = syscall.GetProcAddress(dbifuzz, "DbiSetHook")
	DbiUnsetAddressBreakpoint, _ = syscall.GetProcAddress(dbifuzz, "DbiUnsetAddressBreakpoint")
	DbiWatchMemoryAccess, _      = syscall.GetProcAddress(dbifuzz, "DbiWatchMemoryAccess")
	DbiUnsetMemoryBreakpoint, _  = syscall.GetProcAddress(dbifuzz, "DbiUnsetMemoryBreakpoint")
	DbiSetMemoryWrite, _         = syscall.GetProcAddress(dbifuzz, "DbiSetMemoryWrite")
	DbiUnSetMemoryWrite, _       = syscall.GetProcAddress(dbifuzz, "DbiUnSetMemoryWrite")
	DbiSetMemoryExec, _          = syscall.GetProcAddress(dbifuzz, "DbiSetMemoryExec")
	DbiUnSetMemoryExec, _        = syscall.GetProcAddress(dbifuzz, "DbiUnSetMemoryExec")
	DbiEnumMemory, _             = syscall.GetProcAddress(dbifuzz, "DbiEnumMemory")
	DbiDumpMemory, _             = syscall.GetProcAddress(dbifuzz, "DbiDumpMemory")
	DbiPatchMemory, _            = syscall.GetProcAddress(dbifuzz, "DbiPatchMemory")
	DbiEnumModules, _            = syscall.GetProcAddress(dbifuzz, "DbiEnumModules")
	DbiGetProcAddress, _         = syscall.GetProcAddress(dbifuzz, "DbiGetProcAddress")
)

//=========================
//> declare
//=========================
type DbiFuzz struct {
    m_cid   C.CID_ENUM
    m_ctx   C.DBI_OUT_CONTEXT
    m_memBP map[uintptr]int
}

func (dfuzz DbiFuzz) Close() {
    syscall.FreeLibrary(dbifuzz)
}

func Create(pid uint64) (DbiFuzz) {
    dfuzz := DbiFuzz{}
    dfuzz.m_cid.ProcId = (C.HANDLE)((uintptr)(pid))
    return dfuzz
}

//PageFault, mem access
const (
	ACCESS = 0
	EXEC   = 1
	WRITE  = 2
)

//reason
const (
	BranchTraceFlag = 0
	SingleTraceFlag = 1
	Hook            = 2
	MemoryAccess    = 3
)

//=========================
//> thread specific
//=========================
func (dfuzz DbiFuzz) SwapThreadContext(threadId C.HANDLE) {
	dfuzz.m_cid.ThreadId = threadId

	syscall.Syscall(uintptr(Init), 2, (uintptr)(unsafe.Pointer(&dfuzz.m_cid)), (uintptr)(unsafe.Pointer(&dfuzz.m_ctx)), 0)
}

func (dfuzz DbiFuzz) GetNextThread(threadId C.HANDLE) C.HANDLE {
	cid := dfuzz.m_cid
	cid.ThreadId = threadId
	syscall.Syscall(uintptr(GetNextFuzzThread), 1, (uintptr)(unsafe.Pointer(&cid)), 0, 0)
	if threadId != cid.ThreadId {
		return cid.ThreadId
	}
	return nil
}

//=========================
//> tracing on current thread!
//=========================
func (dfuzz DbiFuzz) GetIp() uint64 {
	return (uint64)(uintptr(unsafe.Pointer(dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Return)))
}

func (dfuzz DbiFuzz) GetPrevIp() *C.void {
	return (*C.void)(unsafe.Pointer(dfuzz.m_ctx.TraceInfo.PrevEip))
}

func (dfuzz DbiFuzz) GetMemoryAccessInfo() *C.MEMORY_ACCESS {
	return &dfuzz.m_ctx.MemoryInfo
}

func (dfuzz DbiFuzz) GetReason() C.ULONG_PTR {
	return dfuzz.m_ctx.TraceInfo.Reason
}

func (dfuzz DbiFuzz) step() *C.void {
	syscall.Syscall(uintptr(SmartTrace), 2, (uintptr)(unsafe.Pointer(&dfuzz.m_cid)), (uintptr)(unsafe.Pointer(&dfuzz.m_ctx)), 0)

	switch dfuzz.GetReason() {
	case Hook:
		hook := C.PARAM_HOOK{unsafe.Pointer(uintptr(dfuzz.GetIp()))}
		syscall.Syscall(uintptr(DbiUnsetAddressBreakpoint), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&hook)), 0)
	case MemoryAccess:
		mem2watch := C.PARAM_MEM2WATCH{dfuzz.GetMemoryAccessInfo().Begin, dfuzz.GetMemoryAccessInfo().Size - 1}

		switch dfuzz.m_memBP[uintptr(unsafe.Pointer(dfuzz.GetMemoryAccessInfo().Begin))] {
		case EXEC:
			syscall.Syscall(uintptr(DbiUnSetMemoryExec), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
		case WRITE:
			syscall.Syscall(uintptr(DbiUnSetMemoryWrite), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
		default:
			syscall.Syscall(uintptr(DbiUnsetMemoryBreakpoint), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
		}
	}
	return (*C.void)(unsafe.Pointer(uintptr(dfuzz.GetIp())))
}


func (dfuzz DbiFuzz) Go(ip *C.void) *C.void {
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Flags &= 0x100
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Return = unsafe.Pointer(ip)
    dfuzz.m_ctx.TraceInfo.Btf = 0
    return dfuzz.step()
}

func (dfuzz DbiFuzz) SingleStep(ip *C.void) *C.void {
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Flags |= 0x100
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Return = unsafe.Pointer(ip)
    dfuzz.m_ctx.TraceInfo.Btf = 0
    return dfuzz.step()
}

func (dfuzz DbiFuzz) BranchStep(ip *C.void) *C.void {
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Flags |= 0x100
    dfuzz.m_ctx.TraceInfo.StateInfo.IRet.Return = unsafe.Pointer(ip)
    dfuzz.m_ctx.TraceInfo.Btf = 1
    return dfuzz.step()
}

//=========================
//> #thread non-specific == affect all threads! -> should be implemented as thread specific!!!
//=========================
func (dfuzz DbiFuzz) SetAddressBreakpoint(ip *C.void) {
    hook := C.PARAM_HOOK{unsafe.Pointer(ip)}
    syscall.Syscall(uintptr(DbiSetHook), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&hook)), 0)
}

func (dfuzz DbiFuzz) SetMemoryAccessBreakpoint(mem *C.void, size C.ULONG_PTR) {
    mem2watch := C.PARAM_MEM2WATCH{unsafe.Pointer(mem), size}
    syscall.Syscall(uintptr(DbiWatchMemoryAccess), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
    dfuzz.m_memBP[uintptr(unsafe.Pointer(mem2watch.Memory))] = ACCESS
}

func (dfuzz DbiFuzz) SetMemoryExecBreakpoint(mem *C.void, size C.ULONG_PTR) {
    mem2watch := C.PARAM_MEM2WATCH{unsafe.Pointer(mem), size}
    syscall.Syscall(uintptr(DbiSetMemoryExec), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
    dfuzz.m_memBP[uintptr(unsafe.Pointer(mem2watch.Memory))] = EXEC
}

func (dfuzz DbiFuzz) SetMemoryWriteBreakpoint(mem *C.void, size C.ULONG_PTR) {
    mem2watch := C.PARAM_MEM2WATCH{unsafe.Pointer(mem), size}
    syscall.Syscall(uintptr(DbiSetMemoryWrite), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem2watch)), 0)
    dfuzz.m_memBP[uintptr(unsafe.Pointer(mem2watch.Memory))] = WRITE
}

//=========================
//> #thread non-specific -> memory access
//=========================
func (dfuzz DbiFuzz) NextMemory(mem *C.void) C.MEMORY_ENUM {
    mem_enum := C.MEMORY_ENUM{unsafe.Pointer(mem), 0, 0}
    syscall.Syscall(uintptr(DbiEnumMemory), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&mem_enum)), 0)
    if (mem_enum.Begin != unsafe.Pointer(mem)) {
        return mem_enum
    }
    return C.MEMORY_ENUM{nil, 0, 0}
}

func (dfuzz DbiFuzz) ReadMemory(mem uint64, size uint64) ([]byte) {
    buffer := make([]byte, size)
    syscall.Syscall6(uintptr(DbiDumpMemory), 4, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), uintptr(mem), (uintptr)(unsafe.Pointer(&buffer[0])), (uintptr)(size), 0, 0)
    return buffer
}

func (dfuzz DbiFuzz) WriteMemory(mem *C.void, buffer []byte, size uint64) {
    syscall.Syscall6(uintptr(DbiPatchMemory), 4, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(mem)), (uintptr)(unsafe.Pointer(&buffer[0])), (uintptr)(size), 0, 0)
}

func (dfuzz DbiFuzz) NextModule(base *C.void) C.MODULE_ENUM {
    img := C.MODULE_ENUM{}//RtlZeroMem
    img.ImageBase = unsafe.Pointer(base)
    syscall.Syscall(uintptr(DbiEnumModules), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&img)), 0)
    if (img.ImageSize != 0) {
        return img
    }
    return C.MODULE_ENUM{}
}

func (dfuzz DbiFuzz) GetModuleByAddr(addr *C.void) C.MODULE_ENUM {
    discovered := make(map[unsafe.Pointer]bool)

    for img := dfuzz.NextModule(addr); img.ImageSize != 0; img = dfuzz.NextModule((*C.void)(img.ImageBase)) {
        if (discovered[img.ImageBase]) {
            break
        }
        discovered[img.ImageBase] = true
        //omg definetely need to play with that and rewrite it more sensly ..
        if ((uintptr)((unsafe.Pointer)(addr)) >= (uintptr)(img.ImageBase) &&
             (uintptr)((unsafe.Pointer)(addr)) <= (uintptr)(((C.ULONG_PTR)((uintptr)(img.ImageBase))) + img.ImageSize)) {
            return img
        }
    }
    return C.MODULE_ENUM{}
}

func (dfuzz DbiFuzz) GetModule(name [0x100]C.WCHAR) C.MODULE_ENUM {
    discovered := make(map[unsafe.Pointer][0x100]C.WCHAR)

    for img := dfuzz.NextModule(nil); img.ImageSize != 0; img = dfuzz.NextModule((*C.void)(img.ImageBase)) {
        _, ok := discovered[img.ImageBase]
        if (ok) {
            break
        }
        discovered[img.ImageBase] = img.ImageName
        //compare whole wstrings or just addresses ??
        if (img.ImageName == name) {
            return img
        }
    }
    return C.MODULE_ENUM{}
}

func (dfuzz DbiFuzz) GetProcAddress(module [0x100]C.WCHAR, api [0x100]C.CHAR) unsafe.Pointer {
    base := dfuzz.GetModule(module).ImageBase
    proc := C.PARAM_API{nil, base, api}
    if (base != nil) {
        syscall.Syscall(uintptr(DbiGetProcAddress), 2, (uintptr)(unsafe.Pointer(dfuzz.m_cid.ProcId)), (uintptr)(unsafe.Pointer(&proc)), 0)
    }
    return proc.ApiAddr
}

func (dfuzz DbiFuzz) ReadPtr(addr uint64) (ptr C.ULONG_PTR) {
    _ptr := dfuzz.ReadMemory(addr, 8)
    ptr = 0
    for i, b := range _ptr {
        ptr |= ((C.ULONG_PTR)(b) << (8 * uint(i)))
    }
    return
}

func main() {
	var dbi_fuzz DbiFuzz
	defer dbi_fuzz.Close()

	var z C.CID_ENUM
	var h C.HANDLE = C.gethandle()
	z.ProcId = h
	fmt.Println(z.ProcId, z.ThreadId)
	fmt.Println(z)

	log.Printf("%x", h)
	fmt.Println(dbi_fuzz.GetIp())
	fmt.Println(Init)
	dbi_fuzz.SwapThreadContext(h)
}
