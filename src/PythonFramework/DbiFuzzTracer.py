#! /usr/bin/env python

from Common import *
from Shared import *
from CPU import *
from os import *

class CDbiFuzzTracer(CCpu):
    def __init__(self, processId):
        CCpu.__init__(self, DBI_OUT_CONTEXT())
        self.m_cid = CID_ENUM(processId, 0)
        self.comm = CCDLL("C:/InAppFuzzDbiModule.dll").GetLib()

        self.GetNextFuzzThread = self.comm.GetNextFuzzThread#cid
        self.GetNextFuzzThread.argtypes = [POINTER(CID_ENUM)]

##########################
# DEFINE EXT INTERFACE
##########################

        self.Init = self.comm.Init#pid, tid, dbiooutcontext
        self.Init.argtypes = [POINTER(CID_ENUM), POINTER(DBI_OUT_CONTEXT)]

        self.SmartTrace = self.comm.SmartTrace#pid, tid, dbioutcontext
        self.SmartTrace.argtypes = [POINTER(CID_ENUM), POINTER(DBI_OUT_CONTEXT)]

        self.DbiSetHook = self.comm.DbiSetHook#pid, PARAM_HOOK
        self.DbiSetHook.argtypes = [c_ulonglong, POINTER(PARAM_HOOK)]
        
        self.DbiUnsetAddressBreakpoint = self.comm.DbiUnsetAddressBreakpoint#pid, PARAM_HOOK
        self.DbiUnsetAddressBreakpoint.argtypes = [c_ulonglong, POINTER(PARAM_HOOK)]

        self.DbiWatchMemoryAccess = self.comm.DbiWatchMemoryAccess#pid, PARAM_MEM2WATCH
        self.DbiWatchMemoryAccess.argtypes = [c_ulonglong, POINTER(PARAM_MEM2WATCH)]
        
        self.DbiUnsetMemoryBreakpoint = self.comm.DbiUnsetMemoryBreakpoint#pid, PARAM_MEM2WATCH
        self.DbiUnsetMemoryBreakpoint.argtypes = [c_ulonglong, POINTER(PARAM_MEM2WATCH)]

        self.DbiEnumMemory = self.comm.DbiEnumMemory#pid, MEMORY_ENUM
        self.DbiEnumMemory.argtypes = [c_ulonglong, POINTER(MEMORY_ENUM)]

        self.DbiDumpMemory = self.comm.DbiDumpMemory#pid, src, dst, size
        self.DbiDumpMemory.argtypes = [c_ulonglong, c_ulonglong, POINTER(BYTE_BUFFER), c_ulonglong]

        self.DbiPatchMemory = self.comm.DbiPatchMemory#pid, dst, src, size
        self.DbiPatchMemory.argtypes = [c_ulonglong, c_ulonglong, POINTER(BYTE_BUFFER), c_ulonglong]

        self.DbiEnumModules = self.comm.DbiEnumModules#pid, MODULE_ENUM
        self.DbiEnumModules.argtypes = [c_ulonglong, POINTER(MODULE_ENUM)]

        self.DbiGetProcAddress = self.comm.DbiGetProcAddress#pid, PARAM_API
        self.DbiGetProcAddress.argtypes = [c_ulonglong, POINTER(PARAM_API)]

        #set current thread
        self.SwapThreadContext(self.GetNextThread(0))

#thread specific
    def GetNextThread(self, threadId):
        cid = self.m_cid
        cid.ThreadId = threadId
        self.GetNextFuzzThread(pointer(cid))
        
        #bullshit, replaced by setting bool return val of GetNextFuzzThread
        if (threadId == cid.ThreadId):
            return 0
        
        return cid.ThreadId
    
    def SwapThreadContext(self, threadId):
        self.m_cid.ThreadId = threadId
        self.Init(pointer(self.m_cid), pointer(self.__Context__()))
        
    def GetThreadStack(self):
        return

#tracing inside current thread
    def GetIp(self):
        return self.__Context__().TraceInfo.StateInfo.IRet.Return
    
    def GetPrevIp(self):
        return self.__Context__().TraceInfo.PrevIp

    def GetReason(self):
        return self.__Context__().TraceInfo.Reason

    def GetMemoryAccesInfo(self):
        return self.__Context__().MemoryInfo

    def __Step(self):
        self.SmartTrace(pointer(self.m_cid), pointer(self.__Context__()))

        #in multithreading tracer -> need to 'freeze' this thread if it is not its event
        #and wait for thread which have setted this address/memory breakpoint
        #'freeze' means get callback to tracer to given thread with signalized state that
        #this is not its own breakpoint! and not unset it!!!
        #unset this breakpoint should only thread for what is this breakpoint supposed ...!
        print("reason : ", self.GetReason())
        if (Hook == self.__Context__().TraceInfo.Reason):            
            hook = PARAM_HOOK(self.GetIp())
            self.DbiUnsetAddressBreakpoint(self.m_cid.ProcId, pointer(hook))
            print("ADRESS HOOK")
        elif (MemoryAccess == self.GetReason()):            
            mem2watch = PARAM_MEM2WATCH(self.__Context__().MemoryInfo.Begin, self.__Context__().MemoryInfo.Size - 1)
            print(hex(self.__Context__().MemoryInfo.OriginalValue), " <--- original value")
            self.DbiUnsetMemoryBreakpoint(self.m_cid.ProcId, pointer(mem2watch))
            print("MEMORY HOOK")
            
        return self.__Context__().TraceInfo.StateInfo.IRet.Return
    
    def Go(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags &= ~0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        self.__Context__().TraceInfo.Btf = 0
        return self.__Step()
        
    def SingleStep(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags |= 0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        self.__Context__().TraceInfo.Btf = 0
        return self.__Step()
        
    def BranchStep(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags |= 0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        self.__Context__().TraceInfo.Btf = 1
        return self.__Step()
        
#thread non-specific == affect all threads! -> should be implemented as thread specific!!!
    def SetAddressBreakpoint(self, ip):
        hook = PARAM_HOOK(ip)
        #ThreadId logic should be placed here == no ThreadId passed to DbiSetHook
        self.DbiSetHook(self.m_cid.ProcId, pointer(hook))

    def SetMemoryBreakpoint(self, mem, size):
        mem2watch = PARAM_MEM2WATCH(mem, size)
        #ThreadId logic should be placed here == no ThreadId passed to DbiWatchMemoryAccess
        self.DbiWatchMemoryAccess(self.m_cid.ProcId, pointer(mem2watch))

#thread non-specific -> memory access
    def NextMemory(self, mem):
        mem_enum = MEMORY_ENUM(mem, 0, 0)
        print("->", hex(mem_enum.Begin))
        self.DbiEnumMemory(self.m_cid.ProcId, pointer(mem_enum))
        if (mem_enum.Begin == mem):
            return None
        return mem_enum

    #size is now default 0x100, but it should be handled another size
    def ReadMemory(self, mem, size):
        buffer = []
        
        buff = BYTE_BUFFER()
        for i in range(0, size, len(buff.Bytes)):
            self.DbiDumpMemory(self.m_cid.ProcId, mem, pointer(buff), len(buff.Bytes))
            buffer[i : i + len(buff.Bytes)] = buff.Bytes

        if (size % len(buff.Bytes)):
            align_s = (size / len(buff.Bytes)) * len(buff.Bytes)
            
            print(hex(size), hex(align_s))
            align_b = ReadMemory(mem + align_s)
            buffer[align_s:] = align_b[:size - align_s]
            
        return buffer
    
    def ReadMemory2(self, mem, size):
        bbuff = BYTE_BUFFER()
        self.DbiDumpMemory(self.m_cid.ProcId, mem, pointer(bbuff), len(bbuff.Bytes))
        return bbuff.Bytes

    def WriteMemory(self, mem, buff, size):
        bbuff = BYTE_BUFFER()
        bbuff.Bytes[0 : len(bbuff.Bytes)] = buff[0 : len(buff)]
        self.DbiPatchMemory(self.m_cid.ProcId, mem, pointer(bbuff), size)

#thread non-specific -> modules
    def NextModule(self, base):
        img = MODULE_ENUM(base, 0)
        self.DbiEnumModules(self.m_cid.ProcId, pointer(img))
        if (img.Size):
            return img
        return None
                             
    def GetModule(self, moduleName):
        discovered = []
        moduleName = moduleName.lower()
        #should be do-implemeted better algo than O(n * logN) {logN due driver bin-finding}
        #in drive do-implemet GetPrevModule...
        img = self.NextModule(0)
        while (None != img and img.Begin not in discovered):
            discovered.append(img.Begin)
            if (moduleName in img.ImageName.lower()):
                return img
            img = self.NextModule(img.Begin)
        return None
                             
    def GetModuleByAddr(self, addr):
        discovered = []
        #should be do-implemeted better algo than O(n * logN) {logN due driver bin-finding}
        #in drive do-implemet GetPrevModule...
        img = self.NextModule(addr)
        while (None != img and img.Begin not in discovered):
            discovered.append(img.Begin)
            if (addr >= img.Begin and addr <= img.Begin + img.Size):
                return img
            img = self.NextModule(img.Begin)
        return None

        #load modules
    def GetProcAddress(self, moduleName, apiName):
        base = self.GetModule(moduleName).Begin
        proc = PARAM_API(0, base)
                             
        for i in range(0, len(apiName)):
            proc.ApiName[i] = ord(apiName[i])
                             
        self.DbiGetProcAddress(self.m_cid.ProcId, pointer(proc))
        return proc.ApiAddr

    def ReadPtr(self, mem):        
        buff = self.ReadMemory(mem, 0x100)
        ptr = 0
        for i in range(0, 0x8):
            ptr |= (buff[i] << (8 * i))
        return ptr
        
