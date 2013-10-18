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
        self.Init.argtypes = [c_ulonglong, c_ulonglong, POINTER(DBI_OUT_CONTEXT)]

        self.SmartTrace = self.comm.SmartTrace#pid, tid, dbioutcontext
        self.SmartTrace.argtypes = [c_ulonglong, c_ulonglong, POINTER(DBI_OUT_CONTEXT)]

        self.DbiSetHook = self.comm.DbiSetHook#pid, PARAM_HOOK
        self.DbiSetHook.argtypes = [c_ulonglong, POINTER(PARAM_HOOK)]

        self.DbiWatchMemoryAccess = self.comm.DbiWatchMemoryAccess#pid, PARAM_MEM2WATCH
        self.DbiWatchMemoryAccess.argtypes = [c_ulonglong, POINTER(PARAM_MEM2WATCH)]

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
        self.Init(self.m_cid.ProcId, self.m_cid.ThreadId, pointer(self.__Context__()))
        
    def GetThreadStack(self):
        return

#tracing inside current thread
    def GetIp(self):
        return self.__Context__().TraceInfo.StateInfo.IRet.Return
    
    def Go(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags &= ~0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        #self.__Context__().TraceInfo.BTF = 0;
        self.SmartTrace(self.m_cid.ProcId, self.m_cid.ThreadId, pointer(self.__Context__()))
        return self.__Context__().TraceInfo.StateInfo.IRet.Return
        
    def SingleStep(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags |= 0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        #self.__Context__().TraceInfo.BTF = 0;
        self.SmartTrace(self.m_cid.ProcId, self.m_cid.ThreadId, pointer(self.__Context__()))
        return self.__Context__().TraceInfo.Eip
        
    def BranchStep(self, ip):
        self.__Context__().TraceInfo.StateInfo.IRet.Flags |= 0x100
        self.__Context__().TraceInfo.StateInfo.IRet.Return = ip
        #self.__Context__().TraceInfo.BTF = 1;
        self.SmartTrace(self.m_cid.ProcId, self.m_cid.ThreadId, pointer(self.__Context__()))
        
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

    def ReadMemory(self, mem, size):
        buff = BYTE_BUFFER()
        self.DbiDumpMemory(self.m_cid.ProcId, mem, pointer(buff), size)
        return buff.Bytes

    def WriteMemory(self, mem, buff, size):
        bbuff = BYTE_BUFFER(buff)        
        self.DbiPatchMemory(self.m_cid.ProcId, mem, pointer(bbuff), size)

#thread non-specific -> modules
    def NextModule(self, base):
        img = MODULE_ENUM(base, 0)
        self.DbiEnumModules(self.m_cid.ProcId, pointer(img))
        if (img.Begin == base):
            return None
        return img
                             
    def GetModule(self, moduleName):
        discovered = []
        moduleName = moduleName.lower()

        img = self.NextModule(0)
        while (img.Begin not in discovered):
            discovered.append(img.Begin)
            if (moduleName in img.ImageName.lower()):
                return img
            img = self.NextModule(img.Begin)

        #load modules
    def GetProcAddress(self, moduleName, apiName):
        base = self.GetModule(moduleName).Begin
        proc = PARAM_API(0, base)
                             
        for i in range(0, len(apiName)):
            proc.ApiName[i] = ord(apiName[i])
                             
        self.DbiGetProcAddress(self.m_cid.ProcId, pointer(proc))
        return proc.ApiAddr
        
def main(pid):
    print("main start {")

    tracer = CDbiFuzzTracer(pid)

    tid = 0
    for i in range(0, 0x10):
        tid = tracer.GetNextThread(tid)
        if (not tid):
            print("threads count reached")
            break
        print("tid : ", hex(tid))

    img = tracer.NextModule(0)
    for i in range(0, 0x10):
        print(img.ImageName, " ", hex(img.Begin), " ", hex(img.Size), " ", img.Is64)
        
        img = tracer.NextModule(img.Begin)
        if (img == None):
            print("modules count reached")
            break

    kernel32 = tracer.GetModule("kernel32").Begin
    ll = tracer.GetProcAddress("kernel32", "LoadLibraryA")
    print("proc addr : ", hex(ll), " [ ", hex(kernel32), " ]")

    buff = tracer.ReadMemory(kernel32, 0x100)
    for i in range(0, 0x4):
        print(hex(buff[i]))
        buff[i] += 1

    #tracer.WriteMemory(kernel32, buff, 0x100)
    
    #buff2 = tracer.ReadMemory(kernel32, 0x100)
    #for i in range(0, 0x4):
        #print(hex(buff2[i]))

    mem = tracer.NextMemory(0)
    for i in range(0, 0x6):
        print(hex(mem.Begin), " ", hex(mem.Size), " ", hex(mem.Flags))
        
        mem = tracer.NextMemory(mem.Begin)
        if (mem == None):
            print("memory chunks count reached")
            break
        
    print("shit")
    mem = tracer.NextMemory(kernel32)
    for i in range(0, 0x6):
        print(hex(mem.Begin), " ", hex(mem.Size), " ", hex(mem.Flags))
        
        mem = tracer.NextMemory(mem.Begin)
        if (mem == None):
            print("memory chunks count reached")
            break

    print(hex(tracer.GetIp()))
    
    
    for i in range(0, 100):
        tracer.BranchStep(tracer.GetIp())
        print(hex(tracer.GetIp()))

    tracer.SetAddressBreakpoint(tracer.GetIp())
    tracer.Go(tracer.GetIp())
    
    for i in range(0, 100):
        tracer.BranchStep(tracer.GetIp())
        print(hex(tracer.GetIp()))
        
    tracer.Go(tracer.GetIp())
    
    print("} main finish")
                        
main(0xfec)
