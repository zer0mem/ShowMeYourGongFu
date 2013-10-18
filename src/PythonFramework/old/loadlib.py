#! /usr/bin/env python

from ctypes import *
from _ctypes import *
from os import *

class CID_ENUM(Structure):
    _fields_ = [
        ('ProcId', c_ulonglong), 
        ('ThreadId', c_ulonglong) ]
    
class BRANCH_INFO(Structure):
    _fields_ = [
        ('DstEip', c_ulonglong), 
        ('SrcEip', c_ulonglong),  
        ('StackPtr', c_ulonglong),
        ('Flags', c_ulonglong),
        ('Reason', c_ulonglong) ]
    
class MEMORY_ACCESS(Structure):
    _fields_ = [
        ('Memory', c_ulonglong), 
        ('Access', c_ulonglong),
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong), 
        ('Flags', c_ulonglong), 
        ('OriginalValue', c_ulonglong) ]

class DBI_OUT_CONTEXT(Structure):
    _fields_ = [
        ('GeneralPurposeContext', c_ulonglong * (16 + 1)), 
        ('LastBranchInfo', BRANCH_INFO),
        ('MemoryInfo', MEMORY_ACCESS) ]
         
class MODULE_ENUM(Structure):
    _fields_ = [
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong),
        ('Is64', c_ulonglong),
        ('ImageName', c_wchar * 0x100) ]
    
class MEMORY_ENUM(Structure):
    _fields_ = [
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong),
        ('Flags', c_ulonglong) ]

class BYTE_BUFFER(Structure):
    _fields_ = [
        ('Bytes', c_ubyte * 0x100) ]
    
class PARAM_API(Structure):
    _fields_ = [
        ('ApiAddr', c_ulonglong), 
        ('ModuleBase', c_ulonglong),
        ('ApiName', c_ubyte * 0x100) ]
    
class PARAM_HOOK(Structure):
    _fields_ = [
        ('HookAddr', c_ulonglong) ]
    
class PARAM_MEM2WATCH(Structure):
    _fields_ = [
        ('Memory', c_ulonglong),
        ('Size', c_ulonglong), ]

def load_library(libn):
    libhndl=LoadLibrary(libn)
    lib=CDLL(libn,handle=libhndl)
    ret=[]
    ret.append(libhndl)
    ret.append(lib)
    return ret

def main(pid):
    inapp = load_library("C:/InAppFuzzDbiModule.dll")
    GetNextFuzzThread = inapp[1].GetNextFuzzThread    
    SmartTrace = inapp[1].SmartTrace
    Init = inapp[1].Init

    
    threads = []
    cid = CID_ENUM(pid, 0)
    while (cid.ThreadId not in threads):
        threads.append(cid.ThreadId)
        if (not GetNextFuzzThread(pointer(cid))):
            print("break")
            break

        print(hex(cid.ThreadId))

    
    dbi = DBI_OUT_CONTEXT()
    Init(pid, threads[1], pointer(dbi))


    hook = PARAM_HOOK(dbi.LastBranchInfo.DstEip + 0x19)    
    dbi.LastBranchInfo.Flags &= ~0x100
    print(hex(hook.HookAddr))
    #inapp[1].DbiSetHook(pid, threads[1], pointer(hook))
    #SmartTrace(pid, threads[1], pointer(dbi))
    

    if (True):
        print(hex(dbi.GeneralPurposeContext[7]))
        print(hex(dbi.LastBranchInfo.Flags))
        print(hex(dbi.LastBranchInfo.SrcEip))
        print(hex(dbi.LastBranchInfo.DstEip))  
        print(hex(dbi.LastBranchInfo.StackPtr))
        print(hex(dbi.LastBranchInfo.Flags))
        print(hex(dbi.MemoryInfo.Memory))
        print(hex(dbi.MemoryInfo.Access))
        print(hex(dbi.MemoryInfo.OriginalValue))
        print(hex(dbi.LastBranchInfo.Reason))
    #return

    mem2watch = PARAM_MEM2WATCH(dbi.GeneralPurposeContext[7], 0x100)
    inapp[1].DbiWatchMemoryAccess(pid, threads[1], pointer(mem2watch))

    img = MODULE_ENUM(0, 0)
    for i in range(0, 0x20):
        print(inapp[1].DbiEnumModules(pid, threads[1], pointer(img)))        
        print(i, " : ", img.ImageName, " ", hex(img.Begin))
        img_name = img.ImageName
        if (not img.Is64 and "kernel32" in img.ImageName.lower()):
            kernel32 = img
            print("!gotcha!")

            api = PARAM_API(0, kernel32.Begin)
            xstr = "GetModuleHandleW"
            for i in range(0, len("GetModuleHandleW")):
                api.ApiName[i] = ord(xstr[i])

            inapp[1].DbiGetProcAddress(pid, threads[1], pointer(api))
            print(hex(api.ApiAddr))

            break

    c_s = c_wchar_p(img.ImageName)
    print(c_s)
    
    mem = MEMORY_ENUM(0, 0, 0)
    for i in range(0, 0x3):
        inapp[1].DbiEnumMemory(pid, threads[1], pointer(mem))
        print(i, " : ", hex(mem.Begin), " ", hex(mem.Size), " ", hex(mem.Flags))

    #return
    buff = BYTE_BUFFER()
    inapp[1].DbiDumpMemory(pid, threads[1], mem.Begin, pointer(buff), 0x100)
    for i in range(0, 0x10):
        print(hex(buff.Bytes[i]))

    for i in range(0, 0x10):
        buff.Bytes[i] = i
    inapp[1].DbiPatchMemory(pid, threads[1], pointer(buff), mem.Begin, 0x10)

    buff2 = BYTE_BUFFER()
    inapp[1].DbiDumpMemory(pid, threads[1], mem.Begin, pointer(buff2), 0x10)
    for i in range(0, 0x10):
        print(hex(buff2.Bytes[i]))
        
    print(hex(threads[1]))
    for i in range(0, 0xFFFFFF):
        SmartTrace(pid, threads[1], pointer(dbi))
        print(hex(dbi.GeneralPurposeContext[7]))
        print(hex(dbi.LastBranchInfo.Flags))
        print(hex(dbi.LastBranchInfo.SrcEip))
        print(hex(dbi.LastBranchInfo.DstEip))  
        print(hex(dbi.LastBranchInfo.StackPtr))
        print(hex(dbi.LastBranchInfo.Flags))
        print(hex(dbi.MemoryInfo.Memory))
        print(hex(dbi.MemoryInfo.Access))
        print(hex(dbi.MemoryInfo.OriginalValue))
        print(hex(dbi.LastBranchInfo.Reason))
        print("----- %i -----"%i)
    
                        
main(0xb84)
