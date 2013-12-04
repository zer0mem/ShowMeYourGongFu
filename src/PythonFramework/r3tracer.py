#! /usr/bin/env python

from BeaEnginePython import *
from DbiFuzzTracer import *
from Disasm import *

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
    
    buff2 = tracer.ReadMemory(kernel32, 0x100)
    for i in range(0, 0x4):
        print(hex(buff2[i]))

    mem = tracer.NextMemory(0)
    for i in range(0, 0x10):
        print(hex(mem.Begin), " ", hex(mem.Size), " ", hex(mem.Flags))
        
        mem = tracer.NextMemory(mem.Begin)
        if (mem == None):
            print("memory chunks count reached")
            break
        
    print("shit")
    mem = tracer.NextMemory(kernel32)
    for i in range(0, 0x10):
        print(hex(mem.Begin), " ", hex(mem.Size), " ", hex(mem.Flags))
        
        mem = tracer.NextMemory(mem.Begin)
        if (mem == None):
            print("memory chunks count reached")
            break

    tracer.SingleStep(tracer.GetIp())
    
    target = tracer.GetModule("codecoverme")
    dis = CDisasm(tracer)
    for i in range(0, 3):
        print("next access")
        
        tracer.SetMemoryBreakpoint(0x2340000, 0x400)
        tracer.Go(tracer.GetIp())
        
        inst = dis.Disasm(tracer.GetIp())       
        print(hex(inst.VirtualAddr), " : ", 
              inst.CompleteInstr)
        
        tracer.SingleStep(tracer.GetIp())

        
    for i in range(0, 0xffffffff):
        
        if (target.Begin > tracer.GetIp() or 
            target.Begin + target.Size < tracer.GetIp()):            
            
            ret = tracer.ReadPtr(tracer.GetRsp())
            tracer.SetAddressBreakpoint(ret)
            tracer.Go(tracer.GetIp())
            print("out-of-module-hook")
        
        inst = dis.Disasm(tracer.GetPrevIp())       
        print(hex(inst.VirtualAddr), " : ", 
              inst.CompleteInstr)
        
        tracer.BranchStep(tracer.GetIp())
    
    return
        
    mmodule = tracer.GetModule("codecoverme")
    print(hex(mmodule.Begin), hex(mmodule.Size))
    
    for i in range(0, 0xFFFFFF):
        if (mmodule.Begin > tracer.GetIp() or mmodule.Begin + mmodule.Size < tracer.GetIp()):            
            tracer.SetAddressBreakpoint(tracer.ReadPtr(tracer.GetRsp()))
            tracer.Go(tracer.GetIp())
            print("HOOKED")
        tracer.BranchStep(tracer.GetIp())
        print(hex(tracer.GetIp()))

    print("} main pre-finish")
    return
        
    for i in range(0, 100):
        tracer.BranchStep(tracer.GetIp())
        print(hex(tracer.GetIp()))
        tracer.SetAddressBreakpoint(tracer.GetIp())
        tracer.Go(tracer.GetIp())
        
    tracer.Go(tracer.GetIp())
    
    print("} main finish")
                        
main(0xd98)
