#! /usr/bin/env python

from DbiFuzzTracer import *
from Disasm import *

def main(pid):
    print("main start {")

    tracer = CDbiFuzzTracer(pid)

    tid = 0
    for i in range(0, 0x10):
        tid = tracer.GetNextThread(tid)
        if (not tid):
            print("no thread for trace")
            return
        break
    
    mem = tracer.NextMemory(0)
    for i in range(0, 0x10):
        if (mem.Begin > 0xFFFFFFFF):
            break
        
        if (None == tracer.GetModuleByAddr(mem.Begin)):           
            print("non module mem : ", hex(mem.Begin), " ",
                  hex(mem.Size), " ", hex(mem.Flags))
            
            tracer.SetMemoryBreakpoint(mem.Begin, mem.Size)        
            mem = tracer.NextMemory(mem.Begin)
        else:
            break
    return
    
    dis = CDisasm(tracer) 
    target = tracer.GetModule("codecoverme.exe").Begin       
    for i in range(0, 50):
        
        if (target.Begin > tracer.GetIp() or
            target.Begin + target.Size < tracer.GetIp()):
            
            tracer.SetAddressBreakpoint(tracer.ReadPtr(tracer.GetRsp()))
            tracer.Go(tracer.GetIp())
            print("HOOKED")

        inst = dis.Disasm(tracer.GetIp())
        print(hex(inst.VirtualAddr), " : ", inst.CompleteInstr)
        
        tracer.BranchStep(tracer.GetIp())

        if (MemoryAccess == tracer.GetReason()):
            print("not in module memory accesed : ",
                  tracer.GetMemoryAccesInfo().Memory)
            break
    
    return
                        
main(0xef8)
