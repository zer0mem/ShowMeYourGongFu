#! /usr/bin/env python

from DbiFuzzTracer import *
from Disasm import *

from pefile import *

ID = 0x7c8

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
    
    dis = CDisasm(tracer) 
    target = tracer.GetModule("codecoverme.exe")

    mem = tracer.ReadMemory(target.Begin, 0x1000)
    
    for i in range(0, 0x10):
        print(hex(mem[i]))


    #pe = PE("c:\\codecoverme.exe")
    
    #return

    ep = target.Begin + 0x2000 + 0xd00
    mem = tracer.ReadMemory(ep, 0x1000)
    for i in range(0xdf0, 0xe00):
        print(hex(mem[i]))

    ep += 0xdf0
    #tracer.SetAddressBreakpoint(target.Begin + 0x2df0)    
    #tracer.Go(tracer.GetIp())

    #info
    inst = dis.Disasm(tracer.GetIp())
    print("BP AT EP : ", hex(inst.VirtualAddr), " : ", inst.CompleteInstr)


    mem = tracer.ReadMemory(tracer.GetIp()-0x2000, 0x4000)
    tracer.SetMemoryAccessBreakpoint(tracer.GetIp(), 0x100)
        #target.Begin + 0x2000 + 0xd00, 0x1000)#parse EP for obtaining PE info...
    print("breakpoint set")
    tracer.Go(tracer.GetIp())
    print("bp after MEMEXEC")
    
    tracer.SwapThreadContext(tid)
    #tracer from freezed thread to executing main image
    while (target.Begin > tracer.GetIp() or target.Begin + target.Size < tracer.GetIp()):        
        #info
        inst = dis.Disasm(tracer.GetIp())
        print("tracing trough : ", hex(inst.VirtualAddr), " : ", inst.CompleteInstr)
        #trace trough
        tracer.SingleStep(tracer.GetIp())
        #info
        inst = dis.Disasm(tracer.GetIp())
        print("tracing trough : ", hex(inst.VirtualAddr), " : ", inst.CompleteInstr)
        
        tracer.SetMemoryExecBreakpoint(target.Begin + 0x2000 + 0xd00, 0x1000)#parse EP for obtaining PE info...
        print("breakpoint set")
        tracer.Go(tracer.GetIp())
        print("bp after MEMEXEC")

    inst = dis.Disasm(tracer.GetIp())
    print("tracing trough : ", hex(inst.VirtualAddr), " : ", inst.CompleteInstr)

    for i in range(0, 0xfffffff):
        inst = dis.Disasm(tracer.GetPrevIp())
        print(hex(inst.VirtualAddr), " : ", inst.CompleteInstr)
            
        if (target.Begin > tracer.GetIp() or
            target.Begin + target.Size < tracer.GetIp()):
            
            tracer.SetAddressBreakpoint(tracer.ReadPtr(tracer.GetRsp()))
            tracer.Go(tracer.GetIp())
            print("HOOKED")
        else:        
            tracer.BranchStep(tracer.GetIp())
            print("BTF")

    
    print("finish")
                        
main(ID)
