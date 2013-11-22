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
    
    tracer.SwapThreadContext(tid)
    
    dis = CDisasm(tracer) 
    target = tracer.GetModule("codecoverme.exe")       
    for i in range(0, 0x20):
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
                        
main(0xce0)
