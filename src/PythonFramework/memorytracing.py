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
            break
            mem = tracer.NextMemory(mem.Begin)
        else:
            break
    
    tracer.SwapThreadContext(tid)
    
    dis = CDisasm(tracer)
    print("start IP : ", hex(tracer.GetIp()))
    for i in range(0, 0x3):        
        tracer.Go(tracer.GetIp())

        inst = dis.Disasm(tracer.GetIp())
        print(hex(inst.VirtualAddr), " : ", inst.CompleteInstr)

        if (MemoryAccess == tracer.GetReason()):
            print("not in module memory accesed : ",
                  hex(tracer.GetMemoryAccesInfo().Memory))

            tracer.SingleStep(tracer.GetIp())
            tracer.SetMemoryBreakpoint(mem.Begin, mem.Size)  
    
    print("finish")
                        
main(0xab4)
