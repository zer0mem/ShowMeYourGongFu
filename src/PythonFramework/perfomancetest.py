#! /usr/bin/env python

from DbiFuzzTracer import *
from Disasm import *

from pefile import *

ID = 0xd04

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
      
    print(hex(tracer.GetIp()))
    print(hex(target.Begin))
    print(hex(target.Begin + target.Size))

    tracer.SwapThreadContext(tid)
    
    tracer.SetAddressBreakpoint(target.Begin + 0x2cd1)    
    tracer.Go(tracer.GetIp())


    
    #for i in range(0, 0xfffffff):            
     #   if (target.Begin < tracer.GetIp() and
      #      target.Begin + target.Size > tracer.GetIp()):
       #     break
        
        #tracer.BranchStep(tracer.GetIp())
        #print(hex(tracer.GetIp()))
    print("i am in")
    
    
    #tracer.SetAddressBreakpoint(target.Begin + 0x2cdc)    
    #tracer.Go(tracer.GetIp())
    #print("i am out")

    count = 0
    for i in range(0, 0xfffff):
        count += 1
            
        if (target.Begin > tracer.GetIp() or
            target.Begin + target.Size < tracer.GetIp()):
            
            tracer.SetAddressBreakpoint(tracer.ReadPtr(tracer.GetRsp()))
            tracer.Go(tracer.GetIp())
            #print("HOOKED")
        else:        
            tracer.BranchStep(tracer.GetIp())
            #print("BTF")

        if (target.Begin + 0x2cdc == tracer.GetIp()):
            print("exit point reached!!")
            break

        #print(hex(tracer.GetIp()))

    
    print("finish ", hex(count))
                        
main(ID)
