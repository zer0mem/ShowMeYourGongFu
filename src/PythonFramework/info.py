#! /usr/bin/env python

from BeaEnginePython import *
from DbiFuzzTracer import *
from Disasm import *

def main(pid):
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
    print("LoadLibraryA addr : ", hex(ll), " [ ", hex(kernel32), " ]")

    buff = tracer.ReadMemory(kernel32, 0x100)
    for i in range(0, 0x4):
        print(hex(buff[i+0x20]))
        buff[i] += 1
    
    #tracer.WriteMemory(kernel32, buff, 0x100)
    print("PATCHED")    
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
                        
for i in range(0, 4):
    main(0xe88)
