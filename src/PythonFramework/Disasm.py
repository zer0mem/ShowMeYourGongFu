#! /usr/bin/env python

from BeaEnginePython import *

class CDisasm():
    def __init__(self, dumper):
        self.ReadMemory = dumper.ReadMemory2
        self.m_instruction = DISASM()
        self.m_instruction.Options = MasmSyntax + SuffixedNumeral + ShowSegmentRegs
    
    def Disasm(self, ip):
        self.m_instruction.VirtualAddr = ip

        #mem = self.ReadMemory(ip, 0x100)
        #print(mem[0], mem[1])
        #code = create_string_buffer(mem, 0x100)
        
        code = self.ReadMemory(ip, 0x100)
        self.m_instruction.EIP = addressof(code)
        Disasm(addressof(self.m_instruction))

        return self.m_instruction

