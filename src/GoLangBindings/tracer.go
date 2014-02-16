package tracer
//package main

import "C"
//USING OF CAPSTONE, usefull dis engine :)
import "github.com/bnagy/gapstone"
//necessary to have InAppFuzzDbiModule.dll in PATH
//but should be rewriten to not use .dll but compile to itself as .lib
import "dbifuzz"
import "log"

type CTracer struct {
    m_dbifuzz dbifuzz.DbiFuzz
    m_engine gapstone.Engine
}

func (tracer CTracer) Close() {
    tracer.m_engine.Close()
    tracer.m_dbifuzz.Close()
}

func Create(pid uint64) (CTracer) {
    tracer := CTracer{}
    tracer.m_dbifuzz = dbifuzz.Create(pid)
    tracer.m_engine, _ = gapstone.New(
        gapstone.CS_ARCH_X86,
        gapstone.CS_MODE_64,
    )
    return tracer
}

func (tracer CTracer) GetDbiFuzz() dbifuzz.DbiFuzz {
    return tracer.m_dbifuzz
}

var (
    MAX_INSTR_SIZE = 0x10
    INSTR_TO_DIS_DEF = 10
)

func (tracer CTracer) Disasm(ip uint64) ([]gapstone.Instruction, error) {
    x64Code := tracer.m_dbifuzz.ReadMemory(ip, uint64(INSTR_TO_DIS_DEF * MAX_INSTR_SIZE))
    return tracer.m_engine.Disasm(
        x64Code, // code buffer
        ip, // starting address
        0, // insns to disassemble, 0 for all
        )
}

func main() {
//error less checking, just quick PoC, when it comes time, rewrite it correctly, all bindings!!
    tracer := Create(0x666)
    defer tracer.Close()

    ip := tracer.GetDbiFuzz().GetIp()
    dis_code, err := tracer.Disasm(ip)
    if (nil == err) {
        for _, ins := range dis_code {
            log.Printf("0x%x:\t%s\t\t%s\n", ins.Address, ins.Mnemonic, ins.OpStr)
        }
    }
}

