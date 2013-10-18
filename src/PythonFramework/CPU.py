#! /usr/bin/env python

from Common import *
from Shared import *

class CCpu:
    def __init__(self, context):
        self.m_ctx = context

    def __Context__(self):
        return self.m_ctx
    
    def GetRax(self):
        return (self.m_ctx.self.m_ctx[0])
    def GetEax(self):
        return (self.m_ctx.self.m_ctx[0] & 0xFFFFFFFF)
    def GetAx(self):
        return (self.m_ctx.self.m_ctx[0] & 0xFFFF)
    def GetAl(self):
        return (self.m_ctx.self.m_ctx[0] & 0xFF)
    def GetAh(self):
        return (GetAx() >> 8)
    
    def GetRbx(self):
        return
    def GetEbx(self):
        return
    def GetBx(self):
        return
    def GetBl(self):
        return
    def GetBh(self):
        return
    
    def GetRcx(self):
        return
    def GetEcx(self):
        return
    def GetCx(self):
        return
    def GetCl(self):
        return
    def GetCh(self):
        return
    
    def GetRdx(self):
        return
    def GetEdx(self):
        return
    def GetDx(self):
        return
    def GetDl(self):
        return
    def GetDh(self):
        return

    def GetRbp(self):
        return
    def GetEbp(self):
        return
    def GetBp(self):
        return
    def GetBpl(self):
        return
    
    def GetRsp(self):
        return
    def GetEsp(self):
        return
    def GetSp(self):
        return
    def GetSpl(self):
        return
    
    def GetRsi(self):
        return
    def GetEsi(self):
        return
    def GetSi(self):
        return
    def GetSil(self):
        return
    
    def GetRdi(self):
        return
    def GetEdi(self):
        return
    def GetDi(self):
        return
    def GetDil(self):
        return
    
    def GetR8(self):
        return
    def GetR8d(self):
        return
    def GetRb(self):
        return
    
    def GetR9(self):
        return
    def GetR9d(self):
        return
    def GetR9b(self):
        return
    
    def GetR10(self):
        return
    def GetR10d(self):
        return
    def GetR10b(self):
        return
    
    def GetR11(self):
        return
    def GetR11d(self):
        return
    def GetR11b(self):
        return
    
    def GetR12(self):
        return
    def GetR12d(self):
        return
    def GetR12b(self):
        return
    
    def GetR13(self):
        return
    def GetR13d(self):
        return
    def GetR13b(self):
        return
    
    def GetR14(self):
        return
    def GetR14d(self):
        return
    def GetR14b(self):
        return
    
    def GetR15(self):
        return
    def GetR15d(self):
        return
    def GetR15b(self):
        return

    def GetEfl(self):
        return
    def GetFl(self):
        return

    def GetCS(self):
        return
    def GetDS(self):
        return
    def GetSS(self):
        return
    def GetGS(self):
        return
    def GetFS(self):
        return
    def GetES(self):
        return
