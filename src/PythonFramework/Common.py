#! /usr/bin/env python

from ctypes import *
from _ctypes import *

def load_library(libn):
    libhndl=LoadLibrary(libn)
    lib=CDLL(libn, handle=libhndl)
    ret=[]
    ret.append(libhndl)
    ret.append(lib)
    return ret

class CCDLL:
    def __init__(self, path):
        self.m_dll = load_library(path)

    def GetLib(self):
        return self.m_dll[1]
        
def x86tox64(val):
    return (val[0] | (val[1] << (8 * 4)))

def x64tox86(val):
    return [val & 0xFFFFFFFF, val >> (8 * 4)]
