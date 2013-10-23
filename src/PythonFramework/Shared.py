#! /usr/bin/env python

from ctypes import *
from _ctypes import *

#common interface

class CID_ENUM(Structure):
    _fields_ = [
        ('ProcId', c_ulonglong), 
        ('ThreadId', c_ulonglong) ]

class IRET(Structure):
    _fields_ = [
        ('Return', c_ulonglong), 
        ('CodeSegment', c_ulonglong),  
        ('Flags', c_ulonglong),
        ('StackPointer', c_ulonglong),
        ('StackSegment', c_ulonglong)]
    
class PFIRET(Structure):
    _fields_ = [
        ('ErrorCode', c_ulonglong), 
        ('IRet', IRET) ]
    
class TRACE_INFO(Structure):
    _fields_ = [
        ('StateInfo', PFIRET), 
        ('Bft', c_ulonglong), 
        ('PrevEip', c_ulonglong), 
        ('Reason', c_ulonglong) ]
    
class MEMORY_ACCESS(Structure):
    _fields_ = [
        ('Memory', c_ulonglong),
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong), 
        ('Flags', c_ulonglong), 
        ('OriginalValue', c_ulonglong) ]

class DBI_OUT_CONTEXT(Structure):
    _fields_ = [
        ('GeneralPurposeContext', c_ulonglong * (16 + 1)), 
        ('TraceInfo', TRACE_INFO),
        ('MemoryInfo', MEMORY_ACCESS) ]
         
class MODULE_ENUM(Structure):
    _fields_ = [
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong),
        ('Is64', c_ulonglong),
        ('ImageName', c_wchar * 0x100) ]
    
class MEMORY_ENUM(Structure):
    _fields_ = [
        ('Begin', c_ulonglong), 
        ('Size', c_ulonglong),
        ('Flags', c_ulonglong) ]

class BYTE_BUFFER(Structure):
    _fields_ = [
        ('Bytes', c_ubyte * 0x100) ]
    
class PARAM_API(Structure):
    _fields_ = [
        ('ApiAddr', c_ulonglong), 
        ('ModuleBase', c_ulonglong),
        ('ApiName', c_ubyte * 0x100) ]
    
class PARAM_HOOK(Structure):
    _fields_ = [
        ('HookAddr', c_ulonglong) ]
    
class PARAM_MEM2WATCH(Structure):
    _fields_ = [
        ('Memory', c_ulonglong),
        ('Size', c_ulonglong), ]

