/**
 * @file InAppFuzzDbiModule.h
 * @author created by: Peter Hlavaty
 * @author created on: 2013/08/04
 * @author \n
 * @author Copyright (c) 2013 ESET, spol. s r. o.
 * @note current owner: Peter Hlavaty (peter.hlavaty@eset.sk)
 * @note IMPORTANT: Before doing any significant change to this file check your plan with the current owner to avoid unexpected behaviour.
 */

#ifndef __INAPPFUZZDBIMODULE_H__
#define __INAPPFUZZDBIMODULE_H__

extern "C" __declspec(dllexport) void ExtWaitForDbiEvent();
extern "C" __declspec(dllexport) void ExtInfo();
extern "C" __declspec(dllexport) void ExtMain();

#endif //__INAPPFUZZDBIMODULE_H__
