import os
import sys
import copy

from ctypes import byref
from ctypes import c_int
from ctypes import c_char
from ctypes import c_long
from ctypes import c_uint
from ctypes import sizeof
from ctypes import c_ubyte
from ctypes import c_ulong
from ctypes import pointer
from ctypes import c_char_p
from ctypes import c_void_p
from ctypes import create_string_buffer
from optparse import OptionParser

import win32api
import win32con

import yara
import win32file
import pywintypes
import win32security

from utils import duplicate
from constants.tmp import open_process
from bva.yara_config import YARA_RULES
from constants.defines import CLOSE_HANDLE
from constants.defines import OPEN_PROCESS
from constants.defines import GETSYSTEMINFO
from constants.defines import GET_LAST_ERROR
from constants.defines import MODULE_32_NEXT
from constants.defines import THREAD_32_NEXT
from constants.defines import VIRTUALQUERYEX
from constants.defines import MODULE_32_FIRST
from constants.defines import PROCESS_32_NEXT
from constants.defines import THREAD_32_FIRST
from constants.defines import MINI_DUMP_WRITER
from constants.defines import PROCESS_32_FIRST
from constants.defines import READ_PROCESS_MEMORY
from constants.defines import CREATETOOLHELP_32_SNAPSHOT
from constants.structures import SYSTEM_INFO
from constants.structures import TH32CS_CLASS
from constants.structures import PROCESS_CLASS
from constants.structures import MINIDUMP_TYPES_CLASS
from constants.structures import MEMORY_BASIC_INFORMATION
from constants.structures import ModuleEntry32
from constants.structures import ThreadEntry32
from constants.structures import ProcessEntry32


system_info = SYSTEM_INFO()
GETSYSTEMINFO(byref(system_info))


def ListProcesses():
    result = []
    hProcessSnap = c_void_p(0)
    hProcessSnap = CREATETOOLHELP_32_SNAPSHOT(TH32CS_CLASS.SNAPPROCESS, 0)

    pe32 = ProcessEntry32()
    pe32.dwSize = sizeof(ProcessEntry32)
    ret = PROCESS_32_FIRST(hProcessSnap, pointer(pe32))

    while ret:
        result.append(duplicate(pe32))
        ret = PROCESS_32_NEXT(hProcessSnap, pointer(pe32))

    CLOSE_HANDLE(hProcessSnap)
    return result


def ListProcessModules(ProcessID):
    result = []
    hModuleSnap = c_void_p(0)
    me32 = ModuleEntry32()
    me32.dwSize = sizeof(ModuleEntry32)
    hModuleSnap = CREATETOOLHELP_32_SNAPSHOT(TH32CS_CLASS.SNAPMODULE, ProcessID)

    ret = MODULE_32_FIRST(hModuleSnap, pointer(me32))
    if ret == 0:
        errmsg = "ListProcessModules() Error on Module32First[%d]" % GET_LAST_ERROR()
        print(errmsg)
        CLOSE_HANDLE(hModuleSnap)

    while ret:
        result.append(duplicate(me32))

        ret = MODULE_32_NEXT(hModuleSnap, pointer(me32))

    CLOSE_HANDLE(hModuleSnap)
    return result


def ListProcessThreads(ProcessID):
    result = []
    hThreadSnap = c_void_p(0)
    te32 = ThreadEntry32()
    te32.dwSize = sizeof(ThreadEntry32)

    hThreadSnap = CREATETOOLHELP_32_SNAPSHOT(TH32CS_CLASS.SNAPTHREAD, 0)

    ret = THREAD_32_FIRST(hThreadSnap, pointer(te32))

    if ret == 0:
        errmsg = "ListProcessThreads() Error on Thread32First[%d]" % GET_LAST_ERROR()
        CLOSE_HANDLE(hThreadSnap)

    while ret:
        if te32.th32OwnerProcessID == ProcessID:
            result.append(duplicate(te32))

        ret = THREAD_32_NEXT(hThreadSnap, pointer(te32))

    CLOSE_HANDLE(hThreadSnap)
    return result


def AdjustPrivilege(priv):
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
    id = win32security.LookupPrivilegeValue(None, priv)
    newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)


def DumpProcess(ProcessID, rules):
    AdjustPrivilege("seDebugPrivilege")

    # PROCESS_ALL_ACCESS
    try:
        pHandle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, ProcessID)
    except pywintypes.error as err:
        print(f"...{err}")
        return
    fHandle = win32file.CreateFile(
        "%d.tmp" % ProcessID,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
        None,
        win32file.CREATE_ALWAYS,
        win32file.FILE_ATTRIBUTE_NORMAL,
        None,
    )

    ret = MINI_DUMP_WRITER(
        pHandle.handle, ProcessID, fHandle.handle, MINIDUMP_TYPES_CLASS.MiniDumpWithFullMemory, None, None, None
    )

    win32api.CloseHandle(pHandle)
    win32api.CloseHandle(fHandle)
    matches = None
    try:
        matches = rules.match("%d.tmp" % ProcessID)
    except:
        pass
    if matches:
        for m in matches:
            print(f"[+] {ProcessID} Matched:", m)
    os.remove("%d.tmp" % ProcessID)


def ReadProcessMemory(ProcessID, rules):

    try:
        base = 0
        memory_basic_information = MEMORY_BASIC_INFORMATION()
        AdjustPrivilege("seDebugPrivilege")
        pHandle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ | win32con.PROCESS_VM_OPERATION, 0, ProcessID
        )

        while (
            VIRTUALQUERYEX(pHandle.handle, base, byref(memory_basic_information), sizeof(memory_basic_information)) > 0
        ):
            count = c_ulong(0)
            # MEM_COMMIT && MEM_PRIVATE
            # if memory_basic_information.State == 0x1000 and memory_basic_information.Type == 0x20000:
            try:
                buff = create_string_buffer(memory_basic_information.RegionSize)
                if READ_PROCESS_MEMORY(pHandle.handle, base, buff, memory_basic_information.RegionSize, byref(count)):
                    # print buff.raw
                    matches = rules.match(data=buff.raw)
                    for m in matches:
                        print(f"{ProcessID}", m, "0x%x" % memory_basic_information.BaseAddress)
            except:
                pass
            base += memory_basic_information.RegionSize

        win32api.CloseHandle(pHandle)
        # base += system_info.dwPageSize
    except pywintypes.error as err:
        print(f"{ProcessID}{err}")


def main(pid: str, mimidump=False):
    rules = YARA_RULES
    try:
        rules = yara.compile(source=rules)
    except yara.Error as err:
        raise err

    if not pid:
        procs = ListProcesses()
        for p in procs:
            print(f"[+] {p.th32ProcessID}\t{p.szExeFile}")
            if p.th32ProcessID != 0:
                if mimidump:
                    DumpProcess(p.th32ProcessID, rules)
                else:
                    ReadProcessMemory(p.th32ProcessID, rules)
    else:
        if mimidump:
            DumpProcess(int(pid), rules)
        else:
            ReadProcessMemory(int(pid), rules)