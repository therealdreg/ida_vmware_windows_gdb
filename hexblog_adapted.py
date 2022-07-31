# Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub
# https://github.com/therealdreg/ida_vmware_windows_gdb
# GNU General Public License v3.0
#
# by David Reguera Garcia aka Dreg
# Twitter @therealdreg
# https://www.fr33project.org
# dreg@fr33project.org
# https://github.com/therealdreg
#
# Based on original vmware_modules.py from Hex Blog article: http://www.hexblog.com/?p=94
# Based on original IDA-VMware-GDB By Oleksiuk Dmytro (aka Cr4sh) https://github.com/Cr4sh/IDA-VMware-GDB
#
# WARNING: Currently only works in old x86 versions (simple port from vmware_modules.py)
#
# 2022/07/31 by Dreg
#   - project renamed to hexblog_adapted.py
#   - ported to python3
#   - ported to idapython 7.4: 
#       - https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
#       - https://www.hex-rays.com/products/ida/support/idapython_docs/index.html
#   - idc.eval_idc('SendGDBMonitor
#   - added ida_kernwin.open_segments_window(0) and ida_kernwin.open_names_window(0)
#   - fixed bug in get_unistr with len
#   - code style fixed using black
#   - added changelog
#   - added some prints
#   - set all segments with +rwx
#   - lincense GNU General Public License v3.0
#   - comestic changes (new header...)
#   - added PDB_MODULES list
#   - ported to new pdb: netnode using $ pdb + altset 0 + supset 0
#   - import new ida modules for inteli
#   - tested:
#       - hosts: windows 10.0.19044 Build 19044
#       - ida pro 7.7, idapython 7.4
#       - targets: windows xp sp3 x86
#       - vmware workstation 16
# -
# for inteli: set ENV VAR PYTHONPATH=C:\Program Files\IDA Pro 7.7\python\3

import idc
import ida_idaapi
import ida_netnode
import ida_loader
import ida_kernwin


cred = '''
Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub
https://github.com/therealdreg/ida_vmware_windows_gdb
GNU General Public License v3.0
-
By Oleksiuk Dmytro (aka Cr4sh)
Twitter @d_olex
http://blog.cr4.sh
cr4sh0@gmail.com
https://github.com/Cr4sh
-
Mod by David Reguera Garcia aka Dreg
Twitter @therealdreg
https://www.fr33project.org
dreg@fr33project.org
https://github.com/therealdreg

WARNING: BEFORE OPEN IDA your must set env var: _NT_SYMBOL_PATH to windows symbols, ex: SRV*C:\winsymbols*
'''
print(cred)

# path to the local copy of System32 directory
local_sys32 = r"C:\dreg\system32"

# just comment the next line to load all PDB symbols
auto_pdb = [
    x.lower()
    for x in ["hal.dll", "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"]
]

# BEFORE OPEN IDA your must set env var: _NT_SYMBOL_PATH to windows symbols, ex: SRV*C:\winsymbols*

def get_unistr(addr):

    length = idc.read_dbg_word(addr)
    start = idc.read_dbg_dword(addr + 4)

    print("length: ", length)

    if length > 1000:
        raise Exception("get_unistr(): String too long")

    res = ""
    while length > 0:
        c = idc.read_dbg_word(start)
        if c == b"\x00\x00":
            break
        res += chr(c).encode('utf-16', 'surrogatepass').decode('utf-16')
        start += 2
        length -= 2

    return res

fs_str = idc.eval_idc('SendGDBMonitor("r fs")')
print(fs_str)
kpcr = int(fs_str[13:23], 16)
print("kpcr: 0x%08X" % kpcr)

kdversionblock = idc.read_dbg_dword(kpcr + 0x34)
print("kdversionblock: 0x%08X" % kdversionblock)

PsLoadedModuleList = idc.read_dbg_dword(kdversionblock + 0x18)
print("PsLoadedModuleList: 0x%08X" % PsLoadedModuleList)

cur_mod = idc.read_dbg_dword(PsLoadedModuleList)
print("first cur_mod: 0x%08X" % cur_mod)
while cur_mod != PsLoadedModuleList and cur_mod != ida_idaapi.BADADDR:
    BaseAddress = idc.read_dbg_dword(cur_mod + 0x18)
    print("BaseAddress: 0x%08X" % BaseAddress)
    SizeOfImage = idc.read_dbg_dword(cur_mod + 0x20)
    print("SizeOfImage: 0x%08X" % SizeOfImage)
    FullDllName = get_unistr(cur_mod + 0x24)
    print("FullDllName: ", str(FullDllName))
    BaseDllName = get_unistr(cur_mod + 0x2C)
    print("BaseDllName: ", str(BaseDllName))
    # create a segment for the module
    idc.AddSeg(BaseAddress, BaseAddress + SizeOfImage, 0, 1, idc.saRelByte, idc.scPriv)
    idc.set_segm_attr(BaseAddress, idc.SEGATTR_PERM, 7)
    # set its name
    idc.set_segm_name(BaseAddress, BaseDllName)
    # get next entry
    cur_mod = idc.read_dbg_dword(cur_mod)
    print("++++++++++")
    filename = ""
    if FullDllName.lower().startswith("\\windows\\system32"):
        FullDllName = "\\SystemRoot\\system32" + FullDllName[17:]
    if FullDllName.find("\\") == -1:
        FullDllName = "\\SystemRoot\\system32\\DRIVERS\\" + FullDllName
    if FullDllName.lower().startswith("\\systemroot\\system32"):
        filename = local_sys32 + "\\" + FullDllName[20:]
    print("filename: ", str(filename))
    if len(auto_pdb) == 0 or BaseDllName.lower() in auto_pdb:
        print("autoloading pdb...")
        node = ida_netnode.netnode()
        node.create("$ pdb")
        node.altset(0, BaseAddress)
        node.supset(0, filename)
        ida_loader.load_and_run_plugin("pdb", 3)
    print("------------")

ida_kernwin.open_segments_window(0)
ida_kernwin.open_names_window(0)