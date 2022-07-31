# ida_vmware_windows_gdb.py
Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub (including PDB symbols)

python3 + idapython 7.4

![kerneldebugida](img/kerneldebugida.PNG)

# Usage

**WARNING**: BEFORE OPEN IDA your must set env var: _NT_SYMBOL_PATH to windows symbols, ex: 
```
SRV*C:\winsymbols*
```` 

1. Open IDA PRO, start a debug session (go to Debugger -> Attach -> Remote GDB debugger)
2. File -> Script File -> ida_bochs_windows.py

Done!

More info:
- Advanced Windows Kernel Debugging with VMWare and IDA’s GDB debugger: https://hex-rays.com/blog/advanced-windows-kernel-debugging-with-vmware-and-idas-gdb-debugger/
- IDA Help Debugging with VMWare: https://hex-rays.com/products/ida/support/idadoc/1357.shtml

## Demo video

https://youtu.be/q5MrGKqtmAg

## Related 

Helper script for Windows kernel debugging with IDA Pro on native Bochs debugger:
- https://github.com/therealdreg/ida_bochs_windows

Helper scripts for windows debugging with symbols for Bochs and IDA Pro (PDB files). Very handy for user mode <--> kernel mode:
- https://github.com/therealdreg/symseghelper

## Credits

Based on original IDA-VMware-GDB By Oleksiuk Dmytro (aka Cr4sh) https://github.com/Cr4sh/IDA-VMware-GDB
