# https://gist.github.com/gavz/01afa5ac5177febc048316cfdaee55ea

from idaapi import *

# with code taken from http://hexblog.com/idapro/vmware_modules.py

class LoadedModulesList(Choose2):

    def __init__(self, title, flags=0, width=None, height=None, embedded=False, modal=False):
        self.ptr = get_name_ea_simple("PsLoadedModuleList")
        if self.ptr == BADADDR:
          raise ValueError('Missing symbol: PsLoadedModuleList')
        self.n = 0
        self.lines = []
        self.modules = []
        self.selcount = 0
        self.modal = modal
        self.is64 = get_inf_structure().is_64bit()
        self.fmt = "%016X" if is64 else "%08X"
        self.bits = 3 if is64 else 2
        self.get_value = Qword if is64 else Dword

        Choose2.__init__(
            self,
            title,
            [ ["BaseAddress", 16], ["BaseDllName", 16], ["FullDllName", 24], ["SizeOfImage", 16], ["EntryPoint", 16] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)

        self.walk_modulelist()

    def OnClose(self):
        self.modules = []
        self.lines = []

    def OnSelectLine(self, n):
        jumpto(self.modules[n][0])

    def OnGetLine(self, n):
        return self.lines[n]

    def OnGetSize(self):
        return len(self.lines)

    def add_module(self, BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):
        self.modules.append((BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint))
    """
    def OnRefresh(self, n):
        print "refresh %d" % n
    """

    def update(self):
        self.n = 0
        self.lines = [self.make_item() for x in xrange(len(self.modules))]
        self.Refresh()
        return self.Show(self.modal) >= 0

    def make_item(self):
        r = [self.fmt % self.modules[self.n][0], # BaseAddress
             "%s" % self.modules[self.n][1], # BaseDllName
             "%s" % self.modules[self.n][2], # FullDllName
             self.fmt % self.modules[self.n][3],# SizeOfImage
             self.fmt % self.modules[self.n][4]]# EntryPoint             
        self.n += 1
        return r

    #read a string from UNICODE_STRING structure
    def get_unistr(self, addr):
      len = Word(addr)      #USHORT Length;
      start = get_value(addr + (1<<self.bits)) #PWSTR  Buffer;
      if len>1000:
        raise Exception(self.fmt + ": String too long (%d)"%(addr, len))
      res = u''
      while len>0:
        c = Word(start)
        if c==0: break
        res += unichr(c)
        start += 2
        len -= 1
      return res

    def walk_modulelist(self):
      # get the first module
      cur_mod = self.get_value(self.ptr)
      # loop until we come back to the beginning

      # TODO: proper parsing of the PsLoadedModuleList
      # structure should involve loading the 
      # _LDR_DATA_TABLE_ENTRY structure and getting
      # offsets from it by field names
      while cur_mod != self.ptr and cur_mod != BADADDR:
        BaseAddress  = self.get_value(cur_mod + (6<<self.bits))
        EntryPoint   = self.get_value(cur_mod + (7<<self.bits))
        SizeOfImage  = Dword(cur_mod + (8<<self.bits))
        FullDllName  = get_unistr(cur_mod + (9<<self.bits)).encode('utf-8')
        BaseDllName  = get_unistr(cur_mod + (0xB<<self.bits)).encode('utf-8')
        self.add_module(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint)
        #get next module (FLink)
        next_mod = self.get_value(cur_mod)
        #check that BLink points to the previous structure
        if self.get_value(next_mod + (1<<self.bits)) != cur_mod:
          print self.fmt + ": List error!" % cur_mod
          break
        cur_mod = next_mod
      self.update()

LoadedModulesList("Loaded Modules", modal=False)
