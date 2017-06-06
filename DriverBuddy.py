from idaapi import *
from idautils import *
from idc import *
from DriverBuddy import data
from DriverBuddy import ioctl
'''#######################################################################################

DriverBuddy.py: Entry point for IDA python plugin used in Windows driver
                vulnerability research.

Written by Braden Hollembaek and Adam Pond of NCC Group
#######################################################################################'''

def copy_to_clip(data):
    QtGui.QApplication.clipboard().setText(data)
    QtGui.QDesktopServices.openUrl("https://social.msdn.microsoft.com/Search/zh-CN?query=" + data)

class DriverBuddyPlugin(plugin_t):
    flags = PLUGIN_UNL
    comment = ('Plugin to aid in Windows driver vulnerability research. ' +
               'Automatically tries to find IOCTL handlers, decode IOCTLS, '+
               'flag dangerous C/C++ functions, find Windows imports for privesc, '+
               'and identify the type of Windows driver.')
    help = ''
    wanted_name = 'Driver Buddy'
    wanted_hotkey = 'Ctrl-Alt-D'

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+I", self.decode))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+S", self.search_highlight))
        self.hotkeys.append(idaapi.add_hotkey("Ctrl+Alt+V", self.scan_printf))
        return PLUGIN_KEEP

    def run(self, args):
        print "[+] Welcome to Driver Buddy"
        autoWait() # Wait for IDA autoanalysis to complete
        driver_entry = data.is_driver()
	if driver_entry == "":
            print "[-] No DriverEntry stub found"
            print "[-] Exiting..."
            return
        print "[+] DriverEntry found"
        if data.populate_data_structures() == False:
            print "[-] Unable to load functions"
            print "[-] Exiting..."
            return
	driver_type = data.get_driver_id(driver_entry)
        if driver_type == "":
            print "[-] Unable to determine driver type assuming wdm"
        else:
            print "[+] Driver type detected: " + driver_type
        if ioctl.find_ioctls() == False:
            print "[-] Unable to automatically find any IOCTLs"
        return

    def decode(self, _=0):
        if idc.GetOpType(idc.ScreenEA(), 1) != 5:   # Immediate
            return
        value = idc.GetOperandValue(idc.ScreenEA(), 1) & 0xffffffff
        ioctl.get_ioctl_code(value)

    def search_highlight(self, _=0):
        name = idaapi.get_highlighted_identifier()
        if name:
            copy_to_clip(name)
            print "%s has been copied to clipboard" % name

    def scan_printf(self, _=0):
        print "\n[+] Finding Format String Vulnerability..."
        found = []
        for addr in Functions():
            name = GetFunctionName(addr)
            if "printf" in name and "v" not in name and SegName(addr) in (".text", ".plt", ".idata"):
                xrefs = CodeRefsTo(addr, False)
                for xref in xrefs:
                    vul = self.check_fmt_function(name, xref)
                    if vul:
                        found.append(vul)
        if found:
            print "[!] Done! %d possible vulnerabilities found." % len(found)
            ch = VulnChoose("Vulnerability", found, None, False)
            ch.Show()
        else:
            print "[-] No format string vulnerabilities found."

    def term(self):
        pass

    @staticmethod
    def check_fmt_function(name, addr):
        """
        Check if the format string argument is not valid
        """
        function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)

        while True:
            addr = idc.PrevHead(addr)
            op = GetMnem(addr).lower()
            dst = GetOpnd(addr, 0)

            if op in ("ret", "retn", "jmp", "b") or addr < function_head:
                return

            c = GetCommentEx(addr, 0)
            if c and c.lower() == "format":
                break
            elif name.endswith(("snprintf_chk",)):
                if op in ("mov", "lea") and dst.endswith(("r8", "r8d", "[esp+10h]")):
                    break
            elif name.endswith(("sprintf_chk",)):
                if op in ("mov", "lea") and ( dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                              dst.endswith("ecx") and bits == 64 ):
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and ( dst.endswith(("rdx", "[esp+8]", "R2")) or
                                              dst.endswith("edx") and bits == 64 ):
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and ( dst.endswith(("rsi", "[esp+4]", "R1")) or
                                              dst.endswith("esi") and bits == 64 ):
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and ( dst.endswith(("rdi", "[esp]", "R0")) or
                                              dst.endswith("edi") and bits == 64 ):
                    break

        # format arg found, check its type and value
        # get last oprend
        op_index = GetDisasm(addr).count(",")
        op_type = GetOpType(addr, op_index)
        opnd = GetOpnd(addr, op_index)

        if op_type == o_reg:
            # format is in register, try to track back and get the source
            _addr = addr
            while True:
                _addr = idc.PrevHead(_addr)
                _op = GetMnem(_addr).lower()
                if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                    break
                elif _op in ("mov", "lea", "ldr") and GetOpnd(_addr, 0) == opnd:
                    op_type = GetOpType(_addr, 1)
                    opnd = GetOpnd(_addr, 1)
                    addr = _addr
                    break

        if op_type == o_imm or op_type == o_mem:
            # format is a memory address, check if it's in writable segment
            op_addr = GetOperandValue(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return

        print "0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd)
        return ["0x%X" % addr, name, opnd]


def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
