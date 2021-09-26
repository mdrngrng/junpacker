import json
import logging
import os
import pefile
import speakeasy
import struct
import sys
import argparse
import random

from lib import utils
from lib import pe_stuff

class LibraryInfo:
    def __init__(self, hmod):
        self.addr = hmod
        self.procs = {}

class GenericEmulator(speakeasy.Speakeasy):
    def __init__(self, config=None, logger=None):
        super(GenericEmulator, self).__init__(config=config, logger=logger)
        self.done = False
        self.unpacked = None
        self.imports = {}
        self.pe_mod = None
        self.jump_hooks = []
        self.jump_count = 0
        self.end_addr = 0

    def log_info(self, msg: str, always: bool = False) -> None:
        if self.logger:
            self.logger.info(msg)
        elif always:
            print(msg)
    
    def log_error(self, msg: str) -> None:
        if self.logger:
            self.logger.error(msg)
        else: print(msg)

    def get_char_width(self, funcname: str) -> int:
        if funcname.endswith("A"):
            return 1
        elif funcname.endswith("W"):
            return 2
        raise speakeasy.errors.ApiEmuError('Failed to get character width from function: %s' % (funcname))

    def set_jump_count(self, jump_count: int) -> None:
        self.jump_count = jump_count
    
    def hook_sectionhop(self, em, addr, size, ctx) -> None:
        if self.mem_read(addr, 1) != b'\xc3': # ret trick (used by aspack)
            if self.jump_count == 0:
                self.log_info(f'[i] Memory hop to OEP: {addr:#x}', True)
                self.oep = addr
                self.done = True
                self.dump_on_hit()
                self.stop()
            else:
                self.set_new_hook_ranges(addr)
                self.jump_count -= 1
    
    def set_new_hook_ranges(self, va) -> None:
        section_num = utils.find_section_by_rva(self.pe_mod, va - self.base)
        if section_num is None:
            if 0 <= va - self.base <= self.pe_mod.sections[0].VirtualAddress:
                # FSG-like loader in header
                start_addr = self.base
                end_addr = self.pe_mod.sections[0].VirtualAddress + start_addr
            else:
                mm = self.get_address_map(va)
                start_addr = mm.get_base()
                end_addr = start_addr + mm.get_size()
        else:
            start_addr = self.pe_mod.sections[section_num].VirtualAddress + self.base
            end_addr = start_addr + self.pe_mod.sections[section_num].Misc_VirtualSize

        for hook in self.jump_hooks:
            hook.disable()
        self.jump_hooks = []

        self.jump_hooks.append(self.add_code_hook(self.hook_sectionhop, begin=0, end=start_addr-1))
        self.jump_hooks.append(self.add_code_hook(self.hook_sectionhop, begin=end_addr, end=self.end_addr))


    def dump_on_hit(self) -> None:
        mm = self.get_address_map(self.base)
        self.unpacked = bytearray(self.mem_read(mm.get_base(), mm.get_size()))

    def record_lib(self, lib_name, hmod) -> None:
        self.imports[lib_name.lower()] = LibraryInfo(hmod)
    
    def record_api(self, hmod, api_name, addr):
        for lib in self.imports:
            if self.imports[lib].addr == hmod:
                self.imports[lib].procs[api_name] = addr    

    def hook_loadlibrary(self, em, api_name, func, params) -> int:
        '''HMODULE LoadLibrary(
          LPTSTR lpLibFileName
        );'''
        # "func(params)" doesn't fit our needs (because of winemu.normalize_dll_name "normalization")
        # hmod = func(params)
        lib_name, = params
        hmod = speakeasy.winenv.defs.windows.windows.NULL
        cw = self.get_char_width(api_name)
        req_lib = self.read_mem_string(lib_name, cw)

        hmod = em.load_library(req_lib)
        params[0] = req_lib

        if hmod != speakeasy.winenv.defs.windows.windows.NULL and hmod != em.get_current_process().base:
            self.record_lib(params[0], hmod)
        return hmod

    def hook_getmodulehandle(self, em, api_name, func, params) -> int:
        '''HMODULE GetModuleHandle(
          LPCSTR lpModuleName
        );'''
        # "func(params)" doesn't fit our needs (because of winemu.normalize_dll_name "normalization")
        # rv = func(params)
        mod_name, = params
        cw = self.get_char_width(api_name)
        rv = 0
        if not mod_name:
            proc = em.get_current_process()
            rv = proc.base
        else:
            lib = self.read_mem_string(mod_name, cw)
            params[0] = lib
            sname, _ = os.path.splitext(lib)
            mods = em.get_user_modules()
            for mod in mods:
                img = os.path.basename(mod.get_emu_path())
                fname, _ = os.path.splitext(img)
                if fname.lower() == sname.lower():
                    rv = mod.get_base()
                    break

        if rv != speakeasy.winenv.defs.windows.windows.NULL and rv != em.get_current_process().base:
            self.record_lib(params[0], rv)
        return rv

    def hook_getprocaddress(self, em, api_name, func, params):
        '''FARPROC GetProcAddress(
        HMODULE hModule,
        LPCSTR  lpProcName
        );'''
        rv = func(params)
        if rv != speakeasy.winenv.defs.windows.windows.NULL:
            self.record_api(params[0], params[1], rv)
        return rv
    
    def find_next_addr(self, procs_addr, lowest_addr, num):
        if len(procs_addr) == 0: return lowest_addr
        for i, addr in enumerate(procs_addr):
            hex_addr = struct.pack("<I", addr)
            if hex_addr == self.unpacked[lowest_addr - 4:lowest_addr]:
                new_procs_addr = procs_addr.copy()
                new_procs_addr.pop(i)
                lowest_addr -= 4
                num += 1
            elif hex_addr == self.unpacked[lowest_addr + 4*num:lowest_addr + 4*(num+1)]:
                new_procs_addr = procs_addr.copy()
                new_procs_addr.pop(i)
                num += 1
            else: return False
            return self.find_next_addr(new_procs_addr, lowest_addr, num)

    def get_iat_addr(self, procs_addr):
        hex_addr = struct.pack("<I", procs_addr.pop(0))
        matches = utils.find_all(self.unpacked, hex_addr)
        for m in matches:
            lowest_addr = m
            num = 1
            lowest_addr = self.find_next_addr(procs_addr, lowest_addr, num)
            if lowest_addr is not False:
                return lowest_addr
        return False
    
    def get_import_info_arr(self):
        imp_info = []
        for libname in self.imports:
            iat_rva = self.get_iat_addr(list(self.imports[libname].procs.values()))
            if iat_rva:
                ii = pe_stuff.ImportInfo(iat_rva, libname)
                proc_dict = self.imports[libname].procs
                for i in range(len(proc_dict)):
                    addr_val = struct.unpack_from("<I", self.unpacked, iat_rva + i*4)[0]
                    procname = utils.get_item_by_value(proc_dict, addr_val)
                    ii.add_proc(procname)
                imp_info.append(ii)
                struct.pack_into(f"<{len(ii.procs) + 1}I", self.unpacked, ii.iat_rva, *([random.randint(0x1, 0xfffffffe)] * len(ii.procs) + [0]))
                self.log_info(f'{libname} IAT at {iat_rva:#x}, number of procs = {len(ii.procs)}')
            else: self.log_info(f'[-] Unable to find {libname} IAT', True)
        return imp_info


    def rebuild_imports(self, imp_rva):
        imp_info = self.get_import_info_arr()
        if imp_info is False:
            return False, 0
        return pe_stuff.generate_import_table(imp_info, imp_rva), len(imp_info) * pe_stuff.IMPORT_DESC_SIZE

    def fix_dump(self):
        pe = pefile.PE(data=self.unpacked)
        
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = self.oep - pe.OPTIONAL_HEADER.ImageBase
        pe.OPTIONAL_HEADER.SizeOfImage = utils.align_up(len(self.unpacked), pe.OPTIONAL_HEADER.SectionAlignment)
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size = 0
        pe_stuff.disable_aslr(pe)

        for i, sect in enumerate(pe.sections):
            sect.PointerToRawData = sect.VirtualAddress
            sect.Characteristics |= 0xE0000000
            # TODO check uninitialized sections
            if i == (len(pe.sections) - 1) and sect.SizeOfRawData == 0:
                break
            sect.SizeOfRawData = sect.Misc_VirtualSize
        
        # fix for PE from mm_image (pefile incorrectly (not like windows loader) handles overlay)
        not_really_overlay = pe.get_overlay()
        if not_really_overlay:
            pe = pefile.PE(data=pe_stuff.pe_write_without_overlay(pe))

        imp_rva = utils.align_up(pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment)
        imp_table, imp_size = self.rebuild_imports(imp_rva)
        if imp_table is False: 
            return False
        
        pe = pe_stuff.add_section(pe, imp_table)
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress = imp_rva
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size = imp_size
        return pe.write()

def generic_unpack(pe_path, out, verb, timeout, jump_count=0):
    config = json.load(open(os.path.join(sys.path[0], 'default.json'),'r'))

    if timeout:
        config.update({'timeout': timeout})
        config.update({'max_api_count': timeout * 500})
    logger = None
    if verb:
        logger = logging.getLogger('speakeasy')
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.DEBUG)

    em = GenericEmulator(config, logger)
    em.set_jump_count(jump_count)

    module = em.load_module(path=pe_path)
    base = module.get_base()
    em.base = base
    em.pe_mod = module
    if module.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        em.end_addr = 0xffffffff
    elif module.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        em.end_addr = 0xffffffffffffffff
    else:
        em.log_error("[-] Arch not supported")
        return False
    ep = module.ep

    em.set_new_hook_ranges(ep + em.base)
    
    # there is much more to hook, but let's keep it simple
    em.add_api_hook(em.hook_getmodulehandle, "kernel32", "GetModuleHandleA")
    em.add_api_hook(em.hook_getmodulehandle, "kernel32", "GetModuleHandleW")
    em.add_api_hook(em.hook_loadlibrary, "kernel32", "LoadLibraryA")
    em.add_api_hook(em.hook_loadlibrary, "kernel32", "LoadLibraryW")
    em.add_api_hook(em.hook_getprocaddress, "kernel32", "GetProcAddress")

    em.log_info('[*] Starting emulation', True)
    em.run_module(module)

    if em.done:
        out_file = em.fix_dump()
        if out_file is False: return False
        overlay = module.get_overlay()
        if overlay:
            em.log_info(f'[+] Overlay copied {len(overlay):#x}')
            out_file += overlay
        open(out, 'wb').write(out_file)
        em.log_info(f"[+] Unpacked PE is written to {out}", True)
        return True
    else:
        em.log_error("[-] Something went wrong...")
        return False

def handle_out_path(args: argparse.Namespace) -> None:
    if args.output is None:
        args.output = utils.get_out_path(args.pe_file)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_file", type=str, help="path to input PE file")
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    parser.add_argument("-o", "--output", type=str, help="path to output PE file")
    parser.add_argument("-j", "--jump", type=int, default=0, help="number of memory jumps to ignore (default 0)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="timeout in seconds (default 10)")
    args = parser.parse_args()
    handle_out_path(args)
    generic_unpack(args.pe_file, args.output, args.verbose, args.timeout, args.jump)

if __name__=="__main__":
    main()