import pefile
import struct
import copy
from typing import Union, List

from lib import utils

IMPORT_DESC_SIZE = 0x14
SECTION_HEADER_SIZE = 0x28

class ImportInfo:
    def __init__(self, iat_rva: int, libname: str) -> None:
        self.iat_rva = iat_rva
        self.libname = libname
        self.procs = []
    
    def add_proc(self, procname: str) -> None:
        self.procs.append(procname)

def pe_write_without_overlay(pe: pefile.PE) -> bytearray:
    pew = pe.write()
    overlay = pe.get_overlay()
    if overlay:
        pew = pew[:len(pew) - len(overlay)]
    return pew

def disable_aslr(pe: pefile.PE) -> None:
    if pe.OPTIONAL_HEADER.DllCharacteristics & pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']:
        pe.OPTIONAL_HEADER.DllCharacteristics ^= pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']

def generate_import_table(imp_info: List[ImportInfo], imp_table_rva: int, align: bool=False, bits: int=32) -> Union[bytearray, bool]:
    imp_num = len(imp_info)
    imp_table_size = 0

    # calculate required table size
    ilt_p = (imp_num + 1) * IMPORT_DESC_SIZE
    hintname_p = ilt_p
    for imp in imp_info:
        hintname_p = hintname_p + (len(imp.procs)+1) * (4 if bits==32 else 8)
    imp_table_size += hintname_p
    for imp in imp_info:
        for pr in imp.procs:
            if isinstance(pr, str):
                imp_table_size += (2 + len(pr) + 1)
                if align:
                    if imp_table_size % 2 == 1: imp_table_size += 1 #1
        imp_table_size += (len(imp.libname) + 1)
        if align:
            if imp_table_size % 2 == 1: imp_table_size += 1 #1
    
    imp_table = bytearray(imp_table_size)

    for i, imp in enumerate(imp_info):
        ilt_rva = ilt_p + imp_table_rva
        for pr in imp.procs:
            if isinstance(pr, str):
                if bits == 32:
                    struct.pack_into("<I", imp_table, ilt_p, imp_table_rva + hintname_p)
                elif bits == 64:
                    struct.pack_into("<Q", imp_table, ilt_p, imp_table_rva + hintname_p)
                struct.pack_into(f"{len(pr)}B", imp_table, hintname_p+2, *pr.encode())
                hintname_p += 2 + len(pr) + 1
                if align:
                    if hintname_p % 2 == 1: hintname_p += 1 #1
            elif type(pr) == int:
                if bits==32:
                    struct.pack_into("<I", imp_table, ilt_p, 0x80000000 | pr)
                elif bits==64:
                    struct.pack_into("<Q", imp_table, ilt_p, 0x8000000000000000 | pr)
            else: return False
            ilt_p = ilt_p + (4 if bits==32 else 8)
        ilt_p = ilt_p + (4 if bits==32 else 8)
        dllname_rva = hintname_p + imp_table_rva
        struct.pack_into(f"{len(imp.libname)}B", imp_table, hintname_p, *imp.libname.encode())
        hintname_p += len(imp.libname) + 1
        if align:
            if hintname_p % 2 == 1: hintname_p += 1 #1
        struct.pack_into("<5I", imp_table, i * IMPORT_DESC_SIZE, ilt_rva, 0xffffffff, 0xffffffff, dllname_rva, imp.iat_rva)

    return imp_table

# pe 
def add_section(pe: pefile.PE, data: bytes) -> pefile.PE:
    new_sect_offs = pe.sections[-1].get_file_offset() + SECTION_HEADER_SIZE
    # TODO very rare case, if there is not enough space for new section header
    # if new_sect_offs + SECTION_HEADER_SIZE > pe.OPTIONAL_HEADER.SizeOfHeaders:
    new_pe = copy.deepcopy(pe)

    data = bytearray(data)
    sect_name = b".imports" + (SECTION_HEADER_SIZE - 8) * b"\x00"
    new_vs = utils.align_up(len(data), new_pe.OPTIONAL_HEADER.SectionAlignment)
    new_va = utils.align_up(new_pe.sections[-1].VirtualAddress + new_pe.sections[-1].Misc_VirtualSize, new_pe.OPTIONAL_HEADER.SectionAlignment)
    data = data + (utils.align_up(len(data), new_pe.OPTIONAL_HEADER.FileAlignment) - len(data)) * b"\x00"
    new_ptrd = utils.align_up(new_pe.sections[-1].PointerToRawData + new_pe.sections[-1].SizeOfRawData, new_pe.OPTIONAL_HEADER.FileAlignment)

    new_pe.OPTIONAL_HEADER.SizeOfImage = utils.align_up(new_va + new_vs, new_pe.OPTIONAL_HEADER.SectionAlignment)
    new_pe.FILE_HEADER.NumberOfSections += 1
    
    pew = pe_write_without_overlay(new_pe)
    struct.pack_into(f"{len(sect_name)}B", pew, new_sect_offs, *sect_name)
    struct.pack_into("<8I", pew, new_sect_offs + 8, new_vs, new_va, len(data), new_ptrd, 0, 0, 0, 0x40000000)

    pew = pew + (new_ptrd - len(pew)) * b"\x00" + data
    overlay = new_pe.get_overlay()
    if overlay:
        pew += overlay
    new_pe = pefile.PE(data=pew)
    return new_pe
