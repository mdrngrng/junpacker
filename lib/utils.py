from typing import Any, Optional, Union, List, Dict
import pefile
import os
import re

def get_out_path(inp: str) -> str:
    filename, extension = os.path.splitext(inp)
    out_path = filename + '_unpacked' + re.sub(r'[^a-zA-Z0-9\.]+', '', extension) + "_"
    return out_path

def find_all(a_str: Union[str, bytes], sub_str: Union[str, bytes]) -> List[int]:
    start = 0
    matches = []
    while True:
        start = a_str.find(sub_str, start)
        if start == -1:
            return matches
        matches.append(start)
        start += 1

def rva_belongs_to_section(vaddr: int, sect: pefile.SectionStructure, alignment: int = -1) -> bool:
    # if vaddr >= sect.VirtualAddress and (vaddr < (sect.VirtualAddress + sect.Misc_VirtualSize) or vaddr < (sect.VirtualAddress + sect.SizeOfRawData)):
    vs = sect.Misc_VirtualSize
    if alignment != -1:
        vs = align_up(vs, alignment)
    if vaddr >= sect.VirtualAddress and vaddr < (sect.VirtualAddress + vs):
        return True
    return False

def find_section_by_rva(pe: pefile.PE, rva: int) -> Optional[int]:
    sect_num = None
    for i, sect in enumerate(pe.sections):
        if rva_belongs_to_section(rva, sect):
            sect_num = i
    return sect_num

def get_item_by_value(dct: Dict[Any, Any], val: Any) -> Any:
    for k, v in dct.items():
        if v == val: return k
    return False

def align_up(num: int, size: int) -> int:
    return (num + size - 1) // size * size