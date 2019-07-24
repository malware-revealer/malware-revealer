"""
ELF Feature Classes.
Contain feature classes that are proper to the ELF format
"""

from .base import BaseFeature
from .utils import lief_from_raw


class ELFHeader(BaseFeature):
    name = "elf_header"

    def can_extract(self, raw_exe):
        b_list = list(raw_exe)
        elf_binary = lief.ELF.parse(raw=b_list)
        if elf_binary:
            return True
        else:
            return False


    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        header = lief_file.header
        features = {
            'header_size': header.header_size,
            'entrypoint': header.entrypoint,
            'file_type': str(header.file_type).split('.')[1],
            'identity_class': str(header.identity_class).split('.')[1],
            'identity_os_abi': str(header.identity_os_abi).split('.')[1],
            'machine_type': str(header.machine_type).split('.')[1],
            'numberof_sections': header.numberof_sections,
            'numberof_segments': header.numberof_segments,
            'program_header_size': header.program_header_size,
            'program_header_offset': header.program_header_offset,
            'section_header_size': header.section_header_size,
            'section_name_table_idx': header.section_name_table_idx,
            'arm_flags_list': list(header.arm_flags_list),
            'hexagon_flags_list': list(header.hexagon_flags_list),
            'mips_flags_list': list(header.mips_flags_list),
            'ppc64_flags_list': list(header.ppc64_flags_list),
            'processor_flag': header.processor_flag,
        }
        return features
