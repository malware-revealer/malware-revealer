"""
PE Feature Classes.
Contain feature classes that are proper to the PE format
"""

from .base import BaseFeature
from .utils import *
import lief
from lief.PE import SECTION_CHARACTERISTICS as SC


class GeneralFileInfo(BaseFeature):
    """
    this class is used to extract the General information from the PE file,
    such as the file size, number of export,import functions ...etc
    """
    name = "General information"
    dim = 11

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, raw_exe):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section, like a dict {'size':true,'imports':False .... etc}
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        """
        we extract the the general informations here
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return {
                'virtual_size': 0,
                'name': '',
                'sizeof_PFheader': 0,
                'has_signature': None,
                'has_debug': 0,
                'exports': 0,
                'imports': 0,
                'has_relocations': 0,
                'has_resources': 0,
                'has_tls': 0,
                'symbols': 0
            }

        else:
            return{
                'virtual_size': lief_file.virtual_size,
                'name': lief_file.name,
                'sizeof_PFheader': lief_file.sizeof_headers,
                'signature': int(lief_file.has_signature),
                'has_debug': int(lief_file.has_debug),
                'exports': len(lief_file.exported_functions),
                'imports': len(lief_file.imported_functions),
                'has_relocations': int(lief_file.has_relocations),
                'has_resources': int(lief_file.has_resources),
                'has_tls': int(lief_file.has_tls),
                'symbols': len(lief_file.symbols)
            }


class MSDOS_Header(BaseFeature):
    name = "MS-DOS Header"
    dim = 5

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, raw_exe):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        """
        we extract all the needed header informations here
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return{
                'magic': None,
                'pages_file': 0,
                'checksum': 0,
                'oem_id': 0,
                'oem_info': 0
            }
        else:
            return{
                'magic': lief_file.dos_header.magic,
                'pages_file': lief_file.dos_header.file_size_in_pages,
                'checksum': lief_file.dos_header.checksum,
                'oem_id': lief_file.dos_header.oem_id,
                'oem_info': lief_file.dos_header.oem_info
            }


class PE_Header(BaseFeature):
    name = "PE Header"
    dim = 6

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, raw_exe):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return {
                'timestamp': 0,
                'machine': "",
                'characteristics': [],
                'numberof_sections': 0,
                'numberof_symbols': 0,
                'PE_signature': None
            }
        else:
            return {
                'timestamp': lief_file.header.time_date_stamps,
                # the lief machine type is not a string it gives something like this MACHINE_TYPES.AMD64
                'machine':  str(lief_file.header.machine).split('.')[-1],
                'characteristics': [str(c).split('.')[-1] for c in lief_file.header.characteristics_list],
                'numberof_sections': lief_file.header.numberof_sections,
                'numberof_symbols': lief_file.header.numberof_symbols,
                # the PE signature should be [80,69,0,0] it means PE\0\0
                'PE_signature': lief_file.header.signature
            }


class Optional_Header(BaseFeature):
    name = "Optional_Header"
    dim = 14

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, raw_exe):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        if lief_file is None:
            return {
                'subsystem': "",
                'dll_characteristics': [],
                'magic': "",
                'major_image_version': 0,
                'minor_image_version': 0,
                'major_linker_version': 0,
                'minor_linker_version': 0,
                'major_operating_system_version': 0,
                'minor_operating_system_version': 0,
                'major_subsystem_version': 0,
                'minor_subsystem_version': 0,
                'sizeof_code': 0,
                'sizeof_headers': 0,
                'sizeof_heap_commit': 0
            }
        else:
            return {
                'subsystem': lief_file.optional_header.subsystem,
                'dll_characteristics': [str(dll_c).split('.')[-1] for dll_c in lief_file.optional_header.dll_characteristics_lists],
                'magic': str(lief_file.optional_header.magic).split('.')[-1],
                'major_image_version': lief_file.optional_header.major_image_version,
                'minor_image_version': lief_file.optional_header.minor_image_version,
                'major_linker_version': lief_file.optional_header.major_linker_version,
                'minor_linker_version': lief_file.optional_header.minor_linker_version,
                'major_operating_system_version': lief_file.optional_header.major_operating_system_version,
                'minor_operating_system_version': lief_file.optional_header.minor_operating_system_version,
                'major_subsystem_version': lief_file.optional_header.major_subsystem_version,
                'minor_subsystem_version': lief_file.optional_header.minor_subsystem_version,
                'sizeof_code': lief_file.optional_header.sizeof_code,
                'sizeof_headers': lief_file.optional_header.sizeof_headers,
                'sizeof_heap_commit': lief_file.optional_header.sizeof_heap_commit
            }


class Libraries(BaseFeature):
    """
    Get the number and the list of all the imported libraries.
    """

    name = 'libraries'

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        libraries = [lib.name for lib in lief_file.imports]
        features = {
            'lib_counts': len(libraries),
            'libs': libraries,
        }
        return features


class Sections(BaseFeature):
    """
    Get the number of sections and informations about each individual section
    in the PE file.
    """

    name = 'sections'

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        sections = lief_file.sections

        features = {
            'sections':{},
            'section_counts': len(sections),
        }
        for section in sections:
            is_readable = section.has_characteristic(SC.MEM_READ)
            is_writable = section.has_characteristic(SC.MEM_WRITE)
            is_executable = section.has_characteristic(SC.MEM_EXECUTE)

            section_info = {
                'virtual_size': section.virtual_size,
                'virtual_address': section.virtual_address,
                'size': section.size,
                'entropy': section.entropy,
                'is_readable': is_readable,
                'is_writable': is_writable,
                'is_executable': is_executable,
            }
            features['sections'][section.name] = section_info

        return features
