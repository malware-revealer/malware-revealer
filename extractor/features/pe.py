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

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section, like a dict {'size':true,'imports':False .... etc}
        """
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        """
        we extract the the general informations here
        """

        lief_file = lief_from_raw(raw_exe)
        features={
                'virtual_size': 0,
                'name': '',
                'sizeof_PFheader': 0,
                'has_signature': False,
                'has_debug': 0,
                'has_relocations': 0,
                'has_resources': 0,
                'has_tls': 0,
                'symbols': 0
            }
        if lief_file is None:
            return features

        features['virtual_size'] =  lief_file.virtual_size
        features['name'] =  lief_file.name
        features['sizeof_PFheader'] = lief_file.sizeof_headers
        features['has_signature'] =  int(lief_file.has_signature)
        features['has_debug'] =  int(lief_file.has_debug)
        features['has_relocations'] = int(lief_file.has_relocations)
        features['has_resources'] = int(lief_file.has_resources)
        features['has_tls'] =  int(lief_file.has_tls)
        features['symbols'] = len(lief_file.symbols)

        return features


class MSDOSHeader(BaseFeature):
    name = "MS-DOS Header"

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):
        """
        we extract all the needed header informations here
        """

        lief_file = lief_from_raw(raw_exe)
        features = {
                'magic': None,
                'pages_file': 0,
                'checksum': 0,
                'oem_id': 0,
                'oem_info': 0
            }

        if lief_file is None:
            return features

        features['magic'] = lief_file.dos_header.magic
        features['pages_file'] = lief_file.dos_header.file_size_in_pages
        features['checksum'] = lief_file.dos_header.checksum
        features['oem_id'] = lief_file.dos_header.oem_id
        features['oem_info'] = lief_file.dos_header.oem_info
        return features



class PEHeader(BaseFeature):
    name = "PE Header"

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):

        lief_file = lief_from_raw(raw_exe)
        features =  {
                'timestamp': 0,
                'machine': "",
                'characteristics': [],
                'numberof_sections': 0,
                'numberof_symbols': 0,
                'PE_signature': None
            }
        if lief_file is None:
            return features

        features['timestamp'] = lief_file.header.time_date_stamps
                # the lief machine type is not a string it gives something like this MACHINE_TYPES.AMD64
        features['machine'] =  str(lief_file.header.machine).split('.')[-1]
        features['characteristics'] = [str(c).split('.')[-1] for c in lief_file.header.characteristics_list]
        features['numberof_sections'] = lief_file.header.numberof_sections
        features['numberof_symbols'] = lief_file.header.numberof_symbols
                # the PE signature should be [80,69,0,0] it means PE\0\0
        features['PE_signature'] = lief_file.header.signature

        return features


class OptionalHeader(BaseFeature):
    name = "Optional_Header"

    def __init__(self):
        super(BaseFeature, self).__init__()

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        if lief_file is None:
            return False
        return True

    def extract_features(self, raw_exe):

        lief_file = lief_from_raw(raw_exe)
        features = {
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
        if lief_file is None:
            return features

        features['subsystem'] = str(lief_file.optional_header.subsystem)
        features['dll_characteristics'] = [str(dll_c).split('.')[-1] for dll_c in lief_file.optional_header.dll_characteristics_lists]
        features['magic'] = str(lief_file.optional_header.magic).split('.')[-1]
        features['major_image_version'] = lief_file.optional_header.major_image_version
        features['minor_image_version'] =  lief_file.optional_header.minor_image_version
        features['major_linker_version'] = lief_file.optional_header.major_linker_version
        features['minor_linker_version'] = lief_file.optional_header.minor_linker_version
        features['major_operating_system_version'] = lief_file.optional_header.major_operating_system_version
        features['minor_operating_system_version'] = lief_file.optional_header.minor_operating_system_version
        features['major_subsystem_version'] = lief_file.optional_header.major_subsystem_version
        features['minor_subsystem_version'] = lief_file.optional_header.minor_subsystem_version
        features['sizeof_code'] = lief_file.optional_header.sizeof_code
        features['sizeof_headers'] = lief_file.optional_header.sizeof_headers
        features['sizeof_heap_commit'] = lief_file.optional_header.sizeof_heap_commit

        return features

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
