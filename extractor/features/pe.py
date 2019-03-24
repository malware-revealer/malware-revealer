"""
ELF Feature Classes.
Contain feature classes that are proper to the PE format
"""

from base import BaseFeature
import lief


class GeneralFileInfo(BaseFeature):
    """
    this class is used to extract the General information from the PE file,
    such as the file size, number of export,import functions ...etc 
    """
    name = "General information"
    dim = 11

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

    def extracted_features(self, lief_file):
        """
        we extract the the general informations here 
        """
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

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        if lief_file is None:
            return False
        return True

    def extracted_features(self, lief_file):
        """
        we extract all the needed header informations here 
        """
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

    def can_extract(self, lief_file):
        """
        we return True if the lief_file is not None, but we can go farther,
        and return true/false for every feature in this section.
        """
        if lief_file is None:
            return False
        return True

    def extracted_features(self, lief_file):
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
