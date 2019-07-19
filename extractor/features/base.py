"""
Base Feature Classes.
Contain feature classes that are common to all executables
"""
import numpy as np
import re
from PIL import Image
from math import sqrt

from .utils import lief_from_raw


class BaseFeature(object):
    """
    The building block of other feature classes.
    Implement default behaviours.
    """

    name = ''
    is_image = False

    def can_extract(self, raw_exe):
        """
        Tell if this feature can be extracted from the provided raw_exe file.
        Default to True. Should be re-implemented when constraints apply.
        """
        return True

    def extract_features(self, raw_exe):
        """
        To extracted the  wanted features, the output of this fuction depends on the feature
        """
        raise NotImplementedError


class ByteCounts(BaseFeature):
    """
    Count the number of occurence of each byte.
    The index is the byte itself, so the number of occurences of byte 0 should
    be the first element in the list.
    """

    name = 'byte_count'

    def extract_features(self, raw_exe):
        array_exe = np.frombuffer(raw_exe, dtype=np.uint8)
        counts = np.bincount(array_exe, minlength=256)
        feature = {'byte_count': counts.tolist()}
        return feature


class BinaryImage(BaseFeature):
    """
    Transform an executable into an image.
    """

    name = 'binary_image'
    is_image = True

    def __init__(self, image_format='png'):
        self.image_format = image_format

    def extract_features(self, raw_exe):
        """
        Use the raw_exe bytes to create a new image.
        Return a PIL image and the image format that the image should
        be saved with.
        """

        exe_len = len(raw_exe)
        side = int(sqrt(exe_len))
        size = (side, side)
        # Create the image
        img = Image.new(mode='L', size=size)
        img.frombytes(raw_exe[: side*side])

        feature = {'image': img, 'image_format': self.image_format}
        return feature


class FileSize(BaseFeature):
    """Simply get the executable size in bytes."""

    name = 'file_size'

    def extract_features(self, raw_exe):
        file_size = len(raw_exe)
        return {'file_size': file_size}


class URLs(BaseFeature):
    """Get the number and the list of all urls."""

    name = 'urls'

    RE_URL = b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    def extract_features(self, raw_exe):
        urls = re.findall(URLs.RE_URL, raw_exe)
        features = {
            'url_counts': len(urls),
            'urls': [url.decode() for url in urls],
        }
        return features


class ImportedFunctions(BaseFeature):
    """
    Get the number and the list of imported functions.
    """

    name = 'imported_functions'

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        imported_functions = lief_file.imported_functions
        features = {
            'imported_functions_counts': len(imported_functions),
            'imported_functions': imported_functions,
        }
        return features


class ExportedFunctions(BaseFeature):
    """
    Get the number and the list of exported functions.
    """

    name = 'exported_functions'

    def extract_features(self, raw_exe):
        lief_file = lief_from_raw(raw_exe)
        exported_functions = lief_file.exported_functions
        features = {
            'exported_functions_counts': len(exported_functions),
            'exported_functions': exported_functions,
        }
        return features


class Strings(BaseFeature):
    """Get the number of strings(+5 char), strings set, avrege length, paths set,
    paths number ,registry and MZ headers number."""

    name = 'Strings'

    RE_STRING = br'[\w$&!]{5,}'
    RE_PATH = br'[A-Z]:\\[\w\\\. ]*'
    RE_REGISTRY = b'^HKEY_'
    RE_MZ = b'^MZ'

    def extract_features(self, raw_exe):
        strings = re.findall(Strings.RE_STRING, raw_exe)
        paths = re.findall(Strings.RE_PATH, raw_exe)
        registry_names = re.findall(Strings.RE_REGISTRY, raw_exe)
        MZ = re.findall(Strings.RE_MZ, raw_exe)
        features = {
            'strings_count': len(strings),
            'printabales': list(map(lambda item: item.decode(), strings)),
            'avg_length':sum([len(str) for str in strings])/len(strings),
            'paths_count': len(paths),
            'paths': list(map(lambda item: item.decode(), paths)),
            'registry_count': len(registry_names),
            'MZ': len(MZ),
        }
        return features
