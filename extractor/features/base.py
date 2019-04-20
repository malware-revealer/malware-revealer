"""
Base Feature Classes.
Contain feature classes that are common to all executables
"""
import numpy as np

class BaseFeature(object):
    """
    The building block of other feature classes.
    Implement default behaviours.
    """

    name = ''
    dim = 0
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
