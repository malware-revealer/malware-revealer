"""
Base Feature Classes.
Contain feature classes that are common to all executables
"""

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

class SomeBaseFeature(BaseFeature):
    pass
