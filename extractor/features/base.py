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

    def can_extract(self, raw_exe):
        """
        Tell if this feature can be extracted from the provided raw_exe file.
        Default to True. Should be re-implemented when constraints apply.
        """
        return True

    def extracted_features(self, raw_exe):
        """
        To extracted the  wanted features, the output of this fuction depends on the feature
        """
        raise (NotImplemented)

class SomeBaseFeature(BaseFeature):
    pass
