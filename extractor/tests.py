import unittest

class TestExtractor(unittest.TestCase):

    def test_creation(self):
        """
        Test the extractor creation using a test conf file.
        """
        import Extractor
        extractor = Extractor.new("test_assets/extractor_conf.yaml")
        feature_list = list(extractor.features.keys())
        self.assertEqual(
            feature_list,
            ['base.BaseFeature', 'elf.SomeELFFeature', 'pe.GeneralFileInfo'],
            "Imported features don't match"
            )


if __name__ == '__main__':
    unittest.main()
