import unittest

class TestExtractor(unittest.TestCase):

    def test_creation(self):
        """
        Test the extractor creation using a test conf file.
        """
        import Extractor
        conf_file = "test_assets/extractor_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        feature_list = list(extractor.features.keys())
        expected_feature_list = sorted([
                                    'base.BaseFeature',
                                    'elf.SomeELFFeature',
                                    'pe.GeneralFileInfo',
                                    ])
        self.assertEqual(
            sorted(feature_list),
            expected_feature_list,
            "Imported features don't match"
            )


if __name__ == '__main__':
    unittest.main()
