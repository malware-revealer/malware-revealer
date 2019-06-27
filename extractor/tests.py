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
                                    'base.BinaryImage',
                                    'base.ByteCounts',
                                    'elf.SomeELFFeature',
                                    'pe.GeneralFileInfo',
                                    'pe.Libraries',
                                    'base.FileSize',
                                    'base.URLs',
                                    'base.ImportedFunctions',
                                    'base.ExportedFunctions',
                                    ])
        self.assertEqual(
            sorted(feature_list),
            expected_feature_list,
            "Imported features don't match"
            )


    def test_general_file_info(self):
        """
        Testing the file general informations extraction using a test conf file.
        """
        import Extractor
        conf_file = "test_assets/extractor_confs/general_file_info_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/general_file_info"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        expected_feature_dict = {
                                "virtual_size": 2674688,
                                "name": "",
                                "sizeof_PFheader": 1024,
                                "signature": 0,
                                "has_debug": 0, 
                                "exports": 0, 
                                "imports": 91, 
                                "has_relocations": 0, 
                                "has_resources": 1, 
                                "has_tls": 0, 
                                "symbols": 0
                                }
        self.assertEqual(
            sorted(feature_dict),
            expected_feature_dict,
            "Imported features don't match"
            )


    def test_msdos_header(self):
        """
        Test the extractor creation using a test conf file.
        """
        import Extractor
        conf_file = "test_assets/extractor_confs/msdos_header_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/msdos_header"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        expected_feature_dict = {
                                "magic": 23117, 
                                "pages_file": 3, 
                                "checksum": 0, 
                                "oem_id": 0, 
                                "oem_info": 0
                                }
        self.assertEqual(
            sorted(feature_dict),
            expected_feature_dict,
            "Imported features don't match"
            )                         


if __name__ == '__main__':
    unittest.main()
