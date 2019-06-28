import unittest
import json
import Extractor

class TestExtractor(unittest.TestCase):

    def test_creation(self):
        """
        Test the extractor creation using a test conf file.
        """

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
        Testing the file general informations extraction .
        """
        conf_file = "test_assets/extractor_confs/general_file_info_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/general_file_info"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/general_file_info.json","r")
        expected_feature_dict = json.load(file)

        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "extracted general file informations don't match"
            )


    def test_msdos_header(self):
        """
        Testing the Msdos Header extraction .
        """
        conf_file = "test_assets/extractor_confs/msdos_header_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/msdos_header"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/msdos_header.json","r")
        expected_feature_dict = json.load(file)

        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "msdos header dosen't match"
            )
            

    def test_optional_header(self):
        """
        Testing the optional header extraction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/optional_header_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/optional_header"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/optional_header.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "Optional Header dosen't match"
            )                         


if __name__ == '__main__':
    unittest.main()
