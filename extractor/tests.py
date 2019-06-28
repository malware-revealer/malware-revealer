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
        
    def test_PE_Header(self):
        """
        Test the extracted features of Pe Header !
        """

        conf_file = "test_assets/extractor_confs/pe_header_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/pe_header"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        feature_dict = extractor.features
        file = open("test_assets/expected_features_dicts/pe_header.json" ,"rb")
        expected_feature_dict = json.load(file)

        self.assertEqual(
            feature_dict,
            expected_feature_dict,
            "The extracted features of Pe Header don't match"
            )

    def test_Libraries(self):
        """
        Test the extracted features of Libraries !
        """

        conf_file = "test_assets/extractor_confs/libraries_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/libraries"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        feature_dict = extractor.features
        file = open("test_assets/expected_features_dicts/libraries.json" ,"rb")
        expected_feature_dict = json.load(file)

        self.assertEqual(
            feature_dict,
            expected_feature_dict,
            "The extracted features of Libraries don't match"
            )
    

    def test_Sections(self):
        """
        Test the extracted features of Sections !
        """

        conf_file = "test_assets/extractor_confs/sections_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/sections"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        feature_dict = extractor.features
        file = open("test_assets/expected_features_dicts/sections.json" ,"rb")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            feature_dict,
            expected_feature_dict,
            "The extracted features of Sections don't match"
            )

if __name__ == '__main__':
    unittest.main()
