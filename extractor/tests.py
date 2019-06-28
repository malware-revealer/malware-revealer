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


    def test_file_size(self):
        """
        Testing file size extarction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/file_size_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/file_size"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/file_size.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "file size dosen't match"
            )

    def test_urls(self):
        """
        Testing URLs extarction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/urls_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/urls"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/urls.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "urls don't match"
            )


    def test_imported_functions(self):
        """
        Testing imported functions extarction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/imported_functions_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/imported_functions"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/imported_functions.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "imported functions don't match"
            )


    def test_byte_counts(self):
        """
        Testing the byte counts extraction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/byte_counts_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/byte_counts"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/byte_counts.yaml.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "Byte Counts dosen't match"
            )

    def test_exported_functions(self):
        """
        Testing exported functions extarction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/exported_functions_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/exported_functions"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/exported_functions.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "exported functions don't match"
            )

    def test_binary_image(self):
        """
        Testing the binary image extraction using a test conf file.
        """

        from PIL import Image, ImageChops

        """
        # Funtion that compares the differences of the two images .
        @param1 image, @param2 image   (extracted & expected images)

        @return an image (difference between pixels)
        if they are equal then it returns a black image
        """
        def assertImage(pic_1,  pic_2):
            diff = ImageChops.difference(pic_1, pic_2)
            theDifferenceImage = diff.convert('RGB')
            theDifferenceImage.paste(pic_2, mask=diff)
            return theDifferenceImage

        conf_file = "test_assets/extractor_confs/binary_image_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/binary_image"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        extracted_image = extractor.features["image"]
        expected_image = Image.open("test_assets/expected_features_images/binary_image.png")

        difference = assertImage(extracted_image, expected_image)

        """
        # Verifying if all pixels are black it return 'None' if they are
        # if not then we print an error msg
        """

        if not difference.getbbox() :
            pass
        else :
            print("Binary images don't match")

    def test_strings(self):
        """
        Testing exported functions extarction using a test conf file.
        """
        conf_file = "test_assets/extractor_confs/strings_conf.yaml"
        in_folder = "test_assets/executables"
        out_folder = "test_assets/extracted_features/strings"
        extractor = Extractor.new(conf_file, in_folder, out_folder)
        extractor.extract_batch()
        features_dict = extractor.features
        file = open("test_assets/expected_features_dicts/strings.json","r")
        expected_feature_dict = json.load(file)
        self.assertEqual(
            features_dict,
            expected_feature_dict,
            "strings don't match"
            )


if __name__ == '__main__':
    unittest.main()
