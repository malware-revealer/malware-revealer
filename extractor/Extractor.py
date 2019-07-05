import yaml
import importlib
import os
import json
import logging as log
from Crypto.Hash import MD5
from binascii import hexlify

FEATURE_BASE_PACKAGE = "features"
JSON_FOLDER = "json"
IMAGE_FOLDER = "image"

class Extractor(object):
    """
    Responsible of calling each feature extractor by first making sure
    it can extract them without any issues, then get those features.
    """

    def __init__(self, features, in_folder, out_folder):
        self.features = features
        self.in_folder = in_folder
        self.out_folder = out_folder

    def extract_batch(self):
        """
        Extract features from all files from the in_folder to the out_folder
        according to the features list.
        """

        features = list(self.features.values())

        prepare_extraction(features, self.in_folder, self.out_folder)
        for name, exe, label in iter_executables(self.in_folder):
            name = get_file_name(exe)
            exe_path = "{label}/{name}".format(label=label, name=name)
            log.info("Extracting features from %s", exe_path)

            features_dict = {}
            for feature in features:
                try:
                    extracted_features = feature().extract_features(exe)
                    if feature.is_image:
                        image = extracted_features['image']
                        image_format = extracted_features['image_format']
                        save_features_image(name, image, image_format, label, feature.name, self.out_folder)
                    else:
                        features_dict.update(extracted_features)
                except Exception as e:
                    log.error("Error while using feature class %s", feature)
                    log.exception(e)

            save_features_json(name, features_dict, label, self.out_folder)



def extract_one(exe, conf):
    """
    Extract features from only one executable file according to
    the features list.

    params:
    executable is the executable to extract features from represented as bytes.
    conf is the extractor configuration represented as a dictionnary.
    """

    features = get_features_from_conf(conf)
    features = list(features.values())

    features_dict = {}
    images = {}
    for feature in features:
        extracted_features = feature().extract_features(exe)
        if feature.is_image:
            image = extracted_features['image']
            image_format = extracted_features['image_format']
            images.update(
                {
                    feature.name: {
                        'image': image,
                        'image_format': image_format,
                    }
                }
            )

        else:
            features_dict.update(extracted_features)

    return features_dict, images


def get_file_name(exe):
    md5 = MD5.new(exe)
    digest = md5.digest()
    name = hexlify(digest).decode()
    return name


def prepare_extraction(features, in_folder, out_folder):
    # Get image feature extractors
    image_extractors = []
    for feature in features:
        if feature.is_image:
            image_extractors.append(feature.name)

    labels = get_labels_from_folder(in_folder)

    return prepare_extraction_(out_folder, labels, image_extractors)


def prepare_extraction_(out_folder, labels, image_extractors):
    json_out = os.path.join(out_folder, JSON_FOLDER)
    image_out = os.path.join(out_folder, IMAGE_FOLDER)
    create_dir_if_does_not_exist(json_out)
    create_dir_if_does_not_exist(image_out)

    ## JSON
    # Create subfolder for each label
    for label in labels:
        create_dir_if_does_not_exist(os.path.join(json_out, label))

    ## IMAGE
    # Create image subfolder for each image extractor
    for image_extractor in image_extractors:
        image_extractor_out = os.path.join(image_out, image_extractor)
        create_dir_if_does_not_exist(image_extractor_out)
        # Create subfolder for each label in each image subfolder
        for label in labels:
            create_dir_if_does_not_exist(os.path.join(image_extractor_out, label))


def iter_executables(in_folder):
    labels = get_labels_from_folder(in_folder)
    for label in labels:
        label_path = os.path.join(in_folder, label)
        for file_name in os.listdir(label_path):
            # Get the raw executable
            file_path = os.path.join(label_path, file_name)
            file = open(file_path, 'rb')
            exe = file.read()
            file.close()
            # Get the name of the executable
            name, _ = os.path.splitext(file_name)

            yield name, exe, label


def save_features_image(name, image, image_format, label, feature_name, out_folder):
    image_path = os.path.join(out_folder, IMAGE_FOLDER, feature_name, label, name + '.' + image_format)
    image.save(image_path)


def save_features_json(name, features_dict, label, out_folder):
    file_path = os.path.join(out_folder, JSON_FOLDER, label, name + '.json')
    file = open(file_path, 'w')
    json.dump(features_dict, file)
    file.close()


def get_labels_from_folder(folder):
    labels = []
    for file in os.listdir(folder):
        if os.path.isdir(os.path.join(folder, file)):
            labels.append(file)
    return labels


def create_dir_if_does_not_exist(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)


def get_features_from_conf(conf):
    """
    Get the feature classes defined by the conf file.
    conf should be an opened file.
    """

    features = {}
    for feature_module in conf["features"]:
        module_name = FEATURE_BASE_PACKAGE + '.' + feature_module
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as error:
            # TODO: print a clear warning
            print(error)
            continue

        for feature_name in conf["features"][feature_module]:
            name = feature_module + '.' + feature_name
            try:
                features[name] = getattr(module, feature_name)
            except AttributeError as error:
                # TODO: print a clear warning
                print(error)
    return features


def new(conf_file, in_folder, out_folder):
    """
    Build an extractor according to the configuration file which list
    feature classes that should be used.

    params:
    in_folder contains a subfolder of executables for each label.
    out_folder will contain two main folders, json/ and image/.
      - json/ will contain a subfolder of extracted features for each label
        - image/ will contain a subfolder for each type of image extraction
          - those folders will then contain a subfolder of images for each label
    """

    stream = open(conf_file)
    conf = yaml.load(stream)
    stream.close()

    features = get_features_from_conf(conf)

    # Prepare folder variable
    curdir = os.path.realpath(os.path.curdir)
    if not os.path.isabs(in_folder):
        in_folder = os.path.join(curdir, in_folder)
    if not os.path.isabs(out_folder):
        out_folder = os.path.join(curdir, out_folder)

    extractor = Extractor(features, in_folder, out_folder)
    return extractor
