import yaml
import importlib

FEATURE_BASE_PACKAGE = "features"

class Extractor(object):
    """
    Responsible of calling each feature extractor by first making sure
    it can extract them without any issues, then get those features.
    """

    def __init__(self, features):
        self.features = features



def new(conf_file):
    """
    Build an extractor according to the configuration file which list
    feature classes that should be used.
    """

    stream = open(conf_file)
    conf = yaml.load(stream)

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

    extractor = Extractor(features)
    return extractor
