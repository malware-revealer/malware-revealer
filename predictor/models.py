from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from torchvision.models import squeezenet1_1
from torch import nn
import torch
import os
from sklearn.externals import joblib


MODEL_STORE = "models-data"

class MalwareRevealerEnsemble(nn.Module):

    def __init__(self, model_checkpoints):
        super(MalwareRevealerEnsemble, self).__init__()
        self.models = [
            custom_squeezenet(model_checkpoint)\
            for model_checkpoint in model_checkpoints
        ]


    def forward(self, x):
        preds = [model(x) for model in self.models]
        votes = preds[0]
        for pred in preds[1:]:
            votes += pred
        votes /= len(preds)
        return votes


def custom_squeezenet(checkpoint_file=None):
    model = squeezenet1_1()
    # Customizing the squeezenet architecture
    features = list(model.classifier.children())
    features[1] = nn.Conv2d(model.classifier[1].in_channels, 2, kernel_size=(1,1))
    model.classifier = nn.Sequential(*features)
    model.num_classes = 2
    if checkpoint_file:
        # Load the trained model
        device = ('cuda' if torch.cuda.is_available() else 'cpu')
        state_dict = torch.load(checkpoint_file, map_location=device)
        model.load_state_dict(state_dict)
    model.eval()
    return model


def new_cnn_v1():
    """
    Instanciate a new CNN Classifier based on squeezenet. This model have been
    trained on our malware dataset (provided by VirusTotal).
    """

    checkpoint_file = os.path.join(MODEL_STORE, 'cnn-v1', 'cnn-v1.pth')
    model = custom_squeezenet(checkpoint_file)

    return model


def new_cnn_v2():
    """
    Instanciate three CNN Classifier based on squeezenet. This models have been
    trained on our malware dataset (provided by VirusTotal). This models make
    predictions individually and aggregate the results by applying soft voting.
    """

    checkpoint_files = [
        os.path.join(MODEL_STORE, 'cnn-v2', 'squeezenet1_1_data%d.pth' % i)\
        for i in range(1, 4)
    ]

    model = MalwareRevealerEnsemble(checkpoint_files)
    return model


def new_LogisticRegression_v1():
    file_path = os.path.join(MODEL_STORE, 'LogisticRegression-v1', 'LogisticRegression.sav')
    model =  joblib.load(file_path)
    return model



MODELS = {
    'cnn-v1': new_cnn_v1,
    'cnn-v2': new_cnn_v2,
    'LogisticRegression-v1': new_LogisticRegression_v1
}


def new(version):
    try:
        model_builder = MODELS[version]
        model = model_builder()
    except KeyError:
        # TODO: print clear warning
        print("Can't find a model with version %s" % version)
    return model
