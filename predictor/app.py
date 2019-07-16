from flask import Flask, request
from flask_restful import Resource, Api
from flask_cors import CORS
import MalwareRevealer


app = Flask(__name__)
api = Api(app)

# Allow all origin to access the API
CORS(app)

malware_revealer_cnn_v1 = MalwareRevealer.new('cnn-v1')
malware_revealer_cnn_ensemble = MalwareRevealer.new('cnn-v2')
malware_revealer_lr_v1 = MalwareRevealer.new("LogisticRegression-v1")


class MalwarePredictionCnnV1(Resource):
    def post(self):
        """
        Return how likely the executable is a malware.
        """
        executable = request.files['exec']
        image = malware_revealer_cnn_v1.get_features(executable)
        probs = malware_revealer_cnn_v1.predict(image)
        return probs


class MalwarePredictionCnnV2(Resource):
    def post(self):
        """
        Return how likely the executable is a malware.
        """
        executable = request.files['exec']
        image = malware_revealer_cnn_ensemble.get_features(executable)
        probs = malware_revealer_cnn_ensemble.predict(image)
        return probs


class MalwarePredictionLRV1(Resource):
    def post(self):
        executable = request.files['exec']
        features = malware_revealer_lr_v1.get_features(executable)

        predict = malware_revealer_lr_v1.predict(features)
        return predict



class Ping(Resource):
    def get(self):
        """Simple endpoint to check that the service is reachable"""
        return "Pong!"


api.add_resource(MalwarePredictionCnnV1, '/cnn/v1/pred')
api.add_resource(MalwarePredictionCnnV2, '/cnn/v2/pred')
api.add_resource(MalwarePredictionLRV1, '/logistic_regression/v1/pred')
api.add_resource(Ping, "/ping")

if __name__ == '__main__':
    app.run('0.0.0.0', 80)
