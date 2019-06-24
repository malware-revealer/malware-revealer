from flask import Flask, request
from flask_restful import Resource, Api
from flask_cors import CORS
from Extractor import extract_one
import yaml


app = Flask(__name__)
api = Api(app)

# Allow all origin to access the API
CORS(app)


def prepare_response(features):
    pass


class Extraction(Resource):
    def post(self):
        """
        Extract features from an executable file.
        """
        executable = request.files['exec']
        extractor_conf = request.files['extractor_conf']

        exec = executable.read()
        conf = yaml.load(extractor_conf)
        features = extract_one(exec, conf)
        resp = prepare_response(features)
        return resp


api.add_resource(Extraction, '/extract')

if __name__ == '__main__':
    app.run('0.0.0.0', 80)
