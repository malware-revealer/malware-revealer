from flask import Flask, request
from flask_restful import Resource, Api
from flask_cors import CORS


app = Flask(__name__)
api = Api(app)

# Allow all origin to access the API
CORS(app)


class Extraction(Resource):
    def post(self):
        """
        Extract features from an executable file.
        """
        executable = request.files['exec']
        extractor_conf = None #request.post['conf']
        # Return Something comprehensif
        return None


api.add_resource(Extraction, '/extract')

if __name__ == '__main__':
    app.run('0.0.0.0', 80)
