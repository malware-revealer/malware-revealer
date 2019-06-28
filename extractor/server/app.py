from flask import Flask, request, send_from_directory
from flask_restful import Resource, Api
from flask_cors import CORS
from Extractor import extract_one
import yaml
import os
from time import time


app = Flask(__name__, static_url_path='')
api = Api(app)

# Allow all origin to access the API
CORS(app)

IMAGES_DIR = "images"


def save_image(name, image, format):
    """
    Take a Pillow image and save it using the format and name provided.
    """

    ts = int(time())
    file_name = '{name}{time}.{format}'
    file_name = file_name.format(name=name, time=ts, format=format)
    image.save(os.path.join(IMAGES_DIR, file_name))
    url = 'http://extractor/{image_dir}/{file_name}'

    return url.format(image_dir=IMAGES_DIR, file_name=file_name)

def prepare_response(features, images):
    image_urls = {}
    for image_name in images.keys():
        image_value = images[image_name]
        image = image_value['image']
        image_format = image_value['image_format']
        url = save_image(image_name, image, image_format)
        image_urls[image_name] = url

    features['image_urls'] = image_urls
    return features


class Extraction(Resource):
    def post(self):
        """
        Extract features from an executable file.
        """
        executable = request.files['exec']
        extractor_conf = request.files['extractor_conf']

        exec = executable.read()
        conf = yaml.load(extractor_conf)
        features, images = extract_one(exec, conf)
        resp = prepare_response(features, images)
        return resp


api.add_resource(Extraction, '/extract')

@app.route('/images/<path:path>')
def send_js(path):
    return send_from_directory(IMAGES_DIR, path)


if __name__ == '__main__':
    # Prepate folder to store images
    if not os.path.exists(IMAGES_DIR):
        os.makedirs(IMAGES_DIR)
        
    app.run('0.0.0.0', 80)
