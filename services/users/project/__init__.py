from flask import Flask, jsonify
from flask_restful import Resource, Api

# instantiate the app
app = Flask(__name__)

api = Api(app)


class UsersPing(Resource):
    def get(self):
        return {
            'status': 'success',
            'message': 'pong!'
        }


api.add_resource(UsersPing, '/users/ping')
