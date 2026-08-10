from flask_restful import Resource


class Token(Resource):
    def post(self):
        return {"status": "ok"}