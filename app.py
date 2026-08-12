from dotenv import load_dotenv
from flask import Flask, render_template
from flask_cors import CORS
from flask_restful import Api

from resources.token import OAuthToken
from seed import seed_database
from views.authorize import authorize_bp
from views.callbacks.google import google_callback_bp
from views.jwks import jwks_bp

app = Flask(__name__)
CORS(app, supports_credentials=True)
api = Api(app, catch_all_404s=True)

api.add_resource(OAuthToken, "/oauth/token")

app.register_blueprint(authorize_bp)
app.register_blueprint(google_callback_bp)
app.register_blueprint(jwks_bp)

@app.get("/")
def index():
    return render_template("index.html", title="Home")


if __name__ == "__main__":
    load_dotenv()
    seed_database()
    app.run(host="0.0.0.0", debug=True)
