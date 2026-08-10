from dotenv import load_dotenv
from flask import Flask, render_template
from flask_restful import Api

from resources.health import Health
from resources.items import Item, ItemList
from seed import seed_database
from views.authorize import authorize_bp
from views.callbacks.google import google_callback_bp

app = Flask(__name__)
api = Api(app, catch_all_404s=True)

api.add_resource(Health, "/api/health")
api.add_resource(ItemList, "/api/items")
api.add_resource(Item, "/api/items/<int:item_id>")

app.register_blueprint(authorize_bp)
app.register_blueprint(google_callback_bp)

@app.get("/")
def index():
    return render_template("index.html", title="Home")


if __name__ == "__main__":
    load_dotenv()
    seed_database()
    app.run(host="0.0.0.0", debug=True)
