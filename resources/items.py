from flask import request
from flask_restful import Resource

from .store import items


class ItemList(Resource):
    def get(self):
        return items

    def post(self):
        data = request.get_json(silent=True) or {}
        name = data.get("name")
        if not name:
            return {"error": "name is required"}, 400

        new_id = max((i["id"] for i in items), default=0) + 1
        item = {"id": new_id, "name": name}
        items.append(item)
        return item, 201


class Item(Resource):
    def get(self, item_id):
        item = next((i for i in items if i["id"] == item_id), None)
        if item is None:
            return {"error": "not found"}, 404
        return item
