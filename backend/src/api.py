from flask import Flask, request, jsonify, abort
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, guard_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()

# ROUTES


@app.route('/drinks', methods=['GET'])
def get_drinks():
    try:
        drinks = Drink.query.all()
        drinks = [drink.short() for drink in drinks]
        return jsonify({
            'success': True,
            'drinks': drinks
        }), 200
    except Exception as e:
        print(e)
        abort(422)


@app.route('/drinks-detail/<int:id>', methods=['GET'])
@guard_auth('get:drinks-detail')
def get_single_drink(id):
    drink = Drink.query.get(id)
    if drink is None:
        abort(404)
    return jsonify({
        'success': True,
        'drink': drink.short(),
    }), 200


@app.route('/drinks-detail', methods=['GET'])
@guard_auth('get:drinks-detail')
def get_drinks_details():
    try:
        drinks = Drink.query.all()
        return jsonify({
            'success': True,
            'drinks': [drink.long() for drink in drinks]
        }), 200
    except Exception as e:
        print(sys.exc_info())
        print(e)


@app.route('/drinks', methods=['POST'])
@guard_auth('post:drinks')
def create_drinks():
    body = request.get_json()
    title = body.get('title', None)
    recipe = body.get('recipe', None)
    if title is None or recipe is None:
        abort(400)
    try:
        drink = Drink(title=title, recipe=json.dumps(recipe))
        drink.insert()
        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200
    except Exception:
        abort(422)


@app.route('/drinks/<int:id>', methods=['PATCH'])
@guard_auth('patch:drinks')
def update_drinks(id):
    drink = Drink.query.get(id)
    if drink is None:
        abort(404)
    body = request.get_json()
    title = body.get('title', None)
    recipe = body.get('recipe', None)
    if title is None or recipe is None:
        abort(400)
    try:
        drink.title = title
        drink.recipe = json.dumps(recipe)
        drink.update()
        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200
    except Exception:
        abort(422)


@app.route('/drinks/<int:id>', methods=['DELETE'])
@guard_auth('delete:drinks')
def delete_drinks(id):
    drink = Drink.query.get(id)

    if drink is None:
        abort(404)
    try:
        drink.delete()
        return jsonify({
            'success': True,
            'delete': id
        }), 200
    except Exception:
        abort(422)


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


@app.errorhandler(404)
def error_404(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    }), error.status_code
