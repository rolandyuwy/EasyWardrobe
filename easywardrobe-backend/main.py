from datetime import datetime

from method import esMethod
from method import shares

# Flask Playground
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = 'secret'
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Start up of the flask backend
@app.route("/", methods=["GET", "POST"])
def start_up():
    print("Backend up and running")
    return "Backend up and running"

# Register user
@app.route('/register', methods=['POST'])
def register():
    user_name = request.get_json()["username"]
    email = request.get_json()["email"]
    password = bcrypt.generate_password_hash(request.get_json()["password"]).decode("utf-8")
    created = datetime.now()
    arg_dict = {"username": user_name.lower()}
    hit = esMethod.search_exact_docs(client=es, index="user", arg_dict=arg_dict)
    if len(hit) == 0:
        json_data = {
            "email": email,
            "password": password,
            "created": created
        }
        json_data.update(arg_dict)
        return esMethod.create_without_uuid(client=es, index="user", json_data=json_data)
    else:
        return "Username already exist"


# Login user
@app.route('/login', methods=['POST'])
def login():
    user_name = request.get_json()["username"]
    password = request.get_json()["password"]
    result = ""
    arg_dict = {
        "username": user_name.lower()
    }
    print(arg_dict)
    hits = esMethod.search_exact_docs(client=es, index="user", arg_dict=arg_dict)
    if len(hits) == 0:
        return "Error - Username not found"
    else:
        body = hits[0]["body"]
        to_check_password = body["password"]
        if bcrypt.check_password_hash(to_check_password, password):
            access_token = create_access_token(identity={"email": body["email"], "uuid": hits[0]["uuid"]})
            print(type(access_token))
            dic = {"token": access_token}
            return dic
        else:
            return "Error - Invalid password"