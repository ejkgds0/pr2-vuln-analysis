import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

# УЯЗВИМОСТЬ #1: Hardcoded Credentials (CWE-798)
SECRET_KEY = "super-secret-key-12345"
ADMIN_PASSWORD = "admin123"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
db.execute("INSERT INTO users VALUES (1, 'admin', 'admin123'), (2, 'alice', 'qwerty')")
db.commit()


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    # УЯЗВИМОСТЬ #2: SQL Injection (CWE-89)
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    row = db.execute(query).fetchone()
    return str(row)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # УЯЗВИМОСТЬ #3: Reflected XSS (CWE-79)
    return f"<h1>Hello, {name}!</h1>"


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # УЯЗВИМОСТЬ #4: OS Command Injection (CWE-78)
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # УЯЗВИМОСТЬ #5: Code Injection через eval (CWE-95)
    return str(eval(expr))


@app.route("/load")
def load():
    data = request.args.get("data", "")
    # УЯЗВИМОСТЬ #6: Небезопасная десериализация pickle (CWE-502)
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)


@app.route("/file")
def read_file():
    name = request.args.get("name", "")
    # УЯЗВИМОСТЬ #7: Path Traversal (CWE-22)
    with open(os.path.join("files", name)) as f:
        return f.read()


def hash_password(password):
    # УЯЗВИМОСТЬ #8: Слабый хеш MD5 (CWE-328)
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    # УЯЗВИМОСТЬ #9: Debug-режим включён, сервер слушает все интерфейсы (CWE-489)
    app.run(host="0.0.0.0", port=3000, debug=True)
