from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = '9qRUJQRw0n0ydjUF2VskwFXV1YfGXj6o'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dbchatroom_user:9qRUJQRw0n0ydjUF2VskwFXV1YfGXj6o@dpg-d0uakvumcj7s739gatrg-a.oregon-postgres.render.com/dbchatroom'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

# ایمپورت مسیرها و روترها (از فایل routes.py)
import routes

if __name__ == '__main__':
    socketio.run(app, debug=True)
