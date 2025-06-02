import os
import routes
from datetime import datetime, timedelta
from flask import Flask, render_template, session, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_session import Session

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://dbchatroom_user:9qRUJQRw0n0ydjUF2VskwFXV1YfGXj6o@dpg-d0uakvumcj7s739gatrg-a.oregon-postgres.render.com/dbchatroom'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
socketio = SocketIO(app, manage_session=False)

user_rooms = {}

# تو این فایل فقط کانفیگ اولیه و اجرای برنامه باشه
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
