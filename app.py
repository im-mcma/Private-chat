import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_session import Session

# تنظیمات اولیه
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql://user:password@localhost/dbname'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

# راه‌اندازی افزونه‌ها
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
socketio = SocketIO(app, manage_session=False)

# مدل کاربر
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# دیکشنری برای نگهداری اتاق فعلی کاربران
user_rooms = {}

# مسیرها

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already taken')
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('chat'))
        flash('Invalid username or password')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

# Socket.IO Events

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = session.get('username')
    if room and username:
        join_room(room)
        user_rooms[username] = room
        send(f"{username} has joined the room.", to=room)

@socketio.on('leave')
def handle_leave():
    username = session.get('username')
    room = user_rooms.get(username)
    if room:
        leave_room(room)
        send(f"{username} has left the room.", to=room)
        user_rooms.pop(username, None)

@socketio.on('message')
def handle_message(msg):
    username = session.get('username')
    room = user_rooms.get(username)
    if room and username:
        send(f"{username}: {msg}", to=room)

# اجرای اپلیکیشن

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
