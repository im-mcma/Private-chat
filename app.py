import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_session import Session

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///chat.db'  # برای تست لوکال
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
socketio = SocketIO(app, manage_session=False)

# مدل‌ها

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    max_users = db.Column(db.Integer, default=10)
    inactive_timeout = db.Column(db.Integer, default=30)  # دقیقه
    password_hash = db.Column(db.String(128), nullable=True)

    is_active = db.Column(db.Boolean, default=True)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

    # ارتباط به میزبان
    host = db.relationship('User')

    def check_password(self, password):
        if not self.password_hash:
            return True  # بدون پسورد
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_password(self, password):
        if password.strip() == '':
            self.password_hash = None
        else:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
    room = db.relationship('Room')

# ذخیره اتاق فعلی کاربران
user_rooms = {}

# ----- مسیرهای اصلی -----

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('rooms'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=pw_hash)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
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
            return redirect(url_for('rooms'))
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ----- مدیریت روم‌ها -----

@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    rooms = Room.query.filter_by(is_active=True).all()
    return render_template('rooms.html', rooms=rooms, user_id=session['user_id'])

@app.route('/rooms/create', methods=['GET', 'POST'])
def create_room():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        if Room.query.filter_by(name=name).first():
            flash('Room name already exists', 'danger')
            return redirect(url_for('create_room'))
        password = request.form.get('password', '').strip()
        max_users = int(request.form.get('max_users', 10))
        inactive_timeout = int(request.form.get('inactive_timeout', 30))

        new_room = Room(
            name=name,
            host_id=session['user_id'],
            max_users=max_users,
            inactive_timeout=inactive_timeout,
            last_active=datetime.utcnow()
        )
        new_room.set_password(password)

        db.session.add(new_room)
        db.session.commit()
        flash(f'Room "{name}" created successfully', 'success')
        return redirect(url_for('rooms'))
    return render_template('create_room.html')

@app.route('/rooms/<int:room_id>/settings', methods=['GET', 'POST'])
def room_settings(room_id):
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    if room.host_id != session['user_id']:
        flash('Access denied', 'danger')
        return redirect(url_for('rooms'))
    if request.method == 'POST':
        max_users = int(request.form.get('max_users', room.max_users))
        inactive_timeout = int(request.form.get('inactive_timeout', room.inactive_timeout))
        password = request.form.get('password', '')
        is_active = request.form.get('is_active') == 'on'

        room.max_users = max_users
        room.inactive_timeout = inactive_timeout
        room.is_active = is_active
        room.set_password(password)
        db.session.commit()
        flash('Settings updated', 'success')
        return redirect(url_for('room_settings', room_id=room_id))
    return render_template('room_settings.html', room=room)

# حذف موقت روم (توسط میزبان)
@app.route('/rooms/<int:room_id>/delete', methods=['POST'])
def room_delete(room_id):
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    if room.host_id != session['user_id']:
        flash('Access denied', 'danger')
        return redirect(url_for('rooms'))
    room.is_active = False
    room.last_active = datetime.utcnow()
    db.session.commit()
    flash(f'Room "{room.name}" has been deactivated.', 'info')
    return redirect(url_for('rooms'))

# ----- صفحه چت -----

@app.route('/rooms/<int:room_id>/chat')
def chat(room_id):
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    if not room.is_active:
        flash('This room is inactive.', 'danger')
        return redirect(url_for('rooms'))

    # بررسی محدودیت رمز
    password = request.args.get('password', '')
    if room.password_hash and not room.check_password(password):
        flash('Incorrect password for this room.', 'danger')
        return redirect(url_for('rooms'))

    # دریافت پیام‌های قبلی (تا 30 روز)
    cutoff = datetime.utcnow() - timedelta(days=30)
    messages = Message.query.filter(
        Message.room_id == room.id,
        Message.timestamp >= cutoff
    ).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', room=room, username=session['username'], messages=messages)

# ----- رویدادهای Socket.IO -----

@socketio.on('join')
def handle_join(data):
    room_name = data.get('room')
    username = session.get('username')
    user_id = session.get('user_id')

    if not (room_name and username and user_id):
        return

    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room:
        send(f"Room '{room_name}' does not exist or is inactive.", to=request.sid)
        return

    # بررسی تعداد کاربران حاضر (ساده، می‌تونیم توسعه بدیم)
    # در این مثال، تعداد کاربران فعال رو نمی‌شماریم به صورت دقیق

    join_room(room_name)
    user_rooms[username] = room_name
    room.last_active = datetime.utcnow()
    db.session.commit()
    send(f"{username} has joined the room.", to=room_name)

@socketio.on('leave')
def handle_leave():
    username = session.get('username')
    room_name = user_rooms.get(username)
    if room_name:
        leave_room(room_name)
        send(f"{username} has left the room.", to=room_name)
        user_rooms.pop(username, None)

@socketio.on('message')
def handle_message(msg):
    username = session.get('username')
    user_id = session.get('user_id')
    room_name = user_rooms.get(username)

    if not (room_name and username and user_id):
        return

    room = Room.query.filter_by(name=room_name, is_active=True).first()
    if not room:
        return

    # ذخیره پیام در دیتابیس
    new_msg = Message(room_id=room.id, user_id=user_id, content=msg, timestamp=datetime.utcnow())
    db.session.add(new_msg)
    room.last_active = datetime.utcnow()
    db.session.commit()

    send(f"{username}: {msg}", to=room_name)

# پاکسازی روم‌های غیرفعال بعد از زمان مشخص (سرویس جداگانه یا هر بار که اجرا میشه)
def cleanup_rooms():
    now = datetime.utcnow()
    rooms = Room.query.filter(Room.is_active == False).all()
    for room in rooms:
        if room.last_active + timedelta(minutes=10) < now:
            # حذف کامل روم و پیام‌ها پس از 10 دقیقه غیرفعال بودن
            Message.query.filter_by(room_id=room.id).delete()
            db.session.delete(room)
    db.session.commit()

# می‌تونیم هر بار اجرای برنامه یا یک کرون جاب این تابع رو اجرا کنیم

# اجرای برنامه

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
