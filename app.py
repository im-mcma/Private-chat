import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from flask_session import Session
from flask_migrate import Migrate, upgrade
import logging

# === App & Config ===
app = Flask(__name__, template_folder='.')
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://dbchatroom_user:9qRUJQRw0n0ydjUF2VskwFXV1YfGXj6o@dpg-d0uakvumcj7s739gatrg-a.oregon-postgres.render.com/dbchatroom'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
migrate = Migrate(app, db)   # فعال سازی Flask-Migrate
bcrypt = Bcrypt(app)
Session(app)
socketio = SocketIO(app, manage_session=False)

# === Models ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    delete_after_minutes = db.Column(db.Integer, default=60)

    def __repr__(self):
        return f'<Room {self.name}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.id} in Room {self.room_id}>'

# === Routes ===
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

        is_admin = (username == 'im_abi' and User.query.filter_by(username='im_abi').count() == 0)

        new_user = User(username=username, password_hash=pw_hash, is_admin=is_admin)
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
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('rooms'))
        flash('Invalid username or password', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    rooms = Room.query.all()
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
        try:
            delete_after = int(request.form.get('delete_after', 60))
        except ValueError:
            delete_after = 60
        new_room = Room(name=name, created_by=session['user_id'], delete_after_minutes=delete_after)
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
    if room.created_by != session['user_id'] and not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('rooms'))
    if request.method == 'POST':
        try:
            delete_after = int(request.form.get('delete_after', room.delete_after_minutes))
        except ValueError:
            delete_after = room.delete_after_minutes
        room.delete_after_minutes = delete_after
        db.session.commit()
        flash('Room settings updated.', 'success')
        return redirect(url_for('room_settings', room_id=room_id))
    return render_template('room_settings.html', room=room)

@app.route('/rooms/<int:room_id>/delete', methods=['POST'])
def room_delete(room_id):
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    if room.created_by != session['user_id'] and not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('rooms'))
    db.session.delete(room)
    db.session.commit()
    flash(f'Room "{room.name}" deleted.', 'info')
    return redirect(url_for('rooms'))

@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        abort(403)
    users = User.query.all()
    rooms = Room.query.all()
    return render_template('admin_panel.html', users=users, rooms=rooms)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        abort(403)
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" deleted.', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_room/<int:room_id>', methods=['POST'])
def admin_delete_room(room_id):
    if not session.get('is_admin'):
        abort(403)
    room = Room.query.get_or_404(room_id)
    db.session.delete(room)
    db.session.commit()
    flash(f'Room "{room.name}" deleted.', 'info')
    return redirect(url_for('admin_panel'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# === Auto upgrade or create DB on startup ===
@app.before_first_request
def auto_db_setup():
    try:
        # سعی کنیم migration ها را آپگرید کنیم (اگر migrations موجود بود)
        upgrade()
        app.logger.info("Database migration upgrade successful.")
    except Exception as e:
        app.logger.warning(f"Migration upgrade failed or no migrations found. Creating tables directly. Error: {e}")
        # اگر migration وجود نداشت یا مشکل داشت، مستقیم جداول را ایجاد کن
        db.create_all()

# === Run ===
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
