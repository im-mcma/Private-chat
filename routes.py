from datetime import datetime, timedelta
from flask import (
    render_template, request, redirect, url_for, session,
    flash, abort
)
from app import app, db, bcrypt, socketio
from models import User, Room, Message
from flask_socketio import join_room, leave_room, send

user_rooms = {}

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

@app.route('/rooms/<int:room_id>/chat')
def chat(room_id):
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    room = Room.query.get_or_404(room_id)
    if not room.is_active:
        flash('This room is inactive.', 'danger')
        return redirect(url_for('rooms'))

    password = request.args.get('password', '')
    if room.password_hash and not room.check_password(password):
        flash('Incorrect password for this room.', 'danger')
        return redirect(url_for('rooms'))

    cutoff = datetime.utcnow() - timedelta(days=30)
    messages = Message.query.filter(
        Message.room_id == room.id,
        Message.timestamp >= cutoff
    ).order_by(Message.timestamp.asc()).all()

    return render_template('chat.html', room=room, username=session['username'], messages=messages)

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

    new_msg = Message(room_id=room.id, user_id=user_id, content=msg, timestamp=datetime.utcnow())
    db.session.add(new_msg)
    room.last_active = datetime.utcnow()
    db.session.commit()

    send(f"{username}: {msg}", to=room_name)

# پاکسازی روم‌های غیرفعال بعد از مدت زمان قابل تنظیم در پنل (مثلاً ۱۰ دقیقه)
def cleanup_rooms():
    now = datetime.utcnow()
    rooms = Room.query.filter(Room.is_active == False).all()
    for room in rooms:
        if room.last_active + timedelta(minutes=10) < now:
            Message.query.filter_by(room_id=room.id).delete()
            db.session.delete(room)
    db.session.commit()
