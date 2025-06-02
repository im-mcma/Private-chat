from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from app import app, db
from models import User, Room, Message
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# ورود و ثبت‌نام

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
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
        if user and check_password_hash(user.password_hash, password):
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

# صفحه اصلی اتاق‌ها

@app.route('/rooms')
def rooms():
    if 'user_id' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))
    rooms = Room.query.all()
    return render_template('rooms.html', rooms=rooms, user_id=session['user_id'])

# ایجاد اتاق

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
        delete_after = int(request.form.get('delete_after', 60))
        new_room = Room(name=name, created_by=session['user_id'], delete_after_minutes=delete_after)
        db.session.add(new_room)
        db.session.commit()
        flash(f'Room "{name}" created successfully', 'success')
        return redirect(url_for('rooms'))
    return render_template('create_room.html')

# تنظیمات اتاق

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
        delete_after = int(request.form.get('delete_after', room.delete_after_minutes))
        room.delete_after_minutes = delete_after
        db.session.commit()
        flash('Room settings updated.', 'success')
        return redirect(url_for('room_settings', room_id=room_id))
    return render_template('room_settings.html', room=room)

# حذف اتاق (غیرفعال سازی)

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

# پنل ادمین

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
