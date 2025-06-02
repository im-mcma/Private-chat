from datetime import datetime
from app import db, bcrypt

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

    host = db.relationship('User')

    def check_password(self, password):
        if not self.password_hash:
            return True
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_password(self, password):
        if not password.strip():
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
