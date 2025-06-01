@routes.route('/admin')
@login_required
def admin_panel():
    if current_user.username != 'admin':
        abort(403)
    users = User.query.all()
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('admin.html', users=users, messages=messages) 
