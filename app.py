from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///time_management.db'
db = SQLAlchemy(app)


# Datenbankmodelle
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    time_entries = db.relationship('TimeEntry', backref='user', lazy=True)


class TimeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    entry_type = db.Column(db.String(10), nullable=False)  # 'check_in' or 'check_out'


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Open')  # 'Open', 'In Progress', 'Closed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    comments = db.relationship('Comment', backref='ticket', lazy=True)

    def __repr__(self):
        return f'<Ticket {self.title}>'


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Comment by User {self.user_id}>'


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    time_entries = TimeEntry.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, time_entries=time_entries)


@app.route('/check_in')
def check_in():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_entry = TimeEntry.query.filter_by(user_id=user_id, entry_type='check_in').order_by(
        TimeEntry.timestamp.desc()).first()
    if existing_entry and not TimeEntry.query.filter_by(user_id=user_id, entry_type='check_out').order_by(
            TimeEntry.timestamp.desc()).first():
        flash('You are already checked in.', 'info')
    else:
        new_entry = TimeEntry(user_id=user_id, entry_type='check_in')
        db.session.add(new_entry)
        db.session.commit()
        flash('Checked in successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/check_out')
def check_out():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_entry = TimeEntry.query.filter_by(user_id=user_id, entry_type='check_out').order_by(
        TimeEntry.timestamp.desc()).first()
    if existing_entry and not TimeEntry.query.filter_by(user_id=user_id, entry_type='check_in').order_by(
            TimeEntry.timestamp.desc()).first():
        flash('You are not checked in.', 'info')
    else:
        new_entry = TimeEntry(user_id=user_id, entry_type='check_out')
        db.session.add(new_entry)
        db.session.commit()
        flash('Checked out successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You need to be an admin to access this page.', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'create_user' in request.form:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            is_admin = 'is_admin' in request.form
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
        elif 'update_user' in request.form:
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if user:
                user.username = request.form['username']
                user.email = request.form['email']
                if request.form['password']:
                    user.password = generate_password_hash(request.form['password'], method='sha256')
                user.is_admin = 'is_admin' in request.form
                db.session.commit()
                flash('User updated successfully!', 'success')

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You need to be an admin to perform this action.', 'warning')
        return redirect(url_for('index'))

    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/create_ticket', methods=['GET', 'POST'])
def create_ticket():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        user_id = session['user_id']
        new_ticket = Ticket(title=title, description=description, user_id=user_id)
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_ticket.html')


@app.route('/admin/tickets')
def admin_tickets():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You need to be an admin to access this page.', 'warning')
        return redirect(url_for('index'))

    tickets = Ticket.query.all()
    return render_template('admin_tickets.html', tickets=tickets)


@app.route('/ticket/<int:id>', methods=['GET', 'POST'])
def ticket_detail(id):
    ticket = Ticket.query.get_or_404(id)

    if request.method == 'POST':
        if 'update_ticket' in request.form:
            ticket.title = request.form['title']
            ticket.description = request.form['description']
            ticket.status = request.form['status']
            db.session.commit()
            flash('Ticket updated successfully!', 'success')
        elif 'add_comment' in request.form:
            content = request.form['comment']
            comment = Comment(ticket_id=ticket.id, user_id=session['user_id'], content=content)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added successfully!', 'success')

    comments = Comment.query.filter_by(ticket_id=ticket.id).all()
    return render_template('ticket_detail.html', ticket=ticket, comments=comments)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
