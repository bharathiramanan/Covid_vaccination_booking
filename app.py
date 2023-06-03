from flask import Flask, render_template, request, redirect, url_for, session, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vaccination.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)

# Database Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    booked_slots = db.relationship('VaccinationSlot', backref='user', lazy=True)

class BookedSlot(db.Model):
    __tablename__ = 'booked_slots'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    centre_id = db.Column(db.Integer, db.ForeignKey('vaccination_centre.id'))

    user = db.relationship('User')
    centre = db.relationship('VaccinationCentre')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

class VaccinationCentre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    working_hours = db.Column(db.String(100), nullable=False)
    slots = db.relationship('VaccinationSlot', backref='vaccination_centre', lazy=True)

class VaccinationSlot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    centre_id = db.Column(db.Integer, db.ForeignKey('vaccination_centre.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


def create_admin_user():
    with app.app_context():
        admin_user = Admin.query.filter_by(username='admin').first()
        if admin_user:
            admin_user.password = generate_password_hash('admin123')
        else:
            admin_user = Admin(username='admin', password=generate_password_hash('admin123'))
            db.session.add(admin_user)
        db.session.commit()

# Routes

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect('/search')
        else:
            error = 'Invalid username or password. Please try again.'
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect('/admin/dashboard')
        else:
            error = 'Invalid username or password. Please try again.'
            return render_template('admin/login.html', error=error)

    return render_template('admin/login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('signup.html', error=error)

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        return redirect('/search')

    return render_template('signup.html')


@app.route('/search')
def search():
    centres = VaccinationCentre.query.all()
    booked_slots = BookedSlot.query.filter_by(user_id=session['user_id']).all()
    user = User.query.get(session['user_id'])

    def slot_available(centre_id, user_id):
        slot = BookedSlot.query.filter_by(centre_id=centre_id, user_id=user_id).first()
        return slot is None

    return render_template('search.html', centres=centres, booked_slots=booked_slots, user=user, slot_available=slot_available)


@app.route('/apply/<int:centre_id>', methods=['POST'])
def apply(centre_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    user = db.session.query(User).get(user_id)
    centre = db.session.query(VaccinationCentre).get(centre_id)

    if len(user.booked_slots) >= 10:
        error = 'You have already booked the maximum number of slots.'
        return render_template('search.html', error=error)

    if db.session.query(db.exists().where(BookedSlot.centre_id == centre_id, BookedSlot.user_id == user_id)).scalar():
        error = 'You have already booked a slot for this centre.'
        return render_template('search.html', error=error)

    new_slot = VaccinationSlot(centre_id=centre_id, user_id=user_id)
    db.session.add(new_slot)
    db.session.commit()

    return redirect('/search')


@app.route('/remove/<int:slot_id>', methods=['POST'])
def remove(slot_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    user = User.query.get(user_id)
    slot = VaccinationSlot.query.get(slot_id)

    if slot.user_id == user_id:
        db.session.delete(slot)
        db.session.commit()

    return redirect('/search')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')

@app.route('/admin/centre/add', methods=['GET', 'POST'])
def admin_add_centre():
    if 'admin_id' not in session:
        return redirect('/admin/login')

    if request.method == 'POST':
        name = request.form['name']
        working_hours = request.form['working_hours']

        existing_centre = VaccinationCentre.query.filter_by(name=name).first()
        if existing_centre:
            error = 'Vaccination Centre already exists. Please choose a different name.'
            return render_template('admin/add_centre.html', error=error)

        new_centre = VaccinationCentre(name=name, working_hours=working_hours)
        db.session.add(new_centre)
        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('admin/add_centre.html')

@app.route('/admin/dosage')
def admin_dosage_details():
    if 'admin_id' not in session:
        return redirect('/admin/login')

    dosage_details = (
        db.session.query(User.username, VaccinationCentre.name, db.func.count(VaccinationSlot.id))
        .join(VaccinationSlot, User.id == VaccinationSlot.user_id)
        .join(VaccinationCentre, VaccinationSlot.centre_id == VaccinationCentre.id)
        .group_by(User.username, VaccinationCentre.name)
        .all()
    )

    return render_template('admin/dosage.html', dosage_details=dosage_details)


@app.route('/admin/centre/remove/<int:centre_id>', methods=['POST'])
def admin_remove_centre(centre_id):
    if 'admin_id' not in session:
        return redirect('/admin/login')

    centre = VaccinationCentre.query.get(centre_id)
    db.session.delete(centre)
    db.session.commit()

    return redirect('/admin/dashboard')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect('/admin/login')

    centres = VaccinationCentre.query.all()

    return render_template('admin/dashboard.html', centres=centres)


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)