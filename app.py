from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask import current_app
from config import Config
from extensions import db, login_manager, migrate
from models import User, Division, District, Upazila, TutorRequest
from forms import RegisterForm, LoginForm, GuardianProfileForm, TutorProfileForm, TutorRequestForm
from werkzeug.datastructures import FileStorage
from flask_wtf import CSRFProtect
import uuid

# === App Initialization ===
app = Flask(__name__)
app.config.from_object(Config)

# === Extensions Init ===
db.init_app(app)
login_manager.init_app(app)
migrate.init_app(app, db)
login_manager.login_view = 'login'
csrf = CSRFProtect()
csrf.init_app(app)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data,
                        password=hashed_pw, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_profile():
    form = GuardianProfileForm(obj=current_user) if current_user.role == 'guardian' else TutorProfileForm(obj=current_user)

    # ⚠️ You must populate SelectField choices before calling validate_on_submit()
    form.division_id.choices = [(d.id, d.name) for d in Division.query.all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.all()]
    form.upazila_id.choices = [(u.id, u.name) for u in Upazila.query.all()]

    if form.validate_on_submit():
        current_user.phone_number = form.phone_number.data
        current_user.address = form.address.data
        current_user.division_id = form.division_id.data
        current_user.district_id = form.district_id.data
        current_user.upazila_id = form.upazila_id.data

        # Profile Picture Handling
        if isinstance(form.profile_picture.data, FileStorage) and form.profile_picture.data.filename:
            picture_file = form.profile_picture.data
            if allowed_file(picture_file.filename):
                filename = f"{uuid.uuid4().hex}_{secure_filename(picture_file.filename)}"
                picture_path = os.path.join(current_app.root_path, 'static/uploads', filename)
                picture_file.save(picture_path)
                current_user.profile_picture = filename
            else:
                flash('Invalid file type for profile picture. Allowed: png, jpg, jpeg, gif.', 'danger')
                return redirect(request.url)
        # Handle NID / Birth Certificate
        if isinstance(form.NID_Birth_Certificate.data, FileStorage) and form.NID_Birth_Certificate.data.filename:
            cert_file = form.NID_Birth_Certificate.data
            if allowed_file(cert_file.filename):  # use your existing allowed_file()
                cert_filename = f"{uuid.uuid4().hex}_{secure_filename(cert_file.filename)}"
                cert_path = os.path.join(current_app.root_path, 'static/uploads', cert_filename)
                cert_file.save(cert_path)
                current_user.NID_Birth_Certificate = cert_filename
            else:
                flash('Invalid file type for certificate. Allowed: png, jpg, jpeg, gif, pdf.', 'danger')
                return redirect(request.url)


        # Role-specific
        if current_user.role == 'guardian':
            current_user.student_name = form.student_name.data
            current_user.student_class = ','.join(form.student_class.data)
            current_user.student_school = form.student_school.data
            current_user.subjects = form.subjects.data
            current_user.preferred_gender = form.preferred_gender.data
            current_user.medium = form.medium.data
            current_user.salary = form.salary.data
        else:
            current_user.education = form.education.data
            current_user.subjects = ','.join(form.subjects.data)
            current_user.experience = form.experience.data
            current_user.institution = form.institution.data
            current_user.qualifications = form.qualifications.data
            current_user.preferred_classes = form.preferred_classes.data
            current_user.salary_expectation = form.salary_expectation.data
            current_user.time_slots = form.time_slots.data
            current_user.available_days = ','.join(form.available_days.data)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    if request.method == 'GET' and current_user.role == 'guardian' and current_user.student_class:
        form.student_class.data = [x.strip() for x in current_user.student_class.split(',') if x.strip()]
    if request.method == 'GET' and current_user.available_days:
        form.available_days.data = [d.strip() for d in current_user.available_days.split(',')]

    return render_template('update_profile.html', form=form, role=current_user.role)

@app.route('/tutor-request', methods=['GET', 'POST'])
@login_required
def tutor_request():
    if current_user.role != 'guardian':
        flash('Only guardians can post tutor requests.', 'warning')
        return redirect(url_for('dashboard'))

    form = TutorRequestForm()

    if request.method == 'GET':
        # Optionally pre-fill phone_number from user profile
        form.phone_number.data = current_user.phone_number

    if form.validate_on_submit():
        # Save data
        tr = TutorRequest(
            user_id=current_user.id,
            students_number=form.students_number.data,
            student_classes=','.join(form.student_classes.data),
            teaching_medium=form.teaching_medium.data,
            subjects=','.join(form.subjects.data),
            starting_date=form.starting_date.data,
            preferred_days=','.join(form.preferred_days.data),
            teaching_time=form.teaching_time.data,
            salary=form.salary.data,
            address_text=form.address_text.data,
            latitude=form.latitude.data,
            longitude=form.longitude.data,
            phone_number=form.phone_number.data,
            preferred_tutor_gender=form.preferred_tutor_gender.data,
            # created_at handled automatically
        )
        db.session.add(tr)
        db.session.commit()
        flash('Tutor request posted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('tutor_request.html', form=form)


@app.route('/districts/<int:division_id>')
def get_districts(division_id):
    districts = District.query.filter_by(division_id=division_id).all()
    return jsonify([(d.id, d.name) for d in districts])

@app.route('/upazilas/<int:district_id>')
def get_upazilas(district_id):
    upazilas = Upazila.query.filter_by(district_id=district_id).all()
    return jsonify([(u.id, u.name) for u in upazilas])


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)
