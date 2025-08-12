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
from sqlalchemy import or_

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
        current_user.gender = form.gender.data

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
            current_user.is_seeking_tuition = 'is_seeking_tuition' in request.form

            current_user.education = form.education.data
            current_user.subjects = ','.join(form.subjects.data)
            current_user.experience = form.experience.data
            
            current_user.qualifications = form.qualifications.data
            current_user.preferred_classes = ','.join(form.preferred_classes.data)

            current_user.salary_expectation = form.salary_expectation.data
            print("Time slots submitted:", request.form.get('time_slots'))

            slots_raw = request.form.get('time_slots', '')
            slots_cleaned = ', '.join([s.strip() for s in slots_raw.split(',') if s.strip()])
            current_user.time_slots = slots_cleaned
            print(current_user.time_slots if current_user.time_slots else "No time slots provided")
            current_user.available_days = ','.join(form.available_days.data)
            def handle_cert_upload(file_field):
                if isinstance(file_field.data, FileStorage) and file_field.data.filename:
                    if allowed_file(file_field.data.filename):
                        filename = f"{uuid.uuid4().hex}_{secure_filename(file_field.data.filename)}"
                        path = os.path.join(current_app.root_path, 'static/uploads', filename)
                        file_field.data.save(path)
                        return filename
                    else:
                        flash('Invalid certificate file type.', 'danger')
                return None

            
            current_user.ssc_institute = form.ssc_institute.data
            current_user.ssc_result = form.ssc_result.data
            current_user.ssc_group = form.ssc_group.data
            current_user.ssc_certificate = handle_cert_upload(form.ssc_certificate) or current_user.ssc_certificate

            current_user.hsc_institute = form.hsc_institute.data
            current_user.hsc_result = form.hsc_result.data      
            current_user.hsc_group = form.hsc_group.data
            current_user.hsc_certificate = handle_cert_upload(form.hsc_certificate) or current_user.hsc_certificate
            current_user.graduation_institute = form.graduation_institute.data
            current_user.graduation_result = form.graduation_result.data
            current_user.graduation_subject = form.graduation_subject.data
            current_user.graduation_certificate = handle_cert_upload(form.graduation_certificate) or current_user.graduation_certificate
                # Handle SSC, HSC, Graduation certificates
                # Repeat for HSC and Graduation


        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    if request.method == 'GET' and current_user.role == 'guardian' and current_user.student_class:
        form.student_class.data = [x.strip() for x in current_user.student_class.split(',') if x.strip()]
    if request.method == 'GET' and current_user.available_days:
        form.available_days.data = [d.strip() for d in current_user.available_days.split(',')]
        form.preferred_classes.data = [c.strip() for c in current_user.preferred_classes.split(',') if c.strip()]

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


@app.route('/api/search_tutors', methods=['GET'])
def search_tutors():
    division_id = request.args.get('division_id', type=int)
    district_id = request.args.get('district_id', type=int)
    upazila_id = request.args.get('upazila_id', type=int)
    preferred_classes = request.args.getlist('preferred_classes')
    subjects = request.args.getlist('subjects')
    available_days = request.args.getlist('available_days')

    query = User.query.filter_by(role='tutor', is_seeking_tuition=True)

    if division_id:
        query = query.filter_by(division_id=division_id)
    if district_id:
        query = query.filter_by(district_id=district_id)
    if upazila_id:
        query = query.filter_by(upazila_id=upazila_id)

    # Partial match filters using OR logic
    if subjects:
        subject_filters = [User.subjects.ilike(f"%{s}%") for s in subjects]
        query = query.filter(or_(*subject_filters))

    if preferred_classes:
        class_filters = [User.preferred_classes.ilike(f"%{c}%") for c in preferred_classes]
        query = query.filter(or_(*class_filters))

    if available_days and 'Any' not in available_days:
        day_filters = [User.available_days.ilike(f"%{d}%") for d in available_days]
        query = query.filter(or_(*day_filters))

    tutors = query.all()

    def calculate_score(tutor):
        score = 0
        if tutor.subjects and subjects:
            score += sum(1 for s in subjects if s.lower() in tutor.subjects.lower())
        if tutor.preferred_classes and preferred_classes:
            score += sum(1 for c in preferred_classes if c.lower() in tutor.preferred_classes.lower())
        if tutor.available_days and available_days and 'Any' not in available_days:
            score += sum(1 for d in available_days if d.lower() in tutor.available_days.lower())
        return score


    sorted_tutors = sorted(tutors, key=calculate_score, reverse=True)
    

    results = []
    for tutor in sorted_tutors:
        results.append({
            'id': tutor.id,
            'name': tutor.username,
            'profile_picture': url_for('static', filename='uploads/' + tutor.profile_picture) if tutor.profile_picture else None,
            'subjects': tutor.subjects,
            'preferred_classes': tutor.preferred_classes,
            'time_slots': tutor.time_slots,
            'available_days': tutor.available_days,
            'experience': tutor.experience,
            'division': tutor.division.name if tutor.division else None,
            'district': tutor.district.name if tutor.district else None,
            'upazila': tutor.upazila.name if tutor.upazila else None,
            'education': tutor.education,
            'salary_expectation': tutor.salary_expectation,
        })

    return jsonify(results)

@app.route('/api/tutor/<int:tutor_id>')
def get_tutor_profile(tutor_id):
    tutor = User.query.get_or_404(tutor_id)
    return jsonify({
        'id': tutor.id,
        'profile_picture': url_for('static', filename='uploads/' + tutor.profile_picture) if tutor.profile_picture else None,
        'username': tutor.username,
        'email': tutor.email,
        'gender': tutor.gender,
        'phone': tutor.phone_number,
        'division': tutor.division.name if tutor.division else '',
        'district': tutor.district.name if tutor.district else '',
        'upazila': tutor.upazila.name if tutor.upazila else '',
        'preferred_classes': tutor.preferred_classes,
        'ssc': {
            'institute': tutor.ssc_institute,
            'result': tutor.ssc_result,
            'group': tutor.ssc_group
        },
        'hsc': {
            'institute': tutor.hsc_institute,
            'result': tutor.hsc_result,
            'group': tutor.hsc_group
        },
        'graduation': {
            'institute': tutor.graduation_institute,
            'result': tutor.graduation_result,
            'group': tutor.graduation_subject
        }
    })

@app.route('/api/search_tuition_requests')
@login_required
def search_tuition_requests():
    division_id = request.args.get('division_id')
    district_id = request.args.get('district_id')

    query = db.session.query(
        TutorRequest,
        District.name.label("district"),
        Division.name.label("division")
    ).select_from(TutorRequest)\
     .join(User, TutorRequest.user_id == User.id)\
     .join(Upazila, Upazila.id == User.upazila_id)\
     .join(District, District.id == Upazila.district_id)\
     .join(Division, Division.id == District.division_id)

    if division_id:
        query = query.filter(Division.id == division_id)
    if district_id:
        query = query.filter(District.id == district_id)

    requests = query.order_by(TutorRequest.created_at.desc()).all()

    def serialize_request(row):
        request, district, division = row
        return {
            'id': request.id,
            'subjects': request.subjects,
            'student_classes': request.student_classes,
            'teaching_medium': request.teaching_medium,
            'preferred_days': request.preferred_days,
            'teaching_time': request.teaching_time,
            'salary': request.salary,
            'address_text': request.address_text,
            'preferred_tutor_gender': request.preferred_tutor_gender,
            'district': district,
            'division': division,
        }

    return jsonify([serialize_request(r) for r in requests])



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
    divisions = Division.query.all()
    return render_template('dashboard.html', user=current_user, divisions=divisions)


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
