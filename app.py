from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask import current_app
from config import Config
from extensions import db, login_manager, migrate
from models import User, Division, District, Upazila, TutorRequest, Notification, TutorRequestInbox, ConfirmedTuition
from datetime import datetime
from forms import RegisterForm, LoginForm, GuardianProfileForm, TutorProfileForm, TutorRequestForm
from werkzeug.datastructures import FileStorage
from flask_wtf import CSRFProtect
import uuid
from sqlalchemy import or_
from flask_socketio import SocketIO, emit, join_room
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

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
socketio = SocketIO(app, cors_allowed_origins='*')
mail = Mail(app)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@socketio.on('join')
def handle_join(data):
    join_room(f"user_{data['user_id']}")
    print(f"User {data['user_id']} joined room user_{data['user_id']}")

def send_notification(user_id, message, link):
    notif = Notification(user_id=user_id, message=message, link=link)
    db.session.add(notif)
    db.session.commit()
    socketio.emit('new_notification', {
        'id': notif.id,
        'message': message,
        'link': link
    }, room=f"user_{user_id}")

@app.route('/mark_notification_read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)
    if notif.user_id != current_user.id:
        return jsonify({'status': 'unauthorized'}), 403
    notif.is_read = True
    db.session.commit()
    return jsonify({'status': 'success'})

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        all_notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).limit(10).all()
        return dict(all_notifications=all_notifs)
    return dict(all_notifications=[])

def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verify')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verify', max_age=expiration)
    except:
        return False
    return email

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data,
                        password=hashed_pw, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        token = generate_token(new_user.email)
        verify_url = url_for('verify_email', token=token, _external=True)
        html = render_template('verify_email.html', verify_url=verify_url, username=new_user.username)

        msg = Message("Confirm Your Email - TuitionApp", recipients=[new_user.email])
        msg.html = html
        mail.send(msg)

        flash('Registered successfully! Please check your email to verify your account.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/verify_email/<token>')
def verify_email(token):
    email = confirm_token(token)
    if not email:
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Email already verified. Please login.', 'success')
    else:
        user.email_verified = True
        db.session.commit()
        flash('Email verified successfully! You can now log in.', 'success')

    return redirect(url_for('login'))


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

    if current_user.email_verified is False:
        flash('Please verify your email before posting a tutor request.', 'warning')
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

    query = User.query.filter_by(role='tutor', is_seeking_tuition=True, email_verified=True, is_verified=True)

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
    subjects = request.args.get('subjects', '').split(',')
    preferred_classes = request.args.get('student_classes', '').split(',')
    available_days = request.args.get('available_days', '').split(',')

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

    results = query.all()

    def calculate_score(req):
        score = 0
        r = req[0]  # TutorRequest model
        if r.subjects and subjects:
            score += sum(1 for s in subjects if s.lower() in r.subjects.lower())
        if r.student_classes and preferred_classes:
            score += sum(1 for c in preferred_classes if c.lower() in r.student_classes.lower())
        if r.preferred_days and available_days and 'Any' not in available_days:
            score += sum(1 for d in available_days if d.lower() in r.preferred_days.lower())
        return score

    sorted_results = sorted(results, key=calculate_score, reverse=True)

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

    return jsonify([serialize_request(r) for r in sorted_results])


@app.route('/api/get_tuition_details/<int:request_id>')
@login_required
def get_tuition_details(request_id):
    req = db.session.query(
        TutorRequest,
        District.name.label("district"),
        Division.name.label("division")
    ).select_from(TutorRequest)\
     .join(User, TutorRequest.user_id == User.id)\
     .join(Upazila, Upazila.id == User.upazila_id)\
     .join(District, District.id == Upazila.district_id)\
     .join(Division, Division.id == District.division_id)\
     .filter(TutorRequest.id == request_id)\
     .first()

    if not req:
        return jsonify({'error': 'Not found'}), 404

    request, district, division = req
    return jsonify({
        'id': request.id,
        'subjects': request.subjects,
        'student_classes': request.student_classes,
        'teaching_medium': request.teaching_medium,
        'students_number': request.students_number,
        'preferred_days': request.preferred_days,
        'teaching_time': request.teaching_time,
        'salary': request.salary,
        'starting_date': request.starting_date.strftime('%Y-%m-%d'),
        'address_text': request.address_text,
        'phone_number': request.phone_number,
        'preferred_tutor_gender': request.preferred_tutor_gender,
        'latitude': request.latitude,
        'longitude': request.longitude,
        'district': district,
        'division': division
    })
@app.route('/send_tutor_request', methods=['POST'])
@login_required
def send_tutor_request():
    if current_user.email_verified is False:
        flash('Please verify your email before sending a tutor request.', 'warning')
        return redirect(url_for('dashboard'))
    data = request.form
    request_entry = TutorRequestInbox(
        tutor_id=data['tutor_id'],
        guardian_id=current_user.id,
        student_classes=','.join(request.form.getlist('student_classes')),
        subjects=','.join(request.form.getlist('subjects')),
        preferred_days=','.join(request.form.getlist('preferred_days')),
        time_slots=data.get('time_slots', ''),
        latitude=data.get('lat', 0.0),
        longitude=data.get('lng', 0.0),
        guardian_name=data['guardian_name'],
        guardian_contact=data['guardian_contact'],
        address=data.get('address', '')
    )
    db.session.add(request_entry)
    db.session.commit()

    new_notification = Notification(
        user_id=data['tutor_id'],
        message=f"New tutor request from {current_user.username}",
        link=url_for('tutor_requests', request_id=request_entry.id),
        is_read=False
    )
    db.session.add(new_notification)
    db.session.commit()

    # ✅ Use new_notification.id instead of request_entry.id
    socketio.emit("new_notification", {
        "id": new_notification.id,
        "message": new_notification.message,
        "link": new_notification.link
    }, room=f"user_{data['tutor_id']}")

    return jsonify({"status": "success"})

def generate_tuition_id():
    last = ConfirmedTuition.query.order_by(ConfirmedTuition.id.desc()).first()
    if not last:
        return 'T00000001'
    num = int(last.id[1:]) + 1
    return f'T{num:08d}'


def normalize_csv(text):
    return ','.join(sorted([item.strip().lower() for item in text.split(',') if item.strip()]))

@app.route('/respond_tutor_request', methods=['POST'])
@login_required
def respond_tutor_request():
    request_id = request.form.get('request_id')
    response = request.form.get('action')
    
    if response not in ['accept', 'reject']:
        return jsonify({'status': 'error', 'message': 'Invalid response'}), 400

    req = TutorRequestInbox.query.get_or_404(request_id)

    if req.tutor_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    if req.status != 'pending':
        return jsonify({'status': 'error', 'message': 'Already responded'}), 400

    if response == 'accept':
        norm_classes = normalize_csv(req.student_classes)
        norm_subjects = normalize_csv(req.subjects)
        norm_days = normalize_csv(req.preferred_days or '')
        norm_times = normalize_csv(req.time_slots or '')
        norm_address = req.address.strip().lower() if req.address else ''

        all_requests = TutorRequestInbox.query.filter(
            TutorRequestInbox.guardian_id == req.guardian_id,
            TutorRequestInbox.status.in_(['pending', 'accepted'])
        ).all()

        for r in all_requests:
            if r.id == req.id:
                continue
            if (
                normalize_csv(r.student_classes) == norm_classes and
                normalize_csv(r.subjects) == norm_subjects and
                normalize_csv(r.preferred_days or '') == norm_days and
                normalize_csv(r.time_slots or '') == norm_times and
                (r.address.strip().lower() if r.address else '') == norm_address
            ):
                if r.status == 'accepted':
                    return jsonify({'status': 'error', 'message': 'Another tutor has already been accepted'}), 400

        # Accept current request
        req.status = 'accepted'

        # Reject similar pending requests
        for r in all_requests:
            if r.id == req.id:
                continue
            if (
                normalize_csv(r.student_classes) == norm_classes and
                normalize_csv(r.subjects) == norm_subjects and
                normalize_csv(r.preferred_days or '') == norm_days and
                normalize_csv(r.time_slots or '') == norm_times and
                (r.address.strip().lower() if r.address else '') == norm_address and
                r.status == 'pending'
            ):
                r.status = 'rejected'

        # Prepare confirmation and notification **before deleting `req`**
        confirmed = ConfirmedTuition(
            id=generate_tuition_id(),
            guardian_id=req.guardian_id,
            tutor_id=current_user.id,
            guardian_name=req.guardian_name,
            guardian_contact=req.guardian_contact,
            student_classes=req.student_classes,
            subjects=req.subjects,
            preferred_days=req.preferred_days,
            time_slots=req.time_slots,
            address=req.address,
            latitude=req.latitude,
            longitude=req.longitude
        )

        notif = Notification(
            user_id=req.guardian_id,
            message="Your tuition request has been accepted by a tutor.",
            link=url_for('guardian_tuition_info', tuition_id=confirmed.id)
        )

        db.session.add(confirmed)
        db.session.add(notif)
        db.session.delete(req)
        db.session.commit()

        socketio.emit("new_notification", {
            "id": notif.id,
            "message": notif.message,
            "link": notif.link
        }, room=f"user_{req.guardian_id}")

        flash('Tuition accepted and confirmed.', 'success')

    else:
        # Just reject the request
        req.status = 'rejected'
        db.session.commit()
        flash('Tuition request rejected.', 'warning')

    return redirect(url_for('dashboard'))


@app.route('/tuition/<tuition_id>')
@login_required
def guardian_tuition_info(tuition_id):
    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    if current_user.id != tuition.guardian_id:
        return redirect(url_for('dashboard'))
    return render_template('guardian_tuition_info.html', tuition=tuition)


@app.route('/tutor_requests')
@login_required
def tutor_requests():
    requests = TutorRequestInbox.query.filter_by(tutor_id=current_user.id, status='pending').all()
    return render_template("tutor_requests.html", requests=requests)


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

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials or not an admin.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    guardians = User.query.filter_by(role='guardian').all()
    tutors = User.query.filter_by(role='tutor').all()
    return render_template('admin_dashboard.html', guardians=guardians, tutors=tutors)


@app.route('/verify_user/<int:user_id>', methods=['POST'])
@login_required
def verify_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified
    db.session.commit()
    flash(f"{user.username} has been {'verified' if user.is_verified else 'unverified'}.", "success")
    return redirect(url_for('admin_dashboard'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    socketio.run(app, debug=True)
