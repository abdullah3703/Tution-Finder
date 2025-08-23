from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask import current_app
from config import Config
from extensions import db, login_manager, migrate
from models import User, Division, District, Upazila, TutorRequest, Notification, ConfirmedTuition, TutorResponse, ReportToAdmin
from datetime import datetime, timezone, timedelta
from collections import Counter
from forms import RegisterForm, LoginForm, GuardianProfileForm, TutorProfileForm, TutorRequestForm
from werkzeug.datastructures import FileStorage
from flask_wtf import CSRFProtect
import uuid
from sqlalchemy import case, func, or_, and_, desc
from flask_socketio import SocketIO, emit, join_room
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import aliased


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
        if user and check_password_hash(user.password, form.password.data) and not user.is_admin:
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

    if request.method == 'GET':
        # Set multi-select data from comma-separated strings
        if current_user.subjects:
            form.subjects.data = [x.strip() for x in current_user.subjects.split(',') if x.strip()]
        if current_user.preferred_classes:
            form.preferred_classes.data = [x.strip() for x in current_user.preferred_classes.split(',') if x.strip()]
        if current_user.available_days:
            form.available_days.data = [x.strip() for x in current_user.available_days.split(',') if x.strip()]
        if current_user.student_class:
            form.student_class.data = [x.strip() for x in current_user.student_class.split(',') if x.strip()]

        # Set radios
        if current_user.preferred_gender:
            form.preferred_gender.data = current_user.preferred_gender

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
            current_user.subjects = ','.join([s.strip() for s in form.subjects.data if s.strip()])

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
            'is_verified': tutor.is_verified,
            'email_verified': tutor.email_verified,
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

    # Include guardian (User) fields in selected columns
    query = db.session.query(
        TutorRequest,
        District.name.label("district"),
        Division.name.label("division"),
        User.id.label("guardian_id"),
        User.username.label("guardian_name")
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
        r = req[0]  # TutorRequest object
        if r.subjects and subjects:
            score += sum(1 for s in subjects if s.lower() in r.subjects.lower())
        if r.student_classes and preferred_classes:
            score += sum(1 for c in preferred_classes if c.lower() in r.student_classes.lower())
        if r.preferred_days and available_days and 'Any' not in available_days:
            score += sum(1 for d in available_days if d.lower() in r.preferred_days.lower())
        return score

    sorted_results = sorted(results, key=calculate_score, reverse=True)

    def serialize_request(row):
        request, district, division, guardian_id, guardian_name = row
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
            'guardian_id': guardian_id,
            'guardian_name': guardian_name
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

@app.route('/api/send_tuition_response/<int:request_id>', methods=['POST'])
@login_required
def send_tuition_response(request_id):
    if current_user.email_verified is False:
        flash('Please verify your Email first!')
        return redirect(url_for('dashboard'))
    tutor_request = TutorRequest.query.get(request_id)
    if not tutor_request:
        return jsonify({'error': 'Tuition request not found'}), 404

    # Prevent same tutor from sending duplicate response
    existing = TutorResponse.query.filter_by(
        tutor_id=current_user.id, request_id=request_id
    ).first()
    if existing:
        return jsonify({'error': 'You have already responded to this request'}), 400

    # Create TutorResponse
    response = TutorResponse(
        tutor_id=current_user.id,
        request_id=request_id
    )
    db.session.add(response)

    # Create Notification for guardian
    notification = Notification(
        user_id=tutor_request.user_id,  # Guardian
        message=f"{current_user.username} has sent their details for your tuition request: {tutor_request.subjects}",
        link=f"/guardian/tuition_request/{request_id}"
    )
    db.session.add(notification)
    db.session.commit()

    # Emit notification to guardian
    socketio.emit("new_notification", {
        "id": notification.id,
        "message": notification.message,
        "link": notification.link,
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notification.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_request.user_id}")

    return jsonify({'success': True})

@app.route('/guardian/tuition_request/<int:request_id>')
@login_required
def guardian_tuition_request(request_id):
    req = TutorRequest.query.get(request_id)
    if not req or req.user_id != current_user.id:
        flash('You do not have permission to view this request.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('guardian_tuition_request.html', request=req)

@app.route('/guardian/select_tutor/<int:request_id>/<int:tutor_id>', methods=['POST'])
@login_required
def select_tutor(request_id, tutor_id):
    req = TutorRequest.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    tution_days = data.get('tution_days')
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')

    if not tution_days or not start_time_str or not end_time_str:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # Convert times to datetime.time
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
    end_time = datetime.strptime(end_time_str, "%H:%M").time()

    # Clash check
    existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=tutor_id).all()
    for tuition in existing_tuitions:
        existing_days = [d.strip() for d in (tuition.tution_days or '').split(',') if d is not None]
        if any(day in existing_days for day in tution_days.split(', ')):
            # None checker for start_time and end_time
            if tuition.start_time is not None and tuition.end_time is not None and start_time is not None and end_time is not None:
                if not (end_time <= tuition.start_time.time() or start_time >= tuition.end_time.time()):
                    return jsonify({'success': False, 'message': 'Schedule clash detected with existing tuition.'}), 400
                

    tuition_id = generate_tuition_id()

    confirmed = ConfirmedTuition(
        id=tuition_id,
        guardian_id=current_user.id,
        tutor_id=tutor_id,
        
        
        student_classes=req.student_classes,
        subjects=req.subjects,
        preferred_days=req.preferred_days,
        
        address=req.address_text,
        latitude=req.latitude,
        longitude=req.longitude,
        tution_days=tution_days,
        start_time=datetime.combine(datetime.today(), start_time),
        end_time=datetime.combine(datetime.today(), end_time)
    )
    db.session.add(confirmed)

    TutorResponse.query.filter_by(request_id=request_id).delete()
    db.session.delete(req)

    Notification.query.filter_by(
        user_id=current_user.id,
        link=f"/guardian/tuition_request/{request_id}"
    ).delete()

    notify = Notification(
        user_id=tutor_id,
        message=f"You have been selected for tuition {tuition_id}.",
        link=f"/tuitions/{tuition_id}"
    )
    db.session.add(notify)
    db.session.commit()

    socketio.emit("new_notification", {
        "id": notify.id,
        "message": notify.message,  
        "link": notify.link,
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notify.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_id}")

    return jsonify({'success': True, 'message': 'Tutor selected and tuition confirmed!'})

@app.route('/tuitions/<tuition_id>')
@login_required
def view_tuition(tuition_id):
    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    if current_user.id not in [tuition.guardian_id, tuition.tutor_id]:
        flash('You do not have permission to view this tuition.', 'danger')
        return redirect(url_for('dashboard'))

    guardian = User.query.get(tuition.guardian_id)
    tutor = User.query.get(tuition.tutor_id)

    return render_template('tuition_info.html', tuition=tuition, guardian=guardian, tutor=tutor)


@app.route('/send_tutor_request', methods=['POST'])
@login_required
def send_tutor_request():
    if not current_user.email_verified:
        return jsonify({"status": "error", "message": "Please verify your email before sending a tutor request."}), 400

    tutor_id = request.form['tutor_id']
    preferred_days = request.form.getlist('preferred_days')
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')

    if not start_time or not end_time:
        return jsonify({"status": "error", "message": "Start and end time are required."}), 400

    teaching_time = f"{start_time},{end_time}"

    # 1. Check for schedule clash
    existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=tutor_id).all()
    for tuition in existing_tuitions:
        tuition_days = tuition.preferred_days.split(',') if tuition.preferred_days else []
        tuition_start = None
        tuition_end = None
        if tuition.start_time and tuition.end_time:
            tuition_start = tuition.start_time.time()
            tuition_end = tuition.end_time.time()

        # Only check overlap if both times exist
        if tuition_start and tuition_end:
            if set(preferred_days) & set(tuition_days):
               

                fmt = "%H:%M"
                req_start = datetime.strptime(start_time, fmt).time()
                req_end = datetime.strptime(end_time, fmt).time()

                # Check time overlap condition
                if (req_start < tuition_end and req_end > tuition_start):
                    return jsonify({"status": "error", "message": "Schedule conflict with tutor's existing classes."}), 400


    # 2. Save new request
    new_request = TutorRequest(
        tutor_id=tutor_id,
        user_id=current_user.id,
        student_classes=','.join(request.form.getlist('student_classes')),
        subjects=','.join(request.form.getlist('subjects')),
        preferred_days=','.join(preferred_days),
        teaching_time=teaching_time,
        latitude=request.form.get('lat', 0.0),
        longitude=request.form.get('lng', 0.0),
        address_text=request.form.get('address', ''),
        phone_number=current_user.phone_number
    )
    db.session.add(new_request)
    db.session.commit()

    # 3. Notify tutor
    notification = Notification(
        user_id=tutor_id,
        message=f"New tutor request from {current_user.username}",
        link=url_for('tutor_requests', request_id=new_request.id),
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()

    socketio.emit("new_notification", {
        "id": notification.id,
        "message": notification.message,
        "link": notification.link,
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notification.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_id}")

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

    req = TutorRequest.query.get_or_404(request_id)

    if req.tutor_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    if req.status != 'pending':
        return jsonify({'status': 'error', 'message': 'Already responded'}), 400

    # Parse start_time and end_time from req.teaching_time (comma separated string)
    try:
        start_time_str, end_time_str = (req.teaching_time or "").split(',', 1)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid teaching_time format in request.'}), 400

    try:
        fmt = "%H:%M"
        req_start_time = datetime.strptime(start_time_str.strip(), fmt).time()
        req_end_time = datetime.strptime(end_time_str.strip(), fmt).time()
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid time format in teaching_time. Use HH:MM'}), 400

    if response == 'accept':
        # Check for schedule clash with existing confirmed tuitions for this tutor
        existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=current_user.id).all()
        req_days_set = set([d.strip().lower() for d in (req.preferred_days or '').split(',')])

        for tuition in existing_tuitions:
            tuition_days_set = set([d.strip().lower() for d in (tuition.tution_days or '').split(',')])
            if req_days_set & tuition_days_set:
                if tuition.start_time and tuition.end_time:
                    tuition_start = tuition.start_time.time()
                    tuition_end = tuition.end_time.time()

                    if (req_start_time < tuition_end and req_end_time > tuition_start):
                        return jsonify({'status': 'error', 'message': 'Schedule conflict with existing confirmed tuition.'}), 400

        # Accept this request and reject others
        req.status = 'accepted'

        similar_requests = TutorRequest.query.filter(
            TutorRequest.user_id == req.user_id,
            TutorRequest.tutor_id != None,
            TutorRequest.status.in_(['pending', 'accepted'])
        ).all()

        for r in similar_requests:
            if r.id != req.id and r.status == 'pending':
                r.status = 'rejected'

        confirmed = ConfirmedTuition(
            id=generate_tuition_id(),
            guardian_id=req.user_id,
            tutor_id=current_user.id,
            student_classes=req.student_classes,
            subjects=req.subjects,
            preferred_days=req.preferred_days,
            tution_days=req.preferred_days,
            address=req.address_text,
            latitude=req.latitude,
            longitude=req.longitude,
            start_time=datetime.combine(datetime.now(timezone.utc).date(), req_start_time),
            end_time=datetime.combine(datetime.now(timezone.utc).date(), req_end_time),
            created_at=datetime.now(timezone.utc)
        )

        notif = Notification(
            user_id=req.user_id,
            message="Your tuition request has been accepted by a tutor.",
            link=url_for('view_tuition', tuition_id=confirmed.id)
        )

        db.session.add(confirmed)
        db.session.add(notif)
        db.session.delete(req)
        db.session.commit()

        socketio.emit("new_notification", {
            "id": notif.id,
            "message": notif.message,
            "link": notif.link,
            "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
             "timestamp": notif.timestamp.strftime('%b %d, %Y %I:%M %p')
        }, room=f"user_{req.user_id}")

        flash('Tuition accepted and confirmed.', 'success')
        return redirect(url_for('dashboard'))

    else:
        req.status = 'rejected'
        db.session.commit()
        flash('Tuition request rejected.', 'warning')

    return redirect(url_for('dashboard'))


@app.route('/tutor_requests')
@login_required
def tutor_requests():
    requests = TutorRequest.query.filter_by(tutor_id=current_user.id, status='pending').all()
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
    today_name = datetime.now().strftime('%A')

    guardian_active = ConfirmedTuition.query.filter_by(guardian_id=current_user.id).all()
    tutor_active = ConfirmedTuition.query.filter_by(tutor_id=current_user.id).all()

    def attach_users(tuitions):
        for t in tuitions:
            t.tutor = User.query.get(t.tutor_id)
            t.guardian = User.query.get(t.guardian_id)
        return tuitions

    guardian_active = attach_users(guardian_active)
    tutor_active = attach_users(tutor_active)

    def filter_today(tuitions):
        return [
            t for t in tuitions
            if today_name in [d.strip() for d in (t.tution_days or "").split(',') if d.strip()]
        ]

    todays_guardian = filter_today(guardian_active)
    todays_tutor = filter_today(tutor_active)

    

    active_tutor_requests = []
    if current_user.role == 'guardian':
        active_tutor_requests = (
            TutorRequest.query
            .filter_by(user_id=current_user.id)
            .filter(TutorRequest.status != 'found')
            .order_by(TutorRequest.created_at.desc())
            .all()
        )

    return render_template(
        'dashboard.html',
        user=current_user,
        divisions=divisions,
        guardian_active=guardian_active,
        tutor_active=tutor_active,
        todays_guardian=todays_guardian,
        todays_tutor=todays_tutor,
        today_name=today_name,
        
        active_tutor_requests=active_tutor_requests
    )

@app.route('/delete_tutor_request/<int:request_id>', methods=['POST'])
@login_required
def delete_tutor_request(request_id):
    req = TutorRequest.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    db.session.delete(req)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Request deleted'})

@app.route('/edit_tutor_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def edit_tutor_request(request_id):
    tutor_request = TutorRequest.query.get_or_404(request_id)

    if tutor_request.user_id != current_user.id:
        flash('You are not authorized to edit this request.', 'danger')
        return redirect(url_for('dashboard'))

    form = TutorRequestForm()

    if request.method == 'GET':
        # Convert comma-separated strings to lists
        form = TutorRequestForm(
            students_number=tutor_request.students_number,
            student_classes=tutor_request.student_classes.split(',') if tutor_request.student_classes else [],
            teaching_medium=tutor_request.teaching_medium,
            subjects=tutor_request.subjects.split(',') if tutor_request.subjects else [],
            starting_date=tutor_request.starting_date,
            preferred_days=tutor_request.preferred_days.split(',') if tutor_request.preferred_days else [],
            teaching_time=tutor_request.teaching_time,
            salary=tutor_request.salary,
            phone_number=tutor_request.phone_number,
            preferred_tutor_gender=tutor_request.preferred_tutor_gender,
            address_text=tutor_request.address_text,
            latitude=tutor_request.latitude,
            longitude=tutor_request.longitude
        )

    if form.validate_on_submit():
        tutor_request.students_number = form.students_number.data
        tutor_request.student_classes = ','.join(form.student_classes.data)
        tutor_request.teaching_medium = form.teaching_medium.data
        tutor_request.subjects = ','.join(form.subjects.data)
        tutor_request.starting_date = form.starting_date.data
        tutor_request.preferred_days = ','.join(form.preferred_days.data)
        tutor_request.teaching_time = form.teaching_time.data
        tutor_request.salary = form.salary.data
        tutor_request.phone_number = form.phone_number.data
        tutor_request.preferred_tutor_gender = form.preferred_tutor_gender.data
        tutor_request.address_text = form.address_text.data
        tutor_request.latitude = form.latitude.data
        tutor_request.longitude = form.longitude.data

        db.session.commit()
        flash('Tutor request updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_tutor_request.html', form=form, tutor_request=tutor_request)





@app.route('/request_tuition_delete/<tuition_id>', methods=['POST'])
@login_required
def request_tuition_delete(tuition_id):
    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    if current_user.id not in (tuition.guardian_id, tuition.tutor_id):
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    # Toggle cancel request
    if tuition.delete_requested and tuition.delete_requested_by == current_user.id:
        tuition.delete_requested = False
        tuition.delete_requested_by = None
        tuition.delete_requested_at = None
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Delete request cancelled.'})

    # Create delete request
    tuition.delete_requested = True
    tuition.delete_requested_by = current_user.id
    tuition.delete_requested_at = datetime.now(timezone.utc)
    db.session.commit()

    # Determine recipient (the other party)
    recipient_id = tuition.guardian_id if current_user.id == tuition.tutor_id else tuition.tutor_id

    # Create notification
    notif = Notification(
        user_id=recipient_id,
        message=f"{current_user.username} has requested to delete a tuition.",
        link="/dashboard"
    )
    db.session.add(notif)
    db.session.commit()

    # Emit socket notification to recipient
    socketio.emit(
        'new_notification',
        {   
            'id' : notif.id,
            'message': notif.message,
            'link': notif.link,
            
            "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
            "timestamp": notif.timestamp.strftime('%b %d, %Y %I:%M %p')
        },
        room=f"user_{recipient_id}"
    )

    return jsonify({'status': 'success', 'message': 'Delete request sent to the other party.'})


@app.route('/respond_tuition_delete/<tuition_id>', methods=['POST'])
@login_required
def respond_tuition_delete(tuition_id):
    action = (request.json or request.form).get('action')
    if action not in ('approve', 'reject'):
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400

    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    if not tuition.delete_requested:
        return jsonify({'status': 'error', 'message': 'No pending delete request.'}), 400

    # Only the other party can respond
    if current_user.id == tuition.delete_requested_by:
        return jsonify({'status': 'error', 'message': "Requester can't respond."}), 403

    requester_id = tuition.delete_requested_by

    if action == 'approve':
        db.session.delete(tuition)
        db.session.commit()

        notif_msg = f"{current_user.username} approved your delete request for tuition {tuition.id}."
        notif_link = "/dashboard"
    else:
        tuition.delete_requested = False
        tuition.delete_requested_by = None
        tuition.delete_requested_at = None
        db.session.commit()

        notif_msg = f"{current_user.username} rejected your delete request for tuition {tuition.id}."
        notif_link = f"/tuitions/{tuition.id}"

    # Create notification
    notif = Notification(
        user_id=requester_id,
        message=notif_msg,
        link=notif_link
    )
    db.session.add(notif)
    db.session.commit()

    # Emit socket notification to requester
    socketio.emit(
        'new_notification',
        {   
            'id' : notif.id,
            'message': notif.message,
            'link': notif.link,
            "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                     if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
            "timestamp": notif.timestamp.strftime('%b %d, %Y %I:%M %p')
        },
        room=f"user_{requester_id}"
    )

    return jsonify({'status': 'success', 'message': notif.message})



@app.route("/view_profile/<int:user_id>")
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)

    # Restrict to opposite roles or allow admin
    if current_user.role == user.role and not current_user.is_admin:
        abort(403)

    

    # Query active TutorRequests if guardian
    active_tutor_requests = []
    if user.role == "guardian":
        active_tutor_requests = TutorRequest.query.filter_by(user_id=user.id, status='pending').all()

    # Query confirmed tuitions either guardian or tutor
    confirmed_tuitions = []
    if user.role == "guardian":
        confirmed_tuitions = ConfirmedTuition.query.filter_by(guardian_id=user.id).all()
    elif user.role == "tutor":
        confirmed_tuitions = ConfirmedTuition.query.filter_by(tutor_id=user.id).all()

    return render_template(
        "view_profile.html",
        profile_user=user,
        active_tutor_requests=active_tutor_requests,
        confirmed_tuitions=confirmed_tuitions,
    )


@app.route('/report', methods=['POST'])
@login_required
def report_to_admin():
    reported_user_id = request.form.get('reported_user_id')
    report_type = request.form.get('report_type')
    description = request.form.get('description')

    if not report_type:
        flash("Please select a reason for reporting.", "danger")
        return redirect(request.referrer)

    report = ReportToAdmin(
        reporter_id=current_user.id,
        reported_user_id=reported_user_id,
        report_type=report_type,
        description=description,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(report)
    db.session.commit()

    flash("Your report has been submitted to the admin.", "success")
    return redirect(request.referrer)

@app.route('/report_tuition_request', methods=['POST'])
@login_required
def report_tuition_request():
    from datetime import datetime, timezone
    reported_request_id = request.form.get('reported_request_id')
    report_type = request.form.get('report_type')
    description = request.form.get('description')

    if not reported_request_id or not report_type:
        flash("Invalid report submission.", "danger")
        return redirect(request.referrer)

    new_report = ReportToAdmin(
        reporter_id=current_user.id,
        reported_request_id=reported_request_id,
        report_type=report_type,
        description=description,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(new_report)
    db.session.commit()

    flash("Your report has been submitted to the admin.", "success")
    return redirect(request.referrer)


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

        # Core lists
    guardians = User.query.filter_by(role='guardian').all()
    tutors = User.query.filter_by(role='tutor').all()
    reported_profiles = ReportToAdmin.query.filter(
        ReportToAdmin.reported_user_id.isnot(None)
    ).all()
    reported_posts = ReportToAdmin.query.filter(
        ReportToAdmin.reported_request_id.isnot(None)
    ).all()

    # Analytics - new
    # If you have a last_login field, use this; otherwise, skip or replace with other metric
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        active_users_count = User.query.filter(User.last_login >= thirty_days_ago).count()
    except AttributeError:
        # Fallback if you do not store last_login
        active_users_count = User.query.count()

    tuition_requests_count = TutorRequest.query.count()
    tutor_count = len(tutors)
    tutor_request_ratio = (
        f"{tutor_count}:{tuition_requests_count}"
        if tuition_requests_count
        else f"{tutor_count}:0"
    )

    demand_by_division = Counter(
        r.user.division.name
        for r in TutorRequest.query.join(User, TutorRequest.user_id == User.id).all()
        if r.user and r.user.division
    )


    return render_template(
        'admin_dashboard.html',
        guardians=guardians,
        tutors=tutors,
        reported_profiles=reported_profiles,
        reported_posts=reported_posts,
        active_users_count=active_users_count,
        tutor_request_ratio=tutor_request_ratio,
        demand_by_division=demand_by_division
    )

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(request.referrer)

@app.route('/admin/delete_post/<int:request_id>', methods=['POST'])
@login_required
def admin_delete_post(request_id):
    if not current_user.is_admin:
        abort(403)
    post = TutorRequest.query.get_or_404(request_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(request.referrer)


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

@app.route("/remove_report/<int:report_id>", methods=["POST"])
@login_required
def remove_report(report_id):
    if not current_user.is_admin:
        abort(403)

    report = ReportToAdmin.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash("Report removed successfully.", "success")
    return redirect(request.referrer or url_for("admin_dashboard"))

@app.route("/add_admin", methods=["GET", "POST"])
@login_required
def add_admin():
    if not current_user.is_admin:
        abort(403)

    if request.method == "POST":
        user_id = request.form.get("user_id")
        user = User.query.get_or_404(user_id)
        user.is_admin = True
        db.session.commit()
        flash(f"{user.username} is now an admin!", "success")
        return redirect(url_for("admin_dashboard"))

    all_users = User.query.all()
    return render_template("add_admin.html", users=all_users)



@app.route("/create_admin", methods=["POST"])
@login_required
def create_admin():
    if not current_user.is_admin:
        abort(403)

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("User with this username or email already exists.", "danger")
        return redirect(url_for("add_admin"))

    new_admin = User(
        username=username,
        email=email,
        password=generate_password_hash(password),
        role="guardian",   # default role, but flagged admin
        is_admin=True
    )
    db.session.add(new_admin)
    db.session.commit()
    flash(f"New admin {username} created!", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/remove_admin/<int:user_id>", methods=["POST"])
@login_required
def remove_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        user.is_admin = False
        db.session.commit()
        flash(f"{user.username} is no longer an admin.", "success")
    else:
        flash(f"{user.username} is not an admin.", "warning")

    return redirect(request.referrer or url_for("admin_dashboard"))

@app.route("/manage_admins")
@login_required
def manage_admins():
    if not current_user.is_admin:
        abort(403)

    admins = User.query.filter_by(is_admin=True).all()
    return render_template("manage_admins.html", admins=admins)


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
