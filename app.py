from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask import current_app
from config import Config
from extensions import db, login_manager, migrate 
from models import User, Division, District, Upazila, TutorRequest, Notification, ConfirmedTuition, TutorResponse, Feedback, ReportToAdmin, ChatMessage
from datetime import datetime, timezone, timedelta
from collections import Counter
from forms import RegisterForm, LoginForm, GuardianProfileForm, TutorProfileForm, TutorRequestForm #import forms from forms.py
from werkzeug.datastructures import FileStorage
from flask_wtf import CSRFProtect
import uuid
from sqlalchemy import case, func, or_, and_, desc
from flask_socketio import SocketIO, emit, join_room #dynamic update of chat and notification
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import aliased
import math


# === App Initialization ===
app = Flask(__name__)
app.config.from_object(Config)

# === Extensions Initialization ===
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

# 🔹 Flask-Login: loads user object from user_id stored in session cookie
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))   # Retrieves User by primary key

# 🔹 Homepage route → renders home.html
@app.route('/')
def home():
    return render_template('home.html')  # Just serves static homepage template

# 🔹 Socket.IO event: runs when a client "joins"
@socketio.on('join')
def handle_join(data):
    # Each user gets their own private room: "user_<id>"
    join_room(f"user_{data['user_id']}")
    print(f"User {data['user_id']} joined room user_{data['user_id']}")

# 🔹 Marks a specific notification read for the logged-in user
@app.route('/mark_notification_read/<int:notif_id>', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    notif = Notification.query.get_or_404(notif_id)  # 404 if not found
    if notif.user_id != current_user.id:  # Ensure user is owner of notification
        return jsonify({'status': 'unauthorized'}), 403  # Unauthorized
    notif.is_read = True  # Mark as read
    db.session.commit()
    return jsonify({'status': 'success'})  # Returns JSON response {status:success}

# 🔹 Context processor → injects data into ALL templates
@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        # Get latest 10 notifications for logged-in user, newest first
        all_notifs = (Notification.query
                      .filter_by(user_id=current_user.id)
                      .order_by(Notification.timestamp.desc())
                      .limit(10).all())
        return dict(all_notifications=all_notifs)  # Makes {{ all_notifications }} available in templates
    return dict(all_notifications=[])  # If not logged in, provide empty list


@app.route("/get_unread_count", methods=["GET"])
@login_required
def get_unread_count():
    # Count all unread messages where the current user is the recipient
    unread_count = ChatMessage.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    
    return jsonify({"chat_unread": unread_count})

# 🔹 Marks all unread chat messages from 'other_user_id' to the current user as read
@app.route('/mark_chat_read/<int:other_user_id>', methods=['POST'])
@login_required
def mark_chat_read(other_user_id):
    ChatMessage.query.filter_by(sender_id=other_user_id, receiver_id=current_user.id, is_read=False) \
                     .update({'is_read': True})  # Bulk update unread messages to read
    db.session.commit()
    return '', 204  # Returns HTTP 204 No Content (success, no body)

# 🔹 Endpoint to get list of chats with latest messages and unread counts for current user
@app.route('/inject_chats')
@login_required
def inject_chats():
    from sqlalchemy import case, func, or_, and_
    from sqlalchemy.orm import aliased

    Msg = aliased(ChatMessage)

    # Subquery: for each unique chat pair (sorted user IDs), get latest ChatMessage.id
    latest_ids_subq = (
        db.session.query(
            func.least(Msg.sender_id, Msg.receiver_id).label("user1_id"),     # smaller ID in pair
            func.greatest(Msg.sender_id, Msg.receiver_id).label("user2_id"),  # larger ID in pair
            func.max(Msg.id).label("latest_msg_id"),                         # latest message id in that pair
        )
        .filter(or_(
            Msg.sender_id == current_user.id,
            Msg.receiver_id == current_user.id
        ))  # Only chats involving current user
        .group_by(
            func.least(Msg.sender_id, Msg.receiver_id),
            func.greatest(Msg.sender_id, Msg.receiver_id)
        )
        .subquery()
    )

    User1 = aliased(User)  # Alias for first user in pair
    User2 = aliased(User)  # Alias for second user in pair
    LatestMsg = aliased(ChatMessage)

    # Calculates total unread messages where receiver is current user and message is unread
    unread_case = func.sum(
        case(
            (and_(
                ChatMessage.receiver_id == current_user.id,
                ChatMessage.is_read == False
            ), 1),
            else_=0
        )
    ).label('unread_count')

    rows = (
        db.session.query(
            # Determine chat partner ID, the one that is NOT the current user
            func.if_(
                latest_ids_subq.c.user1_id != current_user.id,
                latest_ids_subq.c.user1_id,
                latest_ids_subq.c.user2_id
            ).label("chat_partner_id"),

            # User1 info (id, username, profile picture)
            User1.id.label('u1_id'),
            User1.username.label('u1_username'),
            User1.profile_picture.label('u1_picture'),

            # User2 info (id, username, profile picture)
            User2.id.label('u2_id'),
            User2.username.label('u2_username'),
            User2.profile_picture.label('u2_picture'),

            # Latest message content and image
            LatestMsg.message,
            LatestMsg.image_path,
            unread_case  # Number of unread messages in this chat
        )
        .join(LatestMsg, LatestMsg.id == latest_ids_subq.c.latest_msg_id)  # Join with latest message
        .join(User1, User1.id == latest_ids_subq.c.user1_id)               # Join with User1
        .join(User2, User2.id == latest_ids_subq.c.user2_id)               # Join with User2
        .join(
            ChatMessage,
            or_(
                and_(ChatMessage.sender_id == User1.id, ChatMessage.receiver_id == current_user.id),
                and_(ChatMessage.receiver_id == User1.id, ChatMessage.sender_id == current_user.id),
                and_(ChatMessage.sender_id == User2.id, ChatMessage.receiver_id == current_user.id),
                and_(ChatMessage.receiver_id == User2.id, ChatMessage.sender_id == current_user.id)
            )
        )
        .group_by(
            "chat_partner_id", "u1_id", "u1_username", "u1_picture",
            "u2_id", "u2_username", "u2_picture",
            LatestMsg.message, LatestMsg.image_path
        )
        .order_by(LatestMsg.timestamp.desc())  # Order chats by recent message time
    ).all()

    chat_items = []
    for row in rows:
        # Determine the chat partner's username and profile picture from the two users
        if row.chat_partner_id == row.u1_id:
            username = row.u1_username
            profile_pic = row.u1_picture
        else:
            username = row.u2_username
            profile_pic = row.u2_picture

        # Create preview text based on message and image
        if row.image_path and not row.message:
            preview = 'Sent an image'
        elif row.message and len(row.message) > 23:
            preview = row.message[:20] + '...'  # Preview truncated
        else:
            preview = row.message or ''

        chat_items.append({
            'user_id': row.chat_partner_id,
            'username': username,
            'profile_pic': profile_pic,
            'preview': preview,
            'unread_count': row.unread_count or 0  # Default to 0 if None
        })

    return jsonify(chat_items)  # Return a JSON array of chats with latest message previews and unread counts


@socketio.on('send_message')
def handle_send_message(data):
    # Extract data sent from client
    sender_id = data['sender_id']           # ID of user sending the message
    receiver_id = data['receiver_id']       # ID of recipient user
    message_text = data.get('message')      # Optional text message
    image_path = data.get('image_path')     # Optional image path (string)

    # Create and store a new ChatMessage in the database
    msg = ChatMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message=message_text,
        image_path=image_path
    )
    db.session.add(msg)
    db.session.commit()                     # Save to DB, msg.id and timestamp assigned

    # Emit the new message to the receiver's private Socket.IO room for real-time delivery
    socketio.emit('receive_message', {
        'id': msg.id,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'message': message_text,
        'image_path': image_path,
        'timestamp': msg.timestamp.strftime('%b %d, %Y %I:%M %p')  # formatted string
    }, room=f"user_{receiver_id}")

    # Also emit the message to the sender's private room to instantly update their chat UI
    socketio.emit('receive_message', {
        'id': msg.id,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'message': message_text,
        'image_path': image_path,
        'timestamp': msg.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{sender_id}")


# 🔹 Endpoint to fetch full chat message history between current user and another user
@app.route('/chat_history/<int:other_user_id>')
@login_required
def chat_history(other_user_id):
    # Query all messages where either:
    # - current user sent to other_user_id, or
    # - other_user_id sent to current user
    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == other_user_id)) |
        ((ChatMessage.sender_id == other_user_id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.timestamp).all()   # Messages ordered by timestamp ascending (oldest first)

    # Return JSON list of messages with relevant fields and formatted timestamps
    return jsonify([
        {
            'id': m.id,
            'sender_id': m.sender_id,
            'receiver_id': m.receiver_id,
            'message': m.message,
            'image_path': m.image_path,
            'timestamp': m.timestamp.strftime('%b %d, %Y %I:%M %p')
        }
        for m in messages
    ])


# 🔹 Endpoint to upload image files for chat messages
@app.route('/upload_chat_image', methods=['POST'])
@login_required
def upload_chat_image():
    # Check if 'image' file part is included in the request
    if 'image' not in request.files:
        return jsonify({'error': 'No file'}), 400  # 400 Bad Request if no file sent

    file = request.files['image']

    # Secure the filename (avoid dangerous paths, etc.)
    filename = secure_filename(file.filename)

    # Compose path where file will be saved under /static/uploads in project
    save_path = os.path.join(current_app.root_path, 'static/uploads', filename)

    # Save the uploaded file to disk
    file.save(save_path)

    # Return URL path to the saved image
    return jsonify({'path': url_for('static', filename=f'uploads/{filename}')})

# Generate a timed token for email verification using user's email
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verify')  # Token encodes email with salt

# Confirm token validity and get email if valid; returns False if expired or invalid
def confirm_token(token, expiration=3600):  # expiration in seconds (default 1 hour)
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verify', max_age=expiration)
    except:
        return False
    return email

# User registration route: GET shows form, POST handles registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)  # Hash password securely

        # Create User object with form data
        new_user = User(username=form.username.data, email=form.email.data,
                        password=hashed_pw, role=form.role.data)
        db.session.add(new_user)
        db.session.commit()

        # Generate email verification token and link
        token = generate_token(new_user.email)
        verify_url = url_for('verify_email', token=token, _external=True)  # Full URL
        html = render_template('verify_email.html', verify_url=verify_url, username=new_user.username)

        # Send verification email via Flask-Mail
        msg = Message("Confirm Your Email - TuitionApp", recipients=[new_user.email])
        msg.html = html
        mail.send(msg)

        flash('Registered successfully! Please check your email to verify your account.', 'info')
        return redirect(url_for('login'))

    # Render registration form page if GET or form invalid
    return render_template('register.html', form=form)

# Email verification route triggered when user clicks email link with token
@app.route('/verify_email/<token>')
def verify_email(token):
    email = confirm_token(token)   # Validate token and get email
    if not email:
        flash('Verification link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    # Find user by email, 404 if not found
    user = User.query.filter_by(email=email).first_or_404()
    if user.email_verified:
        flash('Email already verified. Please login.', 'success')
    else:
        user.email_verified = True   # Mark user email as verified
        db.session.commit()
        flash('Email verified successfully! You can now log in.', 'success')

    return redirect(url_for('login'))

# Login route: shows login form, validates credentials on POST
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()  # Lookup user by email
        # Verify password hash and ensure user is not admin
        if user and check_password_hash(user.password, form.password.data) and not user.is_admin:
            login_user(user)  # Logs in user with Flask-Login session management
            return redirect(url_for('dashboard'))  # Redirect to dashboard after login
        else:
            flash('Invalid credentials.', 'danger')  # On failed login

    return render_template('login.html', form=form)


@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_profile():
    # Select form class based on user role: guardian or tutor, pre-populate with current user data
    form = GuardianProfileForm(obj=current_user) if current_user.role == 'guardian' else TutorProfileForm(obj=current_user)

    # ⚠️ Must populate SelectField choices BEFORE validate_on_submit()
    form.division_id.choices = [(d.id, d.name) for d in Division.query.all()]
    form.district_id.choices = [(d.id, d.name) for d in District.query.all()]
    form.upazila_id.choices = [(u.id, u.name) for u in Upazila.query.all()]

    if request.method == 'GET':
        # For GET requests, pre-fill multiselect fields from comma-separated strings saved in DB
        if current_user.subjects:
            form.subjects.data = [x.strip() for x in current_user.subjects.split(',') if x.strip()]
        if current_user.preferred_classes:
            form.preferred_classes.data = [x.strip() for x in current_user.preferred_classes.split(',') if x.strip()]
        if current_user.available_days:
            form.available_days.data = [x.strip() for x in current_user.available_days.split(',') if x.strip()]
        if current_user.student_class:
            form.student_class.data = [x.strip() for x in current_user.student_class.split(',') if x.strip()]

        # Pre-fill radio/select for preferred_gender
        if current_user.preferred_gender:
            form.preferred_gender.data = current_user.preferred_gender

    if form.validate_on_submit():  # POST with valid form data
        # Common fields updated for both guardian and tutor
        current_user.phone_number = form.phone_number.data
        current_user.address = form.address.data
        current_user.division_id = form.division_id.data
        current_user.district_id = form.district_id.data
        current_user.upazila_id = form.upazila_id.data
        current_user.gender = form.gender.data

        # Profile picture upload handling
        if isinstance(form.profile_picture.data, FileStorage) and form.profile_picture.data.filename:
            picture_file = form.profile_picture.data
            if allowed_file(picture_file.filename):  # check file extension allowed
                filename = f"{uuid.uuid4().hex}_{secure_filename(picture_file.filename)}"  # unique filename
                picture_path = os.path.join(current_app.root_path, 'static/uploads', filename)
                picture_file.save(picture_path)  # save file
                current_user.profile_picture = filename  # update DB field
            else:
                flash('Invalid file type for profile picture. Allowed: png, jpg, jpeg, gif.', 'danger')
                return redirect(request.url)

        # NID/Birth certificate upload handling (similar to profile image)
        if isinstance(form.NID_Birth_Certificate.data, FileStorage) and form.NID_Birth_Certificate.data.filename:
            cert_file = form.NID_Birth_Certificate.data
            if allowed_file(cert_file.filename):  # file type validation
                cert_filename = f"{uuid.uuid4().hex}_{secure_filename(cert_file.filename)}"
                cert_path = os.path.join(current_app.root_path, 'static/uploads', cert_filename)
                cert_file.save(cert_path)
                current_user.NID_Birth_Certificate = cert_filename
            else:
                flash('Invalid file type for certificate. Allowed: png, jpg, jpeg, gif, pdf.', 'danger')
                return redirect(request.url)

        # Role-specific field updates
        if current_user.role == 'guardian':
            # Guardian-specific student info and preferences
            current_user.student_name = form.student_name.data
            current_user.student_class = ','.join(form.student_class.data)  # store as CSV string
            current_user.student_school = form.student_school.data
            current_user.subjects = ','.join([s.strip() for s in form.subjects.data if s.strip()])

            current_user.preferred_gender = form.preferred_gender.data
            current_user.medium = form.medium.data
            current_user.salary = form.salary.data

        else:  # Tutor
            # Check if tutor seeks tuition from checkbox in form
            current_user.is_seeking_tuition = 'is_seeking_tuition' in request.form

            # Tutor educational and preferences fields
            current_user.education = form.education.data
            current_user.subjects = ','.join(form.subjects.data)
            current_user.experience = form.experience.data

            current_user.qualifications = form.qualifications.data
            current_user.preferred_classes = ','.join(form.preferred_classes.data)
            current_user.medium = form.medium.data

            current_user.salary_expectation = form.salary_expectation.data

            # Time slots (comma-separated string cleaned from raw input)
            slots_raw = request.form.get('time_slots', '')
            slots_cleaned = ', '.join([s.strip() for s in slots_raw.split(',') if s.strip()])
            current_user.time_slots = slots_cleaned
            print(current_user.time_slots if current_user.time_slots else "No time slots provided")

            current_user.available_days = ','.join(form.available_days.data)

            # Helper to upload and save certificate files for SSC, HSC, Graduation
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

            # SSC certificate and info
            current_user.ssc_institute = form.ssc_institute.data
            current_user.ssc_result = form.ssc_result.data
            current_user.ssc_group = form.ssc_group.data
            current_user.ssc_certificate = handle_cert_upload(form.ssc_certificate) or current_user.ssc_certificate

            # HSC certificate and info
            current_user.hsc_institute = form.hsc_institute.data
            current_user.hsc_result = form.hsc_result.data     
            current_user.hsc_group = form.hsc_group.data
            current_user.hsc_certificate = handle_cert_upload(form.hsc_certificate) or current_user.hsc_certificate

            # Graduation certificate and info
            current_user.graduation_institute = form.graduation_institute.data
            current_user.graduation_result = form.graduation_result.data
            current_user.graduation_subject = form.graduation_subject.data
            current_user.graduation_certificate = handle_cert_upload(form.graduation_certificate) or current_user.graduation_certificate

        db.session.commit()  # Commit all changes to the database

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    # For GET requests and specific roles, repopulate some fields as lists from CSV strings
    if request.method == 'GET' and current_user.role == 'guardian' and current_user.student_class:
        form.student_class.data = [x.strip() for x in current_user.student_class.split(',') if x.strip()]
    if request.method == 'GET' and current_user.available_days:
        form.available_days.data = [d.strip() for d in current_user.available_days.split(',')]
        form.preferred_classes.data = [c.strip() for c in current_user.preferred_classes.split(',') if c.strip()]
    if request.method == 'GET' and current_user.role == 'tutor':
        form.medium.data = current_user.medium

    # Render profile update page with form and role context
    return render_template('update_profile.html', form=form, role=current_user.role)


# 🔹 Route for guardians to post new tutor requests (GET form and POST submission)
@app.route('/tutor-request', methods=['GET', 'POST'])
@login_required
def tutor_request():
    # Only guardians allowed to post tutor requests
    if current_user.role != 'guardian':
        flash('Only guardians can post tutor requests.', 'warning')
        return redirect(url_for('dashboard'))

    # Require email verification before posting
    if current_user.email_verified is False:
        flash('Please verify your email before posting a tutor request.', 'warning')
        return redirect(url_for('dashboard'))

    form = TutorRequestForm()

    if request.method == 'GET':
        # Optionally prefill phone number from user profile for convenience
        form.phone_number.data = current_user.phone_number

    if form.validate_on_submit():
        # Create TutorRequest record from form data, joining multi-select as CSV strings
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
            # created_at auto-generated
        )
        db.session.add(tr)
        db.session.commit()
        flash('Tutor request posted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('tutor_request.html', form=form)


# 🔹 API endpoint to search tutors based on multiple optional filters
@app.route('/api/search_tutors', methods=['GET'])
def search_tutors():
    # Extract filter parameters from query string
    division_id = request.args.get('division_id', type=int)
    district_id = request.args.get('district_id', type=int)
    upazila_id = request.args.get('upazila_id', type=int)
    preferred_classes = request.args.getlist('preferred_classes')
    subjects = request.args.getlist('subjects')
    available_days = request.args.getlist('available_days')
    gender_preference = request.args.get('gender_preference', type=str)
    medium = request.args.get('medium', type=str)

    # Base query for tutors who are actively seeking tuition and verified by email/admin
    query = User.query.filter_by(role='tutor', is_seeking_tuition=True, email_verified=True, is_verified=True)

    # Location filters
    if division_id:
        query = query.filter_by(division_id=division_id)
    if district_id:
        query = query.filter_by(district_id=district_id)
    if upazila_id:
        query = query.filter_by(upazila_id=upazila_id)

    # Gender filtering if specific preference other than 'Any'
    if gender_preference and gender_preference.lower() != 'any':
        query = query.filter_by(gender=gender_preference)

    # Teaching medium filter with partial match (case insensitive)
    if medium and medium.lower() != 'any':
        query = query.filter(User.medium.ilike(f"%{medium}%"))

    # Subjects filter: tutors matching any requested subject (ILIKE with OR)
    if subjects:
        subject_filters = [User.subjects.ilike(f"%{s}%") for s in subjects]
        query = query.filter(or_(*subject_filters))

    # Preferred classes filter similarly (OR condition)
    if preferred_classes:
        class_filters = [User.preferred_classes.ilike(f"%{c}%") for c in preferred_classes]
        query = query.filter(or_(*class_filters))

    # Available days filter if specified and not 'Any'
    if available_days and 'Any' not in available_days:
        day_filters = [User.available_days.ilike(f"%{d}%") for d in available_days]
        query = query.filter(or_(*day_filters))

    tutors = query.all()  # Execute query

    # Scoring function for sorting tutors by match quality
    def calculate_score(tutor):
        score = 0
        if tutor.subjects and subjects:
            score += sum(1 for s in subjects if s.lower() in tutor.subjects.lower())
        if tutor.preferred_classes and preferred_classes:
            score += sum(1 for c in preferred_classes if c.lower() in tutor.preferred_classes.lower())
        if tutor.available_days and available_days and 'Any' not in available_days:
            score += sum(1 for d in available_days if d.lower() in tutor.available_days.lower())
        return score

    # Sort tutors descending by score (best matches first)
    sorted_tutors = sorted(tutors, key=calculate_score, reverse=True)

    # Format results into JSON serializable dictionaries
    results = []
    for tutor in sorted_tutors:
        results.append({
            'id': tutor.id,
            'email': tutor.email,
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

    return jsonify(results)  # Return JSON array of matching tutors


@app.route('/api/tutor/<int:tutor_id>')
def get_tutor_profile(tutor_id):
    # Query the User table for a tutor with the given ID or return 404 error if not found
    tutor = User.query.get_or_404(tutor_id)

    # Return tutor details as JSON including profile info, education, verification, and location
    return jsonify({
        'id': tutor.id,
        # Public URL of profile picture if set
        'profile_picture': url_for('static', filename='uploads/' + tutor.profile_picture) if tutor.profile_picture else None,
        'username': tutor.username,
        'email': tutor.email,
        'gender': tutor.gender,
        'phone': tutor.phone_number,
        'email_verified': tutor.email_verified,
        'is_verified': tutor.is_verified,  # Admin or system verification flag
        'NID_Birth_Certificate': tutor.NID_Birth_Certificate,

        # Location names or empty string if none assigned
        'division': tutor.division.name if tutor.division else '',
        'district': tutor.district.name if tutor.district else '',
        'upazila': tutor.upazila.name if tutor.upazila else '',

        # Tutor-specific fields
        'preferred_classes': tutor.preferred_classes,

        # Nested objects for SSC, HSC, Graduation academic details
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


# Calculate distance between two lat/lng points on Earth using Haversine formula
def haversine(lat1, lng1, lat2, lng2):
    R = 6371  # Earth radius in kilometers
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lng2 - lng1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c  # Distance in km


@app.route('/api/search_tuition_requests')
@login_required
def search_tuition_requests():
    # Extract filter parameters from query string
    division_id = request.args.get('division_id', type=int)           # Division chosen by tutor
    district_id = request.args.get('district_id', type=int)           # District chosen by tutor
    subjects = list(filter(None, request.args.get('subjects', '').split(',')))  # Subjects filter as list
    preferred_classes = list(filter(None, request.args.get('student_classes', '').split(',')))  # Classes filter
    available_days = list(filter(None, request.args.get('available_days', '').split(',')))  # Days filter

    # Get geographic coordinates for selected Division and District from DB (models Division and District)
    division_lat = division_lng = None
    district_lat = district_lng = None

    if division_id:
        division = Division.query.get(division_id)  # Division model instance
        if division:
            division_lat, division_lng = division.latitude, division.longitude

    if district_id:
        district = District.query.get(district_id)  # District model instance
        if district:
            district_lat, district_lng = district.latitude, district.longitude

    # Use district coordinates if present, else fall back on division's coordinates
    location_lat, location_lng = district_lat or division_lat, district_lng or division_lng

    # If no valid location to filter, return empty result immediately
    if location_lat is None or location_lng is None:
        return jsonify([])

    # Query all TutorRequests (model TutorRequest)
    possible_requests = TutorRequest.query.all()

    # Filter TutorRequests within a radius (e.g., 50 km) of the selected location (lat/lng of tutor's division/district)
    radius_km = 50
    filtered_requests = [
        r for r in possible_requests
        if r.latitude is not None and r.longitude is not None and
        haversine(location_lat, location_lng, r.latitude, r.longitude) <= radius_km
    ]

    # Calculate a relevance score for each request based on subjects, classes, days, and proximity
    def calculate_score(req: TutorRequest) -> float:
        score = 0

        # Match subjects: count number of requested subjects that appear in the TutorRequest subjects CSV string
        if req.subjects and subjects:
            score += sum(1 for s in subjects if s.lower() in req.subjects.lower())

        # Match student classes similarly
        if req.student_classes and preferred_classes:
            score += sum(1 for c in preferred_classes if c.lower() in req.student_classes.lower())

        # Match preferred days if tutor specified, excluding "Any"
        if req.preferred_days and available_days and 'Any' not in available_days:
            score += sum(1 for d in available_days if d.lower() in req.preferred_days.lower())

        # Add proximity score: closer tutor requests get up to 5 points, linearly scaled by distance
        distance = haversine(location_lat, location_lng, req.latitude, req.longitude)
        proximity_score = max(0, 5 - distance)
        score += proximity_score

        return score

    # Sort filtered tutor requests by relevance score descending
    sorted_requests = sorted(filtered_requests, key=calculate_score, reverse=True)

    # Prepare JSON serializable dict for each TutorRequest
    def serialize_request(req: TutorRequest) -> dict:
        return {
            'id': req.id,
            'subjects': req.subjects,
            'student_classes': req.student_classes,
            'teaching_medium': req.teaching_medium,
            'preferred_days': req.preferred_days,
            'teaching_time': req.teaching_time,
            'salary': req.salary,
            'address_text': req.address_text,
            'latitude': req.latitude,
            'longitude': req.longitude,
            'preferred_tutor_gender': req.preferred_tutor_gender,
            'guardian_id': req.user_id,
            'guardian_name': req.user.username if req.user else None  # TutorRequest.user relationship
        }

    # Return JSON list of matched, sorted tuition requests
    return jsonify([serialize_request(r) for r in sorted_requests])


# Endpoint to get detailed information about a specific TutorRequest by its id
@app.route('/api/get_tuition_details/<int:request_id>')
@login_required
def get_tuition_details(request_id):
    # Query TutorRequest joined with guardian's location via User -> Upazila -> District -> Division
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

    # Unpack query result tuple: TutorRequest instance, district name, division name
    request, district, division = req

    # Return detailed data about the tutor request covering subjects, timing, salary, location, etc.
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


# Endpoint for tutors to send a response (offer) to a TutorRequest
@app.route('/api/send_tuition_response/<int:request_id>', methods=['POST'])
@login_required
def send_tuition_response(request_id):
    # Require email verification for tutors before allowing response
    if current_user.email_verified is False:
        flash('Please verify your Email first!')
        return redirect(url_for('dashboard'))
    
    tutor_request = TutorRequest.query.get(request_id)  # Fetch the TutorRequest
    if not tutor_request:
        return jsonify({'error': 'Tuition request not found'}), 404

    # Prevent duplicate tutor responses for same request
    existing = TutorResponse.query.filter_by(
        tutor_id=current_user.id, request_id=request_id
    ).first()
    if existing:
        return jsonify({'error': 'You have already responded to this request'}), 400

    # Create a new TutorResponse record
    response = TutorResponse(
        tutor_id=current_user.id,
        request_id=request_id
    )
    db.session.add(response)

    # Create a Notification for the guardian about this tutor's response
    notification = Notification(
        user_id=tutor_request.user_id,  # Guardian user id
        message=f"{current_user.username} has sent their details for your tuition request: {tutor_request.subjects}",
        link=f"/guardian/tuition_request/{request_id}"  # Link to guardian's view of the request
    )
    db.session.add(notification)
    db.session.commit()

    # Emit real-time notification via Socket.IO to guardian's private room
    socketio.emit("new_notification", {
        "id": notification.id,
        "message": notification.message,
        "link": notification.link,
        # Send tutor's profile picture or default avatar
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                         if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notification.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_request.user_id}")

    return jsonify({'success': True})


# Route for guardian to view details of a specific TutorRequest
@app.route('/guardian/tuition_request/<int:request_id>')
@login_required
def guardian_tuition_request(request_id):
    req = TutorRequest.query.get(request_id)  # Fetch TutorRequest by id
    # Ensure current user owns this request for authorization
    if not req or req.user_id != current_user.id:
        flash('You do not have permission to view this request.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('guardian_tuition_request.html', request=req)  # Render details page


# Route for guardian to select a tutor for a TutorRequest and confirm tuition
@app.route('/guardian/select_tutor/<int:request_id>/<int:tutor_id>', methods=['POST'])
@login_required
def select_tutor(request_id, tutor_id):
    req = TutorRequest.query.get_or_404(request_id)
    # Authorization: only guardian who created request can select tutor
    if req.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.get_json()
    tution_days = data.get('tution_days')            # e.g., "Monday, Wednesday"
    start_time_str = data.get('start_time')           # e.g., "17:00"
    end_time_str = data.get('end_time')               # e.g., "19:00"

    # Validate required fields
    if not tution_days or not start_time_str or not end_time_str:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    # Parse time strings to datetime.time objects
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
    end_time = datetime.strptime(end_time_str, "%H:%M").time()

    # Check for scheduling conflicts with this tutor's existing confirmed tuitions
    existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=tutor_id).all()
    for tuition in existing_tuitions:
        existing_days = [d.strip() for d in (tuition.tution_days or '').split(',') if d]
        # If any days overlap
        if any(day in existing_days for day in tution_days.split(', ')):
            # Check time overlap only if all times are set
            if tuition.start_time and tuition.end_time and start_time and end_time:
                # No overlap means end_time earlier or equal to existing start or start_time later or equal existing end
                if not (end_time <= tuition.start_time.time() or start_time >= tuition.end_time.time()):
                    return jsonify({'success': False, 'message': 'Schedule clash detected with existing tuition.'}), 400

    # Generate a unique tuition ID (e.g., T00000001)
    tuition_id = generate_tuition_id()

    # Create ConfirmedTuition record linking guardian, tutor and tuition details
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
        start_time=datetime.combine(datetime.today(), start_time),  # Date+Time
        end_time=datetime.combine(datetime.today(), end_time)
    )
    db.session.add(confirmed)

    # Delete all TutorResponses related to this TutorRequest since tutoring is now confirmed
    TutorResponse.query.filter_by(request_id=request_id).delete()
    # Delete the TutorRequest itself (closed)
    db.session.delete(req)

    # Remove any notifications sent to the guardian related to this request (clean up)
    Notification.query.filter_by(
        user_id=current_user.id,
        link=f"/guardian/tuition_request/{request_id}"
    ).delete()

    # Notify the selected tutor about the confirmation
    notify = Notification(
        user_id=tutor_id,
        message=f"You have been selected for tuition {tuition_id}.",
        link=f"/tuitions/{tuition_id}"
    )
    db.session.add(notify)
    db.session.commit()

    # Emit real-time notification to the tutor privately
    socketio.emit("new_notification", {
        "id": notify.id,
        "message": notify.message,
        "link": notify.link,
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture)
                         if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notify.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_id}")

    return jsonify({'success': True, 'message': 'Tutor selected and tuition confirmed!'})

# Route to view details of a confirmed tuition by its unique tuition_id (string)
@app.route('/tuitions/<tuition_id>')
@login_required
def view_tuition(tuition_id):
    # Get the ConfirmedTuition record or 404 if not found
    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    
    # Authorization: only guardian or tutor involved in the tuition can view it
    if current_user.id not in [tuition.guardian_id, tuition.tutor_id]:
        flash('You do not have permission to view this tuition.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch guardian and tutor User objects linked to this tuition
    guardian = User.query.get(tuition.guardian_id)
    tutor = User.query.get(tuition.tutor_id)

    # Render tuition info template with all related data
    return render_template('tuition_info.html', tuition=tuition, guardian=guardian, tutor=tutor)


# Route for tutors to receive and send a tutor request (POST)
@app.route('/send_tutor_request', methods=['POST'])
@login_required
def send_tutor_request():
    # Require user email verification before submitting a tutor request
    if not current_user.email_verified:
        return jsonify({"status": "error", "message": "Please verify your email before sending a tutor request."}), 400

    tutor_id = request.form['tutor_id']
    preferred_days = request.form.getlist('preferred_days')
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')

    # Validate required start and end times
    if not start_time or not end_time:
        return jsonify({"status": "error", "message": "Start and end time are required."}), 400

    teaching_time = f"{start_time},{end_time}"

    # 1. Schedule clash detection against existing ConfirmedTuitions for this tutor
    existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=tutor_id).all()
    for tuition in existing_tuitions:
        tuition_days = tuition.preferred_days.split(',') if tuition.preferred_days else []
        tuition_start = tuition.start_time.time() if tuition.start_time else None
        tuition_end = tuition.end_time.time() if tuition.end_time else None

        # Only check for time overlap if times exist
        if tuition_start and tuition_end:
            # If days overlap between requested and existing tuition
            if set(preferred_days) & set(tuition_days):
                fmt = "%H:%M"
                req_start = datetime.strptime(start_time, fmt).time()
                req_end = datetime.strptime(end_time, fmt).time()

                # Overlapping time condition: request start is before existing end
                # and request end is after existing start
                if (req_start < tuition_end and req_end > tuition_start):
                    return jsonify({"status": "error", "message": "Schedule conflict with tutor's existing classes."}), 400

    # 2. Create and save new TutorRequest with form data and current user as guardian
    new_request = TutorRequest(
        tutor_id=tutor_id,
        user_id=current_user.id,
        student_classes=','.join(request.form.getlist('student_classes')),
        subjects=','.join(request.form.getlist('subjects')),
        preferred_days=','.join(preferred_days),
        teaching_time=teaching_time,
        latitude=float(request.form.get('lat', 0.0)),
        longitude=float(request.form.get('lng', 0.0)),
        address_text=request.form.get('address', ''),
        phone_number=current_user.phone_number
    )
    db.session.add(new_request)
    db.session.commit()

    # 3. Create a Notification for the tutor about the new request
    notification = Notification(
        user_id=tutor_id,
        message=f"New tutor request from {current_user.username}",
        link=url_for('tutor_requests', request_id=new_request.id),
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()

    # Emit real-time notification to tutor via Socket.IO
    socketio.emit("new_notification", {
        "id": notification.id,
        "message": notification.message,
        "link": notification.link,
        "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture)
                         if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
        "timestamp": notification.timestamp.strftime('%b %d, %Y %I:%M %p')
    }, room=f"user_{tutor_id}")

    return jsonify({"status": "success"})



# Generate a unique tuition ID in the format T00000001, T00000002, ...
def generate_tuition_id():
    last = ConfirmedTuition.query.order_by(ConfirmedTuition.id.desc()).first()
    if not last:
        return 'T00000001'
    num = int(last.id[1:]) + 1
    return f'T{num:08d}'


# Utility to normalize CSV string: trims, lowercases, sorts items, then rejoins as CSV
def normalize_csv(text):
    return ','.join(sorted([item.strip().lower() for item in text.split(',') if item.strip()]))


# Route for tutors to respond (accept/reject) a TutorRequest
@app.route('/respond_tutor_request', methods=['POST'])
@login_required
def respond_tutor_request():
    request_id = request.form.get('request_id')
    response = request.form.get('action')  # expected 'accept' or 'reject'

    if response not in ['accept', 'reject']:
        return jsonify({'status': 'error', 'message': 'Invalid response'}), 400

    # Fetch the TutorRequest record
    req = TutorRequest.query.get_or_404(request_id)

    # Authorization: Only assigned tutor can respond
    if req.tutor_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    # Prevent responding multiple times to the same request
    if req.status != 'pending':
        return jsonify({'status': 'error', 'message': 'Already responded'}), 400

    # Parse the teaching_time field (CSV, ex: "17:00,19:00") into start/end times
    try:
        start_time_str, end_time_str = (req.teaching_time or "").split(',', 1)
        fmt = "%H:%M"
        req_start_time = datetime.strptime(start_time_str.strip(), fmt).time()
        req_end_time = datetime.strptime(end_time_str.strip(), fmt).time()
    except (ValueError, AttributeError):
        return jsonify({'status': 'error', 'message': 'Invalid teaching_time format.'}), 400

    if response == 'accept':
        # Check for schedule conflicts with already confirmed tuitions for this tutor
        existing_tuitions = ConfirmedTuition.query.filter_by(tutor_id=current_user.id).all()
        req_days_set = set(d.strip().lower() for d in (req.preferred_days or '').split(','))

        for tuition in existing_tuitions:
            tuition_days_set = set(d.strip().lower() for d in (tuition.tution_days or '').split(','))
            # If days overlap, check time overlap
            if req_days_set & tuition_days_set:
                if tuition.start_time and tuition.end_time:
                    tuition_start = tuition.start_time.time()
                    tuition_end = tuition.end_time.time()
                    # Overlap check: request start < existing end and request end > existing start
                    if req_start_time < tuition_end and req_end_time > tuition_start:
                        return jsonify({
                            'status': 'error',
                            'message': 'Schedule conflict with existing confirmed tuition.'
                        }), 400

        # Mark request as accepted
        req.status = 'accepted'

        # Create new ConfirmedTuition record with all necessary details
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

        # Notify guardian that tutor accepted the request
        notif = Notification(
            user_id=req.user_id,
            message="Your tuition request has been accepted by a tutor.",
            link=url_for('view_tuition', tuition_id=confirmed.id)
        )

        db.session.add(confirmed)
        db.session.add(notif)
        db.session.delete(req)  # Remove original pending request
        db.session.commit()

        # Emit real-time notification to guardian's notification room
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
        # Response is 'reject' → mark request as rejected and commit
        req.status = 'rejected'
        db.session.commit()
        flash('Tuition request rejected.', 'warning')

    return redirect(url_for('dashboard'))


# Route to show all pending tutor requests assigned to the logged-in tutor
@app.route('/tutor_requests')
@login_required
def tutor_requests():
    # Query TutorRequest where tutor_id matches current user and status is 'pending'
    requests = TutorRequest.query.filter_by(tutor_id=current_user.id, status='pending').all()
    # Render the tutor_requests.html template passing these requests for display
    return render_template("tutor_requests.html", requests=requests)


# Route to get all Districts under a given Division by division_id
@app.route('/districts/<int:division_id>')
def get_districts(division_id):
    # Query District model filtering by division_id foreign key
    districts = District.query.filter_by(division_id=division_id).all()
    # Return JSON list of tuples (district id, district name)
    return jsonify([(d.id, d.name) for d in districts])


# Route to get all Upazilas under a given District by district_id
@app.route('/upazilas/<int:district_id>')
def get_upazilas(district_id):
    # Query Upazila model filtering by district_id foreign key
    upazilas = Upazila.query.filter_by(district_id=district_id).all()
    # Return JSON list of tuples (upazila id, upazila name)
    return jsonify([(u.id, u.name) for u in upazilas])


# Main dashboard route showing tutor and guardian related data
@app.route('/dashboard')
@login_required
def dashboard():
    # Get all Divisions for dropdown or filtering in UI
    divisions = Division.query.all()

    # Get current weekday name, e.g. 'Thursday'
    today_name = datetime.now().strftime('%A')

    # Query all confirmed tuitions where current user is guardian or tutor
    guardian_active = ConfirmedTuition.query.filter_by(guardian_id=current_user.id).all()
    tutor_active = ConfirmedTuition.query.filter_by(tutor_id=current_user.id).all()

    # Helper to attach User objects (tutor and guardian) to tuition objects for easy display
    def attach_users(tuitions):
        for t in tuitions:
            t.tutor = User.query.get(t.tutor_id)
            t.guardian = User.query.get(t.guardian_id)
        return tuitions

    guardian_active = attach_users(guardian_active)
    tutor_active = attach_users(tutor_active)

    # Filter tuition sessions to those matching today's day, reading tution_days CSV string
    def filter_today(tuitions):
        return [
            t for t in tuitions
            if today_name in [d.strip() for d in (t.tution_days or "").split(',') if d.strip()]
        ]

    todays_guardian = filter_today(guardian_active)
    todays_tutor = filter_today(tutor_active)

    # Get all feedback where current user (guardian or tutor) is receiver, calculate average rating
    feedback_list = Feedback.query.filter_by(receiver_id=current_user.id).all()
    avg_rating = (sum(fb.rating for fb in feedback_list) / len(feedback_list)) if feedback_list else None

    # Fetch 10 most recent feedback received by user
    feedback_list = (
        Feedback.query
        .filter_by(receiver_id=current_user.id)
        .order_by(Feedback.created_at.desc())
        .limit(10)
        .all()
    )

    # Fetch 10 most recent feedback given by user
    feedback_given = (
        Feedback.query
        .filter_by(giver_id=current_user.id)
        .order_by(Feedback.created_at.desc())
        .limit(10)
        .all()
    )

    # Active tutor requests for guardian users only (excluding those marked 'found')
    active_tutor_requests = []
    if current_user.role == 'guardian':
        active_tutor_requests = (
            TutorRequest.query
            .filter_by(user_id=current_user.id)
            .filter(TutorRequest.status != 'found')
            .order_by(TutorRequest.created_at.desc())
            .all()
        )

    # Render dashboard passing all gathered data for display
    return render_template(
        'dashboard.html',
        user=current_user,
        divisions=divisions,
        guardian_active=guardian_active,
        tutor_active=tutor_active,
        todays_guardian=todays_guardian,
        todays_tutor=todays_tutor,
        today_name=today_name,
        avg_rating=avg_rating,
        feedback_list=feedback_list,
        feedback_given=feedback_given,
        active_tutor_requests=active_tutor_requests
    )

# Route to delete a TutorRequest by its ID
@app.route('/delete_tutor_request/<int:request_id>', methods=['POST'])
@login_required
def delete_tutor_request(request_id):
    # Fetch the TutorRequest or 404 if not found
    req = TutorRequest.query.get_or_404(request_id)
    # Authorization: Only the guardian (user_id) who created the request can delete it
    if req.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    # Delete the TutorRequest record from DB
    db.session.delete(req)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Request deleted'})


# Route to edit an existing TutorRequest (both GET to load form and POST to submit changes)
@app.route('/edit_tutor_request/<int:request_id>', methods=['GET', 'POST'])
@login_required
def edit_tutor_request(request_id):
    tutor_request = TutorRequest.query.get_or_404(request_id)

    # Authorization: only the guardian who posted the request can edit it
    if tutor_request.user_id != current_user.id:
        flash('You are not authorized to edit this request.', 'danger')
        return redirect(url_for('dashboard'))

    form = TutorRequestForm()

    if request.method == 'GET':
        # Pre-fill the form with existing TutorRequest data
        # Convert comma-separated strings to lists for multi-select fields
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

    # Process the submitted form
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

        # Commit the updates to database
        db.session.commit()
        flash('Tutor request updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Render the edit form template if GET or form validation fails
    return render_template('edit_tutor_request.html', form=form, tutor_request=tutor_request)



# Route to give or update feedback about another user (tutor or guardian)
@app.route("/give_feedback/<int:user_id>", methods=["GET", "POST"])
@login_required
def give_feedback(user_id):
    receiver = User.query.get_or_404(user_id)  # User receiving feedback

    # Prevent giving feedback to users with the same role (optional business rule)
    if current_user.role == receiver.role:
        flash("You cannot give feedback to a user with the same role.", "warning")
        return redirect(url_for("view_profile", user_id=user_id))

    # Check if feedback already exists from current_user to receiver
    feedback = Feedback.query.filter_by(giver_id=current_user.id, receiver_id=user_id).first()

    if request.method == "POST":
        rating = int(request.form.get("rating"))
        comment = request.form.get("comment", "").strip()

        if feedback:
            # Update existing feedback
            feedback.rating = rating
            feedback.comment = comment
            flash("Feedback updated successfully!", "success")
        else:
            # Create new feedback record
            feedback = Feedback(
                giver_id=current_user.id,
                receiver_id=user_id,
                rating=rating,
                comment=comment
            )
            db.session.add(feedback)
            flash("Feedback submitted successfully!", "success")

        db.session.commit()
        # Redirect back to the profile of the user receiving feedback
        return redirect(url_for("view_profile", user_id=user_id))

    # Render feedback submission form for GET or if no POST yet
    return render_template("feedback_form.html", receiver=receiver, feedback=feedback)


# Route for guardian or tutor to request deletion of a confirmed tuition session
@app.route('/request_tuition_delete/<tuition_id>', methods=['POST'])
@login_required
def request_tuition_delete(tuition_id):
    tuition = ConfirmedTuition.query.get_or_404(tuition_id)
    # Only involved guardian or tutor can request deletion
    if current_user.id not in (tuition.guardian_id, tuition.tutor_id):
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    # Toggle deletion request: if already requested by the current user, cancel it
    if tuition.delete_requested and tuition.delete_requested_by == current_user.id:
        tuition.delete_requested = False
        tuition.delete_requested_by = None
        tuition.delete_requested_at = None
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Delete request cancelled.'})

    # Otherwise, create new delete request
    tuition.delete_requested = True
    tuition.delete_requested_by = current_user.id
    tuition.delete_requested_at = datetime.now(timezone.utc)
    db.session.commit()

    # Notify the other party about the deletion request
    recipient_id = tuition.guardian_id if current_user.id == tuition.tutor_id else tuition.tutor_id
    notif = Notification(
        user_id=recipient_id,
        message=f"{current_user.username} has requested to delete a tuition.",
        link="/dashboard"
    )
    db.session.add(notif)
    db.session.commit()

    # Emit real-time notification to other party
    socketio.emit(
        'new_notification',
        {   
            'id': notif.id,
            'message': notif.message,
            'link': notif.link,
            "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                             if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
            "timestamp": notif.timestamp.strftime('%b %d, %Y %I:%M %p')
        },
        room=f"user_{recipient_id}"
    )

    return jsonify({'status': 'success', 'message': 'Delete request sent to the other party.'})


# Route for the other party to approve or reject a delete request for a tuition session
@app.route('/respond_tuition_delete/<tuition_id>', methods=['POST'])
@login_required
def respond_tuition_delete(tuition_id):
    action = (request.json or request.form).get('action')
    if action not in ('approve', 'reject'):
        return jsonify({'status': 'error', 'message': 'Invalid action'}), 400

    tuition = ConfirmedTuition.query.get_or_404(tuition_id)

    # Cannot respond if there's no pending delete request
    if not tuition.delete_requested:
        return jsonify({'status': 'error', 'message': 'No pending delete request.'}), 400

    # Only the other party can respond (not the requester)
    if current_user.id == tuition.delete_requested_by:
        return jsonify({'status': 'error', 'message': "Requester can't respond."}), 403

    requester_id = tuition.delete_requested_by

    if action == 'approve':
        # Delete tuition record permanently
        db.session.delete(tuition)
        db.session.commit()

        notif_msg = f"{current_user.username} approved your delete request for tuition {tuition.id}."
        notif_link = "/dashboard"
    else:
        # Reject deletion, clear delete request flags
        tuition.delete_requested = False
        tuition.delete_requested_by = None
        tuition.delete_requested_at = None
        db.session.commit()

        notif_msg = f"{current_user.username} rejected your delete request for tuition {tuition.id}."
        notif_link = f"/tuitions/{tuition.id}"

    # Create notification to requester with result of their deletion request
    notif = Notification(
        user_id=requester_id,
        message=notif_msg,
        link=notif_link
    )
    db.session.add(notif)
    db.session.commit()

    # Emit real-time notification to the requester
    socketio.emit(
        'new_notification',
        {   
            'id': notif.id,
            'message': notif.message,
            'link': notif.link,
            "sender_avatar": url_for('static', filename='uploads/' + current_user.profile_picture) 
                             if current_user.profile_picture else url_for('static', filename='default-avatar.png'),
            "timestamp": notif.timestamp.strftime('%b %d, %Y %I:%M %p')
        },
        room=f"user_{requester_id}"
    )

    return jsonify({'status': 'success', 'message': notif.message})



# Route for viewing a user's profile by user_id
@app.route("/view_profile/<int:user_id>")
@login_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)  # Fetch User from database

    # Restrict viewing profiles of users with same role unless current user is admin
    if current_user.role == user.role and not current_user.is_admin:
        abort(403)  # Forbidden

    # Calculate average rating from all feedback received by this user
    all_feedback = Feedback.query.filter_by(receiver_id=user.id).all()
    avg_rating = None
    if all_feedback:
        avg_rating = sum(fb.rating for fb in all_feedback) / len(all_feedback)

    # Check if current user has already given feedback to this user
    my_feedback = Feedback.query.filter_by(receiver_id=user.id, giver_id=current_user.id).first()

    # If profile user is a guardian, get their pending tutor requests
    active_tutor_requests = []
    if user.role == "guardian":
        active_tutor_requests = TutorRequest.query.filter_by(user_id=user.id, status='pending').all()

    # Fetch confirmed tuitions to show on profile, depends on role
    confirmed_tuitions = []
    if user.role == "guardian":
        confirmed_tuitions = ConfirmedTuition.query.filter_by(guardian_id=user.id).all()
    elif user.role == "tutor":
        confirmed_tuitions = ConfirmedTuition.query.filter_by(tutor_id=user.id).all()

    # Render profile page with user, ratings, feedback, tutor requests, and confirmed tuitions
    return render_template(
        "view_profile.html",
        profile_user=user,
        avg_rating=avg_rating,
        my_feedback=my_feedback,
        active_tutor_requests=active_tutor_requests,
        confirmed_tuitions=confirmed_tuitions,
    )


# Route to submit a general report to admin about a user
@app.route('/report', methods=['POST'])
@login_required
def report_to_admin():
    reported_user_id = request.form.get('reported_user_id')
    report_type = request.form.get('report_type')  # e.g., 'fake_profile', 'spam'
    description = request.form.get('description')

    # Validate that a report type is selected
    if not report_type:
        flash("Please select a reason for reporting.", "danger")
        return redirect(request.referrer)

    # Create ReportToAdmin record linked to reporter and reported user
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


# Route to submit a report about a specific tutor request (e.g. fake or inappropriate)
@app.route('/report_tuition_request', methods=['POST'])
@login_required
def report_tuition_request():
    from datetime import datetime, timezone
    reported_request_id = request.form.get('reported_request_id')
    report_type = request.form.get('report_type')
    description = request.form.get('description')

    # Validate required report fields
    if not reported_request_id or not report_type:
        flash("Invalid report submission.", "danger")
        return redirect(request.referrer)

    # Create ReportToAdmin record linked to reporter and tutor request
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

# Admin login route, serves login form and handles credentials POST
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # Query User model for admin with this email
        user = User.query.filter_by(email=email, is_admin=True).first()
        # Verify hash matches password
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log in admin user via Flask-Login
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials or not an admin.', 'danger')
    # Render admin login form
    return render_template('admin_login.html')


# Admin dashboard route with role-based access control
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Only allow admins to access dashboard
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    # Fetch core user lists
    guardians = User.query.filter_by(role='guardian').all()
    tutors = User.query.filter_by(role='tutor').all()

    # Fetch reported profiles and posts for moderation
    reported_profiles = ReportToAdmin.query.filter(
        ReportToAdmin.reported_user_id.isnot(None)
    ).all()
    reported_posts = ReportToAdmin.query.filter(
        ReportToAdmin.reported_request_id.isnot(None)
    ).all()

    # Basic analytics
    active_users_count = User.query.count()
    tuition_requests_count = TutorRequest.query.count()
    tutor_count = len(tutors)
    tutor_request_ratio = (
        f"{tutor_count}:{tuition_requests_count}" if tuition_requests_count else f"{tutor_count}:0"
    )

    # Haversine formula to calculate distance between two lat/lng points (in km)
    def haversine(lat1, lng1, lat2, lng2):
        R = 6371  # Earth radius in kilometers
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lng2 - lng1)

        a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c  # Distance in kilometers

    # Aggregate tutor request demand matched by closest division via lat/lng proximity
    divisions = Division.query.all()
    tutor_requests = TutorRequest.query.all()

    demand_by_division = Counter()
    for req in tutor_requests:
        min_distance = float('inf')
        matched_division = None
        for div in divisions:
            dist = haversine(req.latitude, req.longitude, div.latitude, div.longitude)
            if dist < min_distance:
                min_distance = dist
                matched_division = div.name
        if matched_division:
            demand_by_division[matched_division] += 1

    # Render admin dashboard template passing all data for display and moderation
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

# Route for admin to delete a User by user_id
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)  # Only admins allowed
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully.", "success")
    return redirect(request.referrer)


# Route for admin to delete a TutorRequest post
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


# Toggle user verification flag by admin
@app.route('/verify_user/<int:user_id>', methods=['POST'])
@login_required
def verify_user(user_id):
    if not current_user.is_admin:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    user.is_verified = not user.is_verified  # Flip verified flag
    db.session.commit()
    flash(f"{user.username} has been {'verified' if user.is_verified else 'unverified'}.", "success")
    return redirect(url_for('admin_dashboard'))


# Admin route to remove a user or post report
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


# Admin route to add admin flag to a user
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


# Admin view of all feedback for moderation and review
@app.route("/view_feedbacks")
@login_required
def view_all_feedbacks():
    if not current_user.is_admin:
        abort(403)

    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template("all_feedbacks.html", feedbacks=feedbacks)


# Create a new admin with form inputs for username/email/password
@app.route("/create_admin", methods=["POST"])
@login_required
def create_admin():
    if not current_user.is_admin:
        abort(403)

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    # Prevent duplicates on username or email
    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("User with this username or email already exists.", "danger")
        return redirect(url_for("add_admin"))

    new_admin = User(
        username=username,
        email=email,
        password=generate_password_hash(password),
        role="guardian",   # Default role but with admin privileges
        is_admin=True
    )
    db.session.add(new_admin)
    db.session.commit()
    flash(f"New admin {username} created!", "success")
    return redirect(url_for("admin_dashboard"))


# Remove admin privilege from a user
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


# View page to manage all admins (list)
@app.route("/manage_admins")
@login_required
def manage_admins():
    if not current_user.is_admin:
        abort(403)

    admins = User.query.filter_by(is_admin=True).all()
    return render_template("manage_admins.html", admins=admins)


# Delete individual feedback by admin
@app.route("/delete_feedback/<int:feedback_id>", methods=["POST"])
@login_required
def delete_feedback(feedback_id):
    if not current_user.is_admin:
        abort(403)

    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted.", "success")
    return redirect(url_for("view_all_feedbacks"))


# Standard logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables automatically if not exist
    socketio.run(app, debug=True)

