from flask_login import UserMixin
from extensions import db  # ✅ import db from extensions
from datetime import datetime, timezone

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    is_admin = db.Column(db.Boolean, default=False)


    # Basic Info
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='guardian')  # 'guardian' or 'tutor'
    profile_picture = db.Column(db.String(100), nullable=True)
    
    NID_Birth_Certificate = db.Column(db.String(255))  # Previously 100

    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    gender = db.Column(db.String(10), nullable=True)  # e


    # Common Fields
    phone_number = db.Column(db.String(20))
    address = db.Column(db.String(200))
    division_id = db.Column(db.Integer, db.ForeignKey('divisions.id'), nullable=True)
    district_id = db.Column(db.Integer, db.ForeignKey('districts.id'), nullable=True)
    upazila_id = db.Column(db.Integer, db.ForeignKey('upazilas.id'), nullable=True)

    # Relationships (optional for easier access)
    division = db.relationship('Division', foreign_keys=[division_id])
    district = db.relationship('District', foreign_keys=[district_id])
    upazila = db.relationship('Upazila', foreign_keys=[upazila_id])


    # Guardian-Specific Fields
    student_name = db.Column(db.String(100))
    student_class = db.Column(db.String(20))
    student_school = db.Column(db.String(100))
    subjects = db.Column(db.String(200))  # Comma-separated, e.g. "Math, Science"
    preferred_gender = db.Column(db.String(10))  # e
    medium = db.Column(db.String(50))  # e.g. "English", "Bengali"
    salary = db.Column(db.String(50))  # e.g. "5000-7000 BDT"

    # Tutor-Specific Fields
    education = db.Column(db.Text)  # Example: "BSc in Math from XYZ University"
    subjects = db.Column(db.String(200))  # Comma-separated, e.g. "Math, Physics"
    qualifications = db.Column(db.Text)  # Tutor qualifications
    preferred_classes = db.Column(db.String(200))  # e.g. "Class 5, Class 6"
    salary_expectation = db.Column(db.String(50))  # e.g. "5000-7000 BDT"
    time_slots = db.Column(db.String(200))  # e.g. "Mon-Fri 5-7 PM"
    experience = db.Column(db.Text)  # Teaching experience or background info
    is_seeking_tuition = db.Column(db.Boolean, default=False)  # New field for tutors
    available_days = db.Column(db.String(255))  # comma-separated values
    # SSC
    ssc_institute = db.Column(db.String(100))
    ssc_result = db.Column(db.String(10))
    ssc_group = db.Column(db.String(50))
    ssc_certificate = db.Column(db.String(255))

    # HSC
    hsc_institute = db.Column(db.String(100))
    hsc_result = db.Column(db.String(10))
    hsc_group = db.Column(db.String(50))
    hsc_certificate = db.Column(db.String(255))

    # Graduation
    graduation_institute = db.Column(db.String(100))
    graduation_result = db.Column(db.String(10))
    graduation_subject = db.Column(db.String(100))
    graduation_certificate = db.Column(db.String(255))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    message = db.Column(db.String(255))
    link = db.Column(db.String(255))  # URL to redirect
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship('User', backref='notifications')



class Division(db.Model):
    __tablename__ = 'divisions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

    districts = db.relationship('District', backref='division', cascade='all, delete', lazy=True)



class District(db.Model):
    __tablename__ = 'districts'
    id = db.Column(db.Integer, primary_key=True)
    division_id = db.Column(db.Integer, db.ForeignKey('divisions.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

    upazilas = db.relationship('Upazila', backref='district', cascade='all, delete', lazy=True)



class Upazila(db.Model):
    __tablename__ = 'upazilas'
    id = db.Column(db.Integer, primary_key=True)
    district_id = db.Column(db.Integer, db.ForeignKey('districts.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)

class TutorRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)  # guardian
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)  # optional

    students_number = db.Column(db.Integer, nullable=True)
    student_classes = db.Column(db.String(200), nullable=False)  # CSV
    teaching_medium = db.Column(db.String(20), nullable=True)
    subjects = db.Column(db.String(200), nullable=False)  # CSV

    starting_date = db.Column(db.Date, nullable=True)
    preferred_days = db.Column(db.String(100), nullable=True)
    teaching_time = db.Column(db.String(100))
    salary = db.Column(db.String(50))

    address_text = db.Column(db.String(300))
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    phone_number = db.Column(db.String(20), nullable=True)
    preferred_tutor_gender = db.Column(db.String(10), default='any')

    guardian_name = db.Column(db.String(100))
    guardian_contact = db.Column(db.String(100))

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default='pending')  # pending / accepted / rejected / found

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('tutor_requests', passive_deletes=True))
    tutor = db.relationship('User', foreign_keys=[tutor_id])
    

class TutorResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('tutor_request.id', ondelete='CASCADE'), nullable=False)

    status = db.Column(db.String(20), default='pending')  # pending / accepted / rejected
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    tutor = db.relationship('User')
    tutor_request = db.relationship('TutorRequest', backref=db.backref('tutor_responses', cascade="all, delete-orphan"))


class ConfirmedTuition(db.Model):
    id = db.Column(db.String(10), primary_key=True)  # e.g., T00000001
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    student_classes = db.Column(db.String(200))
    subjects = db.Column(db.String(300))
    preferred_days = db.Column(db.String(100))
    
    address = db.Column(db.String(300))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    tution_days = db.Column(db.String(100))  # e.g., "Monday, Wednesday, Friday"
    start_time = db.Column(db.DateTime, nullable=True)  # Start date and time of the tuition
    end_time = db.Column(db.DateTime, nullable=True)  # End date and time
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    delete_requested = db.Column(db.Boolean, default=False, nullable=False)
    delete_requested_by = db.Column(db.Integer, nullable=True)  # user.id who asked
    delete_requested_at = db.Column(db.DateTime, nullable=True, default=None)




class ReportToAdmin(db.Model):
    __tablename__ = 'report_to_admin'

    id = db.Column(db.Integer, primary_key=True)

    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=True)  # if reporting a user
    reported_request_id = db.Column(db.Integer, db.ForeignKey('tutor_request.id', ondelete="CASCADE"), nullable=True)  # if reporting a post

    report_type = db.Column(db.String(50), nullable=False)  # e.g., 'fake_profile', 'spam', 'inappropriate', etc.
    description = db.Column(db.Text, nullable=True)  # Optional details
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    reporter = db.relationship('User', foreign_keys=[reporter_id], backref=db.backref('reports_made', passive_deletes=True))
    reported_user = db.relationship('User', foreign_keys=[reported_user_id], backref=db.backref('reports_received', passive_deletes=True))
    reported_request = db.relationship('TutorRequest', backref=db.backref('reports', cascade="all, delete-orphan"))

