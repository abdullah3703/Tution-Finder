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

    user_id = db.Column(
        db.Integer, 
        db.ForeignKey('user.id', ondelete="CASCADE"), 
        nullable=False
    )


    students_number = db.Column(db.Integer, nullable=False)
    student_classes = db.Column(db.String(200), nullable=False)  # CSV string, e.g. "Class 5,Class 6"
    teaching_medium = db.Column(db.String(20), nullable=False)  # "Bangla" or "EV"
    subjects = db.Column(db.String(200), nullable=False)  # CSV string

    starting_date = db.Column(db.Date, nullable=False)
    preferred_days = db.Column(db.String(100), nullable=False)  # CSV string, e.g. "Sat,Mon,Wed"
    teaching_time = db.Column(db.String(100))  # Optional e.g. "5-7 PM"
    salary = db.Column(db.String(50))  # Optional

    address_text = db.Column(db.String(300))  # Extra location info
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    phone_number = db.Column(db.String(20), nullable=False)
    preferred_tutor_gender = db.Column(db.String(10), default='any')  # "any", "male", "female"

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    status = db.Column(db.String(20), default='pending')  # e.g. 'pending' or 'found'

    user = db.relationship('User', backref=db.backref('tutor_requests', passive_deletes=True))

class TutorRequestInbox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    student_classes = db.Column(db.String(100), nullable=False)  # CSV
    subjects = db.Column(db.String(200), nullable=False)  # CSV
    preferred_days = db.Column(db.String(100), nullable=True)
    time_slots = db.Column(db.String(100), nullable=True)

    guardian_name = db.Column(db.String(100), nullable=False)
    guardian_contact = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(300), nullable=True)

    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class ConfirmedTuition(db.Model):
    id = db.Column(db.String(10), primary_key=True)  # e.g., T00000001
    guardian_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tutor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    guardian_name = db.Column(db.String(100))
    guardian_contact = db.Column(db.String(100))
    student_classes = db.Column(db.String(200))
    subjects = db.Column(db.String(300))
    preferred_days = db.Column(db.String(100))
    time_slots = db.Column(db.String(100))
    address = db.Column(db.String(300))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
