from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, SelectMultipleField, widgets, FloatField, IntegerField, DateField, RadioField
from wtforms.validators import DataRequired, Optional
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms.validators import DataRequired, Email, Length
from wtforms.validators import Optional
from flask_wtf.file import FileField, FileAllowed


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('guardian', 'Guardian'), ('tutor', 'Tutor')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class GuardianProfileForm(FlaskForm):
    profile_picture = FileField('Update Profile Picture', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female'), ('others', 'Others')], validators=[Optional()])

    phone_number = StringField('Phone Number', validators=[Optional()])
    address = StringField('Address', validators=[Optional()])
    division_id = SelectField('Division', coerce=int, validators=[Optional()])
    district_id = SelectField('District', coerce=int, validators=[Optional()])
    upazila_id = SelectField('Upazila', coerce=int, validators=[Optional()])
    student_name = StringField('Student Name', validators=[Optional()])
    student_class = SelectMultipleField(
        'Student Class(es)',
        choices=[
            ('Nursery', 'Nursery'), ('KG', 'KG'), ('Class 1', 'Class 1'),
            ('Class 2', 'Class 2'), ('Class 3', 'Class 3'), ('Class 4', 'Class 4'),
            ('Class 5', 'Class 5'), ('Class 6', 'Class 6'), ('Class 7', 'Class 7'),
            ('Class 8', 'Class 8'), ('Class 9', 'Class 9'), ('Class 10', 'Class 10'),
            ('Class 11', 'Class 11'), ('Class 12', 'Class 12')
        ],
        validators=[Optional()]
    )

    student_school = StringField('Student School', validators=[Optional()])
    subjects = SelectMultipleField(
        'Subjects',
        choices=[
            ('Math', 'Math'),
            ('English', 'English'),
            ('Physics', 'Physics'),
            ('Chemistry', 'Chemistry'),
            ('Biology', 'Biology'),
            ('Bangla', 'Bangla'),
            ('History', 'History'),
            ('Geography', 'Geography'),
            ('ICT', 'ICT'),
            ('Accounting', 'Accounting'),
            ('Economics', 'Economics'),
            ('Business Studies', 'Business Studies'),
            ('Statistics', 'Statistics'),
            ('Psychology', 'Psychology'),
            ('Sociology', 'Sociology'),
            ('Arts', 'Arts'),
            ('Music', 'Music'),
            ('Physical Education', 'Physical Education')
        ],
        validators=[Optional()]
    )

    preferred_gender = RadioField(
        'Preferred Gender',
        choices=[
            ('any', 'Any'),
            ('male', 'Male'),
            ('female', 'Female')
        ],
        validators=[Optional()]
    )
    medium = StringField('Medium', validators=[Optional()])  # e.g. "English", "Bengali"
    salary = StringField('Expected Salary', validators=[Optional()])  # e.g.
    NID_Birth_Certificate = FileField('NID / Birth Certificate (Image)', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg', 'pdf'], 'Only image or PDF files allowed')
    ])


    submit = SubmitField('Update Profile')

class TutorProfileForm(FlaskForm):
    profile_picture = FileField('Update Profile Picture', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')
    ])
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female'), ('others', 'Others')], validators=[Optional()])
    phone_number = StringField('Phone Number', validators=[Optional()])
    address = StringField('Address', validators=[Optional()])
    division_id = SelectField('Division', coerce=int, validators=[Optional()])
    district_id = SelectField('District', coerce=int, validators=[Optional()])
    upazila_id = SelectField('Upazila', coerce=int, validators=[Optional()])
    education = TextAreaField('Academic Qualifications', validators=[Optional()])
    subjects_list = ['Math', 'Science', 'English', 'Physics', 'Chemistry', 'Biology', 'Bangla', 'General knowledge', 'Arabic']  # extend as needed

    subjects = SelectMultipleField('Subjects You Can Teach', choices=[(s, s) for s in subjects_list], validators=[Optional()])
    experience = TextAreaField('Teaching Experience', validators=[Optional()])
    
    qualifications = TextAreaField('Skills and Qualifications', validators=[Optional()])
    preferred_classes = StringField('Preferred Classes', validators=[Optional()])  # e.g
    salary_expectation = StringField('Expected Salary', validators=[Optional()])  # e.g. "5000-7000 BDT"
    #time_slots = StringField('Available Time Slots', validators=[Optional()])  # e
    NID_Birth_Certificate = FileField('NID / Birth Certificate (Image)', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg', 'pdf'], 'Only image or PDF files allowed')
    ])
    
    available_days = SelectMultipleField('Available Days', choices=[
        ('Monday', 'Monday'),
        ('Tuesday', 'Tuesday'),
        ('Wednesday', 'Wednesday'),
        ('Thursday', 'Thursday'),
        ('Friday', 'Friday'),
        ('Saturday', 'Saturday'),
        ('Sunday', 'Sunday'),
    ], validators=[Optional()])
    preferred_classes = SelectMultipleField(
    'Preferred Classes',
    choices=[
        ('Class 1', 'Class 1'), ('Class 2', 'Class 2'), ('Class 3', 'Class 3'),
        ('Class 4', 'Class 4'), ('Class 5', 'Class 5'), ('Class 6', 'Class 6'),
        ('Class 7', 'Class 7'), ('Class 8', 'Class 8'), ('Class 9', 'Class 9'),
        ('Class 10', 'Class 10'), ('Class 11', 'Class 11'), ('Class 12', 'Class 12')
    ],
    validators=[Optional()]
    )
    # SSC
    ssc_institute = StringField('SSC Institute', validators=[Optional()])
    ssc_result = StringField('SSC Result', validators=[Optional()])
    ssc_group = StringField('SSC Group', validators=[Optional()])
    ssc_certificate = FileField('SSC Certificate', validators=[Optional()])

    # HSC
    hsc_institute = StringField('HSC Institute', validators=[Optional()])
    hsc_result = StringField('HSC Result', validators=[Optional()])
    hsc_group = StringField('HSC Group', validators=[Optional()])
    hsc_certificate = FileField('HSC Certificate', validators=[Optional()])

    # Graduation
    graduation_institute = StringField('Graduation Institute', validators=[Optional()])
    graduation_result = StringField('Graduation Result', validators=[Optional()])
    graduation_subject = StringField('Graduation Subject', validators=[Optional()])
    graduation_certificate = FileField('Graduation Certificate', validators=[Optional()])





    submit = SubmitField('Update Profile')

class MultiCheckboxField(SelectMultipleField):
    """Custom multi-checkbox widget field for better UI (optional)."""
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

class TutorRequestForm(FlaskForm):
    students_number = IntegerField('Number of Students', validators=[DataRequired()])
    
    # Multi-select fields
    student_classes = SelectMultipleField(
        'Student Classes',
        choices=[
            ('Nursery', 'Nursery'), ('KG', 'KG'),
            ('Class 1', 'Class 1'), ('Class 2', 'Class 2'), ('Class 3', 'Class 3'),
            ('Class 4', 'Class 4'), ('Class 5', 'Class 5'), ('Class 6', 'Class 6'),
            ('Class 7', 'Class 7'), ('Class 8', 'Class 8'), ('Class 9', 'Class 9'),
            ('Class 10', 'Class 10'), ('Class 11', 'Class 11'), ('Class 12', 'Class 12')
        ],
        validators=[DataRequired()]
    )

    teaching_medium = SelectField(
        'Teaching Medium',
        choices=[('Bangla', 'Bangla'), ('EV', 'English Version')],
        validators=[DataRequired()]
    )

    subjects = SelectMultipleField(
        'Subjects',
        choices=[
            ('Math', 'Math'), ('Science', 'Science'), ('English', 'English'),
            ('Bangla', 'Bangla'), ('Physics', 'Physics'), ('Chemistry', 'Chemistry'),
            ('Biology', 'Biology'), ('ICT', 'ICT'), ('Economics', 'Economics'),
            ('Accounting', 'Accounting'), ('Business Studies', 'Business Studies')
        ],
        validators=[DataRequired()]
    )

    starting_date = DateField('Starting Date', format='%Y-%m-%d', validators=[DataRequired()])

    preferred_days = SelectMultipleField(
        'Preferred Days',
        choices=[
            ('Saturday', 'Saturday'), ('Sunday', 'Sunday'), ('Monday', 'Monday'),
            ('Tuesday', 'Tuesday'), ('Wednesday', 'Wednesday'),
            ('Thursday', 'Thursday'), ('Friday', 'Friday')
        ],
        validators=[DataRequired()]
    )

    teaching_time = StringField('Teaching Time (Optional)', validators=[Optional()])
    salary = StringField('Salary Expectation (Optional)', validators=[Optional()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])

    address_text = TextAreaField('Additional Location Details', validators=[Optional()])
    
    latitude = FloatField('Latitude', validators=[DataRequired()])
    longitude = FloatField('Longitude', validators=[DataRequired()])
    
    preferred_tutor_gender = SelectField(
        'Preferred Tutor Gender',
        choices=[('any', 'Any'), ('male', 'Male'), ('female', 'Female')],
        default='any'
    )

    submit = SubmitField('Post Tutor Request')