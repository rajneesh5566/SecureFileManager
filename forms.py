from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_password(self, password):
        # Check for password complexity
        if not re.search(r"[A-Z]", password.data):
            raise ValidationError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", password.data):
            raise ValidationError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", password.data):
            raise ValidationError("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password.data):
            raise ValidationError("Password must contain at least one special character")

class TwoFactorForm(FlaskForm):
    otp_code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Verification code must be 6 digits')
    ])
    submit = SubmitField('Verify')

class SetupTwoFactorForm(FlaskForm):
    otp_code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Verification code must be 6 digits')
    ])
    submit = SubmitField('Enable Two-Factor Authentication')

class FileUploadForm(FlaskForm):
    file = FileField('File', validators=[
        FileRequired(),
        FileAllowed(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'], 
                   'Only allowed file types: txt, pdf, png, jpg, jpeg, doc, docx, xls, xlsx, ppt, pptx')
    ])
    notes = TextAreaField('Notes', validators=[Length(max=500)])
    submit = SubmitField('Upload')

class FileShareForm(FlaskForm):
    username = StringField('Username to share with', validators=[DataRequired()])
    permissions = SelectField('Permissions', choices=[
        ('read', 'Read Only'),
        ('edit', 'Read & Edit')
    ], default='read')
    submit = SubmitField('Share')

class SearchForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')

class DeleteFileForm(FlaskForm):
    confirm = HiddenField('Confirm', default='yes')
    submit = SubmitField('Delete')
