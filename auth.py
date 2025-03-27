import os
import logging
import pyotp
import io
import qrcode
import base64
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from models import User
from forms import LoginForm, RegistrationForm, TwoFactorForm, SetupTwoFactorForm

# Setup logging
logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('file_manager.dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == form.username.data) | 
                                         (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return render_template('register.html', form=form)
        
        # Create new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role='user'  # Default role
        )
        
        # First user gets admin role
        if User.query.count() == 0:
            new_user.role = 'admin'
            flash('You have been registered as an admin user', 'info')
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            logger.info(f"New user registered: {new_user.username}")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user: {str(e)}")
            flash('An error occurred during registration', 'danger')
    
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('file_manager.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if not user or not check_password_hash(user.password_hash, form.password.data):
            flash('Invalid username or password', 'danger')
            logger.warning(f"Failed login attempt for username: {form.username.data}")
            return render_template('login.html', form=form)
        
        # Check if 2FA is enabled for this user
        if user.is_2fa_enabled:
            # Store user ID in session for 2FA verification
            session['user_id_for_2fa'] = user.id
            return redirect(url_for('auth.verify_2fa'))
        
        # Login successful
        login_user(user)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"User logged in: {user.username}")
        flash('Login successful!', 'success')
        
        # Redirect to the requested page or dashboard
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('file_manager.dashboard'))
    
    return render_template('login.html', form=form)

@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Check if we have a user to verify
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        user_id = session.get('user_id_for_2fa')
        user = User.query.get(user_id)
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('auth.login'))
        
        # Verify OTP
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.otp_code.data):
            # Clear 2FA session
            session.pop('user_id_for_2fa', None)
            
            # Login the user
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"User completed 2FA: {user.username}")
            flash('Two-factor authentication successful!', 'success')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('file_manager.dashboard'))
        else:
            flash('Invalid verification code', 'danger')
            logger.warning(f"Failed 2FA attempt for user ID: {user_id}")
    
    return render_template('verify_2fa.html', form=form)

@auth_bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    form = SetupTwoFactorForm()
    
    # Generate new OTP secret if not already set
    if not current_user.otp_secret:
        current_user.otp_secret = pyotp.random_base32()
        db.session.commit()
    
    # Generate QR code for the OTP secret
    totp = pyotp.TOTP(current_user.otp_secret)
    provisioning_url = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="Secure File System"
    )
    
    # Create QR code image
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()
    
    if form.validate_on_submit():
        # Verify the entered OTP
        totp = pyotp.TOTP(current_user.otp_secret)
        if totp.verify(form.otp_code.data):
            # Enable 2FA for the user
            current_user.is_2fa_enabled = True
            db.session.commit()
            
            logger.info(f"2FA enabled for user: {current_user.username}")
            flash('Two-factor authentication has been enabled!', 'success')
            return redirect(url_for('file_manager.dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('setup_2fa.html', 
                          form=form, 
                          secret=current_user.otp_secret, 
                          qr_code=qr_code_data)

@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        flash('Two-factor authentication is not enabled', 'warning')
        return redirect(url_for('file_manager.dashboard'))
    
    # Disable 2FA
    current_user.is_2fa_enabled = False
    db.session.commit()
    
    logger.info(f"2FA disabled for user: {current_user.username}")
    flash('Two-factor authentication has been disabled', 'success')
    return redirect(url_for('file_manager.dashboard'))

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
