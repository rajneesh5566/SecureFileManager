import os
import uuid
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from models import User, File, FileShare, AccessLog
from forms import FileUploadForm, FileShareForm, SearchForm, DeleteFileForm
from security import encrypt_file, decrypt_file
from malware_detection import scan_file_for_malware

# Setup logging
logger = logging.getLogger(__name__)

# Create blueprint
file_bp = Blueprint('file_manager', __name__)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def log_file_access(file_id, action):
    """Record an access to a file in the access log"""
    new_log = AccessLog(
        user_id=current_user.id,
        file_id=file_id,
        action=action,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(new_log)
    db.session.commit()
    logger.info(f"File access logged: {action} on file {file_id} by user {current_user.id}")

@file_bp.route('/dashboard')
@login_required
def dashboard():
    # Get all files owned by the user
    my_files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
    
    # Get all files shared with the user
    shared_files_query = db.session.query(File, FileShare) \
        .join(FileShare, File.id == FileShare.file_id) \
        .filter(FileShare.user_id == current_user.id) \
        .order_by(File.upload_date.desc())
    shared_files = shared_files_query.all()
    
    search_form = SearchForm()
    
    return render_template('dashboard.html', 
                          my_files=my_files, 
                          shared_files=shared_files,
                          search_form=search_form)

@file_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FileUploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        
        if file and allowed_file(file.filename):
            # Generate a secure filename with UUID to prevent conflicts and path traversal
            original_filename = secure_filename(file.filename)
            file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            secure_filename_with_uuid = f"{uuid.uuid4().hex}.{file_extension}"
            
            # Save the file temporarily
            temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_filename_with_uuid)
            file.save(temp_path)
            
            # Check file size
            file_size = os.path.getsize(temp_path)
            if file_size > current_app.config['MAX_CONTENT_LENGTH']:
                os.remove(temp_path)
                flash('File is too large', 'danger')
                return redirect(request.url)
            
            # Scan file for malware
            is_malware = scan_file_for_malware(temp_path)
            
            # Encrypt the file and store it
            try:
                file_type = file_extension
                encrypted_path, iv = encrypt_file(temp_path, current_app.config['ENCRYPTED_FOLDER'])
                
                # Remove the temporary file
                os.remove(temp_path)
                
                # Create file record in database
                new_file = File(
                    filename=secure_filename_with_uuid,
                    original_filename=original_filename,
                    encrypted_path=encrypted_path,
                    file_size=file_size,
                    file_type=file_type,
                    iv=iv,
                    user_id=current_user.id,
                    is_malware_scanned=True,
                    is_malware_detected=is_malware
                )
                
                db.session.add(new_file)
                db.session.commit()
                
                # Log the upload
                log_file_access(new_file.id, 'upload')
                
                if is_malware:
                    flash('File uploaded but malware detected! File has been quarantined.', 'warning')
                else:
                    flash('File uploaded successfully!', 'success')
                
                logger.info(f"File uploaded: {original_filename} by user {current_user.id}")
                return redirect(url_for('file_manager.dashboard'))
                
            except Exception as e:
                logger.error(f"Error during file upload: {str(e)}")
                flash('An error occurred during file upload', 'danger')
                return redirect(request.url)
        else:
            flash('Invalid file type', 'danger')
    
    return render_template('file_upload.html', form=form)

@file_bp.route('/file/<int:file_id>')
@login_required
def file_details(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user is the owner or has shared access
    is_owner = file.user_id == current_user.id
    share = None if is_owner else FileShare.query.filter_by(file_id=file.id, user_id=current_user.id).first()
    
    if not is_owner and not share:
        logger.warning(f"Unauthorized access attempt to file {file_id} by user {current_user.id}")
        abort(403)
    
    # Get list of users the file is shared with
    shared_with = []
    if is_owner:
        shared_with_query = db.session.query(User, FileShare) \
            .join(FileShare, User.id == FileShare.user_id) \
            .filter(FileShare.file_id == file.id)
        shared_with = shared_with_query.all()
    
    # Update last accessed time
    file.last_accessed = datetime.utcnow()
    db.session.commit()
    
    # Log the view access
    log_file_access(file.id, 'view')
    
    share_form = FileShareForm() if is_owner else None
    delete_form = DeleteFileForm() if is_owner else None
    
    return render_template('file_details.html', 
                          file=file, 
                          is_owner=is_owner, 
                          share=share, 
                          shared_with=shared_with,
                          share_form=share_form,
                          delete_form=delete_form)

@file_bp.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user is the owner or has shared access
    is_owner = file.user_id == current_user.id
    share = None if is_owner else FileShare.query.filter_by(file_id=file.id, user_id=current_user.id).first()
    
    if not is_owner and not share:
        logger.warning(f"Unauthorized download attempt of file {file_id} by user {current_user.id}")
        abort(403)
    
    if file.is_malware_detected:
        flash('This file has been flagged as potentially malicious and cannot be downloaded', 'danger')
        return redirect(url_for('file_manager.file_details', file_id=file.id))
    
    # Create the temp file name outside try block so it's available in the except block
    temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4().hex}")
    
    try:
        # First, log the download - do this before any possible exceptions
        log_file_access(file.id, 'download')
        
        # Decrypt the file to a temporary location
        decrypt_file(file.encrypted_path, temp_path, file.iv)
        
        # Update last accessed timestamp
        file.last_accessed = datetime.utcnow()
        db.session.commit()
        
        # Send the file
        return_value = send_file(
            temp_path,
            as_attachment=True,
            download_name=file.original_filename
        )
        
        # Set up cleanup function
        def cleanup_temp_file():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    logger.debug(f"Temporary file {temp_path} removed")
            except Exception as e:
                logger.error(f"Error removing temporary file: {str(e)}")
        
        # Register the callback for cleanup
        return_value.call_on_close(cleanup_temp_file)
        
        return return_value
        
    except Exception as e:
        # Attempt to clean up the temp file if it exists
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except:
            pass
            
        # Make sure the transaction is cleaned up
        db.session.rollback()
        
        error_message = str(e)
        logger.error(f"Error during file download: {error_message}")
        
        # Give more specific error message for decryption errors
        if "Padding is incorrect" in error_message:
            flash('Unable to decrypt this file. The encryption key has changed since the file was uploaded. Please re-upload the file.', 'danger')
        else:
            flash('An error occurred during file download', 'danger')
            
        return redirect(url_for('file_manager.file_details', file_id=file.id))

@file_bp.route('/share/<int:file_id>', methods=['POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user is the owner
    if file.user_id != current_user.id:
        logger.warning(f"Unauthorized sharing attempt of file {file_id} by user {current_user.id}")
        abort(403)
    
    form = FileShareForm()
    
    if form.validate_on_submit():
        username = form.username.data
        permissions = form.permissions.data
        
        # Find the user to share with
        user_to_share_with = User.query.filter_by(username=username).first()
        
        if not user_to_share_with:
            flash(f'User {username} not found', 'danger')
            return redirect(url_for('file_manager.file_details', file_id=file_id))
        
        # Check if user is trying to share with themselves
        if user_to_share_with.id == current_user.id:
            flash('You cannot share a file with yourself', 'danger')
            return redirect(url_for('file_manager.file_details', file_id=file_id))
        
        # Check if file is already shared with this user
        existing_share = FileShare.query.filter_by(
            file_id=file_id, 
            user_id=user_to_share_with.id
        ).first()
        
        if existing_share:
            # Update existing share permissions
            existing_share.permissions = permissions
            db.session.commit()
            flash(f'Updated sharing permissions for {username}', 'success')
        else:
            # Create new share
            new_share = FileShare(
                file_id=file_id,
                user_id=user_to_share_with.id,
                shared_by=current_user.id,
                permissions=permissions
            )
            db.session.add(new_share)
            db.session.commit()
            
            flash(f'File shared with {username}', 'success')
        
        # Log the share action
        log_file_access(file_id, 'share')
        
        logger.info(f"File {file_id} shared with user {user_to_share_with.id} by {current_user.id}")
        
    return redirect(url_for('file_manager.file_details', file_id=file_id))

@file_bp.route('/unshare/<int:file_id>/<int:user_id>', methods=['POST'])
@login_required
def unshare_file(file_id, user_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user is the owner
    if file.user_id != current_user.id:
        logger.warning(f"Unauthorized unsharing attempt of file {file_id} by user {current_user.id}")
        abort(403)
    
    # Find the share to remove
    share = FileShare.query.filter_by(file_id=file_id, user_id=user_id).first()
    
    if not share:
        flash('Share not found', 'danger')
        return redirect(url_for('file_manager.file_details', file_id=file_id))
    
    user_to_unshare = User.query.get(user_id)
    username = user_to_unshare.username if user_to_unshare else 'User'
    
    # Remove the share
    db.session.delete(share)
    db.session.commit()
    
    flash(f'File no longer shared with {username}', 'success')
    logger.info(f"File {file_id} unshared from user {user_id} by {current_user.id}")
    
    return redirect(url_for('file_manager.file_details', file_id=file_id))

@file_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user is the owner
    if file.user_id != current_user.id:
        logger.warning(f"Unauthorized delete attempt of file {file_id} by user {current_user.id}")
        abort(403)
    
    form = DeleteFileForm()
    
    if form.validate_on_submit():
        # Get the path to encrypted file
        encrypted_path = file.encrypted_path
        
        # Log the deletion
        log_file_access(file.id, 'delete')
        
        # Delete the file from database (this will cascade to access logs and shares)
        db.session.delete(file)
        db.session.commit()
        
        # Delete the actual encrypted file
        try:
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
        except Exception as e:
            logger.error(f"Error deleting encrypted file: {str(e)}")
        
        flash('File deleted successfully', 'success')
        logger.info(f"File {file_id} deleted by user {current_user.id}")
        
    return redirect(url_for('file_manager.dashboard'))

@file_bp.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    form = SearchForm()
    results = []
    
    if form.validate_on_submit() or request.args.get('query'):
        query = form.query.data if form.validate_on_submit() else request.args.get('query')
        
        # Search user's own files
        own_files = File.query.filter(
            File.user_id == current_user.id,
            File.original_filename.ilike(f"%{query}%")
        ).all()
        
        # Search files shared with the user
        shared_files_query = db.session.query(File, FileShare) \
            .join(FileShare, File.id == FileShare.file_id) \
            .filter(
                FileShare.user_id == current_user.id,
                File.original_filename.ilike(f"%{query}%")
            )
        shared_files = [file for file, _ in shared_files_query.all()]
        
        # Combine results
        all_files = own_files + shared_files
        
        # Remove duplicates
        file_ids = set()
        for file in all_files:
            if file.id not in file_ids:
                results.append(file)
                file_ids.add(file.id)
        
        if not results:
            flash('No files found matching your search', 'info')
    
    return render_template('dashboard.html', 
                          search_results=results, 
                          search_query=request.args.get('query', ''),
                          search_form=form)

@file_bp.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    # Check if user is an admin
    if current_user.role != 'admin':
        logger.warning(f"Non-admin user {current_user.id} attempted to access admin dashboard")
        abort(403)
    
    # Get all users
    users = User.query.all()
    
    # Get all files
    files = File.query.all()
    
    # Get recent access logs
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all()
    
    return render_template('admin.html', 
                          users=users, 
                          files=files, 
                          logs=logs)
