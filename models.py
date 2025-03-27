from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'admin' or 'user'
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy=True)
    shared_files = db.relationship('FileShare', 
                                  primaryjoin="User.id == FileShare.user_id",
                                  backref='user', 
                                  lazy=True,
                                  foreign_keys="[FileShare.user_id]")
    created_shares = db.relationship('FileShare',
                                    primaryjoin="User.id == FileShare.shared_by",
                                    backref='creator',
                                    lazy=True,
                                    foreign_keys="[FileShare.shared_by]")
    access_logs = db.relationship('AccessLog', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    iv = db.Column(db.String(32), nullable=False)  # Initialization vector for AES encryption
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime, nullable=True)
    is_malware_scanned = db.Column(db.Boolean, default=False)
    is_malware_detected = db.Column(db.Boolean, default=False)
    
    # Relationships
    shares = db.relationship('FileShare', backref='file', lazy=True, cascade='all, delete-orphan')
    access_logs = db.relationship('AccessLog', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<File {self.original_filename}>'

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permissions = db.Column(db.String(10), nullable=False, default='read')  # 'read' or 'edit'
    shared_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True)
    
    __table_args__ = (
        db.UniqueConstraint('file_id', 'user_id', name='uix_file_user'),
    )
    
    def __repr__(self):
        return f'<FileShare {self.file_id} shared with {self.user_id}>'

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # upload, download, view, edit, share, delete
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<AccessLog {self.action} on {self.file_id} by {self.user_id}>'
