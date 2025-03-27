import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)

# Configure app
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")  # Use environment variable or default in dev
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///secure_file_system.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ENCRYPTED_FOLDER"] = "encrypted_files"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload size
app.config["ALLOWED_EXTENSIONS"] = {"txt", "pdf", "png", "jpg", "jpeg", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}

# Initialize SQLAlchemy with app
db.init_app(app)

# Ensure upload directories exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCRYPTED_FOLDER"], exist_ok=True)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Import models to ensure they're registered with SQLAlchemy
with app.app_context():
    from models import User, File, FileShare, AccessLog
    db.create_all()

# Import and register blueprints after db initialization to avoid circular imports
from auth import auth_bp
from file_manager import file_bp

app.register_blueprint(auth_bp)
app.register_blueprint(file_bp)

# Import user loader for Flask-Login
from models import User

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Root route redirects to auth routes
@app.route('/')
def index():
    from flask import redirect, url_for
    return redirect(url_for('auth.login'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    from flask import render_template
    return render_template('base.html', error_message="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    from flask import render_template
    logger.error(f"Server error: {e}")
    return render_template('base.html', error_message="Internal server error"), 500

# Template context processors
@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow()}

logger.info("Application initialized")
