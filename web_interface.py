import os
import logging
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from models import db, ScanResult, Vulnerability, ScanDetail, User
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from dns_tools import DNSScanner
from nmap_scanner import NmapScanner
from scan_engine import ScanEngine
import uuid

# Enhanced logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

try:
    # Initialize Flask app
    app = Flask(__name__, static_folder='static', template_folder='templates')

    # Security configurations
    app.config['SECRET_KEY'] = os.urandom(24)

    # Get database URL from environment
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL environment variable not set")
    logger.info(f"Using database URL format: {db_url.split('://')[0]}://<credentials>@<host>/<database>")

    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)

    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 30,
        'pool_recycle': 1800,
    }

    # Cookie security settings
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True

    logger.info("Initializing Flask extensions...")

    # Initialize database
    logger.info("Initializing database...")
    db.init_app(app)

    # Initialize migrations
    logger.info("Setting up database migrations...")
    migrate = Migrate(app, db)

    # Initialize login manager
    logger.info("Configuring login manager...")
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    # Initialize bcrypt
    logger.info("Initializing bcrypt...")
    bcrypt = Bcrypt(app)

    # Initialize scanning engine with proper error handling
    logger.info("Initializing scan engine...")
    try:
        scan_engine = ScanEngine()
        logger.info("Scan engine initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize scan engine: {str(e)}")
        raise

except Exception as e:
    logger.error(f"Failed to initialize application: {str(e)}")
    raise

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        try:
            user = User.query.filter_by(email=email).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user, remember=remember)
                user.last_login = datetime.utcnow()
                db.session.commit()

                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password', 'error')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        try:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(email=email, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash('Registration successful! Welcome to DragonEye Scanner.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')

    query = Vulnerability.query

    if status_filter:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter)

    vulnerabilities = query.all()
    tickets = [{
        'id': v.id,
        'title': f"{v.severity.upper()} - {v.vulnerability_type}",
        'description': v.description,
        'severity': v.severity,
        'status': v.status,
        'affected_components': [v.affected_component] if v.affected_component else [],
        'dateFound': v.created_at.isoformat(),
        'lastUpdated': v.created_at.isoformat()
    } for v in vulnerabilities]

    return jsonify({'tickets': tickets})

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json()
    target = data.get('target', '')
    technique = data.get('technique', '')
    selected_tools = data.get('tools', [])

    if not validate_target(target):
        return jsonify({'error': 'Invalid target specified'}), 400

    if not selected_tools:
        return jsonify({'error': 'No tools selected for scanning'}), 400

    try:
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting new scan with ID {scan_id} for target {target}")

        # Create scan result record
        scan_result = ScanResult(
            scan_id=scan_id,
            target_domain=target,
            scan_type=','.join(selected_tools),  # Store all selected tools
            status='pending',
            progress=0,
            start_time=datetime.utcnow()
        )
        db.session.add(scan_result)
        db.session.commit()
        logger.info(f"Created scan record for scan_id: {scan_id}")

        # Start the scan
        result = scan_engine.start_scan(scan_id, target, technique, selected_tools)

        if result.get('status') == 'started':
            # Execute scan in background thread
            def execute_scan_async():
                with app.app_context():
                    try:
                        logger.info(f"Starting scan execution for scan_id: {scan_id}")
                        result = scan_engine.execute_scan(scan_id)
                        
                        # Update scan status based on result
                        scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
                        if scan_result:
                            if result.get('status') == 'completed':
                                scan_result.status = 'completed'
                                scan_result.progress = 100
                                # Store individual tool results
                                if 'results' in result:
                                    scan_result.results = json.dumps(result['results'])
                            else:
                                scan_result.status = 'failed'
                            scan_result.end_time = datetime.utcnow()
                            db.session.commit()
                            logger.info(f"Scan completed for scan_id: {scan_id}")
                    except Exception as e:
                        logger.error(f"Scan execution error: {str(e)}")
                        try:
                            scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
                            if scan_result:
                                scan_result.status = 'failed'
                                scan_result.end_time = datetime.utcnow()
                                db.session.commit()
                        except Exception as db_error:
                            logger.error(f"Failed to update scan status: {str(db_error)}")
                            db.session.rollback()

            thread = threading.Thread(target=execute_scan_async)
            thread.daemon = True
            thread.start()

            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'message': 'Scan started successfully',
                'target': target,
                'tools': selected_tools
            })
        else:
            error_msg = result.get('message', 'Unknown error starting scan')
            logger.error(f"Failed to start scan: {error_msg}")
            scan_result.status = 'failed'
            db.session.commit()
            return jsonify({
                'error': 'Failed to start scan',
                'message': error_msg
            }), 500

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        try:
            db.session.rollback()
            if 'scan_result' in locals():
                scan_result.status = 'failed'
                db.session.commit()
        except Exception as cleanup_error:
            logger.error(f"Error during cleanup: {str(cleanup_error)}")

        return jsonify({'error': str(e)}), 500

@app.route('/scan/progress/<scan_id>', methods=['GET'])
@login_required
def get_scan_progress(scan_id):
    """Get the current progress of a running scan"""
    try:
        # Get scan result from database
        scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404

        # Get progress from scan engine
        progress_data = scan_engine.get_scan_progress(scan_id)

        # Prepare response data
        response = {
            'status': progress_data.get('status', scan_result.status),
            'progress': progress_data.get('progress', scan_result.progress),
            'target': scan_result.target_domain,
            'tools': scan_result.scan_type.split(',') if scan_result.scan_type else [],
            'current_tool': progress_data.get('current_tool'),
            'start_time': scan_result.start_time.isoformat() if scan_result.start_time else None
        }

        # Include results if they exist
        if 'results' in progress_data:
            response['results'] = progress_data['results']

        return jsonify(response)
    except Exception as e:
        logger.error(f"Error getting scan progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

def validate_target(target):
    """Validate the target domain/IP."""
    if not target:
        return False
    return True

def determine_severity(data):
    """Determine severity based on scan data."""
    if not data:
        return 'low'
    return 'medium'

def format_scan_results(results):
    """Format raw scan results for display."""
    if not results:
        return {}

    formatted = {
        'summary': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        },
        'details': []
    }
    return formatted

@app.route('/health')
def health_check():
    """Simple health check endpoint to verify server is running"""
    logger.info("Health check endpoint accessed")
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    try:
        logger.info("Starting application initialization...")

        # Initialize database tables within app context
        with app.app_context():
            logger.info("Creating database tables...")
            try:
                db.create_all()
                logger.info("Database tables created successfully")
            except Exception as db_error:
                logger.error(f"Database initialization error: {str(db_error)}")
                raise

        # Start the Flask application
        logger.info("Starting Flask application on port 3000...")
        app.run(
            host='0.0.0.0',
            port=3000,
            debug=True,
            use_reloader=False  # Disable reloader to prevent duplicate processes
        )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        raise