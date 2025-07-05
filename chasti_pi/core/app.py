"""
Main Flask application factory for ChastiPi
"""
from flask import Flask, request, redirect, url_for, flash, g, current_app
from pathlib import Path
import logging
from .config import config
from .modes import get_current_mode
from .dependencies import setup_dependencies
from ..services.service_fixes import apply_all_service_fixes
from ..api.main import main_bp
from ..api.punishment import bp as punishment_bp
from ..api.calendar import bp as calendar_bp
from ..api.upload import bp as upload_bp
from ..api.keyholder import keyholder_bp
from ..api.time_verification import time_verification_bp
from ..api.cage_check import cage_check_bp
from ..api.webhook import webhook_bp
from ..api.keyholder_config import keyholder_config_bp
from ..api.setup import setup_bp
from ..api.self_manage import self_manage_bp
from ..api.update import update_bp
from ..services.email_service import EmailService
from .scheduler import start_notification_scheduler, stop_notification_scheduler
import os
import importlib.util
import sys

PLUGINS_PATH = Path(__file__).parent.parent.parent / "plugins"

def create_app():
    """Application factory"""
    # Setup dependencies first
    if not setup_dependencies():
        raise RuntimeError("Failed to setup dependencies. Please check the logs and install missing packages manually.")
    
    # Apply service fixes
    apply_all_service_fixes()
    
    app = Flask(__name__, template_folder='../../templates', static_folder='../../static')
    
    # Secret key for session management
    app.secret_key = os.urandom(24)

    # Load configuration
    app.config['CONFIG'] = config
    
    # Load chastity mode
    app.config['CHASTITY_MODE'] = get_current_mode()

    # Register blueprints
    app.register_blueprint(main_bp, url_prefix='/')
    app.register_blueprint(keyholder_bp, url_prefix='/keyholder')
    if app.config['CHASTITY_MODE'].is_feature_enabled('punishments'):
        app.register_blueprint(punishment_bp, url_prefix='/punishment')
    app.register_blueprint(upload_bp, url_prefix='/upload')
    app.register_blueprint(webhook_bp, url_prefix='/webhook')
    app.register_blueprint(time_verification_bp, url_prefix='/time-verification')
    app.register_blueprint(cage_check_bp, url_prefix='/cage-check')
    app.register_blueprint(calendar_bp, url_prefix='/calendar')
    app.register_blueprint(keyholder_config_bp, url_prefix='/keyholder/config')
    app.register_blueprint(setup_bp)
    app.register_blueprint(self_manage_bp)
    app.register_blueprint(update_bp)
    
    @app.before_request
    def before_request_tasks():
        """Tasks to run before each request"""
        # Set chastity mode in g
        g.chastity_mode = current_app.config['CHASTITY_MODE']
        
        # Original setup check
        check_setup_status()

    def check_setup_status():
        """Redirect to setup if not complete"""
        # Allow access to setup and static files regardless of setup status
        if request.endpoint and (request.endpoint.startswith('setup.') or request.endpoint == 'static'):
            return

        # If setup is not complete, redirect to the welcome page
        if not config.get('system.setup_complete'):
            return redirect(url_for('setup.welcome'))
            
        # If setup is complete and in self-managed mode, redirect away from keyholder pages
        if config.get('keyholder.mode') == 'self_managed' and request.endpoint and request.endpoint.startswith('keyholder.'):
            flash("Keyholder pages are disabled in self-managed mode.", "info")
            return redirect(url_for('self_manage.dashboard'))

    # Configure app
    app.config['UPLOAD_FOLDER'] = config.get('upload_folder', 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Network configuration
    app.config['HOST'] = config.get('host', '0.0.0.0')
    app.config['PORT'] = config.get('port', 5000)
    app.config['EXTERNAL_URL'] = config.get('external_url', 'http://localhost:5000')
    app.config['WEBHOOK_URL'] = config.get('webhook_url', 'http://localhost:5000/webhook/email')
    
    # Setup logging
    setup_logging(app)
    
    # Create upload directory
    Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
    
    # Initialize email service
    email_service = EmailService()
    
    # Start notification scheduler
    with app.app_context():
        try:
            start_notification_scheduler()
            app.logger.info("Notification scheduler started successfully")
        except Exception as e:
            app.logger.error(f"Failed to start notification scheduler: {str(e)}")

    # Load plugins
    load_plugins(app)

    # Register cleanup function
    @app.teardown_appcontext
    def cleanup(error):
        if error:
            app.logger.error(f"Application error: {str(error)}")
    
    return app

def setup_logging(app):
    """Setup application logging"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    log_level = config.get('log_level', 'INFO')
    if log_level is None:
        log_level = 'INFO'
    
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'chasti_pi.log'),
            logging.StreamHandler()
        ]
    )

def register_blueprints(app):
    """Register Flask blueprints"""
    app.register_blueprint(main_bp)
    app.register_blueprint(punishment_bp, url_prefix='/punishment')
    app.register_blueprint(calendar_bp, url_prefix='/calendar')
    app.register_blueprint(upload_bp, url_prefix='/upload')
    app.register_blueprint(keyholder_bp, url_prefix='/keyholder')
    app.register_blueprint(webhook_bp, url_prefix='/webhook')
    app.register_blueprint(time_verification_bp, url_prefix='/api/time')
    app.register_blueprint(cage_check_bp, url_prefix='/cage-check')
    
    # Import and register keyholder config blueprint
    try:
        from ..api import keyholder_config
        app.register_blueprint(keyholder_config.keyholder_config_bp, url_prefix='/keyholder/config')
    except ImportError:
        app.logger.warning("Keyholder config blueprint not available")

def load_plugins(app):
    if not PLUGINS_PATH.exists():
        return
    # Get enabled plugins from config
    enabled_plugins = set(config.get('plugins.enabled_plugins', []))
    for plugin_file in PLUGINS_PATH.glob("*.py"):
        if plugin_file.name.startswith("__"):  # skip __init__.py etc
            continue
        plugin_name = plugin_file.stem
        if enabled_plugins and plugin_name not in enabled_plugins:
            continue
        spec = importlib.util.spec_from_file_location(plugin_name, plugin_file)
        if spec is None or spec.loader is None:
            app.logger.error(f"Could not load spec for plugin {plugin_file.name}")
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[plugin_name] = module
        try:
            spec.loader.exec_module(module)
            if hasattr(module, "register_plugin"):
                module.register_plugin(app)
                app.logger.info(f"Loaded plugin: {plugin_file.name}")
        except Exception as e:
            app.logger.error(f"Failed to load plugin {plugin_file.name}: {e}") 