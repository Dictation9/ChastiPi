#!/usr/bin/env python3
"""
ChastiPi Backup Manager
Handles automated backups of the ChastiPi application
"""

import os
import shutil
import json
import zipfile
from datetime import datetime
from pathlib import Path
import argparse
import sys
import logging
from logging.handlers import RotatingFileHandler
import smtplib
from email.message import EmailMessage

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Set up logging
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
log_file = 'logs/backup.log'
file_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

logger = logging.getLogger('backup_manager')
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

logger.info('Backup manager started')

class BackupManager:
    def __init__(self, backup_dir="backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Files and directories to backup
        self.backup_items = [
            "app.py",
            "requirements.txt",
            "run.py",
            "templates/",
            "static/",
            "README.md",
            "update.sh",
            "install.sh"
        ]
        
        # Files to exclude from backups
        self.exclude_patterns = [
            "__pycache__",
            "*.pyc",
            "*.pyo",
            ".DS_Store",
            "*.log",
            ".git",
            ".venv",
            "venv",
            "node_modules"
        ]
    
    def create_backup(self, backup_name=None, include_logs=False):
        """Create a new backup"""
        if backup_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"chastipi_backup_{timestamp}"
        
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(exist_ok=True)
        
        logger.info(f"Creating backup: {backup_name}")
        
        # Create backup metadata
        metadata = {
            "backup_name": backup_name,
            "created_at": datetime.now().isoformat(),
            "version": "1.0",
            "items_backed_up": [],
            "excluded_items": []
        }
        
        # Backup each item
        for item in self.backup_items:
            source_path = Path(item)
            if source_path.exists():
                dest_path = backup_path / item
                
                if source_path.is_dir():
                    # Create directory and copy contents
                    dest_path.mkdir(parents=True, exist_ok=True)
                    self._copy_directory(source_path, dest_path, metadata)
                else:
                    # Copy file
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, dest_path)
                    metadata["items_backed_up"].append(str(item))
        
        # Include logs if requested
        if include_logs:
            log_files = list(Path(".").glob("*.log"))
            if log_files:
                logs_dir = backup_path / "logs"
                logs_dir.mkdir(exist_ok=True)
                for log_file in log_files:
                    shutil.copy2(log_file, logs_dir / log_file.name)
                    metadata["items_backed_up"].append(f"logs/{log_file.name}")
        
        # Save metadata
        with open(backup_path / "backup_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Backup created successfully: {backup_path}")
        return backup_path
    
    def _copy_directory(self, src, dst, metadata):
        """Copy directory with exclusions"""
        for item in src.iterdir():
            # Check if item should be excluded
            if self._should_exclude(item):
                metadata["excluded_items"].append(str(item))
                continue
            
            if item.is_dir():
                # Recursively copy subdirectories
                new_dst = dst / item.name
                new_dst.mkdir(exist_ok=True)
                self._copy_directory(item, new_dst, metadata)
            else:
                # Copy file
                shutil.copy2(item, dst / item.name)
                metadata["items_backed_up"].append(str(item))
    
    def _should_exclude(self, path):
        """Check if path should be excluded from backup"""
        path_str = str(path)
        for pattern in self.exclude_patterns:
            if pattern in path_str:
                return True
        return False
    
    def list_backups(self):
        """List all available backups"""
        backups = []
        for item in self.backup_dir.iterdir():
            if item.is_dir():
                metadata_file = item / "backup_metadata.json"
                if metadata_file.exists():
                    with open(metadata_file, "r") as f:
                        metadata = json.load(f)
                    backups.append({
                        "name": item.name,
                        "created_at": metadata.get("created_at", "Unknown"),
                        "path": str(item)
                    })
        
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)
    
    def restore_backup(self, backup_name):
        """Restore from a backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            logger.error(f"Error: Backup '{backup_name}' not found")
            return False
        
        metadata_file = backup_path / "backup_metadata.json"
        if not metadata_file.exists():
            logger.error(f"Error: Invalid backup - missing metadata")
            return False
        
        logger.info(f"Restoring from backup: {backup_name}")
        
        # Create a backup of current state before restoring
        current_backup = self.create_backup(backup_name="pre_restore_backup")
        logger.info(f"Current state backed up to: {current_backup}")
        
        # Restore files
        for item in self.backup_items:
            source_path = backup_path / item
            dest_path = Path(item)
            
            if source_path.exists():
                if source_path.is_dir():
                    # Remove existing directory and copy backup
                    if dest_path.exists():
                        shutil.rmtree(dest_path)
                    shutil.copytree(source_path, dest_path)
                else:
                    # Copy file
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, dest_path)
        
        logger.info(f"Restore completed successfully")
        return True
    
    def delete_backup(self, backup_name):
        """Delete a backup"""
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            logger.error(f"Error: Backup '{backup_name}' not found")
            return False
        
        logger.info(f"Deleting backup: {backup_name}")
        shutil.rmtree(backup_path)
        logger.info(f"Backup deleted successfully")
        return True
    
    def create_zip_backup(self, backup_name=None):
        """Create a zip backup"""
        backup_path = self.create_backup(backup_name)
        
        zip_name = f"{backup_path.name}.zip"
        zip_path = self.backup_dir / zip_name
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(backup_path):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(backup_path)
                    zipf.write(file_path, arcname)
        
        # Remove the uncompressed backup
        shutil.rmtree(backup_path)
        
        logger.info(f"Zip backup created: {zip_path}")
        return zip_path

def send_alert_email(subject, body):
    smtp_server = str(os.environ.get('ALERT_EMAIL_SMTP', ''))
    smtp_user = str(os.environ.get('ALERT_EMAIL_USER', ''))
    smtp_pass = str(os.environ.get('ALERT_EMAIL_PASS', ''))
    email_from = str(os.environ.get('ALERT_EMAIL_FROM', ''))
    email_to = str(os.environ.get('ALERT_EMAIL_TO', ''))
    if not all([smtp_server, smtp_user, smtp_pass, email_from, email_to]):
        logger.warning('Alert email not sent: missing SMTP config')
        return
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = email_to
        msg.set_content(body)
        with smtplib.SMTP_SSL(smtp_server) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        logger.info(f'Alert email sent to {email_to}')
    except Exception as e:
        logger.error(f'Failed to send alert email: {e}')

def main():
    parser = argparse.ArgumentParser(description="ChastiPi Backup Manager")
    parser.add_argument("action", choices=["create", "list", "restore", "delete", "zip"],
                       help="Action to perform")
    parser.add_argument("backup_name", nargs="?", help="Backup name (for restore/delete)")
    parser.add_argument("--name", help="Backup name (optional, alternative to positional)")
    parser.add_argument("--include-logs", action="store_true", 
                       help="Include log files in backup")
    parser.add_argument("--backup-dir", default="backups",
                       help="Backup directory (default: backups)")
    
    args = parser.parse_args()
    
    manager = BackupManager(args.backup_dir)
    
    # Use positional argument if provided, otherwise use --name
    backup_name = args.backup_name or args.name
    
    try:
        if args.action == "create":
            logger.info(f"Creating backup: {backup_name or 'timestamped'}")
            manager.create_backup(backup_name, args.include_logs)
        elif args.action == "list":
            logger.info("Listing backups")
            backups = manager.list_backups()
            if not backups:
                print("No backups found")
            else:
                print("Available backups:")
                for backup in backups:
                    print(f"  {backup['name']} - {backup['created_at']}")
        elif args.action == "restore":
            logger.info(f"Restoring backup: {backup_name}")
            if not backup_name:
                print("Error: Backup name required for restore")
                sys.exit(1)
            manager.restore_backup(backup_name)
        elif args.action == "delete":
            logger.info(f"Deleting backup: {backup_name}")
            if not backup_name:
                print("Error: Backup name required for delete")
                sys.exit(1)
            manager.delete_backup(backup_name)
        elif args.action == "zip":
            logger.info(f"Creating zip backup: {backup_name or 'timestamped'}")
            manager.create_zip_backup(backup_name)
    except Exception as e:
        logger.error(f'Backup manager error: {e}', exc_info=True)
        send_alert_email('ChastiPi BACKUP CRITICAL ERROR', f'Backup manager error: {e}')
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 