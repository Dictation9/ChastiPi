# ChastiPi Backup System

This directory contains the backup management system for ChastiPi, providing automated backup creation, restoration, and management capabilities.

## Overview

The backup system consists of:
- **Python Backup Manager** (`backup_manager.py`) - Core backup functionality
- **Shell Script Wrapper** (`backup.sh`) - Easy-to-use command-line interface
- **Backup Storage** - All backups are stored in this directory

## Quick Start

### Create a Backup
```bash
# Create backup with timestamp
./backups/backup.sh create

# Create backup with custom name
./backups/backup.sh create --name my_backup

# Create backup including log files
./backups/backup.sh create --include-logs
```

### List Available Backups
```bash
./backups/backup.sh list
```

### Restore from Backup
```bash
./backups/backup.sh restore chastipi_backup_20240115_143022
```

### Delete a Backup
```bash
./backups/backup.sh delete chastipi_backup_20240115_143022
```

### Create Compressed Backup
```bash
./backups/backup.sh zip --name important_backup
```

## Features

### 🔄 **Automated Backups**
- Timestamped backup names
- Metadata tracking with creation dates
- Automatic backup before updates (via update script)

### 📁 **Comprehensive Coverage**
- Application files (`app.py`, `requirements.txt`, etc.)
- Templates and static assets
- Configuration files
- Optional log file inclusion

### 🛡️ **Smart Exclusions**
- Excludes temporary files (`__pycache__`, `*.pyc`)
- Excludes virtual environments (`.venv`, `venv`)
- Excludes development files (`.git`, `.DS_Store`)
- Excludes large directories (`node_modules`)

### 🔧 **Restoration Safety**
- Creates backup of current state before restoration
- Validates backup integrity before restoration
- Preserves metadata for tracking

### 📦 **Compression Support**
- Create compressed zip backups
- Automatic cleanup of uncompressed versions
- Reduced storage requirements

## Backup Structure

Each backup contains:
```
chastipi_backup_YYYYMMDD_HHMMSS/
├── app.py
├── requirements.txt
├── run.py
├── templates/
├── static/
├── README.md
├── update.sh
├── install.sh
├── logs/ (if --include-logs)
└── backup_metadata.json
```

## Integration with Update System

The backup system integrates with the main update script (`update.sh`):
- Automatic backups before updates
- Fallback to legacy backup method if new system unavailable
- Seamless integration with existing workflow

## Advanced Usage

### Direct Python Usage
```bash
# Create backup
python3 backups/backup_manager.py create --name custom_backup

# List backups
python3 backups/backup_manager.py list

# Restore backup
python3 backups/backup_manager.py restore backup_name

# Create zip backup
python3 backups/backup_manager.py zip --name compressed_backup
```

### Programmatic Usage
```python
from backups.backup_manager import BackupManager

# Create backup manager
manager = BackupManager("backups")

# Create backup
backup_path = manager.create_backup("my_backup", include_logs=True)

# List backups
backups = manager.list_backups()

# Restore backup
success = manager.restore_backup("backup_name")
```

## Configuration

### Backup Items
The following items are backed up by default:
- `app.py` - Main application file
- `requirements.txt` - Python dependencies
- `run.py` - Application runner
- `templates/` - HTML templates
- `static/` - CSS, JavaScript, and assets
- `README.md` - Documentation
- `update.sh` - Update script
- `install.sh` - Installation script

### Excluded Items
The following items are excluded from backups:
- `__pycache__` - Python cache directories
- `*.pyc`, `*.pyo` - Compiled Python files
- `.DS_Store` - macOS system files
- `*.log` - Log files (unless --include-logs)
- `.git` - Git repository
- `.venv`, `venv` - Virtual environments
- `node_modules` - Node.js dependencies

## Best Practices

### Regular Backups
- Create backups before major changes
- Use descriptive names for important backups
- Keep multiple backup versions for safety

### Storage Management
- Use compressed backups for long-term storage
- Regularly clean up old backups
- Monitor backup directory size

### Restoration Testing
- Test restoration process periodically
- Verify backup integrity before relying on them
- Keep backup metadata for troubleshooting

## Troubleshooting

### Common Issues

**Backup creation fails:**
- Check disk space availability
- Verify file permissions
- Ensure Python dependencies are installed

**Restoration fails:**
- Verify backup integrity
- Check for file conflicts
- Review backup metadata

**Large backup sizes:**
- Use `--include-logs` sparingly
- Consider compressed backups
- Review excluded items list

### Log Files
Backup operations are logged to the console. For detailed debugging, run with verbose output:
```bash
python3 backups/backup_manager.py create --verbose
```

## Security Notes

- Backups may contain sensitive configuration data
- Store backups in secure locations
- Consider encryption for sensitive deployments
- Regularly rotate backup credentials if applicable

## File Locations

- **Backup Script**: `backups/backup.sh`
- **Python Manager**: `backups/backup_manager.py`
- **Backup Storage**: `backups/` directory
- **Documentation**: `backups/README.md` 