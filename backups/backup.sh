#!/bin/bash

# ChastiPi Backup Script
# Wrapper for the Python backup manager

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_MANAGER="$SCRIPT_DIR/backup_manager.py"
LOG_FILE="$PROJECT_DIR/logs/backup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== ChastiPi Backup Manager ===${NC}"
}

# Function to show help
show_help() {
    print_header
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  create [--name NAME] [--include-logs]  Create a new backup"
    echo "  list                                    List all available backups"
    echo "  restore <backup_name>                   Restore from a backup"
    echo "  delete <backup_name>                    Delete a backup"
    echo "  zip [--name NAME]                       Create a compressed zip backup"
    echo "  auto                                    Create automatic backup (used by update script)"
    echo ""
    echo "Examples:"
    echo "  $0 create                              Create backup with timestamp"
    echo "  $0 create --name my_backup            Create backup with custom name"
    echo "  $0 create --include-logs              Create backup including log files"
    echo "  $0 list                                List all backups"
    echo "  $0 restore chastipi_backup_20240115_143022"
    echo "  $0 delete chastipi_backup_20240115_143022"
    echo "  $0 zip --name important_backup        Create compressed backup"
    echo ""
    echo "Backup files are stored in: $SCRIPT_DIR"
}

# Function to create automatic backup (used by update script)
create_auto_backup() {
    print_status "Creating automatic backup..."
    cd "$PROJECT_DIR"
    python3 "$BACKUP_MANAGER" create --name "auto_backup_$(date +%Y%m%d_%H%M%S)" 2>&1 | tee -a "$LOG_FILE"
}

# Log invocation
{
    echo "\n--- $(date '+%Y-%m-%d %H:%M:%S') [backup.sh invocation] $0 $@ ---"
} >> "$LOG_FILE"

# Main script logic
case "${1:-}" in
    "create")
        cd "$PROJECT_DIR"
        python3 "$BACKUP_MANAGER" create "${@:2}" 2>&1 | tee -a "$LOG_FILE"
        ;;
    "list")
        cd "$PROJECT_DIR"
        python3 "$BACKUP_MANAGER" list 2>&1 | tee -a "$LOG_FILE"
        ;;
    "restore")
        if [ -z "$2" ]; then
            print_error "Backup name required for restore"
            echo "Usage: $0 restore <backup_name>"
            exit 1
        fi
        cd "$PROJECT_DIR"
        python3 "$BACKUP_MANAGER" restore "$2" 2>&1 | tee -a "$LOG_FILE"
        ;;
    "delete")
        if [ -z "$2" ]; then
            print_error "Backup name required for delete"
            echo "Usage: $0 delete <backup_name>"
            exit 1
        fi
        cd "$PROJECT_DIR"
        python3 "$BACKUP_MANAGER" delete "$2" 2>&1 | tee -a "$LOG_FILE"
        ;;
    "zip")
        cd "$PROJECT_DIR"
        python3 "$BACKUP_MANAGER" zip "${@:2}" 2>&1 | tee -a "$LOG_FILE"
        ;;
    "auto")
        create_auto_backup
        ;;
    "help"|"-h"|"--help"|"")
        show_help | tee -a "$LOG_FILE"
        ;;
    *)
        print_error "Unknown command: $1"
        show_help | tee -a "$LOG_FILE"
        exit 1
        ;;
esac 