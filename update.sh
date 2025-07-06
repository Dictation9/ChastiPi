#!/bin/bash

# ChastiPi Manual Update Script
# This script provides various update options for the ChastiPi dashboard

set -e  # Exit on any error

# Ensure logs directory exists
mkdir -p logs
LOG_FILE="logs/update.log"
echo -e "\n--- $(date '+%Y-%m-%d %H:%M:%S') [update.sh invocation] $0 $@ ---" >> "$LOG_FILE"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Redefine print_status, print_warning, print_error to log to file
print_status() {
    echo -e "[INFO] $1" | tee -a "$LOG_FILE"
}
print_warning() {
    echo -e "[WARNING] $1" | tee -a "$LOG_FILE"
}
print_error() {
    echo -e "[ERROR] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  ChastiPi Manual Update Script${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

# Function to check if we're in a git repository
check_git_repo() {
    if [ ! -d ".git" ]; then
        print_warning "Not a git repository. Some update options will be limited."
        return 1
    fi
    return 0
}

# Function to backup current state
backup_current_state() {
    print_status "Creating backup of current state..."
    
    # Use the new backup system if available
    if [ -f "backups/backup.sh" ]; then
        ./backups/backup.sh auto
    else
        # Fallback to old backup method
        BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        
        # Copy important files
        cp -r templates "$BACKUP_DIR/" 2>/dev/null || true
        cp -r static "$BACKUP_DIR/" 2>/dev/null || true
        cp app.py "$BACKUP_DIR/" 2>/dev/null || true
        cp requirements.txt "$BACKUP_DIR/" 2>/dev/null || true
        cp run.py "$BACKUP_DIR/" 2>/dev/null || true
        
        print_status "Backup created in: $BACKUP_DIR"
    fi
}

# Function to update dependencies
update_dependencies() {
    print_status "Updating Python dependencies..."
    
    # Check if virtual environment exists
    if [ ! -d ".venv" ]; then
        print_warning "Virtual environment not found. Creating one..."
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Upgrade pip
    print_status "Upgrading pip..."
    pip install --upgrade pip
    
    # Update requirements
    print_status "Updating requirements..."
    pip install -r requirements.txt --upgrade
    
    # Generate new requirements.txt with current versions
    print_status "Generating updated requirements.txt..."
    pip freeze > requirements.txt.new
    
    # Show what changed
    if [ -f "requirements.txt" ]; then
        print_status "Changes in dependencies:"
        diff requirements.txt requirements.txt.new || true
        mv requirements.txt.new requirements.txt
    else
        mv requirements.txt.new requirements.txt
    fi
    
    print_status "Dependencies updated successfully!"
}

# Function to merge configuration files
merge_config_files() {
    local file_path="$1"
    local backup_file="$2"
    
    if [ -f "$file_path" ] && [ -f "$backup_file" ]; then
        print_status "Merging configuration file: $file_path"
        
        # Create a temporary file for the merged result
        local temp_file=$(mktemp)
        
        # Try to merge using git merge-file if available
        if command -v git >/dev/null 2>&1; then
            # Use git merge-file for better conflict resolution
            if git merge-file "$file_path" "$backup_file" "$file_path" >/dev/null 2>&1; then
                print_status "Successfully merged $file_path using git merge-file"
                return 0
            fi
        fi
        
        # Fallback: simple line-by-line merge for common config files
        case "$file_path" in
            *.json)
                print_warning "JSON merge not implemented. Please manually merge $file_path"
                ;;
            *.yaml|*.yml)
                print_warning "YAML merge not implemented. Please manually merge $file_path"
                ;;
            *.ini|*.cfg|*.conf)
                merge_ini_file "$file_path" "$backup_file" "$temp_file"
                ;;
            *.txt|*.log)
                # For text files, keep both versions
                print_status "Keeping both versions of $file_path"
                cp "$file_path" "${file_path}.new"
                cp "$backup_file" "${file_path}.old"
                ;;
            *)
                print_warning "Unknown file type. Please manually merge $file_path"
                ;;
        esac
        
        rm -f "$temp_file"
    fi
}

# Function to merge INI-style configuration files
merge_ini_file() {
    local current_file="$1"
    local backup_file="$2"
    local output_file="$3"
    
    print_status "Merging INI-style configuration..."
    
    # Create a simple merge by combining sections
    # This is a basic implementation - more sophisticated merging could be added
    
    # Start with the current file
    cp "$current_file" "$output_file"
    
    # Add sections from backup that don't exist in current
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            section="${line#[}"
            section="${section%]}"
            if ! grep -q "^\[$section\]" "$output_file"; then
                echo "" >> "$output_file"
                echo "$line" >> "$output_file"
                # Add the section content
                sed -n "/^\[$section\]/,/^\[/p" "$backup_file" | tail -n +2 | head -n -1 >> "$output_file" 2>/dev/null || true
            fi
        fi
    done < "$backup_file"
    
    # Replace the current file with merged version
    mv "$output_file" "$current_file"
    print_status "INI file merged successfully"
}

# Function to handle merge conflicts gracefully
handle_merge_conflicts() {
    local backup_dir="$1"
    
    print_warning "Merge conflicts detected. Attempting to resolve automatically..."
    
    # Check for common conflict patterns and resolve them
    for file in *.py *.js *.html *.css *.txt *.ini *.json *.yaml *.yml; do
        if [ -f "$file" ] && grep -q "<<<<<<< HEAD" "$file"; then
            print_status "Resolving conflicts in $file..."
            
            # Create a backup of the conflicted file
            cp "$file" "$file.conflict"
            
            # Try to resolve common patterns
            if [[ "$file" == *.py ]] || [[ "$file" == *.js ]]; then
                # For code files, prefer the newer version but keep local customizations
                sed '/<<<<<<< HEAD/,/=======/d' "$file" | sed '/>>>>>>> /d' > "$file.tmp"
                mv "$file.tmp" "$file"
            elif [[ "$file" == *.ini ]] || [[ "$file" == *.conf ]]; then
                # For config files, merge sections
                merge_ini_file "$file" "$backup_dir/$file" "$file.tmp"
            else
                # For other files, keep both versions
                print_warning "Manual resolution needed for $file"
                cp "$file" "${file}.conflict"
            fi
        fi
    done
    
    # Remove conflict markers from any remaining files
    find . -name "*.py" -o -name "*.js" -o -name "*.html" -o -name "*.css" | xargs sed -i '/<<<<<<< HEAD/,/>>>>>>> /d' 2>/dev/null || true
}

# Function to update code from git
update_code() {
    if ! check_git_repo; then
        print_error "Cannot update code: not a git repository"
        return 1
    fi
    
    print_status "Updating code from git repository..."
    
    # Create a list of important files to backup before update
    IMPORTANT_FILES=(
        "config.ini"
        "settings.json"
        "app.py"
        "requirements.txt"
        "run.py"
    )
    
    # Backup important files
    BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    for file in "${IMPORTANT_FILES[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/"
        fi
    done
    
    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        print_warning "You have uncommitted changes. Stashing them..."
        git stash
        STASHED=true
    else
        STASHED=false
    fi
    
    # Fetch latest changes
    print_status "Fetching latest changes..."
    git fetch origin
    
    # Check if there are updates
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)
    
    if [ "$LOCAL" = "$REMOTE" ]; then
        print_status "Code is already up to date!"
        return 0
    fi
    
    # Try to pull with merge strategy
    print_status "Pulling latest changes with merge strategy..."
    
    # Set merge strategy to favor local changes
    git config pull.rebase false
    git config merge.ours.driver true
    
    # Attempt to pull with automatic merging
    if git pull origin main 2>/dev/null || git pull origin master 2>/dev/null; then
        print_status "Successfully pulled and merged changes!"
    else
        print_warning "Automatic merge failed. Attempting manual merge..."
        
        # Reset to before the failed merge
        git reset --hard HEAD
        
        # Try a different approach - merge with strategy
        if git pull --strategy=ours origin main 2>/dev/null || git pull --strategy=ours origin master 2>/dev/null; then
            print_status "Merged with local changes preserved!"
        else
            print_error "Merge failed. Attempting automatic conflict resolution..."
            handle_merge_conflicts "$BACKUP_DIR"
            
            # Try to commit the resolved conflicts
            if git add . && git commit -m "Auto-resolved merge conflicts" 2>/dev/null; then
                print_status "Successfully resolved conflicts automatically!"
            else
                print_error "Automatic resolution failed. Manual intervention required."
                print_status "Backup files are available in: $BACKUP_DIR"
                print_status "Please resolve conflicts manually and then run:"
                print_status "  git add ."
                print_status "  git commit -m 'Resolved merge conflicts'"
                return 1
            fi
        fi
    fi
    
    # Restore stashed changes if any
    if [ "$STASHED" = true ]; then
        print_status "Restoring stashed changes..."
        if ! git stash pop; then
            print_warning "Could not restore stashed changes. Check git status."
        fi
    fi
    
    # Merge important configuration files
    print_status "Checking for configuration file conflicts..."
    for file in "${IMPORTANT_FILES[@]}"; do
        if [ -f "$file" ] && [ -f "$BACKUP_DIR/$file" ]; then
            # Check if files are different
            if ! cmp -s "$file" "$BACKUP_DIR/$file"; then
                merge_config_files "$file" "$BACKUP_DIR/$file"
            fi
        fi
    done
    
    print_status "Code updated successfully!"
    print_status "Backup files available in: $BACKUP_DIR"
}

# Function to update system packages
update_system() {
    print_status "Updating system packages..."
    
    # Check if running on Raspberry Pi
    if [ -f "/etc/rpi-issue" ] || grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_status "Detected Raspberry Pi - updating system packages..."
        
        # Update package lists
        sudo apt update
        
        # Upgrade packages
        sudo apt upgrade -y
        
        # Clean up
        sudo apt autoremove -y
        sudo apt autoclean
        
        print_status "System packages updated successfully!"
    else
        print_warning "Not running on Raspberry Pi. Skipping system updates."
    fi
}

# Function to restart the application
restart_app() {
    print_status "Restarting ChastiPi application..."
    
    # Find and kill existing process
    PID=$(pgrep -f "python.*app.py" || pgrep -f "python.*run.py" || echo "")
    if [ ! -z "$PID" ]; then
        print_status "Stopping existing ChastiPi process (PID: $PID)..."
        kill $PID
        sleep 2
    fi
    
    # Start the application
    print_status "Starting ChastiPi..."
    nohup python run.py > chastipi.log 2>&1 &
    
    print_status "ChastiPi restarted successfully!"
    print_status "Check logs with: tail -f chastipi.log"
}

# Function to setup autostart
setup_autostart() {
    print_status "Setting up ChastiPi to start on boot..."
    
    # Get the current directory
    CURRENT_DIR=$(pwd)
    SCRIPT_PATH="$CURRENT_DIR/run.py"
    
    # Check if running on Raspberry Pi
    if [ -f "/etc/rpi-issue" ] || grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_status "Detected Raspberry Pi - setting up systemd service..."
        
        # Create systemd service file
        SERVICE_FILE="/etc/systemd/system/chastipi.service"
        
        cat > /tmp/chastipi.service << EOF
[Unit]
Description=ChastiPi Dashboard
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$CURRENT_DIR
Environment=PATH=$CURRENT_DIR/.venv/bin
ExecStart=$CURRENT_DIR/.venv/bin/python $SCRIPT_PATH
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        # Copy service file to systemd directory
        sudo cp /tmp/chastipi.service "$SERVICE_FILE"
        
        # Reload systemd
        sudo systemctl daemon-reload
        
        # Enable the service
        sudo systemctl enable chastipi.service
        
        print_status "ChastiPi autostart service created and enabled!"
        print_status "Service file: $SERVICE_FILE"
        print_status "To manage the service:"
        print_status "  sudo systemctl start chastipi"
        print_status "  sudo systemctl stop chastipi"
        print_status "  sudo systemctl status chastipi"
        print_status "  sudo systemctl disable chastipi"
        
    else
        print_status "Setting up crontab for autostart..."
        
        # Create startup script
        STARTUP_SCRIPT="$CURRENT_DIR/startup.sh"
        
        cat > "$STARTUP_SCRIPT" << EOF
#!/bin/bash
cd "$CURRENT_DIR"
source .venv/bin/activate
python run.py > chastipi.log 2>&1 &
EOF
        
        chmod +x "$STARTUP_SCRIPT"
        
        # Add to crontab
        (crontab -l 2>/dev/null; echo "@reboot $STARTUP_SCRIPT") | crontab -
        
        print_status "ChastiPi autostart configured via crontab!"
        print_status "Startup script: $STARTUP_SCRIPT"
        print_status "To remove autostart: crontab -e"
    fi
}

# Function to remove autostart
remove_autostart() {
    print_status "Removing ChastiPi autostart configuration..."
    
    # Check if running on Raspberry Pi
    if [ -f "/etc/rpi-issue" ] || grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_status "Removing systemd service..."
        
        # Disable and remove service
        sudo systemctl disable chastipi.service 2>/dev/null || true
        sudo rm -f /etc/systemd/system/chastipi.service
        sudo systemctl daemon-reload
        
        print_status "Systemd service removed!"
        
    else
        print_status "Removing from crontab..."
        
        # Remove from crontab
        crontab -l 2>/dev/null | grep -v "startup.sh" | crontab -
        
        # Remove startup script
        rm -f "$CURRENT_DIR/startup.sh"
        
        print_status "Crontab autostart removed!"
    fi
}

# Function to show update menu
show_menu() {
    echo ""
    echo "Available update options:"
    echo "1) Update dependencies only"
    echo "2) Update code from git repository"
    echo "3) Update system packages (Raspberry Pi only)"
    echo "4) Full update (dependencies + code + system)"
    echo "5) Restart application"
    echo "6) Show current status"
    echo "7) Setup autostart (start on boot)"
    echo "8) Remove autostart"
    echo "9) Exit"
    echo ""
    read -p "Select an option (1-9): " choice
}

# Function to show current status
show_status() {
    print_status "Current ChastiPi Status:"
    echo ""
    
    # Check if app is running
    PID=$(pgrep -f "python.*app.py" || pgrep -f "python.*run.py" || echo "")
    if [ ! -z "$PID" ]; then
        echo -e "${GREEN}✓${NC} ChastiPi is running (PID: $PID)"
    else
        echo -e "${RED}✗${NC} ChastiPi is not running"
    fi
    
    # Check git status
    if check_git_repo; then
        echo -e "${GREEN}✓${NC} Git repository detected"
        BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
        echo "   Current branch: $BRANCH"
        COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        echo "   Current commit: $COMMIT"
    else
        echo -e "${YELLOW}⚠${NC} Not a git repository"
    fi
    
    # Check virtual environment
    if [ -d ".venv" ]; then
        echo -e "${GREEN}✓${NC} Virtual environment exists"
    else
        echo -e "${YELLOW}⚠${NC} Virtual environment not found"
    fi
    
    # Check if running on Raspberry Pi
    if [ -f "/etc/rpi-issue" ] || grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Running on Raspberry Pi"
    else
        echo -e "${YELLOW}⚠${NC} Not running on Raspberry Pi"
    fi
}

# Main function
main() {
    print_header
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for security reasons."
    fi
    
    # Parse command line arguments
    if [ "$1" = "--deps" ]; then
        update_dependencies
        exit 0
    elif [ "$1" = "--code" ]; then
        update_code
        exit 0
    elif [ "$1" = "--system" ]; then
        update_system
        exit 0
    elif [ "$1" = "--full" ]; then
        backup_current_state
        update_dependencies
        update_code
        update_system
        restart_app
        exit 0
    elif [ "$1" = "--restart" ]; then
        restart_app
        exit 0
    elif [ "$1" = "--status" ]; then
        show_status
        exit 0
    elif [ "$1" = "--autostart" ]; then
        setup_autostart
        exit 0
    elif [ "$1" = "--remove-autostart" ]; then
        remove_autostart
        exit 0
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --deps              Update Python dependencies only"
        echo "  --code              Update code from git repository"
        echo "  --system            Update system packages (Raspberry Pi only)"
        echo "  --full              Perform full update (dependencies + code + system)"
        echo "  --restart           Restart the ChastiPi application"
        echo "  --status            Show current status"
        echo "  --autostart         Setup autostart (start on boot)"
        echo "  --remove-autostart  Remove autostart configuration"
        echo "  --help              Show this help message"
        echo ""
        echo "If no option is provided, an interactive menu will be shown."
        exit 0
    fi
    
    # Interactive mode
    while true; do
        show_menu
        
        case $choice in
            1)
                backup_current_state
                update_dependencies
                ;;
            2)
                backup_current_state
                update_code
                ;;
            3)
                update_system
                ;;
            4)
                backup_current_state
                update_dependencies
                update_code
                update_system
                restart_app
                ;;
            5)
                restart_app
                ;;
            6)
                show_status
                ;;
            7)
                setup_autostart
                ;;
            8)
                remove_autostart
                ;;
            9)
                print_status "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-9."
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@" 