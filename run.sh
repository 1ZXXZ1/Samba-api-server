#!/bin/bash
#
# Samba API Server - Auto-start script
# Starts the API server on 127.0.0.1:8099
# Auto-initializes PostgreSQL database on first run
#
# Usage:
#   ./run.sh              # Start with INFO log level (default)
#   ./run.sh -d           # Start with DEBUG log level
#   ./run.sh --debug      # Same as -d
#   ./run.sh --setup-db   # Force database re-initialization
#   ./run.sh -p PASSWORD  # Set PostgreSQL password for DB_USER
#   ./run.sh --password PASSWORD  # Same as -p
#
# v1.6.8-3 fixes:
#   #1  DB init: only runs setup if DB does not already exist.
#   #2  Password: sudo password is entered only ONCE at the start.
#   #3  Ctrl+C works cleanly.
#   #4  Added -p/--password flag for PostgreSQL password.
#   #5  No more "Password for user postgres:" prompt on normal start.
#

set -e

# Configuration
DB_USER="samba_api"
DB_PASSWORD="${DB_PASSWORD:-12345}"
DB_NAME="samba_api"
DB_HOST="localhost"
DB_PORT="5432"

# Parse command-line arguments with getopt
DEBUG_MODE=false
SETUP_DB=false
OPTS=$(getopt -o dp: --long debug,setup-db,password: -n 'run.sh' -- "$@")
if [ $? -ne 0 ]; then
    echo "Usage: $0 [-d|--debug] [--setup-db] [-p|--password PASSWORD]"
    exit 1
fi
eval set -- "$OPTS"

while true; do
    case "$1" in
        -d|--debug)
            DEBUG_MODE=true
            shift
            ;;
        --setup-db)
            SETUP_DB=true
            shift
            ;;
        -p|--password)
            DB_PASSWORD="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error!"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Force TMPDIR for samba-tool
export TMPDIR="${TMPDIR:-/var/tmp}"
export TMP="${TMP:-/var/tmp}"
export TEMP="${TEMP:-/var/tmp}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Set log level
if [ "$DEBUG_MODE" = true ]; then
    export SAMBA_LOG_LEVEL=DEBUG
    UVICORN_LOG_LEVEL=debug
    echo -e "${CYAN}[DEBUG]${NC} Debug mode enabled"
else
    export SAMBA_LOG_LEVEL="${SAMBA_LOG_LEVEL:-INFO}"
    UVICORN_LOG_LEVEL=info
fi

echo -e "${GREEN}[OK]${NC} TMPDIR set to ${TMPDIR}"

HOST="${SAMBA_API_HOST:-127.0.0.1}"
PORT="${SAMBA_API_PORT:-8099}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Samba AD DC Management API Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Cache sudo password once
echo -e "${CYAN}[SETUP]${NC} Checking sudo access (enter password if prompted)..."
sudo -v || { echo -e "${RED}[ERROR]${NC} sudo required"; exit 1; }

# Keep sudo alive
(
    while sudo -n true 2>/dev/null; do
        sleep 30
    done
) &
SUDO_KEEPALIVE_PID=$!
trap "kill $SUDO_KEEPALIVE_PID 2>/dev/null; exit 0" EXIT INT TERM

# Check samba-tool
if command -v samba-tool &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} samba-tool found: $(command -v samba-tool)"
else
    echo -e "${YELLOW}[WARN]${NC} samba-tool not found"
fi

# Check Python
PYTHON=${PYTHON:-python3}
if command -v "$PYTHON" &> /dev/null; then
    PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo -e "${GREEN}[OK]${NC} Python $PY_VERSION found"
else
    echo -e "${RED}[ERROR]${NC} Python 3 not found!"
    exit 1
fi

# PostgreSQL setup (improved: avoid postgres password prompt if DB already exists)
setup_postgresql() {
    echo ""

    # Ensure PostgreSQL is running
    if ! sudo systemctl is-active --quiet postgresql; then
        echo -e "${YELLOW}[WARN]${NC} PostgreSQL not running. Starting..."
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    fi
    echo -e "${GREEN}[OK]${NC} PostgreSQL is running"

    # Try to connect as DB_USER first – if it works, DB exists and is ready
    if PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" -c "SELECT 1;" &>/dev/null; then
        if [ "$SETUP_DB" = true ]; then
            echo -e "${YELLOW}[WARN]${NC} Database exists, but --setup-db forced. Re-initializing..."
        else
            echo -e "${GREEN}[OK]${NC} Database '$DB_NAME' already exists and accessible — skipping init"
            return 0
        fi
    else
        if [ "$SETUP_DB" != true ]; then
            echo -e "${CYAN}[INFO]${NC} Database not accessible or does not exist. Attempting creation."
        fi
    fi

    # If we get here, we need superuser (postgres) to create/drop DB
    if [ "$SETUP_DB" = true ]; then
        echo -e "${YELLOW}[WARN]${NC} Dropping existing database (forced by --setup-db)..."
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null
        sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" 2>/dev/null
    fi

    echo -e "${CYAN}[SETUP]${NC} Creating user '$DB_USER'..."
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || true

    echo -e "${CYAN}[SETUP]${NC} Creating database '$DB_NAME'..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || true

    echo -e "${CYAN}[SETUP]${NC} Granting privileges..."
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
    sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;"

    echo -e "${GREEN}[OK]${NC} Database setup complete!"

    # Final connection test
    if PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" -c "SELECT 1;" &>/dev/null; then
        echo -e "${GREEN}[OK]${NC} Database connection test successful"
    else
        echo -e "${RED}[ERROR]${NC} Cannot connect after setup!"
        exit 1
    fi
}

# Check PostgreSQL client
if command -v psql &> /dev/null; then
    PSQL_VERSION=$(psql --version | awk '{print $3}')
    echo -e "${GREEN}[OK]${NC} PostgreSQL client $PSQL_VERSION found"
    setup_postgresql
else
    echo -e "${YELLOW}[WARN]${NC} PostgreSQL client not found. DB features will fail."
    echo "       Install: sudo apt-get install postgresql-client"
fi

echo ""
echo -e "${GREEN}Starting server on ${HOST}:${PORT}${NC}"
echo -e "API docs:  http://${HOST}:${PORT}/docs"
echo -e "Health:    http://${HOST}:${PORT}/health"
echo -e "Log level: ${SAMBA_LOG_LEVEL} (uvicorn: ${UVICORN_LOG_LEVEL})"
echo -e "Press Ctrl+C to stop"
echo ""

# Export environment for the app
export DB_USER DB_PASSWORD DB_NAME DB_HOST DB_PORT
export SAMBA_SHELL_PROJET_PG_HOST="$DB_HOST"
export SAMBA_SHELL_PROJET_PG_PORT="$DB_PORT"
export SAMBA_SHELL_PROJET_PG_DBNAME="$DB_NAME"
export SAMBA_SHELL_PROJET_PG_USER="$DB_USER"
export SAMBA_SHELL_PROJET_PG_PASSWORD="$DB_PASSWORD"

# Start server
exec sudo -E python3 -m uvicorn app.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --log-level "$UVICORN_LOG_LEVEL" \
    --access-log
