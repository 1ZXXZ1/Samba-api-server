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
#
# v1.6.8-2 fixes:
#   #1  DB init: only runs setup if DB does not already exist.
#       If DB is already initialized, skips all CREATE/GRANT commands.
#   #2  Password: sudo password is entered only ONCE at the start,
#       then cached via sudo -v for the rest of the script.
#   #3  Ctrl+C now works cleanly — no more 7x shutdown messages.
#

set -e

# Configuration
DB_USER="samba_api"
DB_PASSWORD="12345"
DB_NAME="samba_api"
DB_HOST="localhost"
DB_PORT="5432"

# Parse command-line arguments
DEBUG_MODE=false
SETUP_DB=false
for arg in "$@"; do
    case "$arg" in
        -d|--debug)
            DEBUG_MODE=true
            ;;
        --setup-db)
            SETUP_DB=true
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [-d|--debug] [--setup-db]"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Fix v18: Force TMPDIR=/var/tmp for samba-tool.
export TMPDIR="${TMPDIR:-/var/tmp}"
export TMP="${TMP:-/var/tmp}"
export TEMP="${TEMP:-/var/tmp}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Set log level based on debug flag
if [ "$DEBUG_MODE" = true ]; then
    export SAMBA_LOG_LEVEL=DEBUG
    UVICORN_LOG_LEVEL=debug
    echo -e "${CYAN}[DEBUG]${NC} Debug mode enabled — SAMBA_LOG_LEVEL=DEBUG, uvicorn --log-level debug"
else
    export SAMBA_LOG_LEVEL="${SAMBA_LOG_LEVEL:-INFO}"
    UVICORN_LOG_LEVEL=info
fi

echo -e "${GREEN}[OK]${NC} TMPDIR set to ${TMPDIR}"

# Default configuration
HOST="${SAMBA_API_HOST:-127.0.0.1}"
PORT="${SAMBA_API_PORT:-8099}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Samba AD DC Management API Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# ── v1.6.8-2 fix #2: Ask sudo password ONCE at the start ─────────────
# Pre-cache sudo credentials so we don't prompt multiple times later.
echo -e "${CYAN}[SETUP]${NC} Checking sudo access (enter password if prompted)..."
sudo -v || {
    echo -e "${RED}[ERROR]${NC} sudo access required. Cannot continue."
    exit 1
}

# ── v1.6.8-2 fix #2: Keep sudo cache alive in background ─────────────
# While the script runs, refresh sudo timestamp every 30s so it doesn't expire.
(
    while sudo -n true 2>/dev/null; do
        sleep 30
    done
) &
SUDO_KEEPALIVE_PID=$!

# Ensure we kill the keepalive on exit
trap "kill $SUDO_KEEPALIVE_PID 2>/dev/null; exit 0" EXIT INT TERM

# Check if samba-tool is available
if command -v samba-tool &> /dev/null; then
    echo -e "${GREEN}[OK]${NC} samba-tool found: $(command -v samba-tool)"
else
    echo -e "${YELLOW}[WARN]${NC} samba-tool not found in PATH. API calls will fail."
fi

# Check if Python 3.12+ is available
PYTHON=${PYTHON:-python3}
if command -v "$PYTHON" &> /dev/null; then
    PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    echo -e "${GREEN}[OK]${NC} Python $PY_VERSION found"
else
    echo -e "${RED}[ERROR]${NC} Python 3 not found!"
    exit 1
fi

# PostgreSQL setup function
# v1.6.8-2 fix #1: Only initialize DB if it does not already exist.
setup_postgresql() {
    echo ""

    # Check if PostgreSQL is running
    if ! sudo systemctl is-active --quiet postgresql; then
        echo -e "${YELLOW}[WARN]${NC} PostgreSQL is not running. Starting..."
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    fi
    echo -e "${GREEN}[OK]${NC} PostgreSQL is running"

    # Check if database already exists
    DB_EXISTS=$(sudo -u postgres psql -t -c "SELECT 1 FROM pg_database WHERE datname='$DB_NAME';" 2>/dev/null || echo "")
    DB_EXISTS=$(echo "$DB_EXISTS" | tr -d '[:space:]')

    if [ "$DB_EXISTS" = "1" ] && [ "$SETUP_DB" != true ]; then
        # v1.6.8-2 fix #1: DB already exists — skip all CREATE/GRANT
        echo -e "${GREEN}[OK]${NC} Database '$DB_NAME' already exists — skipping init"
    else
        # DB does not exist, or --setup-db was requested
        if [ "$SETUP_DB" = true ] && [ "$DB_EXISTS" = "1" ]; then
            echo -e "${YELLOW}[WARN]${NC} Dropping existing database (forced by --setup-db)..."
            sudo -u postgres psql -c "DROP DATABASE $DB_NAME;" 2>/dev/null
            sudo -u postgres psql -c "DROP USER IF EXISTS $DB_USER;" 2>/dev/null
        fi

        echo -e "${CYAN}[SETUP]${NC} Creating user '$DB_USER'..."
        sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || true

        echo -e "${CYAN}[SETUP]${NC} Creating database '$DB_NAME'..."
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" 2>/dev/null || true

        echo -e "${CYAN}[SETUP]${NC} Granting privileges..."
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

        # Grant schema permissions
        sudo -u postgres psql -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER;"

        echo -e "${GREEN}[OK]${NC} Database setup complete!"
    fi

    # Test connection
    if PGPASSWORD="$DB_PASSWORD" psql -U "$DB_USER" -d "$DB_NAME" -h "$DB_HOST" -c "SELECT 1;" &>/dev/null; then
        echo -e "${GREEN}[OK]${NC} Database connection test successful"
    else
        echo -e "${RED}[ERROR]${NC} Cannot connect to database!"
        echo -e "       Try: ./run.sh --setup-db"
        exit 1
    fi
}

# Check PostgreSQL installation
if command -v psql &> /dev/null; then
    PSQL_VERSION=$(psql --version | awk '{print $3}')
    echo -e "${GREEN}[OK]${NC} PostgreSQL client $PSQL_VERSION found"

    # Initialize database if needed
    setup_postgresql
else
    echo -e "${YELLOW}[WARN]${NC} PostgreSQL not found. Database features will fail."
    echo -e "       Install: sudo apt-get install postgresql postgresql-server postgresql-contrib"
fi

echo ""
echo -e "${GREEN}Starting server on ${HOST}:${PORT}${NC}"
echo -e "API docs:  http://${HOST}:${PORT}/docs"
echo -e "Health:    http://${HOST}:${PORT}/health"
echo -e "Log level: ${SAMBA_LOG_LEVEL} (uvicorn: ${UVICORN_LOG_LEVEL})"
echo ""
echo -e "Press Ctrl+C to stop"
echo ""

# v1.6.7-6 fix: Export BOTH DB_* and SAMBA_SHELL_PROJET_PG_* env vars
# so the app can read them regardless of which prefix is used.
export DB_USER DB_PASSWORD DB_NAME DB_HOST DB_PORT
export SAMBA_SHELL_PROJET_PG_HOST="$DB_HOST"
export SAMBA_SHELL_PROJET_PG_PORT="$DB_PORT"
export SAMBA_SHELL_PROJET_PG_DBNAME="$DB_NAME"
export SAMBA_SHELL_PROJET_PG_USER="$DB_USER"
export SAMBA_SHELL_PROJET_PG_PASSWORD="$DB_PASSWORD"

# Start the server
exec sudo -E python3 -m uvicorn app.main:app \
    --host "$HOST" \
    --port "$PORT" \
    --log-level "$UVICORN_LOG_LEVEL" \
    --access-log
