#!/bin/bash
# Setup PostgreSQL for Final RAG System

echo "============================================================"
echo "PostgreSQL Setup for Final RAG System"
echo "============================================================"
echo ""

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "⚠️ PostgreSQL is not installed."
    echo ""
    echo "Install PostgreSQL:"
    echo "  Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
    echo "  Or use Docker: docker run -d --name postgres-rag -e POSTGRES_PASSWORD=wazuh -p 5432:5432 postgres:15"
    echo ""
    exit 1
fi

echo "✅ PostgreSQL is installed"
echo ""

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p 5432 &> /dev/null; then
    echo "⚠️ PostgreSQL is not running."
    echo "Start PostgreSQL:"
    echo "  Ubuntu/Debian: sudo systemctl start postgresql"
    echo "  Or start Docker: docker start postgres-rag"
    echo ""
    exit 1
fi

echo "✅ PostgreSQL is running"
echo ""

# Create database and user
echo "Creating database and user..."
echo "You may need to enter PostgreSQL admin password (usually 'postgres' or your system password)"
echo ""

# Try to create database
sudo -u postgres psql << EOF
-- Create database
CREATE DATABASE wazuh_rag;

-- Create user
CREATE USER wazuh WITH PASSWORD 'wazuh';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE wazuh_rag TO wazuh;

-- Connect to database and grant schema privileges
\c wazuh_rag
GRANT ALL ON SCHEMA public TO wazuh;

\q
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Database and user created successfully!"
    echo ""
    echo "Now run migration:"
    echo "  cd rag_core/database"
    echo "  python3 postgres_setup.py"
else
    echo ""
    echo "⚠️ Error creating database. You may need to run manually:"
    echo ""
    echo "  sudo -u postgres psql"
    echo "  CREATE DATABASE wazuh_rag;"
    echo "  CREATE USER wazuh WITH PASSWORD 'wazuh';"
    echo "  GRANT ALL PRIVILEGES ON DATABASE wazuh_rag TO wazuh;"
    echo "  \\q"
fi
