-- Quick PostgreSQL Setup for Final RAG System
-- Run this file with: psql -f quick_setup.sql (as superuser)

-- Create database
CREATE DATABASE wazuh_rag;

-- Create user
CREATE USER wazuh WITH PASSWORD 'wazuh';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE wazuh_rag TO wazuh;

-- Connect to database
\c wazuh_rag

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO wazuh;

-- Exit
\q
