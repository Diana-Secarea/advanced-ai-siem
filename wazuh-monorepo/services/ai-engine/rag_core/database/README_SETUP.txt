============================================================
PostgreSQL Setup - Quick Guide
============================================================

PostgreSQL is installed but needs database/user creation.

QUICK SETUP:
-----------

1. Connect to PostgreSQL (choose one):
   sudo -u postgres psql
   OR
   psql -U postgres -h localhost

2. Run SQL commands:
   CREATE DATABASE wazuh_rag;
   CREATE USER wazuh WITH PASSWORD 'wazuh';
   GRANT ALL PRIVILEGES ON DATABASE wazuh_rag TO wazuh;
   \c wazuh_rag
   GRANT ALL ON SCHEMA public TO wazuh;
   \q

3. Run migration:
   python3 postgres_setup.py

4. Verify:
   python3 postgres_viewer.py --stats

ALTERNATIVE - Use SQL file:
   psql -U postgres -f quick_setup.sql

DOCKER ALTERNATIVE:
   sudo docker run -d --name postgres-rag \
     -e POSTGRES_PASSWORD=wazuh \
     -e POSTGRES_USER=wazuh \
     -e POSTGRES_DB=wazuh_rag \
     -p 5432:5432 postgres:15

   Then: python3 postgres_setup.py

============================================================
