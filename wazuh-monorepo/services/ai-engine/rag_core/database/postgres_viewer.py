"""
PostgreSQL Knowledge Database Viewer
Visualize threat intelligence data from PostgreSQL
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("⚠️ psycopg2 not installed. Install with: pip install psycopg2-binary")


class PostgresRAGViewer:
    """View and query PostgreSQL RAG database"""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "wazuh_rag",
        user: str = "wazuh",
        password: str = "wazuh"
    ):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.conn = None
    
    def connect(self):
        """Connect to database"""
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            return True
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        if not self.conn:
            if not self.connect():
                return {}
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        stats = {}
        
        tables = ['threats', 'iocs', 'yara_rules', 'sigma_rules', 'episodes', 'playbooks']
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                stats[table] = cursor.fetchone()['count']
            except:
                stats[table] = 0
        
        cursor.close()
        return stats
    
    def search_threats(
        self,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Search threats"""
        if not self.conn:
            if not self.connect():
                return []
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        sql_query = "SELECT * FROM threats WHERE 1=1"
        params = []
        
        if query:
            sql_query += " AND (title ILIKE %s OR description ILIKE %s)"
            params.extend([f"%{query}%", f"%{query}%"])
        
        if severity:
            sql_query += " AND severity = %s"
            params.append(severity)
        
        if source:
            sql_query += " AND source = %s"
            params.append(source)
        
        sql_query += " ORDER BY ingested_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(sql_query, params)
        results = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        
        return results
    
    def search_iocs(
        self,
        ioc_type: Optional[str] = None,
        ioc_value: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Search IOCs"""
        if not self.conn:
            if not self.connect():
                return []
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        sql_query = "SELECT * FROM iocs WHERE 1=1"
        params = []
        
        if ioc_type:
            sql_query += " AND ioc_type = %s"
            params.append(ioc_type)
        
        if ioc_value:
            sql_query += " AND ioc_value ILIKE %s"
            params.append(f"%{ioc_value}%")
        
        if source:
            sql_query += " AND source = %s"
            params.append(source)
        
        sql_query += " ORDER BY first_seen DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(sql_query, params)
        results = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        
        return results
    
    def search_episodes(
        self,
        episode_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Search episodes"""
        if not self.conn:
            if not self.connect():
                return []
        
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        
        sql_query = "SELECT * FROM episodes WHERE 1=1"
        params = []
        
        if episode_type:
            sql_query += " AND episode_type = %s"
            params.append(episode_type)
        
        if tags:
            for tag in tags:
                sql_query += f" AND %s = ANY(tags)"
                params.append(tag)
        
        if time_start:
            sql_query += " AND time_start >= %s"
            params.append(time_start)
        
        if time_end:
            sql_query += " AND time_end <= %s"
            params.append(time_end)
        
        sql_query += " ORDER BY time_start DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(sql_query, params)
        results = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        
        return results
    
    def export_to_html(self, output_file: str = "postgres_rag_view.html"):
        """Export database view to HTML"""
        stats = self.get_statistics()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PostgreSQL RAG Knowledge Database</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f1419;
            color: #e4e4e4;
            padding: 2rem;
        }}
        .header {{
            background: linear-gradient(135deg, #1a2332 0%, #0f1419 100%);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid #2d3748;
        }}
        .header h1 {{ color: #4fd1c7; margin-bottom: 1rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: #1a2332;
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid #374151;
        }}
        .stat-label {{ color: #9ca3af; font-size: 0.9rem; }}
        .stat-value {{ color: #4fd1c7; font-size: 2rem; font-weight: bold; }}
        .section {{
            background: #1a2332;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border: 1px solid #374151;
        }}
        .section h2 {{ color: #4fd1c7; margin-bottom: 1rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #374151;
        }}
        th {{
            background: #2d3748;
            color: #4fd1c7;
            font-weight: bold;
        }}
        tr:hover {{ background: #2d3748; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🗄️ PostgreSQL RAG Knowledge Database</h1>
        <p>Database: {self.database} | Host: {self.host}:{self.port}</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-label">Threats</div>
            <div class="stat-value">{stats.get('threats', 0)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">IOCs</div>
            <div class="stat-value">{stats.get('iocs', 0)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">YARA Rules</div>
            <div class="stat-value">{stats.get('yara_rules', 0)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Sigma Rules</div>
            <div class="stat-value">{stats.get('sigma_rules', 0)}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Episodes</div>
            <div class="stat-value">{stats.get('episodes', 0)}</div>
        </div>
    </div>
    
    <div class="section">
        <h2>📊 Database Statistics</h2>
        <p>Total records: {sum(stats.values())}</p>
        <p>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>💡 How to Query</h2>
        <p>Use the Python API or connect directly with psql:</p>
        <pre style="background: #2d3748; padding: 1rem; border-radius: 4px; margin-top: 1rem;">
psql -h {self.host} -U {self.user} -d {self.database}

-- Example queries:
SELECT * FROM threats WHERE severity = 'HIGH' LIMIT 10;
SELECT * FROM iocs WHERE ioc_type = 'ip' LIMIT 10;
SELECT * FROM episodes WHERE episode_type = 'process' LIMIT 10;
        </pre>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"✅ HTML view exported to: {output_file}")
    
    def close(self):
        """Close connection"""
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PostgreSQL RAG Viewer")
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=5432)
    parser.add_argument('--database', default='wazuh_rag')
    parser.add_argument('--user', default='wazuh')
    parser.add_argument('--password', default='wazuh')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--export-html', action='store_true', help='Export HTML view')
    
    args = parser.parse_args()
    
    viewer = PostgresRAGViewer(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=args.password
    )
    
    if args.stats:
        if viewer.connect():
            stats = viewer.get_statistics()
            print("\nDatabase Statistics:")
            print("=" * 40)
            for table, count in stats.items():
                print(f"  {table:20} {count:>10}")
            viewer.close()
    
    if args.export_html:
        if viewer.connect():
            viewer.export_to_html()
            viewer.close()
