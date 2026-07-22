"""
PostgreSQL Database Setup for Final RAG System
Creates schema and migrates data from JSON files to PostgreSQL
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import execute_values, Json as PGJson
    from psycopg2 import sql
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("⚠️ psycopg2 not installed. Install with: pip install psycopg2-binary")


class PostgresRAGDatabase:
    """
    PostgreSQL database for Final RAG System
    
    Tables:
    - threats: Threat intelligence (ATT&CK, vendor, internal)
    - iocs: Indicators of Compromise
    - yara_rules: YARA detection rules
    - sigma_rules: Sigma detection rules
    - episodes: Security episodes (process, auth, network, alert)
    - playbooks: Incident response playbooks
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "wazuh_rag",
        user: str = "wazuh",
        password: str = "wazuh",
        json_data_path: str = None
    ):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        
        # Default to ai_threat_engine_starter/threat_intel
        if json_data_path is None:
            import os
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            json_data_path = os.path.join(base_path, "threat_intel")
        
        self.json_data_path = Path(json_data_path)
        self.conn = None
        
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2 is required. Install with: pip install psycopg2-binary")
    
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            self.conn.autocommit = False
            print(f"✅ Connected to PostgreSQL: {self.database}")
            return True
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False
    
    def create_schema(self):
        """Create database schema"""
        if not self.conn:
            self.connect()
        
        cursor = self.conn.cursor()
        
        print("\nCreating database schema...")
        
        # Table: threats
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id SERIAL PRIMARY KEY,
                threat_id VARCHAR(255) UNIQUE NOT NULL,
                title VARCHAR(500),
                description TEXT,
                severity VARCHAR(50),
                source VARCHAR(100),
                ioc_tags TEXT[],
                mitigation TEXT,
                metadata JSONB,
                tactics TEXT[],
                platforms TEXT[],
                data_sources TEXT[],
                detection_info JSONB,
                freshness_score FLOAT DEFAULT 1.0,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for threats
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_threat_id ON threats (threat_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats (severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_source ON threats (source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_ingested_at ON threats (ingested_at)")
        
        # Table: iocs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id SERIAL PRIMARY KEY,
                ioc_id VARCHAR(255) UNIQUE NOT NULL,
                ioc_type VARCHAR(50) NOT NULL,
                ioc_value VARCHAR(1000) NOT NULL,
                description TEXT,
                source VARCHAR(100),
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                tags TEXT[],
                metadata JSONB,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for iocs
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_ioc_type ON iocs (ioc_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_ioc_value ON iocs (ioc_value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs (source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs (first_seen)")
        
        # Table: yara_rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS yara_rules (
                id SERIAL PRIMARY KEY,
                rule_id VARCHAR(255) UNIQUE NOT NULL,
                rule_name VARCHAR(500),
                rule_content TEXT,
                source VARCHAR(100),
                category VARCHAR(100),
                tags TEXT[],
                metadata JSONB,
                freshness_score FLOAT DEFAULT 0.7,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for yara_rules
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yara_rule_name ON yara_rules (rule_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yara_source ON yara_rules (source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_yara_category ON yara_rules (category)")
        
        # Table: sigma_rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sigma_rules (
                id SERIAL PRIMARY KEY,
                rule_id VARCHAR(255) UNIQUE NOT NULL,
                title VARCHAR(500),
                description TEXT,
                logsource JSONB,
                detection JSONB,
                tags TEXT[],
                level VARCHAR(50),
                source VARCHAR(100),
                metadata JSONB,
                freshness_score FLOAT DEFAULT 0.7,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for sigma_rules
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sigma_title ON sigma_rules (title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sigma_level ON sigma_rules (level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sigma_source ON sigma_rules (source)")
        
        # Table: episodes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS episodes (
                id SERIAL PRIMARY KEY,
                episode_id VARCHAR(255) UNIQUE NOT NULL,
                episode_type VARCHAR(50) NOT NULL,
                summary TEXT,
                time_start TIMESTAMP,
                time_end TIMESTAMP,
                entities JSONB,
                tags TEXT[],
                source VARCHAR(100),
                raw_refs TEXT[],
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for episodes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_episodes_episode_type ON episodes (episode_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_episodes_time_start ON episodes (time_start)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_episodes_created_at ON episodes (created_at)")
        
        # Table: playbooks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS playbooks (
                id SERIAL PRIMARY KEY,
                playbook_id VARCHAR(255) UNIQUE NOT NULL,
                title VARCHAR(500),
                content TEXT,
                tags TEXT[],
                category VARCHAR(100),
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for playbooks
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_title ON playbooks (title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_playbooks_category ON playbooks (category)")
        
        # Create GIN indexes for JSONB and array searches
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threats_metadata_gin ON threats USING GIN (metadata);
            CREATE INDEX IF NOT EXISTS idx_threats_ioc_tags_gin ON threats USING GIN (ioc_tags);
            CREATE INDEX IF NOT EXISTS idx_iocs_tags_gin ON iocs USING GIN (tags);
            CREATE INDEX IF NOT EXISTS idx_episodes_entities_gin ON episodes USING GIN (entities);
            CREATE INDEX IF NOT EXISTS idx_episodes_tags_gin ON episodes USING GIN (tags);
        """)
        
        self.conn.commit()
        cursor.close()
        print("✅ Database schema created")
    
    def migrate_threats(self, force_refresh: bool = False):
        """Migrate threats from JSON to PostgreSQL"""
        print("\nMigrating threats...")
        
        cursor = self.conn.cursor()
        
        # Load from ATT&CK
        attack_file = self.json_data_path / "attack" / "attack_techniques.json"
        if attack_file.exists():
            with open(attack_file, 'r') as f:
                data = json.load(f)
                techniques = data.get('techniques', [])
                
                for tech in techniques:
                    try:
                        cursor.execute("""
                            INSERT INTO threats (
                                threat_id, title, description, severity, source,
                                ioc_tags, mitigation, metadata, tactics, platforms,
                                data_sources, detection_info, freshness_score, ingested_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (threat_id) DO UPDATE SET
                                title = EXCLUDED.title,
                                description = EXCLUDED.description,
                                updated_at = CURRENT_TIMESTAMP
                        """, (
                            tech.get('id', ''),
                            tech.get('name', ''),
                            tech.get('description', ''),
                            tech.get('severity', 'MEDIUM'),
                            tech.get('source', 'MITRE_ATTACK'),
                            tech.get('ioc', []),
                            tech.get('mitigation', ''),
                            PGJson(tech.get('metadata', {})),
                            tech.get('tactics', []),
                            tech.get('platforms', []),
                            tech.get('data_sources', []),
                            PGJson(tech.get('detection', {})),
                            tech.get('freshness_score', 1.0),
                            datetime.fromisoformat(tech.get('ingested_at', datetime.utcnow().isoformat()))
                        ))
                    except Exception as e:
                        print(f"⚠️ Error inserting {tech.get('id')}: {e}")
                        continue
        
        # Load from vendor advisories
        vendor_file = self.json_data_path / "vendor" / "advisories.json"
        if vendor_file.exists():
            with open(vendor_file, 'r') as f:
                data = json.load(f)
                advisories = data.get('advisories', [])
                
                for adv in advisories:
                    try:
                        cursor.execute("""
                            INSERT INTO threats (
                                threat_id, title, description, source, metadata, freshness_score, ingested_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (threat_id) DO UPDATE SET
                                title = EXCLUDED.title,
                                updated_at = CURRENT_TIMESTAMP
                        """, (
                            adv.get('id', ''),
                            adv.get('title', ''),
                            adv.get('description', ''),
                            adv.get('source', 'VENDOR'),
                            PGJson(adv.get('metadata', {})),
                            adv.get('freshness_score', 0.9),
                            datetime.fromisoformat(adv.get('ingested_at', datetime.utcnow().isoformat()))
                        ))
                    except Exception as e:
                        print(f"⚠️ Error inserting {adv.get('id')}: {e}")
                        continue
        
        # Load from internal TI
        internal_file = self.json_data_path / "internal" / "notes.json"
        if internal_file.exists():
            with open(internal_file, 'r') as f:
                data = json.load(f)
                notes = data.get('notes', [])
                
                for note in notes:
                    try:
                        cursor.execute("""
                            INSERT INTO threats (
                                threat_id, title, description, source, metadata, tags, freshness_score, ingested_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (threat_id) DO UPDATE SET
                                title = EXCLUDED.title,
                                description = EXCLUDED.description,
                                updated_at = CURRENT_TIMESTAMP
                        """, (
                            note.get('id', ''),
                            note.get('title', ''),
                            note.get('content', ''),
                            'INTERNAL',
                            PGJson(note.get('metadata', {})),
                            note.get('tags', []),
                            note.get('freshness_score', 0.6),
                            datetime.fromisoformat(note.get('ingested_at', datetime.utcnow().isoformat()))
                        ))
                    except Exception as e:
                        print(f"⚠️ Error inserting {note.get('id')}: {e}")
                        continue
        
        self.conn.commit()
        cursor.close()
        
        # Count
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threats")
        count = cursor.fetchone()[0]
        cursor.close()
        
        print(f"✅ Migrated {count} threats to PostgreSQL")
    
    def migrate_iocs(self):
        """Migrate IOCs from JSON to PostgreSQL"""
        print("\nMigrating IOCs...")
        
        ioc_file = self.json_data_path / "ioc" / "iocs.json"
        if not ioc_file.exists():
            print("⚠️ IOCs file not found")
            return
        
        cursor = self.conn.cursor()
        
        with open(ioc_file, 'r') as f:
            data = json.load(f)
            iocs = data.get('iocs', [])
            
            for ioc in iocs:
                try:
                    cursor.execute("""
                        INSERT INTO iocs (
                            ioc_id, ioc_type, ioc_value, description, source,
                            first_seen, tags, metadata, ingested_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (ioc_id) DO UPDATE SET
                            last_seen = CURRENT_TIMESTAMP
                    """, (
                        ioc.get('id', ''),
                        ioc.get('type', 'unknown'),
                        ioc.get('value', ''),
                        ioc.get('description', ''),
                        ioc.get('source', 'unknown'),
                        datetime.fromisoformat(ioc.get('first_seen', datetime.utcnow().isoformat())) if ioc.get('first_seen') else None,
                        ioc.get('tags', []),
                        PGJson(ioc.get('metadata', {})),
                        datetime.fromisoformat(ioc.get('ingested_at', datetime.utcnow().isoformat()))
                    ))
                except Exception as e:
                    print(f"⚠️ Error inserting IOC {ioc.get('id')}: {e}")
                    continue
        
        self.conn.commit()
        cursor.close()
        
        # Count
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM iocs")
        count = cursor.fetchone()[0]
        cursor.close()
        
        print(f"✅ Migrated {count} IOCs to PostgreSQL")
    
    def migrate_yara_rules(self):
        """Migrate YARA rules from JSON to PostgreSQL"""
        print("\nMigrating YARA rules...")
        
        yara_file = self.json_data_path / "yara" / "rules.json"
        if not yara_file.exists():
            print("⚠️ YARA rules file not found")
            return
        
        cursor = self.conn.cursor()
        
        with open(yara_file, 'r') as f:
            data = json.load(f)
            rules = data.get('rules', [])
            
            for rule in rules:
                try:
                    cursor.execute("""
                        INSERT INTO yara_rules (
                            rule_id, rule_name, rule_content, source, category,
                            tags, metadata, freshness_score, ingested_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (rule_id) DO UPDATE SET
                            rule_content = EXCLUDED.rule_content
                    """, (
                        rule.get('id', ''),
                        rule.get('name', ''),
                        rule.get('content', ''),
                        rule.get('source', 'unknown'),
                        rule.get('category', 'malware'),
                        rule.get('tags', []),
                        PGJson(rule.get('metadata', {})),
                        rule.get('freshness_score', 0.7),
                        datetime.fromisoformat(rule.get('ingested_at', datetime.utcnow().isoformat()))
                    ))
                except Exception as e:
                    print(f"⚠️ Error inserting YARA rule {rule.get('id')}: {e}")
                    continue
        
        self.conn.commit()
        cursor.close()
        
        # Count
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM yara_rules")
        count = cursor.fetchone()[0]
        cursor.close()
        
        print(f"✅ Migrated {count} YARA rules to PostgreSQL")
    
    def migrate_sigma_rules(self):
        """Migrate Sigma rules from JSON to PostgreSQL"""
        print("\nMigrating Sigma rules...")
        
        sigma_file = self.json_data_path / "sigma" / "rules.json"
        if not sigma_file.exists():
            print("⚠️ Sigma rules file not found")
            return
        
        cursor = self.conn.cursor()
        
        with open(sigma_file, 'r') as f:
            data = json.load(f)
            rules = data.get('rules', [])
            
            for rule in rules:
                try:
                    cursor.execute("""
                        INSERT INTO sigma_rules (
                            rule_id, title, description, logsource, detection,
                            tags, level, source, metadata, freshness_score, ingested_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (rule_id) DO UPDATE SET
                            detection = EXCLUDED.detection
                    """, (
                        rule.get('id', ''),
                        rule.get('title', ''),
                        rule.get('description', ''),
                        PGJson(rule.get('logsource', {})),
                        PGJson(rule.get('detection', {})),
                        rule.get('tags', []),
                        rule.get('level', 'medium'),
                        rule.get('source', 'unknown'),
                        PGJson(rule.get('metadata', {})),
                        rule.get('freshness_score', 0.7),
                        datetime.fromisoformat(rule.get('ingested_at', datetime.utcnow().isoformat()))
                    ))
                except Exception as e:
                    print(f"⚠️ Error inserting Sigma rule {rule.get('id')}: {e}")
                    continue
        
        self.conn.commit()
        cursor.close()
        
        # Count
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sigma_rules")
        count = cursor.fetchone()[0]
        cursor.close()
        
        print(f"✅ Migrated {count} Sigma rules to PostgreSQL")
    
    def migrate_episodes(self, episodes_path: str = "/var/ossec/ai_models/episodes"):
        """Migrate episodes from JSON to PostgreSQL"""
        print("\nMigrating episodes...")
        
        episodes_file = Path(episodes_path) / "episodes.json"
        if not episodes_file.exists():
            print("⚠️ Episodes file not found")
            return
        
        cursor = self.conn.cursor()
        
        with open(episodes_file, 'r') as f:
            episodes = json.load(f)
            
            for episode in episodes:
                try:
                    time_range = episode.get('time_range', {})
                    time_start = None
                    time_end = None
                    
                    if time_range.get('start'):
                        time_start = datetime.fromisoformat(time_range['start'].replace('Z', '+00:00'))
                    if time_range.get('end'):
                        time_end = datetime.fromisoformat(time_range['end'].replace('Z', '+00:00'))
                    
                    cursor.execute("""
                        INSERT INTO episodes (
                            episode_id, episode_type, summary, time_start, time_end,
                            entities, tags, source, raw_refs, metadata, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (episode_id) DO UPDATE SET
                            summary = EXCLUDED.summary,
                            time_end = EXCLUDED.time_end
                    """, (
                        episode.get('episode_id', ''),
                        episode.get('episode_type', ''),
                        episode.get('summary', ''),
                        time_start,
                        time_end,
                        PGJson(episode.get('entities', {})),
                        episode.get('tags', []),
                        episode.get('source', 'Wazuh'),
                        episode.get('raw_refs', []),
                        PGJson(episode.get('metadata', {})),
                        datetime.fromisoformat(episode.get('created_at', datetime.utcnow().isoformat()))
                    ))
                except Exception as e:
                    print(f"⚠️ Error inserting episode {episode.get('episode_id')}: {e}")
                    continue
        
        self.conn.commit()
        cursor.close()
        
        # Count
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM episodes")
        count = cursor.fetchone()[0]
        cursor.close()
        
        print(f"✅ Migrated {count} episodes to PostgreSQL")
    
    def migrate_all(self, episodes_path: Optional[str] = None):
        """Migrate all data to PostgreSQL"""
        print("=" * 60)
        print("PostgreSQL Migration - Final RAG System")
        print("=" * 60)
        
        if not self.conn:
            if not self.connect():
                return False
        
        # Create schema
        self.create_schema()
        
        # Migrate all
        self.migrate_threats()
        self.migrate_iocs()
        self.migrate_yara_rules()
        self.migrate_sigma_rules()
        
        if episodes_path:
            self.migrate_episodes(episodes_path)
        
        # Summary
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threats")
        threats_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM iocs")
        iocs_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM yara_rules")
        yara_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sigma_rules")
        sigma_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM episodes")
        episodes_count = cursor.fetchone()[0]
        cursor.close()
        
        print("\n" + "=" * 60)
        print("Migration Summary:")
        print("=" * 60)
        print(f"  Threats:  {threats_count}")
        print(f"  IOCs:     {iocs_count}")
        print(f"  YARA:     {yara_count}")
        print(f"  Sigma:    {sigma_count}")
        print(f"  Episodes: {episodes_count}")
        print("=" * 60)
        
        return True
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✅ Database connection closed")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PostgreSQL Setup for Final RAG")
    parser.add_argument('--host', default='localhost', help='PostgreSQL host')
    parser.add_argument('--port', type=int, default=5432, help='PostgreSQL port')
    parser.add_argument('--database', default='wazuh_rag', help='Database name')
    parser.add_argument('--user', default='wazuh', help='Database user')
    parser.add_argument('--password', default='wazuh', help='Database password')
    parser.add_argument('--json-path', default='/var/ossec/ai_models/threat_intel', help='JSON data path')
    parser.add_argument('--episodes-path', help='Episodes JSON path')
    parser.add_argument('--create-only', action='store_true', help='Only create schema, do not migrate')
    
    args = parser.parse_args()
    
    db = PostgresRAGDatabase(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=args.password,
        json_data_path=args.json_path
    )
    
    if args.create_only:
        if db.connect():
            db.create_schema()
            db.close()
    else:
        db.migrate_all(episodes_path=args.episodes_path)
        db.close()
