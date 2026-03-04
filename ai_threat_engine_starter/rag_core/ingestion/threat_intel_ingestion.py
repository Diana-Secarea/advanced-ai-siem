"""
Threat Intelligence Ingestion
Ingests multiple sources: ATT&CK, vendor blogs, IOCs, YARA, Sigma, internal TI
"""

import json
import os
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import hashlib


class ThreatIntelIngestion:
    """Ingest threat intelligence from multiple sources"""
    
    def __init__(self, storage_path: str = None):
        if storage_path is None:
            # Default to ai_threat_engine_starter/threat_intel
            import os
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            storage_path = os.path.join(base_path, "threat_intel")
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Separate storage for different source types
        self.sources = {
            'attack': self.storage_path / "attack",
            'vendor': self.storage_path / "vendor",
            'ioc': self.storage_path / "ioc",
            'yara': self.storage_path / "yara",
            'sigma': self.storage_path / "sigma",
            'internal': self.storage_path / "internal"
        }
        
        for path in self.sources.values():
            path.mkdir(parents=True, exist_ok=True)
    
    def ingest_mitre_attack(self, force_refresh: bool = False) -> List[Dict]:
        """Ingest MITRE ATT&CK techniques"""
        print("Ingesting MITRE ATT&CK...")
        
        attack_file = self.sources['attack'] / "attack_techniques.json"
        
        # Check if we have recent data
        if attack_file.exists() and not force_refresh:
            try:
                with open(attack_file, 'r') as f:
                    data = json.load(f)
                    if data.get('last_updated'):
                        print(f"Using cached ATT&CK data (updated: {data['last_updated']})")
                        return data.get('techniques', [])
            except:
                pass
        
        # Download from MITRE
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            stix_data = response.json()
            
            techniques = []
            for obj in stix_data.get('objects', []):
                if obj.get('type') == 'attack-pattern' and 'x_mitre_deprecated' not in obj:
                    technique = {
                        'id': self._extract_mitre_id(obj),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactics': [p.get('phase_name', '') for p in obj.get('kill_chain_phases', [])],
                        'platforms': obj.get('x_mitre_platforms', []),
                        'data_sources': obj.get('x_mitre_data_sources', []),
                        'detection': obj.get('x_mitre_detection', []),
                        'mitigations': self._extract_mitigations(obj, stix_data),
                        'source': 'MITRE_ATTACK',
                        'ingested_at': datetime.utcnow().isoformat(),
                        'freshness_score': 1.0  # ATT&CK is stable, high freshness
                    }
                    techniques.append(technique)
            
            # Save
            data = {
                'techniques': techniques,
                'last_updated': datetime.utcnow().isoformat(),
                'count': len(techniques)
            }
            
            with open(attack_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"✅ Ingested {len(techniques)} MITRE ATT&CK techniques")
            return techniques
            
        except Exception as e:
            print(f"❌ Error ingesting MITRE ATT&CK: {e}")
            return []
    
    def ingest_vendor_advisories(self, sources: List[Dict] = None) -> List[Dict]:
        """Ingest vendor security advisories and blogs"""
        print("Ingesting vendor advisories...")
        
        # Default sources
        if sources is None:
            sources = [
                {
                    'name': 'Microsoft Security',
                    'url': 'https://api.msrc.microsoft.com/cvrf/v2.0/cvrf',
                    'type': 'CVRF'
                },
                {
                    'name': 'CISA Advisories',
                    'url': 'https://www.cisa.gov/news-events/cybersecurity-advisories',
                    'type': 'RSS'  # Simplified - would need RSS parser
                }
            ]
        
        advisories = []
        
        for source in sources:
            try:
                if source['type'] == 'CVRF':
                    # Microsoft CVRF format
                    response = requests.get(source['url'], timeout=30)
                    if response.status_code == 200:
                        # Parse CVRF (simplified)
                        advisory = {
                            'id': f"VENDOR-{source['name']}-{datetime.utcnow().timestamp()}",
                            'title': f"Advisory from {source['name']}",
                            'source': source['name'],
                            'url': source['url'],
                            'ingested_at': datetime.utcnow().isoformat(),
                            'freshness_score': 0.9  # Vendor advisories are recent
                        }
                        advisories.append(advisory)
                
                elif source['type'] == 'GITHUB_API':
                    # GitHub Releases API
                    url = source.get('url', '')
                    if 'releases' in url:
                        # Get all releases (not just first page)
                        all_releases = []
                        page = 1
                        per_page = 100
                        
                        while True:
                            api_url = f"https://api.github.com/repos/wazuh/wazuh/releases?page={page}&per_page={per_page}"
                            response = requests.get(api_url, timeout=30, headers={'Accept': 'application/vnd.github.v3+json'})
                            
                            if response.status_code != 200:
                                break
                            
                            releases = response.json()
                            if not releases:
                                break
                            
                            all_releases.extend(releases)
                            
                            # Check if there are more pages
                            if len(releases) < per_page:
                                break
                            page += 1
                        
                        print(f"  Found {len(all_releases)} releases from GitHub")
                        
                        for release in all_releases:
                            # Extract security-related info from release notes
                            body = release.get('body', '')
                            is_security = any(keyword in body.lower() for keyword in [
                                'security', 'vulnerability', 'cve', 'fix', 'patch', 
                                'exploit', 'attack', 'malware', 'threat'
                            ])
                            
                            advisory = {
                                'id': f"WAZUH-RELEASE-{release.get('id', '')}",
                                'title': release.get('name', release.get('tag_name', '')),
                                'description': body[:1000] if body else '',  # First 1000 chars
                                'url': release.get('html_url', ''),
                                'source': source.get('name', 'Wazuh GitHub'),
                                'published_at': release.get('published_at', ''),
                                'tag_name': release.get('tag_name', ''),
                                'is_security_related': is_security,
                                'ingested_at': datetime.utcnow().isoformat(),
                                'freshness_score': 0.9
                            }
                            advisories.append(advisory)
                
                elif source['type'] == 'BLOG':
                    # Wazuh Blog - web scraping
                    blog_url = source.get('url', 'https://wazuh.com/blog')
                    try:
                        response = requests.get(blog_url, timeout=30, headers={
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        })
                        if response.status_code == 200:
                            from bs4 import BeautifulSoup
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Find blog post links
                            blog_posts = []
                            for link in soup.find_all('a', href=True):
                                href = link.get('href', '')
                                text = link.get_text(strip=True)
                                
                                # Look for blog post links
                                if '/blog/' in href or 'blog' in href.lower():
                                    full_url = href if href.startswith('http') else f"https://wazuh.com{href}"
                                    
                                    # Check if it's a security-related post
                                    is_security = any(keyword in text.lower() for keyword in [
                                        'security', 'vulnerability', 'cve', 'threat', 
                                        'attack', 'malware', 'advisory'
                                    ])
                                    
                                    if full_url not in [p.get('url') for p in blog_posts]:
                                        blog_posts.append({
                                            'title': text[:200] if text else 'Wazuh Blog Post',
                                            'url': full_url,
                                            'is_security_related': is_security
                                        })
                            
                            # Limit to reasonable number and get full content for security posts
                            for post in blog_posts[:50]:  # Limit to 50 posts
                                if post.get('is_security_related'):
                                    try:
                                        post_response = requests.get(post['url'], timeout=30, headers={
                                            'User-Agent': 'Mozilla/5.0'
                                        })
                                        if post_response.status_code == 200:
                                            post_soup = BeautifulSoup(post_response.text, 'html.parser')
                                            content = post_soup.get_text()[:2000]  # First 2000 chars
                                            
                                            advisory = {
                                                'id': f"WAZUH-BLOG-{hashlib.md5(post['url'].encode()).hexdigest()[:12]}",
                                                'title': post['title'],
                                                'description': content,
                                                'url': post['url'],
                                                'source': 'Wazuh Blog',
                                                'ingested_at': datetime.utcnow().isoformat(),
                                                'freshness_score': 0.8
                                            }
                                            advisories.append(advisory)
                                    except:
                                        pass
                            
                            print(f"  Found {len([p for p in blog_posts if p.get('is_security_related')])} security-related blog posts")
                    except ImportError:
                        print(f"⚠️ BeautifulSoup not installed. Install with: pip install beautifulsoup4")
                    except Exception as e:
                        print(f"⚠️ Error scraping blog: {e}")
                
                elif source['type'] == 'DOCS':
                    # Wazuh Documentation - security section
                    docs_url = source.get('url', 'https://documentation.wazuh.com/current/security/index.html')
                    try:
                        response = requests.get(docs_url, timeout=30, headers={
                            'User-Agent': 'Mozilla/5.0'
                        })
                        if response.status_code == 200:
                            from bs4 import BeautifulSoup
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Extract security documentation content
                            content = soup.get_text()[:2000]
                            
                            # Find links to security-related pages
                            security_links = []
                            for link in soup.find_all('a', href=True):
                                href = link.get('href', '')
                                text = link.get_text(strip=True)
                                
                                if any(keyword in text.lower() or keyword in href.lower() for keyword in [
                                    'security', 'vulnerability', 'cve', 'threat', 'advisory'
                                ]):
                                    full_url = href if href.startswith('http') else f"https://documentation.wazuh.com{href}"
                                    security_links.append({
                                        'title': text[:200] if text else 'Security Documentation',
                                        'url': full_url
                                    })
                            
                            # Create advisory from main security page
                            if content:
                                advisory = {
                                    'id': f"WAZUH-DOCS-SECURITY-{hashlib.md5(docs_url.encode()).hexdigest()[:12]}",
                                    'title': 'Wazuh Security Documentation',
                                    'description': content,
                                    'url': docs_url,
                                    'source': 'Wazuh Documentation',
                                    'related_links': security_links[:10],  # First 10 related links
                                    'ingested_at': datetime.utcnow().isoformat(),
                                    'freshness_score': 0.7
                                }
                                advisories.append(advisory)
                            
                            print(f"  Found security documentation with {len(security_links)} related links")
                    except ImportError:
                        print(f"⚠️ BeautifulSoup not installed. Install with: pip install beautifulsoup4")
                    except Exception as e:
                        print(f"⚠️ Error scraping documentation: {e}")
                
            except Exception as e:
                print(f"⚠️ Error ingesting {source.get('name', 'unknown')}: {e}")
        
        # Save
        vendor_file = self.sources['vendor'] / "advisories.json"
        with open(vendor_file, 'w') as f:
            json.dump({'advisories': advisories, 'last_updated': datetime.utcnow().isoformat()}, f, indent=2)
        
        print(f"✅ Ingested {len(advisories)} vendor advisories")
        return advisories
    
    def ingest_iocs(self, ioc_file: Optional[str] = None) -> List[Dict]:
        """Ingest Indicators of Compromise (IOCs)"""
        print("Ingesting IOCs...")
        
        iocs = []
        
        # If file provided, load from file
        if ioc_file and os.path.exists(ioc_file):
            try:
                with open(ioc_file, 'r') as f:
                    data = json.load(f)
                    iocs = data.get('iocs', [])
            except Exception as e:
                print(f"⚠️ Error loading IOCs from file: {e}")
        
        # Fetch from public sources
        public_sources = [
            {
                'name': 'ThreatHuntingProject',
                'url': 'https://raw.githubusercontent.com/ThreatHuntingProject/hunts/master/iocs.json',
                'type': 'json'
            }
        ]
        
        for source in public_sources:
            try:
                response = requests.get(source['url'], timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                ioc = {
                                    'type': item.get('type', 'unknown'),
                                    'value': item.get('value', str(item)),
                                    'description': item.get('description', ''),
                                    'source': source['name'],
                                    'tags': item.get('tags', [])
                                }
                                iocs.append(ioc)
                    elif isinstance(data, dict):
                        if 'iocs' in data:
                            iocs.extend(data['iocs'])
                        elif 'indicators' in data:
                            iocs.extend(data['indicators'])
                    print(f"  Found {len([i for i in iocs if isinstance(i, dict) and i.get('source') == source['name']])} IOCs from {source['name']}")
            except Exception as e:
                print(f"⚠️ Error ingesting IOCs from {source.get('name', 'unknown')}: {e}")
        
        # Normalize IOC format
        normalized_iocs = []
        for ioc in iocs:
            normalized = {
                'id': self._generate_ioc_id(ioc),
                'type': ioc.get('type', 'unknown'),  # ip, domain, hash, url
                'value': ioc.get('value', ''),
                'description': ioc.get('description', ''),
                'source': ioc.get('source', 'unknown'),
                'first_seen': ioc.get('first_seen', datetime.utcnow().isoformat()),
                'ingested_at': datetime.utcnow().isoformat(),
                'freshness_score': 0.8  # IOCs are time-sensitive
            }
            normalized_iocs.append(normalized)
        
        # Save
        ioc_file_path = self.sources['ioc'] / "iocs.json"
        with open(ioc_file_path, 'w') as f:
            json.dump({'iocs': normalized_iocs, 'last_updated': datetime.utcnow().isoformat()}, f, indent=2)
        
        print(f"✅ Ingested {len(normalized_iocs)} IOCs")
        return normalized_iocs
    
    def ingest_yara_rules(self, yara_dir: Optional[str] = None) -> List[Dict]:
        """Ingest YARA rules"""
        print("Ingesting YARA rules...")
        
        yara_rules = []
        
        # If directory provided, scan for .yar files
        if yara_dir and os.path.isdir(yara_dir):
            for yar_file in Path(yara_dir).glob("*.yar"):
                try:
                    with open(yar_file, 'r') as f:
                        content = f.read()
                        rule = {
                            'id': f"YARA-{yar_file.stem}",
                            'name': yar_file.stem,
                            'content': content,
                            'source': 'local',
                            'ingested_at': datetime.utcnow().isoformat(),
                            'freshness_score': 0.7
                        }
                        yara_rules.append(rule)
                except Exception as e:
                    print(f"⚠️ Error reading {yar_file}: {e}")
        
        # Fetch from GitHub repos
        github_sources = [
            {
                'name': 'Yara-Rules/rules',
                'base_url': 'https://api.github.com/repos/Yara-Rules/rules/contents',
                'paths': ['malware', 'CVE_Rules', 'webshells', 'packers']
            }
        ]
        
        for source in github_sources:
            try:
                for path in source.get('paths', []):
                    api_url = f"{source['base_url']}/{path}"
                    response = requests.get(api_url, timeout=30, headers={'Accept': 'application/vnd.github.v3+json'})
                    
                    if response.status_code == 200:
                        files = response.json()
                        for file_info in files:
                            if file_info.get('type') == 'file' and file_info.get('name', '').endswith('.yar'):
                                # Get file content
                                content_url = file_info.get('download_url')
                                if content_url:
                                    content_response = requests.get(content_url, timeout=30)
                                    if content_response.status_code == 200:
                                        rule = {
                                            'id': f"YARA-{source['name']}-{file_info.get('name', '').replace('.yar', '')}",
                                            'name': file_info.get('name', ''),
                                            'content': content_response.text[:5000],  # Limit to 5000 chars
                                            'source': source['name'],
                                            'category': path,
                                            'url': file_info.get('html_url', ''),
                                            'ingested_at': datetime.utcnow().isoformat(),
                                            'freshness_score': 0.7
                                        }
                                        yara_rules.append(rule)
                        
                        print(f"  Found {len([r for r in yara_rules if r.get('category') == path])} rules in {path}")
            except Exception as e:
                print(f"⚠️ Error ingesting YARA rules from {source.get('name', 'unknown')}: {e}")
        
        # Save
        yara_file = self.sources['yara'] / "rules.json"
        with open(yara_file, 'w') as f:
            json.dump({'rules': yara_rules, 'last_updated': datetime.utcnow().isoformat()}, f, indent=2)
        
        print(f"✅ Ingested {len(yara_rules)} YARA rules")
        return yara_rules
    
    def ingest_sigma_rules(self, sigma_dir: Optional[str] = None) -> List[Dict]:
        """Ingest Sigma detection rules"""
        print("Ingesting Sigma rules...")
        
        sigma_rules = []
        
        # If directory provided, scan for .yml files
        if sigma_dir and os.path.isdir(sigma_dir):
            import yaml
            for yml_file in Path(sigma_dir).glob("**/*.yml"):
                try:
                    with open(yml_file, 'r') as f:
                        content = yaml.safe_load(f)
                        rule = {
                            'id': f"SIGMA-{yml_file.stem}",
                            'title': content.get('title', yml_file.stem),
                            'description': content.get('description', ''),
                            'logsource': content.get('logsource', {}),
                            'detection': content.get('detection', {}),
                            'tags': content.get('tags', []),
                            'source': 'local',
                            'ingested_at': datetime.utcnow().isoformat(),
                            'freshness_score': 0.7
                        }
                        sigma_rules.append(rule)
                except Exception as e:
                    print(f"⚠️ Error reading {yml_file}: {e}")
        
        # Fetch from GitHub SigmaHQ repo
        try:
            github_url = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules"
            response = requests.get(github_url, timeout=30, headers={'Accept': 'application/vnd.github.v3+json'})
            
            if response.status_code == 200:
                categories = response.json()
                print(f"  Found {len(categories)} Sigma rule categories")
                
                for category in categories[:10]:  # Limit to first 10 categories
                    if category.get('type') == 'dir':
                        category_name = category.get('name', '')
                        category_url = f"{github_url}/{category_name}"
                        
                        cat_response = requests.get(category_url, timeout=30, headers={'Accept': 'application/vnd.github.v3+json'})
                        if cat_response.status_code == 200:
                            rule_files = cat_response.json()
                            
                            for rule_file in rule_files[:20]:  # Limit to 20 rules per category
                                if rule_file.get('type') == 'file' and rule_file.get('name', '').endswith('.yml'):
                                    download_url = rule_file.get('download_url')
                                    if download_url:
                                        rule_response = requests.get(download_url, timeout=30)
                                        if rule_response.status_code == 200:
                                            try:
                                                import yaml
                                                content = yaml.safe_load(rule_response.text)
                                                
                                                rule = {
                                                    'id': f"SIGMA-{category_name}-{rule_file.get('name', '').replace('.yml', '')}",
                                                    'title': content.get('title', rule_file.get('name', '')),
                                                    'description': content.get('description', '')[:500],
                                                    'logsource': content.get('logsource', {}),
                                                    'detection': content.get('detection', {}),
                                                    'tags': content.get('tags', []),
                                                    'level': content.get('level', 'medium'),
                                                    'source': 'SigmaHQ/sigma',
                                                    'category': category_name,
                                                    'url': rule_file.get('html_url', ''),
                                                    'ingested_at': datetime.utcnow().isoformat(),
                                                    'freshness_score': 0.7
                                                }
                                                sigma_rules.append(rule)
                                            except Exception as e:
                                                pass
                            
                            print(f"  Processed {category_name}: {len([r for r in sigma_rules if r.get('category') == category_name])} rules")
        except ImportError:
            print("⚠️ PyYAML not installed. Install with: pip install pyyaml")
        except Exception as e:
            print(f"⚠️ Error ingesting Sigma rules from GitHub: {e}")
        
        # Save
        sigma_file = self.sources['sigma'] / "rules.json"
        with open(sigma_file, 'w') as f:
            json.dump({'rules': sigma_rules, 'last_updated': datetime.utcnow().isoformat()}, f, indent=2)
        
        print(f"✅ Ingested {len(sigma_rules)} Sigma rules")
        return sigma_rules
    
    def ingest_internal_ti(self, internal_file: Optional[str] = None) -> List[Dict]:
        """Ingest internal threat intelligence notes"""
        print("Ingesting internal threat intelligence...")
        
        notes = []
        
        # If file provided, load from file
        if internal_file and os.path.exists(internal_file):
            try:
                with open(internal_file, 'r') as f:
                    data = json.load(f)
                    notes = data.get('notes', [])
            except Exception as e:
                print(f"⚠️ Error loading internal TI from file: {e}")
        
        # Create template structure if file doesn't exist
        if not notes:
            # Create example internal TI structure
            template_notes = [
                {
                    'id': 'INTERNAL-EXAMPLE-001',
                    'title': 'Example Internal Threat Note',
                    'content': 'This is a template for internal threat intelligence notes. Add your own notes here.',
                    'tags': ['example', 'template'],
                    'created_at': datetime.utcnow().isoformat(),
                    'source': 'internal'
                }
            ]
            notes = template_notes
            print("  Created template structure for internal TI")
        
        # Save
        internal_file = self.sources['internal'] / "notes.json"
        with open(internal_file, 'w') as f:
            json.dump({'notes': notes, 'last_updated': datetime.utcnow().isoformat()}, f, indent=2)
        
        print(f"✅ Ingested {len(notes)} internal TI notes")
        return notes
    
    def ingest_all(self, **kwargs) -> Dict[str, List]:
        """Ingest from all sources"""
        results = {
            'attack': self.ingest_mitre_attack(kwargs.get('force_refresh_attack', False)),
            'vendor': self.ingest_vendor_advisories(kwargs.get('vendor_sources')),
            'ioc': self.ingest_iocs(kwargs.get('ioc_file')),
            'yara': self.ingest_yara_rules(kwargs.get('yara_dir')),
            'sigma': self.ingest_sigma_rules(kwargs.get('sigma_dir')),
            'internal': self.ingest_internal_ti(kwargs.get('internal_file', ''))
        }
        
        total = sum(len(v) for v in results.values())
        print(f"\n✅ Total ingested: {total} threat intelligence items")
        
        return results
    
    def _extract_mitre_id(self, obj: Dict) -> str:
        """Extract MITRE technique ID"""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', 'UNKNOWN')
        return 'UNKNOWN'
    
    def _extract_mitigations(self, technique: Dict, stix_data: Dict) -> List[str]:
        """Extract mitigation relationships"""
        mitigations = []
        tech_id = technique.get('id', '')
        
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'relationship':
                if (obj.get('source_ref') == tech_id and 
                    obj.get('relationship_type') == 'mitigates'):
                    target_id = obj.get('target_ref', '')
                    # Find mitigation object
                    for mit_obj in stix_data.get('objects', []):
                        if mit_obj.get('id') == target_id:
                            mitigations.append(mit_obj.get('name', ''))
        
        return mitigations
    
    def _generate_ioc_id(self, ioc: Dict) -> str:
        """Generate unique ID for IOC"""
        value = ioc.get('value', '')
        ioc_type = ioc.get('type', 'unknown')
        return f"IOC-{ioc_type}-{hashlib.md5(value.encode()).hexdigest()[:12]}"


if __name__ == "__main__":
    # Example usage
    ingester = ThreatIntelIngestion()
    
    # Ingest all sources
    results = ingester.ingest_all(
        force_refresh_attack=False,
        ioc_file=None,  # Provide path to IOC file if available
        yara_dir=None,  # Provide path to YARA rules directory
        sigma_dir=None,  # Provide path to Sigma rules directory
        internal_file=None  # Provide path to internal TI file
    )
    
    print("\nIngestion complete!")
    for source, items in results.items():
        print(f"  {source}: {len(items)} items")
