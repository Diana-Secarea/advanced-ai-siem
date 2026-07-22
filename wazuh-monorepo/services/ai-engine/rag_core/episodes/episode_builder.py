"""
Security Episode Builders
Convert raw Wazuh events into structured "security objects" (episodes)
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class SecurityEpisode:
    """Base security episode structure"""
    episode_id: str
    episode_type: str  # process, authentication, network, alert
    time_range: Dict[str, str]  # start, end
    entities: Dict[str, List[str]]  # users, hosts, IPs, domains, hashes
    source: str  # EDR/SIEM source
    tags: List[str]  # ATT&CK guesses, environment, severity
    summary: str  # Compact description (200-2000 tokens)
    raw_refs: List[str]  # Pointers to raw events (not in LLM)
    metadata: Dict[str, Any]
    created_at: str


class ProcessEpisodeBuilder:
    """Build process tree episodes from Wazuh events"""
    
    def __init__(self, time_window_minutes: int = 5):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.process_trees = defaultdict(list)
    
    def build_episode(self, events: List[Dict]) -> Optional[SecurityEpisode]:
        """Build process episode from related events"""
        if not events:
            return None
        
        # Group events by process tree
        process_groups = self._group_by_process_tree(events)
        
        if not process_groups:
            return None
        
        # Build episode from largest process tree
        largest_tree = max(process_groups.values(), key=len)
        
        # Extract entities
        entities = self._extract_entities(largest_tree)
        
        # Build summary
        summary = self._build_summary(largest_tree, entities)
        
        # Extract time range
        timestamps = [self._extract_timestamp(e) for e in largest_tree]
        time_range = {
            'start': min(timestamps),
            'end': max(timestamps)
        }
        
        # Extract tags
        tags = self._extract_tags(largest_tree, entities)
        
        # Generate episode ID
        episode_id = f"PROC-{hashlib.md5(str(largest_tree[0]).encode()).hexdigest()[:12]}"
        
        return SecurityEpisode(
            episode_id=episode_id,
            episode_type='process',
            time_range=time_range,
            entities=entities,
            source='Wazuh',
            tags=tags,
            summary=summary,
            raw_refs=[e.get('id', '') for e in largest_tree],
            metadata={
                'process_count': len(largest_tree),
                'tree_depth': self._calculate_tree_depth(largest_tree),
                'suspicious_indicators': self._detect_suspicious_indicators(largest_tree)
            },
            created_at=datetime.utcnow().isoformat()
        )
    
    def _group_by_process_tree(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by process tree relationships"""
        groups = defaultdict(list)
        
        for event in events:
            # Extract process info
            process_id = self._extract_process_id(event)
            parent_id = self._extract_parent_id(event)
            
            if process_id:
                # Find or create group
                group_key = parent_id or process_id
                groups[group_key].append(event)
        
        return dict(groups)
    
    def _extract_process_id(self, event: Dict) -> Optional[str]:
        """Extract process ID from event"""
        # Wazuh format
        if 'data' in event:
            return event['data'].get('process_id') or event['data'].get('pid')
        return event.get('process_id') or event.get('pid')
    
    def _extract_parent_id(self, event: Dict) -> Optional[str]:
        """Extract parent process ID"""
        if 'data' in event:
            return event['data'].get('parent_process_id') or event['data'].get('ppid')
        return event.get('parent_process_id') or event.get('ppid')
    
    def _extract_entities(self, events: List[Dict]) -> Dict[str, List[str]]:
        """Extract entities from events"""
        entities = {
            'users': set(),
            'hosts': set(),
            'ips': set(),
            'domains': set(),
            'hashes': set(),
            'processes': set(),
            'files': set()
        }
        
        for event in events:
            data = event.get('data', event)
            
            # Users
            if 'user' in data:
                entities['users'].add(str(data['user']))
            if 'srcuser' in data:
                entities['users'].add(str(data['srcuser']))
            
            # Hosts
            if 'hostname' in data:
                entities['hosts'].add(str(data['hostname']))
            agent = event.get('agent', {})
            if isinstance(agent, dict) and 'name' in agent:
                entities['hosts'].add(agent['name'])
            
            # IPs
            for ip_field in ['srcip', 'dstip', 'ip']:
                if ip_field in data:
                    entities['ips'].add(str(data[ip_field]))
            
            # Domains
            for domain_field in ['domain', 'hostname', 'dns']:
                if domain_field in data:
                    val = str(data[domain_field])
                    if '.' in val and not val.replace('.', '').isdigit():
                        entities['domains'].add(val)
            
            # Hashes
            for hash_field in ['md5', 'sha1', 'sha256', 'hash']:
                if hash_field in data:
                    entities['hashes'].add(str(data[hash_field]))
            
            # Processes
            if 'process' in data:
                entities['processes'].add(str(data['process']))
            if 'command' in data:
                entities['processes'].add(str(data['command']))
            
            # Files
            if 'file' in data:
                entities['files'].add(str(data['file']))
            if 'path' in data:
                entities['files'].add(str(data['path']))
        
        # Convert sets to lists
        return {k: list(v) for k, v in entities.items() if v}
    
    def _build_summary(self, events: List[Dict], entities: Dict) -> str:
        """Build compact episode summary"""
        parts = []
        
        # Process count
        parts.append(f"Process tree with {len(events)} events")
        
        # Key entities
        if entities.get('users'):
            parts.append(f"User: {entities['users'][0]}")
        if entities.get('hosts'):
            parts.append(f"Host: {entities['hosts'][0]}")
        if entities.get('processes'):
            parts.append(f"Processes: {', '.join(entities['processes'][:3])}")
        
        # Suspicious indicators
        suspicious = self._detect_suspicious_indicators(events)
        if suspicious:
            parts.append(f"Suspicious: {', '.join(suspicious[:3])}")
        
        return ". ".join(parts)
    
    def _detect_suspicious_indicators(self, events: List[Dict]) -> List[str]:
        """Detect suspicious indicators in process tree"""
        indicators = []
        
        for event in events:
            data = event.get('data', event)
            message = str(event.get('message', '')).lower()
            
            # Check for suspicious patterns
            if any(word in message for word in ['powershell', 'cmd', 'encoded', 'base64']):
                indicators.append('suspicious_command')
            if any(word in message for word in ['privilege', 'escalation', 'sudo', 'su']):
                indicators.append('privilege_escalation')
            if any(word in message for word in ['injection', 'dll', 'process']):
                indicators.append('process_injection')
            if data.get('signed', False) == False and 'process' in data:
                indicators.append('unsigned_process')
        
        return list(set(indicators))
    
    def _extract_tags(self, events: List[Dict], entities: Dict) -> List[str]:
        """Extract tags for episode"""
        tags = ['process_episode']
        
        # Environment
        for host in entities.get('hosts', []):
            if any(env in host.lower() for env in ['prod', 'production']):
                tags.append('environment:production')
            elif any(env in host.lower() for env in ['dev', 'test']):
                tags.append('environment:development')
        
        # ATT&CK tags (simplified - would use proper ATT&CK mapping)
        suspicious = self._detect_suspicious_indicators(events)
        if 'process_injection' in suspicious:
            tags.append('technique:T1055')
        if 'privilege_escalation' in suspicious:
            tags.append('technique:T1068')
        
        # Severity
        if len(suspicious) > 2:
            tags.append('severity:high')
        elif suspicious:
            tags.append('severity:medium')
        else:
            tags.append('severity:low')
        
        return tags
    
    def _extract_timestamp(self, event: Dict) -> str:
        """Extract timestamp from event"""
        for field in ['timestamp', '@timestamp', 'time']:
            if field in event:
                return str(event[field])
        return datetime.utcnow().isoformat()
    
    def _calculate_tree_depth(self, events: List[Dict]) -> int:
        """Calculate process tree depth"""
        # Simplified - would need proper tree traversal
        return max(len(str(e).split('->')) for e in events) if events else 1


class AuthenticationEpisodeBuilder:
    """Build authentication episodes"""
    
    def build_episode(self, events: List[Dict]) -> Optional[SecurityEpisode]:
        """Build authentication episode"""
        if not events:
            return None
        
        # Filter authentication events
        auth_events = [e for e in events if self._is_auth_event(e)]
        
        if not auth_events:
            return None
        
        entities = self._extract_entities(auth_events)
        summary = self._build_summary(auth_events, entities)
        
        timestamps = [self._extract_timestamp(e) for e in auth_events]
        time_range = {
            'start': min(timestamps),
            'end': max(timestamps)
        }
        
        tags = self._extract_tags(auth_events, entities)
        
        episode_id = f"AUTH-{hashlib.md5(str(auth_events[0]).encode()).hexdigest()[:12]}"
        
        return SecurityEpisode(
            episode_id=episode_id,
            episode_type='authentication',
            time_range=time_range,
            entities=entities,
            source='Wazuh',
            tags=tags,
            summary=summary,
            raw_refs=[e.get('id', '') for e in auth_events],
            metadata={
                'auth_attempts': len(auth_events),
                'failed_attempts': sum(1 for e in auth_events if 'failed' in str(e.get('message', '')).lower()),
                'mfa_used': any('mfa' in str(e.get('message', '')).lower() for e in auth_events)
            },
            created_at=datetime.utcnow().isoformat()
        )
    
    def _is_auth_event(self, event: Dict) -> bool:
        """Check if event is authentication-related"""
        message = str(event.get('message', '')).lower()
        return any(keyword in message for keyword in ['login', 'auth', 'ssh', 'rdp', 'su', 'sudo'])
    
    def _extract_entities(self, events: List[Dict]) -> Dict[str, List[str]]:
        """Extract entities from auth events"""
        # Similar to ProcessEpisodeBuilder but focused on auth
        entities = {'users': set(), 'hosts': set(), 'ips': set()}
        
        for event in events:
            data = event.get('data', event)
            if 'user' in data:
                entities['users'].add(str(data['user']))
            if 'srcip' in data:
                entities['ips'].add(str(data['srcip']))
            agent = event.get('agent', {})
            if isinstance(agent, dict) and 'name' in agent:
                entities['hosts'].add(agent['name'])
        
        return {k: list(v) for k, v in entities.items() if v}
    
    def _build_summary(self, events: List[Dict], entities: Dict) -> str:
        """Build auth episode summary"""
        failed = sum(1 for e in events if 'failed' in str(e.get('message', '')).lower())
        total = len(events)
        
        parts = [f"Authentication episode: {total} attempts"]
        if failed > 0:
            parts.append(f"{failed} failed")
        if entities.get('users'):
            parts.append(f"User: {entities['users'][0]}")
        if entities.get('ips'):
            parts.append(f"IP: {entities['ips'][0]}")
        
        return ". ".join(parts)
    
    def _extract_tags(self, events: List[Dict], entities: Dict) -> List[str]:
        """Extract tags"""
        tags = ['authentication_episode']
        
        failed = sum(1 for e in events if 'failed' in str(e.get('message', '')).lower())
        if failed > 5:
            tags.append('technique:T1110')  # Brute force
            tags.append('severity:high')
        elif failed > 0:
            tags.append('severity:medium')
        else:
            tags.append('severity:low')
        
        return tags
    
    def _extract_timestamp(self, event: Dict) -> str:
        """Extract timestamp"""
        for field in ['timestamp', '@timestamp', 'time']:
            if field in event:
                return str(event[field])
        return datetime.utcnow().isoformat()


class NetworkEpisodeBuilder:
    """Build network flow episodes"""
    
    def build_episode(self, events: List[Dict]) -> Optional[SecurityEpisode]:
        """Build network episode"""
        if not events:
            return None
        
        network_events = [e for e in events if self._is_network_event(e)]
        
        if not network_events:
            return None
        
        entities = self._extract_entities(network_events)
        summary = self._build_summary(network_events, entities)
        
        timestamps = [self._extract_timestamp(e) for e in network_events]
        time_range = {
            'start': min(timestamps),
            'end': max(timestamps)
        }
        
        tags = self._extract_tags(network_events, entities)
        
        episode_id = f"NET-{hashlib.md5(str(network_events[0]).encode()).hexdigest()[:12]}"
        
        return SecurityEpisode(
            episode_id=episode_id,
            episode_type='network',
            time_range=time_range,
            entities=entities,
            source='Wazuh',
            tags=tags,
            summary=summary,
            raw_refs=[e.get('id', '') for e in network_events],
            metadata={
                'connections': len(network_events),
                'unique_ports': len(set(e.get('data', {}).get('dstport', '') for e in network_events)),
                'bytes_sent': sum(e.get('data', {}).get('bytes_sent', 0) for e in network_events),
                'bytes_received': sum(e.get('data', {}).get('bytes_received', 0) for e in network_events)
            },
            created_at=datetime.utcnow().isoformat()
        )
    
    def _is_network_event(self, event: Dict) -> bool:
        """Check if event is network-related"""
        message = str(event.get('message', '')).lower()
        data = event.get('data', {})
        return ('network' in message or 'connection' in message or 
                'srcip' in data or 'dstip' in data or 'port' in data)
    
    def _extract_entities(self, events: List[Dict]) -> Dict[str, List[str]]:
        """Extract network entities"""
        entities = {'ips': set(), 'domains': set(), 'hosts': set()}
        
        for event in events:
            data = event.get('data', event)
            if 'srcip' in data:
                entities['ips'].add(str(data['srcip']))
            if 'dstip' in data:
                entities['ips'].add(str(data['dstip']))
            if 'domain' in data:
                entities['domains'].add(str(data['domain']))
            agent = event.get('agent', {})
            if isinstance(agent, dict) and 'name' in agent:
                entities['hosts'].add(agent['name'])
        
        return {k: list(v) for k, v in entities.items() if v}
    
    def _build_summary(self, events: List[Dict], entities: Dict) -> str:
        """Build network summary"""
        parts = [f"Network episode: {len(events)} connections"]
        if entities.get('ips'):
            parts.append(f"IPs: {len(entities['ips'])} unique")
        if entities.get('domains'):
            parts.append(f"Domains: {', '.join(entities['domains'][:3])}")
        return ". ".join(parts)
    
    def _extract_tags(self, events: List[Dict], entities: Dict) -> List[str]:
        """Extract network tags"""
        tags = ['network_episode']
        
        # Check for port scanning
        ports = set()
        for event in events:
            data = event.get('data', {})
            if 'dstport' in data:
                ports.add(str(data['dstport']))
        
        if len(ports) > 10:
            tags.append('technique:T1046')  # Network scanning
            tags.append('severity:medium')
        
        return tags
    
    def _extract_timestamp(self, event: Dict) -> str:
        """Extract timestamp"""
        for field in ['timestamp', '@timestamp', 'time']:
            if field in event:
                return str(event[field])
        return datetime.utcnow().isoformat()


class AlertEpisodeBuilder:
    """Build alert episodes from Wazuh alerts"""
    
    def build_episode(self, alert: Dict, correlated_events: List[Dict] = None) -> SecurityEpisode:
        """Build alert episode"""
        correlated_events = correlated_events or []
        
        entities = self._extract_entities([alert] + correlated_events)
        summary = self._build_summary(alert, correlated_events, entities)
        
        timestamp = self._extract_timestamp(alert)
        time_range = {
            'start': timestamp,
            'end': timestamp
        }
        
        tags = self._extract_tags(alert, entities)
        
        episode_id = f"ALERT-{alert.get('id', hashlib.md5(str(alert).encode()).hexdigest()[:12])}"
        
        return SecurityEpisode(
            episode_id=episode_id,
            episode_type='alert',
            time_range=time_range,
            entities=entities,
            source='Wazuh',
            tags=tags,
            summary=summary,
            raw_refs=[alert.get('id', '')] + [e.get('id', '') for e in correlated_events],
            metadata={
                'alert_level': alert.get('level', 0),
                'rule_id': alert.get('rule', {}).get('id'),
                'correlated_events_count': len(correlated_events)
            },
            created_at=datetime.utcnow().isoformat()
        )
    
    def _extract_entities(self, events: List[Dict]) -> Dict[str, List[str]]:
        """Extract entities from alert and events"""
        # Similar extraction logic
        entities = {'users': set(), 'hosts': set(), 'ips': set(), 'hashes': set()}
        
        for event in events:
            data = event.get('data', event)
            if 'srcuser' in data:
                entities['users'].add(str(data['srcuser']))
            if 'srcip' in data:
                entities['ips'].add(str(data['srcip']))
            agent = event.get('agent', {})
            if isinstance(agent, dict) and 'name' in agent:
                entities['hosts'].add(agent['name'])
        
        return {k: list(v) for k, v in entities.items() if v}
    
    def _build_summary(self, alert: Dict, correlated: List[Dict], entities: Dict) -> str:
        """Build alert summary"""
        rule = alert.get('rule', {})
        description = rule.get('description', alert.get('message', 'Alert'))
        
        parts = [description[:200]]
        if correlated:
            parts.append(f"Correlated with {len(correlated)} events")
        if entities.get('ips'):
            parts.append(f"IP: {entities['ips'][0]}")
        
        return ". ".join(parts)
    
    def _extract_tags(self, alert: Dict, entities: Dict) -> List[str]:
        """Extract alert tags"""
        tags = ['alert_episode']
        
        level = alert.get('level', 0)
        if level >= 12:
            tags.append('severity:critical')
        elif level >= 10:
            tags.append('severity:high')
        elif level >= 7:
            tags.append('severity:medium')
        else:
            tags.append('severity:low')
        
        # Extract ATT&CK from rule
        rule = alert.get('rule', {})
        if 'mitre' in str(rule).lower():
            # Would parse MITRE IDs from rule
            tags.append('technique:detected')
        
        return tags
    
    def _extract_timestamp(self, event: Dict) -> str:
        """Extract timestamp"""
        for field in ['timestamp', '@timestamp', 'time']:
            if field in event:
                return str(event[field])
        return datetime.utcnow().isoformat()


# Import hashlib for ID generation
import hashlib
