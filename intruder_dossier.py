!/usr/bin/env python3
"""
HONEYTRACE - Intruder Dossier Generator
The "Who They Are" - Strategic Intelligence Profile
"""

import os
import json
import logging
from datetime import datetime
import subprocess
import socket

logger = logging.getLogger('HONEYTRACE')

class IntruderDossier:
    """Generates comprehensive intruder intelligence profile"""
    
    def __init__(self, source_ip, timestamp, session_data):
        self.source_ip = source_ip
        self.timestamp = timestamp
        self.session_data = session_data
        self.report_dir = os.path.expanduser('~/.honeytrace/reports')
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_dossier(self):
        """Generate complete intruder intelligence dossier"""
        report_path = os.path.join(self.report_dir, f"recon_{self.source_ip}_{self.timestamp}>
        
        try:
            with open(report_path, 'w') as f:
                # Header
                f.write("=== HONEYTRACE INTRUDER INTELLIGENCE DOSSIER ===\n")
                f.write("THE 'WHO THEY ARE' - STRATEGIC INTELLIGENCE PROFILE\n")
                f.write("=" * 65 + "\n")
                f.write(f"Target: {self.source_ip}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 65 + "\n\n")
                
                # 1. IDENTITY
                f.write("1. IDENTITY & ATTRIBUTION\n")
                f.write("-" * 25 + "\n")
                self._write_identity_section(f)
                f.write("\n")
                
                # 2. SESSION CONTEXT
                f.write("2. SESSION CONTEXT\n")
                f.write("-" * 18 + "\n")
                self._write_session_context(f)
                f.write("\n")
                
                # 3. NETWORK FINGERPRINT
                f.write("3. NETWORK FINGERPRINT\n")
                f.write("-" * 22 + "\n")
                self._write_network_fingerprint(f)
                f.write("\n")
                
                # 4. SYSTEM INTERACTION FOOTPRINT
                f.write("4. SYSTEM INTERACTION FOOTPRINT\n")
                f.write("-" * 32 + "\n")
                self._write_system_interaction(f)
                f.write("\n")
                
                # 8. SYSTEM IMPACT
                f.write("8. SYSTEM IMPACT & PERSISTENCE\n")
                f.write("-" * 35 + "\n")
                self._write_system_impact(f)
                f.write("\n")
                
                f.write(f"Dossier saved: {report_path}\n")
            
            logger.info(f"✅ Intruder dossier: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"❌ Intruder dossier generation failed: {e}")
            return None
    
    def _write_identity_section(self, f):
        """Write identity and attribution information"""
        process_info = self.session_data.get('process_info', {})
        live_intel = self.session_data.get('live_intelligence', {})
        
        # Basic identity
        f.write(f"Username: {process_info.get('username', 'UNKNOWN')}\n")
        f.write(f"UID: {process_info.get('uid', 'UNKNOWN')}\n")
        f.write(f"GID: {process_info.get('gid', 'UNKNOWN')}\n")
        
        # Groups and permissions
        user_context = live_intel.get('user_context', {})
        if user_context.get('user_info'):
            f.write(f"User Info: {user_context['user_info']}\n")
        if user_context.get('groups'):
            f.write(f"Groups: {', '.join(user_context['groups'])}\n")
        
        # Privilege escalation detection
        if self._detect_privilege_escalation():
            f.write("🚨 PRIVILEGE ESCALATION ATTEMPTS: DETECTED\n")
        else:
            f.write("Privilege Escalation: No attempts detected\n")
    
    def _write_session_context(self, f):
        """Write session context information"""
        process_info = self.session_data.get('process_info', {})
        
        f.write(f"Authentication: {self.session_data.get('authentication_method', 'UNKNOWN')}>
        f.write(f"Source IP: {self.source_ip}\n")
        
        # TTY information
        if process_info.get('terminal'):
            f.write(f"Terminal: {process_info['terminal']}\n")
        
        # Session timing
        session_start = self.session_data.get('session_start')
        if session_start:
            start_time = datetime.fromtimestamp(session_start).strftime('%Y-%m-%d %H:%M:%S')
            duration = time.time() - session_start
            f.write(f"Login Time: {start_time}\n")
            f.write(f"Session Duration: {duration:.2f} seconds\n")
        
        # SSH context
        env = process_info.get('environment', {})
        for key in ['SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY']:
            if key in env:
                f.write(f"{key}: {env[key]}\n")
    
    def _write_network_fingerprint(self, f):
        """Write network intelligence"""
        if self.source_ip in ['LOCAL_ACCESS', 'UNKNOWN']:
            f.write("Local access - No external network fingerprint\n")
            return
        
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(self.source_ip)[0]
            f.write(f"Reverse DNS: {hostname}\n")
        except:
            f.write("Reverse DNS: Lookup failed\n")
        
        # GeoIP
        geo_data = self._get_geoip_data()
        if geo_data:
            f.write(f"GeoIP: {geo_data}\n")
        
        # WHOIS data
        whois_data = self._get_whois_data()
        if whois_data:
            f.write("WHOIS Intelligence:\n")
            for line in whois_data.split('\n')[:10]:  # First 10 lines
                if any(keyword in line.lower() for keyword in ['netname', 'country', 'descr',>
                    f.write(f"  {line.strip()}\n")
    
    def _write_system_interaction(self, f):
        """Write system interaction footprint"""
        process_info = self.session_data.get('process_info', {})
        live_intel = self.session_data.get('live_intelligence', {})
        
        # Working directory
        f.write(f"Initial Working Directory: {process_info.get('cwd', 'UNKNOWN')}\n")
        
        # Process tree
        system_state = live_intel.get('system_state', {})
        if system_state.get('process_tree'):
            f.write("Process Tree:\n")
            for proc in system_state['process_tree'][:5]:
                f.write(f"  {proc}\n")
        
        # Live network connections
        network_intel = live_intel.get('network_intel', {})
        if network_intel.get('connections'):
            f.write("Active Network Connections:\n")
            for conn in network_intel['connections'][:3]:
                f.write(f"  {conn}\n")
    
    def _write_system_impact(self, f):
        """Write system impact analysis"""
        live_intel = self.session_data.get('live_intelligence', {})
        system_state = live_intel.get('system_state', {})
        process_forensics = live_intel.get('process_forensics', {})
        
        # Resource usage
        resource_usage = system_state.get('resource_usage', {})
        if resource_usage:
            f.write("Resource Usage:\n")
            f.write(f"  CPU: {resource_usage.get('cpu_percent', 'N/A')}%\n")
            f.write(f"  Memory: {resource_usage.get('memory_percent', 'N/A')}%\n")
            f.write(f"  File Descriptors: {resource_usage.get('num_fds', 'N/A')}\n")
        
        # Process information
        if process_forensics:
            f.write(f"Processes Spawned: {process_forensics.get('num_threads', 'N/A')} thread>
        
        # Persistence detection
        persistence_attempts = self._detect_persistence_attempts()
        if persistence_attempts:
            f.write("🚨 PERSISTENCE ATTEMPTS DETECTED:\n")
            for attempt in persistence_attempts:
                f.write(f"  - {attempt}\n")
        else:
            f.write("Persistence: No attempts detected\n")
    
    def _get_geoip_data(self):
        """Get GeoIP information"""
        try:
            result = subprocess.run(['geoiplookup', self.source_ip], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def _get_whois_data(self):
        """Get WHOIS information"""
        try:
            result = subprocess.run(['whois', self.source_ip], 
                                  capture_output=True, text=True, timeout=10)
            return result.stdout
        except:
            pass
        return None
    
    def _detect_privilege_escalation(self):
        """Detect privilege escalation attempts"""
        process_info = self.session_data.get('process_info', {})
        cmdline = process_info.get('cmdline', '').lower()
        
        escalation_indicators = ['sudo', 'su ', 'pkexec', 'passwd', 'visudo']
        return any(indicator in cmdline for indicator in escalation_indicators)
    
    def _detect_persistence_attempts(self):
        """Detect persistence mechanism attempts"""
        process_info = self.session_data.get('process_info', {})
        cmdline = process_info.get('cmdline', '').lower()
        
        persistence_indicators = {
            'cron': 'cron job modification',
            'systemctl': 'service modification', 
            'rc.local': 'startup script modification',
            'profile': 'shell profile modification',
            'bashrc': 'bash configuration modification'
        }
        
        detected = []
        for indicator, description in persistence_indicators.items():
            if indicator in cmdline:
                detected.append(description)
        
        return detected

