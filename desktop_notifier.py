!/usr/bin/env python3
"""
HONEYTRACE - Desktop Notification System
System tray icon with intrusion alerts and click-to-view dashboard
"""

import threading
import time
import os
import json
import webbrowser
from datetime import datetime

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_GUI = True
except ImportError:
    HAS_GUI = False
    print("⚠ GUI libraries not available - running in console mode")

class DesktopNotifier:
    """Manages desktop notifications and system tray icon"""
    
    def __init__(self, dashboard_port=8080):
        self.intrusion_count = 0
        self.recent_intrusions = []
        self.dashboard_port = dashboard_port
        self.icon = None
        self.is_running = False
        
    def start(self):
        """Start the notification system"""
        if not HAS_GUI:
            print("🚨 Running in console mode - no system tray available")
            return
            
        self.is_running = True
        self._create_tray_icon()
        
        # Start background monitoring
        thread = threading.Thread(target=self._monitor_loop, daemon=True)
        thread.start()
        
    def stop(self):
        """Stop the notification system"""
        self.is_running = False
        if self.icon:
            self.icon.stop()
            
    def alert_intrusion(self, source_ip, command, report_paths):
        """Alert about new intrusion"""
        self.intrusion_count += 1
        
        intrusion_data = {
            'source_ip': source_ip,
            'command': command[:100] + "..." if len(command) > 100 else command,
            'timestamp': datetime.now().isoformat(),
            'report_paths': report_paths,
            'id': f"intrusion_{self.intrusion_count}"
        }
        
        self.recent_intrusions.append(intrusion_data)
        # Keep only last 10 intrusions
        self.recent_intrusions = self.recent_intrusions[-10:]
        
        # Update tray icon
        self._update_tray_icon()
        
        # Send desktop notification
        self._send_notification(source_ip, command)
        
    def _create_tray_icon(self):
        """Create system tray icon"""
        if not HAS_GUI:
            return
            
        # Create menu
        menu = pystray.Menu(
            pystray.MenuItem(
                f"Intrusions: {self.intrusion_count}",
                lambda: None,  # No action
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "📊 Open Dashboard",
                self._open_dashboard
            ),
            pystray.MenuItem(
                "🔄 Update",
                self._update_icon
            ),
            pystray.MenuItem(
                "❌ Exit",
                self.stop
            )
        )
        
        # Create icon
        self.icon = pystray.Icon(
            "honeytrace",
            self._create_icon_image(),
            "HONEYTRACE Intrusion Monitor",
            menu
        )
        
        # Start the icon in a separate thread
        icon_thread = threading.Thread(target=self.icon.run, daemon=True)
        icon_thread.start()
        
    def _create_icon_image(self):
        """Create dynamic icon image with intrusion count"""
        if not HAS_GUI:
            return None
            
        # Create a 64x64 image
        image = Image.new('RGB', (64, 64), color='green')
        draw = ImageDraw.Draw(image)
        
        # Draw background circle
        draw.ellipse([2, 2, 62, 62], fill='red' if self.intrusion_count > 0 else 'green')
        
        # Draw intrusion count
        if self.intrusion_count > 0:

            text = str(self.intrusion_count) if self.intrusion_count < 10 else "9+"
            draw.text((32, 32), text, fill='white', anchor='mm', font_size=20)
        
        return image
    
    def _update_tray_icon(self):
        """Update the tray icon with current intrusion count"""
        if self.icon:
            self.icon.icon = self._create_icon_image()
            self._update_menu()
    
    def _update_menu(self):
        """Update the tray menu with current intrusions"""
        if not self.icon:
            return
            
        # Build dynamic menu with recent intrusions
        menu_items = []
        
        # Status item
        menu_items.append(
            pystray.MenuItem(
                f"🔴 Intrusions: {self.intrusion_count}" if self.intrusion_count > 0 else "🟢>
                lambda: None,
                enabled=False
            )
        )
        
        menu_items.append(pystray.Menu.SEPARATOR)
        
        # Recent intrusions
        if self.recent_intrusions:
            menu_items.append(pystray.MenuItem("Recent Intrusions:", lambda: None, enabled=Fa>
            
            for intrusion in reversed(self.recent_intrusions[-5:]):  # Last 5
                menu_items.append(
                    pystray.MenuItem(
                        f"• {intrusion['source_ip']} - {intrusion['timestamp'][11:16]}",
                        lambda icon, item=intrusion: self._view_intrusion_details(item)
                    )
                )
            
           
            menu_items.append(pystray.Menu.SEPARATOR)
        
        # Standard items
        menu_items.extend([
            pystray.MenuItem("📊 Open Dashboard", self._open_dashboard),
            pystray.MenuItem("🔄 Update", self._update_icon),
            pystray.MenuItem("❌ Exit", self.stop)
        ])
        
        self.icon.menu = pystray.Menu(*menu_items)
    
    def _open_dashboard(self, icon=None, item=None):
        """Open the web dashboard"""
        webbrowser.open(f"http://localhost:{self.dashboard_port}")
        
    def _view_intrusion_details(self, intrusion_data):
        """View details of a specific intrusion"""
        # Open a detailed view for this intrusion
        detail_url = f"http://localhost:{self.dashboard_port}/intrusion/{intrusion_data['id']>
        webbrowser.open(detail_url)
    
    def _update_icon(self, icon=None, item=None):
        """Force update the icon"""
        self._update_tray_icon()
    
    def _send_notification(self, source_ip, command):
        """Send desktop notification"""
        try:
            import subprocess
            title = "🚨 HONEYTRACE ALERT"
            message = f"Intrusion from {source_ip}\nCommand: {command[:50]}..."
            
            # Using notify-send for Linux
            subprocess.run([
                'notify-send', 
                title, 
                message,
                '-u', 'critical',
                '-i', 'security-high',
                '-t', '5000'
            ])
            
            print(f"🔴 INTRUSION ALERT: {source_ip} | Command: {command}")

           
        except Exception as e:
            print(f"Notification failed: {e}")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.is_running:
            time.sleep(5)
    
    def get_dashboard_data(self):
        """Get data for HTML dashboard"""
        return {
            'intrusion_count': self.intrusion_count,
            'recent_intrusions': self.recent_intrusions,
            'status': 'active'
        }


