#!/usr/bin/env python3
"""
HONEYTRACE - Main entry point with desktop notifications
"""

import logging
from honeytrace.desktop_notifier import DesktopNotifier
from honeytrace.dashboard import start_dashboard_thread

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

if __name__ == "__main__":
    # Start desktop notifier
    notifier = DesktopNotifier(dashboard_port=8080)
    notifier.start()
    
    # Start dashboard
    start_dashboard_thread(port=8080)
    
    print("🚀 HONEYTRACE with Desktop Notifications Started!")
    print("📊 Dashboard: http://localhost:8080")
    print("🎯 System tray icon should appear shortly...")
    
    # Start main daemon
    from honeytrace.daemon import main
    main()




