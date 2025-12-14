#!/usr/bin/env python3
"""
HONEYTRACE - The Heart
Main daemon process and inotify event handler
"""

import inotify.adapters
import logging
import os
import signal
import sys
import subprocess
import time

# Import our modular components
from honeytrace.config_loader import load_decoy_paths, setup_report_directory
from honeytrace.forensic_analyzer import investigate_process
from honeytrace.session_manager import activate_trap

logger = logging.getLogger('HONEYTRACE')

def _main():
    """Main daemon entry point - SIMPLE & RELIABLE"""
    # Initialize debounce tracking
    last_detection_time = 0
    DEBOUNCE_SECONDS = 2
    
    def signal_handler(sig, frame):
        logger.info("HONEYTRACE shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if os.geteuid() != 0:
        logger.error("HONEYTRACE must be run as root. Use: sudo python3 -m honeytrace")
        exit(1)

    # Setup directories
    setup_report_directory()
    
    # Load decoy paths from config file
    decoy_files = load_decoy_paths()
    if not decoy_files:
        logger.error("No decoy files found in config. Exiting.")
        exit(1)

    logger.info(f"Loaded {len(decoy_files)} decoy file(s) from config.")

    # Check if decoy files exist before monitoring
    for decoy in decoy_files[:]:
        if not os.path.exists(decoy):
            logger.error(f"Decoy file not found: {decoy}. Please create it. Skipping.")
            decoy_files.remove(decoy)

    if not decoy_files:
        logger.error("No valid decoy files to monitor. Exiting.")
        exit(1)

    # Set up the inotify watcher
    notifier = inotify.adapters.Inotify()
    
    # Add watches for each decoy file
    for decoy in decoy_files:
        notifier.add_watch(decoy)
        logger.info(f"🟢 Now monitoring: {decoy}")

    logger.info("HONEYTRACE Professional Architecture Active! Press Ctrl+C to stop.")
    
    # Main event loop - SIMPLE AND RELIABLE
    try:
        for event in notifier.event_gen():
            if event is not None:
                (header, type_names, watch_path, filename) = event
                
                # Check for file access events
                if any(t in ['IN_OPEN', 'IN_ACCESS', 'IN_MODIFY', 'IN_DELETE'] for t in type_>
                    full_path = os.path.join(watch_path, filename) if filename else watch_path
                    
                    # DEBOUNCE: Prevent duplicate detections
                    current_time = time.time()
                    if current_time - last_detection_time < DEBOUNCE_SECONDS:
                        continue
                    last_detection_time = current_time
                    
                    logger.warning(f"🔴 ALERT: Event detected on decoy file! Event: {type_nam>
                    

  GNU nano 8.4                               daemon.py                                        
                    # Find the process that accessed the file
                    pid = get_pid_via_lsof(full_path)
                    
                    if pid is None:
                        logger.error("Could not find process with file open.")
                        continue

                    logger.critical(f"🎯 FOUND PROCESS: PID {pid}")
                    
                    # Investigate and activate trap
                    process, parent, process_info = investigate_process(pid)
                    
                    if process and parent and process_info:
                        activate_trap(pid, parent.pid, process_info)
                    else:
                        logger.error("Process investigation failed")
                        
    except KeyboardInterrupt:
        logger.info("HONEYTRACE stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise

def get_pid_via_lsof(filepath):
    """Find which process has the file open - SIMPLE & RELIABLE"""
    try:
        # Try lsof first (most reliable)
        for attempt in range(2):
            try:
                cmd = ['lsof', '-t', filepath]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
                
                if result.returncode == 0 and result.stdout.strip():
                    pid = int(result.stdout.strip())
                    logger.info(f"🎯 Found PID {pid} via lsof")
                    return pid
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
            
            time.sleep(0.1)
        
        # Fallback: fuser
        try:
            cmd = ['fuser', filepath]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            if result.returncode == 0 and result.stdout.strip():
                # fuser returns: "/path/to/file: 12345"
                pid_str = result.stdout.strip().split()[-1]
                if pid_str.isdigit():
                    pid = int(pid_str)
                    logger.info(f"🎯 Found PID {pid} via fuser")
                    return pid
        except Exception:
            pass
            
        # Final fallback: most recent shell process
        try:
            cmd = ['ps', '-eo', 'pid,comm', '--sort=-pid']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            for line in result.stdout.split('\n'):
                if any(shell in line for shell in ['bash', 'zsh', 'sh', 'python']):
                    parts = line.strip().split()
                    if len(parts) >= 1 and parts[0].isdigit():
                        pid = int(parts[0])
                        if pid != os.getpid():  # Don't return our own PID
                            logger.info(f"🎯 Using fallback PID {pid}")
                            return pid
        except Exception:
            pass
            
        logger.error(f"❌ All PID detection methods failed for {filepath}")
        return None
        
    except Exception as e:
        logger.error(f"PID detection error: {e}")
        return None

def main():
    """Wrapper for main function"""
    _main()

