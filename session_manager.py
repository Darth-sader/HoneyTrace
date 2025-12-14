  GNU nano 8.4                          session_manager.py                                    
#!/usr/bin/env python3
"""
HONEYTRACE - REAL COMMAND LOGGING
"""

import subprocess
import threading
import time
import psutil
import logging
import os

logger = logging.getLogger('HONEYTRACE')

active_sessions = {}

def is_process_alive(pid):
    """Check if process is alive, including zombie processes"""
    try:
        process = psutil.Process(pid)
        # Consider zombie processes as "alive" for our purposes
        # since the terminal might still be active
        return process.status() in ['running', 'sleeping', 'disk-sleep', 'zombie']
    except psutil.NoSuchProcess:
        return False

def activate_trap(target_pid, parent_pid, process_info):
    from honeytrace.report_generator import generate_intrusion_reports
    
    shell_pid = target_pid
    username = process_info.get('username', 'unknown')
    session_key = f"honeytrace_{shell_pid}"
    
    if session_key in active_sessions:
        return session_key
    
    logger.critical(f"🚀 STARTING REAL COMMAND LOGGING FOR SHELL: {username} (PID: {shell_pid>

    active_sessions[session_key] = {
        'shell_pid': shell_pid,
        'username': username,
        'session_start': time.time(),
        'process_info': process_info,
        'all_commands': []
    }

    # Start REAL command logging
    monitor_thread = threading.Thread(
        target=log_real_commands,
        args=(shell_pid, session_key, username)
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    
    return session_key

def log_real_commands(shell_pid, session_key, username):
    logger.critical(f"📝 MONITORING TERMINAL FOR SHELL {shell_pid}")
    
    try:
        # Get the terminal device of the shell
        shell_process = psutil.Process(shell_pid)
        terminal = shell_process.terminal()
        
        if not terminal:
            logger.error("❌ Cannot detect terminal device")
            generate_real_report(session_key)
            return
        
        terminal_device = os.path.basename(terminal)
        logger.info(f"🎯 Monitoring terminal: {terminal} (device: {terminal_device})")
        
        # Monitor until terminal device disappears
        start_time = time.time()
        max_monitor_time = 600  # 10 minutes maximum
        
        command_count = 0
        
        while time.time() - start_time < max_monitor_time:
            # Check if terminal still exists
            if not terminal_exists(terminal_device):
                logger.info(f"🏁 Terminal {terminal_device} closed - ending monitoring")
                break
            
            # CAPTURE COMMANDS EVERY LOOP ITERATION
            new_commands = capture_commands_with_strace(shell_pid, session_key)
            if new_commands > 0:
                command_count += new_commands
                logger.info(f"📊 Total commands captured: {command_count}")
            
            # Brief sleep to prevent CPU overload
            time.sleep(1)
            
        logger.info(f"🏁 Monitoring ended. Captured {command_count} commands total.")
            
    except Exception as e:
        logger.error(f"Terminal monitoring error: {e}")
    finally:
        generate_real_report(session_key)

def terminal_exists(terminal_device):
    """Check if terminal device still exists"""
    try:
        result = subprocess.run(['ps', '-t', terminal_device], 
                              capture_output=True, text=True)
        return result.returncode == 0 and len(result.stdout.strip().split('\n')) > 1
    except:
        return False

def find_shell_in_terminal(terminal_device):
    """Find shell process in the given terminal"""
    try:
        result = subprocess.run(['ps', '-t', terminal_device, '-o', 'pid,comm', '--no-headers>
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    pid, comm = parts
                    if comm in ['bash', 'zsh', 'sh', 'fish']:  # Common shells
                        return int(pid)
        return None
    except:
        return None

def capture_commands_with_strace(shell_pid, session_key):
    """DEBUG VERSION - Actually capture commands and return count"""
    new_commands = 0
    
    try:
        logger.debug(f"🔍 Checking for children of shell {shell_pid}")

        
        result = subprocess.run([
            'ps', '--ppid', str(shell_pid), '-o', 'pid,comm,args', '--no-headers'
        ], capture_output=True, text=True, timeout=2)
        
        logger.debug(f"PS found {len(result.stdout.strip().split(chr(10)))} potential command>
        
        if result.stdout.strip():
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.strip().split(maxsplit=2)
                    if len(parts) >= 3:
                        pid, comm, args = parts
                        full_command = f"{comm} {args}" if args else comm
                        
                        # Skip system processes
                        skip_commands = ['ps', 'strace', 'timeout', 'grep', 'sed', 'awk']
                        if any(skip in full_command for skip in skip_commands):
                            continue
                            
                        logger.debug(f"📝 Processing command: {full_command}")
                        
                        timestamp = time.strftime('%H:%M:%S')
                        command_entry = f"[{timestamp}] {full_command}"
                        
                        # Check if this command is already captured
                        existing_commands = [cmd.split('] ')[1] if '] ' in cmd else cmd 
                                           for cmd in active_sessions[session_key]['all_comma>
                        
                        if full_command not in existing_commands:
                            active_sessions[session_key]['all_commands'].append(command_entry)
                            logger.info(f"🎯 CAPTURED REAL COMMAND: {full_command}")
                            new_commands += 1
        else:
            logger.debug("📝 No child processes found at this moment")
            
    except subprocess.TimeoutExpired:
        logger.debug("PS command timed out")
    except Exception as e:
        logger.debug(f"Command capture error: {e}")
    
    return new_commands

def parse_strace_commands(strace_log, session_key):
    """Parse strace log for execve calls (actual commands)"""
    try:
        if not os.path.exists(strace_log):
            return
            
        with open(strace_log, 'r') as f:
            content = f.read()
            
        lines = content.split('\n')
        for line in lines:
            if 'execve' in line and '["' in line and '+++' not in line and '---' not in line:
                # Extract the command from execve call
                # Example: 12345 execve("/usr/bin/whoami", ["whoami"], 0x7ffc...)
                
                # Get PID from the line
                pid_match = re.search(r'^(\d+)\s+', line)
                if pid_match and pid_match.group(1) == str(active_sessions[session_key]['shel>
                    continue  # Skip the shell process itself
                
                # Extract command and arguments
                if '", ["' in line:
                    cmd_start = line.find('"/') + 1
                    cmd_end = line.find('"', cmd_start)
                    if cmd_end != -1:
                        command_path = line[cmd_start:cmd_end]
                        command_name = os.path.basename(command_path)
                        
                        # Extract arguments
                        args_start = line.find('", ["') + 5
                        args_end = line.find('"]', args_start)
                        if args_end != -1:
                            args_str = line[args_start:args_end]
                            args = [arg for arg in args_str.split('", "') if arg]
                            
                            # Build full command
                            if args and len(args) > 0:
                                full_command = ' '.join(args)
                            else:
                                full_command = command_name
                            
                            # Skip common system commands we don't care about
                            skip_commands = ['strace', 'ps', 'grep', 'sed', 'awk', 'cat', 'ls>
                            if (full_command and 
                                len(full_command) > 1 and

                                not any(skip in full_command for skip in skip_commands) and
                                full_command not in [cmd.split('] ')[1] if '] ' in cmd else c>
                                
                                timestamp = time.strftime('%H:%M:%S')
                                command_entry = f"[{timestamp}] {full_command}"
                                active_sessions[session_key]['all_commands'].append(command_e>
                                logger.info(f"🎯 CAPTURED REAL COMMAND: {full_command}")
                                
    except Exception as e:
        logger.debug(f"Strace parsing error: {e}")

def capture_real_commands(shell_pid, session_key, username):
    try:
        # Get ALL processes from this shell
        result = subprocess.run([
            'ps', '--ppid', str(shell_pid), '-o', 'pid,comm,args', '--no-headers'
        ], capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3:
                    pid, comm, args = parts
                    full_command = f"{comm} {args}" if args else comm
                    
                    # Only log if it's a real command (not system processes)
                    if (full_command and 
                        len(full_command) > 2 and 
                        'ps --ppid' not in full_command and
                        full_command not in active_sessions[session_key]['all_commands']):
                        
                        timestamp = time.strftime('%H:%M:%S')
                        command_entry = f"[{timestamp}] {full_command}"
                        active_sessions[session_key]['all_commands'].append(command_entry)
                        logger.info(f"📝 CAPTURED: {full_command}")
                        
    except Exception as e:
        logger.debug(f"Command capture: {e}")

def generate_real_report(session_key):
    from honeytrace.report_generator import generate_intrusion_reports
    
    logger.critical(f"📊 GENERATING FINAL REPORT FOR {session_key}")
    
    
    session_info = active_sessions.get(session_key, {})
    shell_pid = session_info.get('shell_pid')
    process_info = session_info.get('process_info', {})
    
    # DEBUG: Check what's actually in the session
    logger.critical(f"🔍 DEBUG - Session keys: {list(session_info.keys())}")
    logger.critical(f"🔍 DEBUG - All commands in session: {session_info.get('all_commands', [>
    logger.critical(f"🔍 DEBUG - Process info keys: {list(process_info.keys())}")
    
    # Make sure we pass the captured commands
    if process_info and 'all_commands' in session_info:
        # Create a COPY of process_info with the commands
        enhanced_process_info = process_info.copy()
        enhanced_process_info['all_commands'] = session_info['all_commands']
        logger.info(f"📝 Passing {len(enhanced_process_info['all_commands'])} commands to rep>
        
        if shell_pid and enhanced_process_info:
            generate_intrusion_reports(session_key, shell_pid, shell_pid, enhanced_process_in>
        else:
            logger.error("❌ Missing shell PID or process info!")
    else:
        logger.error(f"❌ No commands to pass! Has all_commands: {'all_commands' in session_i>
    
    # Clean up
    if session_key in active_sessions:
        del active_sessions[session_key]


