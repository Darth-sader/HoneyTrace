#!/usr/bin/env python3
"""
HONEYTRACE - The Detective
Forensic process investigation and analysis
"""

import psutil
import logging
import subprocess

logger = logging.getLogger('HONEYTRACE')

def investigate_process(pid):
    """Gathers forensic information about the process with the given PID."""
    try:
        process = psutil.Process(pid)
        parent = process.parent()
        process_info = {
            'pid': pid,
            'exe': process.exe(),
            'cmdline': ' '.join(process.cmdline()),
            'username': process.username(),
            'uid': process.uids().real,
            'gid': process.gids().real,
            'parent_pid': parent.pid if parent else None,
            'parent_exe': parent.exe() if parent else None,
            'terminal': process.terminal(),
            'cwd': process.cwd(),
            'environment': {},
            'groups': []
        }

        # Environment variables
        try:
            process_info['environment'] = process.environ()
        except: 
            pass

        # Process groups
        try:
            groups_output = subprocess.run(['id', process_info['username']], 
                                         capture_output=True, text=True)
            process_info['groups'] = groups_output.stdout.strip()
        except: 
            pass

    except psutil.NoSuchProcess:
        logger.error(f"Process {pid} terminated too quickly. Could not investigate.")
        return None, None, None
    except psutil.AccessDenied:
        logger.error(f"Access denied to process {pid}. Run as root.")
        return None, None, None 

    # Log the critical forensic data
    logger.critical("=== START OF FORENSIC DUMP ===")
    logger.critical(f"INTRUDER PROCESS PID: {pid}")
    logger.critical(f"PROCESS PATH: {process.exe()}")
    logger.critical(f"FULL COMMAND: {' '.join(process.cmdline())}")
    logger.critical(f"USER: {process.username()} (UID: {process.uids().real})")
    
    if parent:
        logger.critical(f"PARENT PROCESS: {parent.exe()} (PID: {parent.pid})")
    if process.terminal():
        logger.critical(f"TERMINAL (TTY): {process.terminal()}")

    # Get advanced intelligence
    try:
        cwd = process.cwd()
        logger.critical(f"CURRENT WORKING DIR: {cwd}")
    except Exception as e:
        logger.error(f"Could not get CWD: {e}")

    try:
        env = process.environ()
        logger.critical("ENVIRONMENT VARIABLES:")
        for key in ['SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'USER', 'HOME']:
            if key in env:
                logger.critical(f"    {key}={env[key]}")
    except Exception as e:
        logger.error(f"Could not get ENV: {e}")

    logger.critical("=== END OF FORENSIC DUMP ===")
    
    return process, parent, process_info

