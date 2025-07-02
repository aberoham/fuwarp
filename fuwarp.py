#!/usr/bin/env python3

import os
import sys
import subprocess
import tempfile
import shutil
import argparse
import platform
import json
import ssl
import base64
import hashlib
import pwd
import socket
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

# Version and metadata
__description__ = "Cloudflare WARP Certificate Fixer Upper for macOS"
__author__ = "Ingersoll & Claude"


def get_version_info():
    """Get version information from Git."""
    version_info = {
        'version': 'unknown',
        'commit': 'unknown',
        'date': 'unknown',
        'branch': 'unknown',
        'dirty': False
    }
    
    try:
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if we're in a git repository
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=script_dir,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            # Get commit hash (short)
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['commit'] = result.stdout.strip()
            
            # Get commit date
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%cd', '--date=short'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['date'] = result.stdout.strip()
            
            # Get branch name
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_info['branch'] = result.stdout.strip()
            
            # Check if working directory is dirty
            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['dirty'] = True
            
            # Get tag if available
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                cwd=script_dir,
                capture_output=True,
                text=True,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and result.stdout.strip():
                version_info['version'] = result.stdout.strip()
            else:
                # No tags, use commit count as version
                result = subprocess.run(
                    ['git', 'rev-list', '--count', 'HEAD'],
                    cwd=script_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    count = result.stdout.strip()
                    version_info['version'] = f"0.{count}.0"
            
            # Add dirty flag to version if needed
            if version_info['dirty'] and version_info['version'] != 'unknown':
                version_info['version'] += '-dirty'
    
    except Exception:
        # Git not available or not a git repository
        pass
    
    return version_info


# Get version info once at module load
VERSION_INFO = get_version_info()

# Colors for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

# Certificate details
CERT_PATH = os.path.expanduser("~/.cloudflare-ca.pem")
SHELL_MODIFIED = False
CERT_FINGERPRINT = ""  # Cache for certificate fingerprint

class FuwarpPython:
    def __init__(self, mode='status', debug=False, selected_tools=None):
        self.mode = mode
        self.debug = debug
        self.shell_modified = False
        self.cert_fingerprint = ""
        self.selected_tools = selected_tools or []
        
        # Define tool registry with tags and descriptions
        self.tools_registry = {
            'node': {
                'name': 'Node.js',
                'tags': ['node', 'nodejs', 'node-npm', 'javascript', 'js'],
                'setup_func': self.setup_node_cert,
                'check_func': self.check_node_status,
                'description': 'Node.js runtime and npm package manager'
            },
            'python': {
                'name': 'Python',
                'tags': ['python', 'python3', 'pip', 'requests'],
                'setup_func': self.setup_python_cert,
                'check_func': self.check_python_status,
                'description': 'Python runtime and pip package manager'
            },
            'gcloud': {
                'name': 'Google Cloud SDK',
                'tags': ['gcloud', 'google-cloud', 'gcp'],
                'setup_func': self.setup_gcloud_cert,
                'check_func': self.check_gcloud_status,
                'description': 'Google Cloud SDK (gcloud CLI)'
            },
            'java': {
                'name': 'Java/JVM',
                'tags': ['java', 'jvm', 'keytool', 'jdk'],
                'setup_func': self.setup_java_cert,
                'check_func': self.check_java_status,
                'description': 'Java runtime and development kit'
            },
            'dbeaver': {
                'name': 'DBeaver',
                'tags': ['dbeaver', 'database', 'db'],
                'setup_func': self.setup_dbeaver_cert,
                'check_func': self.check_dbeaver_status,
                'description': 'DBeaver database client'
            },
            'wget': {
                'name': 'wget',
                'tags': ['wget', 'download'],
                'setup_func': self.setup_wget_cert,
                'check_func': self.check_wget_status,
                'description': 'wget download utility'
            },
            'podman': {
                'name': 'Podman',
                'tags': ['podman', 'container', 'docker-alternative'],
                'setup_func': self.setup_podman_cert,
                'check_func': self.check_podman_status,
                'description': 'Podman container runtime'
            },
            'rancher': {
                'name': 'Rancher Desktop',
                'tags': ['rancher', 'rancher-desktop', 'kubernetes', 'k8s'],
                'setup_func': self.setup_rancher_cert,
                'check_func': self.check_rancher_status,
                'description': 'Rancher Desktop Kubernetes'
            },
            'android': {
                'name': 'Android Emulator',
                'tags': ['android', 'emulator', 'adb'],
                'setup_func': self.setup_android_emulator_cert,
                'check_func': self.check_android_status,
                'description': 'Android SDK emulator'
            },
            'colima': {
                'name': 'Colima',
                'tags': ['colima', 'docker', 'docker-desktop', 'container', 'vm'],
                'setup_func': self.setup_colima_cert,
                'check_func': self.check_colima_status,
                'description': 'Colima Docker runtime'
            }
        }
        
        # Add platform check
        if platform.system() != 'Darwin':
            self.print_warn("This script is designed for macOS. Most features will not work correctly.")

    def is_install_mode(self):
        return self.mode == 'install'
    
    def is_debug_mode(self):
        return self.debug
    
    def should_process_tool(self, tool_key):
        """Check if a tool should be processed based on selected tools."""
        if not self.selected_tools:
            # No selection means process all tools
            return True
        
        tool_info = self.tools_registry.get(tool_key, {})
        if not tool_info:
            return False
        
        # Check if tool key or any of its tags match the selection
        for selection in self.selected_tools:
            selection_lower = selection.lower()
            if selection_lower == tool_key:
                return True
            if selection_lower in [tag.lower() for tag in tool_info.get('tags', [])]:
                return True
        
        return False
    
    def get_selected_tools_info(self):
        """Get information about selected tools."""
        if not self.selected_tools:
            return list(self.tools_registry.keys())
        
        selected = []
        for tool_key, tool_info in self.tools_registry.items():
            if self.should_process_tool(tool_key):
                selected.append(tool_key)
        
        return selected
    
    def validate_selected_tools(self):
        """Validate that selected tools exist and return list of invalid ones."""
        if not self.selected_tools:
            return []
        
        invalid_tools = []
        for selection in self.selected_tools:
            selection_lower = selection.lower()
            found = False
            
            # Check all tools for matching key or tag
            for tool_key, tool_info in self.tools_registry.items():
                if selection_lower == tool_key:
                    found = True
                    break
                if selection_lower in [tag.lower() for tag in tool_info.get('tags', [])]:
                    found = True
                    break
            
            if not found:
                invalid_tools.append(selection)
        
        return invalid_tools
    
    # Printing functions
    def print_info(self, msg):
        print(f"{GREEN}[INFO]{NC} {msg}")
    
    def print_warn(self, msg):
        print(f"{YELLOW}[WARN]{NC} {msg}")
    
    def print_error(self, msg):
        print(f"{RED}[ERROR]{NC} {msg}")
    
    def print_status(self, msg):
        print(f"{BLUE}[STATUS]{NC} {msg}")
    
    def print_action(self, msg):
        print(f"{YELLOW}[ACTION]{NC} {msg}")
    
    def print_debug(self, msg):
        if self.is_debug_mode():
            print(f"{BLUE}[DEBUG]{NC} {msg}", file=sys.stderr)
    
    def command_exists(self, cmd):
        """Check if a command exists."""
        return shutil.which(cmd) is not None
    
    def is_writable(self, path):
        """Check if a file/directory is writable."""
        if os.path.isfile(path):
            return os.access(path, os.W_OK)
        elif os.path.isdir(os.path.dirname(path)):
            return os.access(os.path.dirname(path), os.W_OK)
        else:
            # Path doesn't exist, check parent directories
            parent = os.path.dirname(path)
            while not os.path.isdir(parent) and parent != '/':
                parent = os.path.dirname(parent)
            return os.access(parent, os.W_OK)
    
    def suggest_user_path(self, original_path, purpose):
        """Suggest alternative path."""
        filename = os.path.basename(original_path)
        return os.path.expanduser(f"~/.cloudflare-warp/{purpose}/{filename}")
    
    def detect_shell(self):
        """Detect the user's default shell with multiple fallbacks."""
        # Try environment variable first (current session)
        shell_path = os.environ.get('SHELL')
        
        # Fallback to pwd module (system configured default)
        if not shell_path:
            try:
                shell_path = pwd.getpwuid(os.getuid()).pw_shell
            except:
                shell_path = None
        
        # Final fallback for modern macOS
        if not shell_path:
            shell_path = '/bin/zsh'
        
        # Extract just the shell name
        shell_name = os.path.basename(shell_path)
        
        # Normalize common shells
        known_shells = {'bash', 'zsh', 'fish', 'sh', 'tcsh', 'csh', 'dash'}
        
        if shell_name in known_shells:
            return shell_name
        else:
            # Return actual name rather than 'unknown'
            return shell_name

    def get_shell_config(self, shell_type):
        """Get shell config file."""
        home = os.path.expanduser("~")
        if shell_type == 'bash':
            # For macOS, .bash_profile is the primary config file for login shells
            for config in ['.bash_profile', '.bashrc', '.profile']:
                if os.path.exists(os.path.join(home, config)):
                    return os.path.join(home, config)
            return os.path.join(home, '.profile')
        elif shell_type == 'zsh':
            return os.path.join(home, '.zshrc')
        elif shell_type == 'fish':
            return os.path.join(home, '.config/fish/config.fish')
        else:
            return os.path.join(home, '.profile')
    
    def get_cert_fingerprint(self, cert_path=None):
        """Get certificate fingerprint (cached)."""
        if cert_path is None:
            cert_path = CERT_PATH
            
        if self.cert_fingerprint and cert_path == CERT_PATH:
            return self.cert_fingerprint
            
        if os.path.exists(cert_path):
            try:
                result = subprocess.run(
                    ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    fingerprint = result.stdout.strip().split('=')[1]
                    if cert_path == CERT_PATH:
                        self.cert_fingerprint = fingerprint
                    self.print_debug(f"Cached certificate fingerprint: {fingerprint}")
                    return fingerprint
            except Exception as e:
                self.print_debug(f"Error getting fingerprint: {e}")
        return ""
    
    def certificate_likely_exists_in_file(self, cert_file, target_file):
        """Fast certificate check using grep (for status mode)."""
        if not os.path.exists(target_file) or not os.path.exists(cert_file):
            return False
        
        # Method 1: Try to match by subject CN
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert_file, '-noout', '-subject'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                # Extract CN
                subject = result.stdout.strip()
                if 'CN=' in subject:
                    cn_start = subject.find('CN=')
                    cn_end = subject.find(',', cn_start) if ',' in subject[cn_start:] else len(subject)
                    cn = subject[cn_start:cn_end]
                    
                    with open(target_file, 'r') as f:
                        if cn in f.read():
                            self.print_debug(f"Certificate likely exists in {target_file} (found matching CN: {cn})")
                            return True
        except Exception as e:
            self.print_debug(f"Error checking CN: {e}")
        
        # Method 2: Try to match certificate content
        try:
            with open(cert_file, 'r') as f:
                cert_lines = []
                in_cert = False
                for line in f:
                    if '-----BEGIN CERTIFICATE-----' in line:
                        in_cert = True
                    elif '-----END CERTIFICATE-----' in line:
                        in_cert = False
                    elif in_cert:
                        cert_lines.append(line.strip())
                
                if cert_lines:
                    # Get first 100 chars of cert content
                    cert_content = ''.join(cert_lines)[:100]
                    
                    with open(target_file, 'r') as tf:
                        target_content = tf.read()
                        # Remove all whitespace for comparison
                        target_normalized = ''.join(target_content.split())
                        if cert_content.replace('\n', '').replace(' ', '') in target_normalized:
                            self.print_debug(f"Certificate likely exists in {target_file} (found matching content)")
                            return True
        except Exception as e:
            self.print_debug(f"Error checking content: {e}")
        
        return False
    
    def certificate_exists_in_file(self, cert_file, target_file):
        """Check if a certificate already exists in a file (thorough check for install mode)."""
        if not os.path.exists(target_file):
            return False
        
        # In status mode, use the fast check
        if not self.is_install_mode():
            return self.certificate_likely_exists_in_file(cert_file, target_file)
        
        # Get cached fingerprint
        cert_fingerprint = self.get_cert_fingerprint(cert_file)
        if not cert_fingerprint:
            return False
        
        # For install mode, do the thorough check
        try:
            with open(target_file, 'r') as f:
                content = f.read()
                
            # Split content into certificates
            certs = []
            current_cert = []
            in_cert = False
            
            for line in content.splitlines():
                if '-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    current_cert = [line]
                elif '-----END CERTIFICATE-----' in line:
                    current_cert.append(line)
                    if in_cert:
                        certs.append('\n'.join(current_cert))
                    in_cert = False
                    current_cert = []
                elif in_cert:
                    current_cert.append(line)
            
            # Check each certificate
            for cert in certs:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                    tf.write(cert)
                    tf.flush()
                    
                    file_fingerprint = self.get_cert_fingerprint(tf.name)
                    os.unlink(tf.name)
                    
                    if file_fingerprint == cert_fingerprint:
                        return True
        except Exception as e:
            self.print_debug(f"Error checking certificate existence: {e}")
        
        return False
    
    def add_to_shell_config(self, var_name, var_value, shell_config):
        """Add export to shell config."""
        # Check if the export already exists
        if os.path.exists(shell_config):
            with open(shell_config, 'r') as f:
                content = f.read()
                
            if f"export {var_name}=" in content:
                self.print_warn(f"{var_name} already exists in {shell_config}")
                # Find current value
                for line in content.splitlines():
                    if line.strip().startswith(f"export {var_name}="):
                        self.print_info(f"Current value: {line.strip()}")
                        break
                
                if not self.is_install_mode():
                    self.print_action(f"Would ask to update {var_name} in {shell_config}")
                    self.print_action(f"Would set: export {var_name}=\"{var_value}\"")
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() == 'y':
                        # Comment out old entries
                        lines = content.splitlines()
                        new_lines = []
                        for line in lines:
                            if line.strip().startswith(f"export {var_name}="):
                                new_lines.append(f"#{line}")
                            else:
                                new_lines.append(line)
                        
                        # Add new entry
                        new_lines.append(f'export {var_name}="{var_value}"')
                        
                        # Write back
                        with open(shell_config + '.bak', 'w') as f:
                            f.write(content)
                        with open(shell_config, 'w') as f:
                            f.write('\n'.join(new_lines) + '\n')
                        
                        self.shell_modified = True
                        self.print_info(f"Updated {var_name} in {shell_config}")
                return
        
        # Variable doesn't exist, add it
        if not self.is_install_mode():
            self.print_action(f"Would add to {shell_config}:")
            self.print_action(f'export {var_name}="{var_value}"')
        else:
            with open(shell_config, 'a') as f:
                f.write(f'\nexport {var_name}="{var_value}"\n')
            self.shell_modified = True
            self.print_info(f"Added {var_name} to {shell_config}")
    
    def download_certificate(self):
        """Download and verify certificate."""
        self.print_info("Retrieving Cloudflare WARP certificate...")
        
        # Check if warp-cli is available
        if not self.command_exists('warp-cli'):
            self.print_error("warp-cli command not found. Please ensure Cloudflare WARP is installed.")
            return False
        
        # Get current certificate from warp-cli
        try:
            result = subprocess.run(
                ['warp-cli', 'certs', '--no-paginate'],
                capture_output=True, text=True
            )
            
            if result.returncode != 0 or not result.stdout.strip():
                self.print_error("Failed to get certificate from warp-cli")
                self.print_error("Make sure you are connected to Cloudflare WARP")
                return False
            
            warp_cert = result.stdout.strip()
        except Exception as e:
            self.print_error(f"Error running warp-cli: {e}")
            return False
        
        # Create a temp file for the WARP certificate
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
            temp_cert.write(warp_cert)
            temp_cert_path = temp_cert.name
        
        # Verify it's a valid PEM certificate
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-in', temp_cert_path],
                capture_output=True
            )
            if result.returncode != 0:
                self.print_error("Retrieved file is not a valid PEM certificate")
                os.unlink(temp_cert_path)
                return False
        except Exception as e:
            self.print_error(f"Error verifying certificate: {e}")
            os.unlink(temp_cert_path)
            return False
        
        self.print_info("WARP certificate retrieved successfully")
        
        # Check if certificate needs to be saved to CERT_PATH
        needs_save = False
        if os.path.exists(CERT_PATH):
            # Check if existing cert matches WARP cert
            with open(CERT_PATH, 'r') as f:
                existing_cert = f.read()
            
            if existing_cert != warp_cert:
                self.print_info(f"Certificate at {CERT_PATH} needs updating")
                needs_save = True
            else:
                self.print_info(f"Certificate at {CERT_PATH} is up to date")
        else:
            self.print_info(f"Certificate will be saved to {CERT_PATH}")
            needs_save = True
        
        # Save certificate if needed
        if needs_save:
            if not self.is_install_mode():
                self.print_action(f"Would save certificate to {CERT_PATH}")
            else:
                # Save certificate
                shutil.copy(temp_cert_path, CERT_PATH)
                self.print_info(f"Certificate saved to {CERT_PATH}")
        
        # Clean up
        os.unlink(temp_cert_path)
        
        # Cache the fingerprint for later use
        self.get_cert_fingerprint()
        
        return True
    
    def setup_node_cert(self):
        """Setup Node.js certificate."""
        if not self.command_exists('node'):
            return
        
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        needs_setup = False
        
        node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
        
        if node_extra_ca_certs:
            if os.path.exists(node_extra_ca_certs):
                # Check if the file contains our certificate
                with open(CERT_PATH, 'r') as f:
                    cert_content = f.read()
                
                with open(node_extra_ca_certs, 'r') as f:
                    file_content = f.read()
                
                if cert_content in file_content:
                    # Certificate already exists, nothing to do
                    return
                else:
                    needs_setup = True
                    self.print_info("Setting up Node.js certificate...")
                    self.print_info(f"NODE_EXTRA_CA_CERTS is already set to: {node_extra_ca_certs}")
                    
                    # Check if we can write to the file
                    if not self.is_writable(node_extra_ca_certs):
                        self.print_error(f"Cannot write to {node_extra_ca_certs} (permission denied)")
                        new_path = self.suggest_user_path(node_extra_ca_certs, "node")
                        self.print_warn(f"Suggesting alternative path: {new_path}")
                        
                        if not self.is_install_mode():
                            self.print_action(f"Would create directory: {os.path.dirname(new_path)}")
                            self.print_action(f"Would copy {node_extra_ca_certs} to {new_path}")
                            self.print_action(f"Would append Cloudflare certificate to {new_path}")
                            self.print_action(f"Would update NODE_EXTRA_CA_CERTS to point to {new_path}")
                        else:
                            response = input("Do you want to use this alternative path? (Y/n) ")
                            if response.lower() != 'n':
                                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                                if os.path.exists(node_extra_ca_certs):
                                    try:
                                        shutil.copy(node_extra_ca_certs, new_path)
                                    except:
                                        Path(new_path).touch()
                                
                                if not self.certificate_exists_in_file(CERT_PATH, new_path):
                                    with open(new_path, 'a') as f:
                                        f.write(cert_content)
                                
                                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", new_path, shell_config)
                                self.print_info(f"Created new certificate bundle at {new_path}")
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would append Cloudflare certificate to {node_extra_ca_certs}")
                        else:
                            self.print_info(f"Appending Cloudflare certificate to {node_extra_ca_certs}")
                            if not self.certificate_exists_in_file(CERT_PATH, node_extra_ca_certs):
                                with open(node_extra_ca_certs, 'a') as f:
                                    f.write(cert_content)
                            else:
                                self.print_info(f"Certificate already exists in {node_extra_ca_certs}")
            else:
                needs_setup = True
                self.print_info("Setting up Node.js certificate...")
                self.print_warn(f"NODE_EXTRA_CA_CERTS points to a non-existent file: {node_extra_ca_certs}")
                self.print_warn("Please fix this manually")
        else:
            needs_setup = True
            self.print_info("Setting up Node.js certificate...")
            # NODE_EXTRA_CA_CERTS not set, create a new bundle
            node_bundle = os.path.expanduser("~/.cloudflare-warp/node/ca-bundle.pem")
            
            if not self.is_install_mode():
                self.print_action(f"Would create Node.js CA bundle at {node_bundle}")
                self.print_action("Would include Cloudflare certificate in the bundle")
                self.print_action(f"Would set NODE_EXTRA_CA_CERTS={node_bundle}")
            else:
                self.print_info(f"Creating Node.js CA bundle at {node_bundle}")
                os.makedirs(os.path.dirname(node_bundle), exist_ok=True)
                
                # Start with just the Cloudflare certificate
                # (NODE_EXTRA_CA_CERTS supplements system certs, doesn't replace them)
                shutil.copy(CERT_PATH, node_bundle)
                
                self.add_to_shell_config("NODE_EXTRA_CA_CERTS", node_bundle, shell_config)
                self.print_info("Created Node.js CA bundle with Cloudflare certificate")
        
        # Setup npm cafile if npm is available
        if self.command_exists('npm'):
            self.setup_npm_cafile()
    
    def setup_npm_cafile(self):
        """Setup npm cafile."""
        # Check current npm cafile setting
        try:
            result = subprocess.run(
                ['npm', 'config', 'get', 'cafile'],
                capture_output=True, text=True
            )
            current_cafile = result.stdout.strip() if result.returncode == 0 else ""
        except:
            current_cafile = ""
        
        # npm needs a full CA bundle, not just a single certificate
        npm_bundle = os.path.expanduser("~/.cloudflare-warp/npm/ca-bundle.pem")
        needs_setup = False
        
        if current_cafile and current_cafile not in ["null", "undefined"]:
            if os.path.exists(current_cafile):
                # Check if the file contains our certificate
                with open(CERT_PATH, 'r') as f:
                    cert_content = f.read()
                
                with open(current_cafile, 'r') as f:
                    file_content = f.read()
                
                if cert_content not in file_content:
                    needs_setup = True
                    self.print_info("Configuring npm certificate...")
                    self.print_warn("Current npm cafile doesn't contain Cloudflare certificate")
                    
                    # Check if we can write to the npm cafile
                    if not self.is_writable(current_cafile):
                        self.print_error(f"Cannot write to npm cafile: {current_cafile} (permission denied)")
                        self.print_warn(f"Will use alternative path: {npm_bundle}")
                        
                        if not self.is_install_mode():
                            self.print_action(f"Would create directory: {os.path.dirname(npm_bundle)}")
                            self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and Cloudflare certificate")
                            self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                        else:
                            os.makedirs(os.path.dirname(npm_bundle), exist_ok=True)
                            # Create a full bundle with system certs
                            if os.path.exists("/etc/ssl/cert.pem"):
                                shutil.copy("/etc/ssl/cert.pem", npm_bundle)
                            elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                                shutil.copy("/etc/ssl/certs/ca-certificates.crt", npm_bundle)
                            else:
                                # Copy existing bundle if available
                                if os.path.exists(current_cafile):
                                    shutil.copy(current_cafile, npm_bundle)
                                else:
                                    Path(npm_bundle).touch()
                            
                            # Check if certificate already exists in bundle
                            if not self.certificate_exists_in_file(CERT_PATH, npm_bundle):
                                with open(npm_bundle, 'a') as f:
                                    f.write(cert_content)
                            
                            subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                            self.print_info(f"Created new npm cafile at {npm_bundle}")
                    else:
                        if not self.is_install_mode():
                            self.print_action(f"Would ask to append Cloudflare certificate to {current_cafile}")
                        else:
                            response = input("Do you want to append it to the existing cafile? (y/N) ")
                            if response.lower() == 'y':
                                self.print_info(f"Appending Cloudflare certificate to {current_cafile}")
                                if not self.certificate_exists_in_file(CERT_PATH, current_cafile):
                                    with open(current_cafile, 'a') as f:
                                        f.write(cert_content)
                                else:
                                    self.print_info(f"Certificate already exists in {current_cafile}")
            else:
                needs_setup = True
                self.print_info("Configuring npm certificate...")
                self.print_warn(f"npm cafile points to non-existent file: {current_cafile}")
                
                if not self.is_install_mode():
                    self.print_action(f"Would create full CA bundle at {npm_bundle}")
                    self.print_action(f"Would run: npm config set cafile {npm_bundle}")
                else:
                    response = input("Do you want to create a new CA bundle for npm? (Y/n) ")
                    if response.lower() != 'n':
                        os.makedirs(os.path.dirname(npm_bundle), exist_ok=True)
                        # Create full bundle with system certs
                        if os.path.exists("/etc/ssl/cert.pem"):
                            shutil.copy("/etc/ssl/cert.pem", npm_bundle)
                        elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                            shutil.copy("/etc/ssl/certs/ca-certificates.crt", npm_bundle)
                        else:
                            Path(npm_bundle).touch()
                        
                        if not self.certificate_exists_in_file(CERT_PATH, npm_bundle):
                            with open(npm_bundle, 'a') as f:
                                with open(CERT_PATH, 'r') as cf:
                                    f.write(cf.read())
                        
                        subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                        self.print_info(f"Created and configured npm cafile at {npm_bundle}")
        else:
            needs_setup = True
            self.print_info("Configuring npm certificate...")
            self.print_info("npm cafile is not configured")
            
            if not self.is_install_mode():
                self.print_action(f"Would create full CA bundle at {npm_bundle} with system certificates and Cloudflare certificate")
                self.print_action(f"Would run: npm config set cafile {npm_bundle}")
            else:
                response = input("Do you want to configure npm with a CA bundle including Cloudflare certificate? (Y/n) ")
                if response.lower() != 'n':
                    os.makedirs(os.path.dirname(npm_bundle), exist_ok=True)
                    # Create full bundle with system certs
                    if os.path.exists("/etc/ssl/cert.pem"):
                        shutil.copy("/etc/ssl/cert.pem", npm_bundle)
                    elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                        shutil.copy("/etc/ssl/certs/ca-certificates.crt", npm_bundle)
                    else:
                        self.print_warn("Could not find system CA bundle, creating new bundle with only Cloudflare certificate")
                        Path(npm_bundle).touch()
                    
                    with open(npm_bundle, 'a') as f:
                        with open(CERT_PATH, 'r') as cf:
                            f.write(cf.read())
                    
                    subprocess.run(['npm', 'config', 'set', 'cafile', npm_bundle])
                    self.print_info(f"Configured npm cafile to: {npm_bundle}")
                    
                    # Verify the setting
                    try:
                        result = subprocess.run(
                            ['npm', 'config', 'get', 'cafile'],
                            capture_output=True, text=True
                        )
                        verify_cafile = result.stdout.strip()
                        if verify_cafile == npm_bundle:
                            self.print_info("npm cafile configured successfully")
                        else:
                            self.print_error("Failed to configure npm cafile")
                    except:
                        pass
    
    def setup_python_cert(self):
        """Setup Python certificate."""
        if not self.command_exists('python3') and not self.command_exists('python'):
            self.print_info("Python not found, skipping Python setup")
            return
        
        shell_type = self.detect_shell()
        shell_config = self.get_shell_config(shell_type)
        
        # Create combined certificate bundle for Python
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        needs_setup = False
        
        requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
        
        if requests_ca_bundle:
            if os.path.exists(requests_ca_bundle):
                # Check if we can write to the file
                if not self.is_writable(requests_ca_bundle):
                    self.print_error(f"Cannot write to {requests_ca_bundle} (permission denied)")
                    new_path = self.suggest_user_path(requests_ca_bundle, "python")
                    self.print_warn(f"Suggesting alternative path: {new_path}")
                    
                    if not self.is_install_mode():
                        self.print_action(f"Would create directory: {os.path.dirname(new_path)}")
                        self.print_action(f"Would copy {requests_ca_bundle} to {new_path}")
                        self.print_action(f"Would append Cloudflare certificate to {new_path}")
                        self.print_action(f"Would update REQUESTS_CA_BUNDLE to point to {new_path}")
                    else:
                        response = input("Do you want to use this alternative path? (Y/n) ")
                        if response.lower() != 'n':
                            os.makedirs(os.path.dirname(new_path), exist_ok=True)
                            if os.path.exists(requests_ca_bundle):
                                try:
                                    shutil.copy(requests_ca_bundle, new_path)
                                except:
                                    Path(new_path).touch()
                            
                            # Check if certificate already exists in the new path
                            if not self.certificate_exists_in_file(CERT_PATH, new_path):
                                with open(new_path, 'a') as f:
                                    with open(CERT_PATH, 'r') as cf:
                                        f.write(cf.read())
                            
                            needs_setup = True
                            self.print_info("Setting up Python certificate...")
                            self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                            self.add_to_shell_config("REQUESTS_CA_BUNDLE", new_path, shell_config)
                            self.add_to_shell_config("SSL_CERT_FILE", new_path, shell_config)
                            self.add_to_shell_config("CURL_CA_BUNDLE", new_path, shell_config)
                            self.print_info(f"Created new certificate bundle at {new_path}")
                else:
                    # Check if the file contains our certificate
                    with open(CERT_PATH, 'r') as f:
                        cert_content = f.read()
                    
                    with open(requests_ca_bundle, 'r') as f:
                        file_content = f.read()
                    
                    if cert_content not in file_content:
                        needs_setup = True
                        self.print_info("Setting up Python certificate...")
                        self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                        
                        if not self.is_install_mode():
                            self.print_action(f"Would append Cloudflare certificate to {requests_ca_bundle}")
                        else:
                            self.print_info(f"Appending Cloudflare certificate to {requests_ca_bundle}")
                            if not self.certificate_exists_in_file(CERT_PATH, requests_ca_bundle):
                                with open(requests_ca_bundle, 'a') as f:
                                    f.write(cert_content)
                            else:
                                self.print_info(f"Certificate already exists in {requests_ca_bundle}")
            else:
                needs_setup = True
                self.print_info("Setting up Python certificate...")
                self.print_info(f"REQUESTS_CA_BUNDLE is already set to: {requests_ca_bundle}")
                self.print_warn(f"REQUESTS_CA_BUNDLE points to a non-existent file: {requests_ca_bundle}")
        else:
            needs_setup = True
            self.print_info("Setting up Python certificate...")
            
            if not self.is_install_mode():
                self.print_action(f"Would create Python CA bundle at {python_bundle}")
                self.print_action("Would copy system certificates and append Cloudflare certificate")
            else:
                self.print_info(f"Creating Python CA bundle at {python_bundle}")
                
                # Copy system certificates
                if os.path.exists("/etc/ssl/cert.pem"):
                    shutil.copy("/etc/ssl/cert.pem", python_bundle)
                elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                    shutil.copy("/etc/ssl/certs/ca-certificates.crt", python_bundle)
                else:
                    self.print_warn("Could not find system CA bundle, creating new bundle")
                    Path(python_bundle).touch()
                
                # Append Cloudflare certificate
                # Check if certificate already exists in bundle
                if not self.certificate_exists_in_file(CERT_PATH, python_bundle):
                    with open(python_bundle, 'a') as f:
                        with open(CERT_PATH, 'r') as cf:
                            f.write(cf.read())
            
            self.add_to_shell_config("REQUESTS_CA_BUNDLE", python_bundle, shell_config)
            self.add_to_shell_config("SSL_CERT_FILE", python_bundle, shell_config)
            self.add_to_shell_config("CURL_CA_BUNDLE", python_bundle, shell_config)
    
    def setup_gcloud_cert(self):
        """Setup gcloud certificate."""
        if not self.command_exists('gcloud'):
            self.print_info("gcloud not found, skipping gcloud setup")
            return
        
        gcloud_cert_dir = os.path.expanduser("~/.config/gcloud/certs")
        gcloud_bundle = os.path.join(gcloud_cert_dir, "combined-ca-bundle.pem")
        needs_setup = False
        
        # Check current gcloud custom CA setting
        try:
            result = subprocess.run(
                ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                capture_output=True, text=True
            )
            current_ca_file = result.stdout.strip() if result.returncode == 0 else ""
        except:
            current_ca_file = ""
        
        # Check if gcloud needs configuration
        if not current_ca_file:
            needs_setup = True
        elif os.path.exists(current_ca_file):
            # Check if current CA file contains our certificate
            with open(CERT_PATH, 'r') as f:
                cert_content = f.read()
            with open(current_ca_file, 'r') as f:
                file_content = f.read()
            if cert_content not in file_content:
                needs_setup = True
        else:
            needs_setup = True
        
        if not needs_setup:
            return
        
        self.print_info("Setting up gcloud certificate...")
        
        # Create directory if it doesn't exist
        if self.is_install_mode():
            os.makedirs(gcloud_cert_dir, exist_ok=True)
        
        if current_ca_file and current_ca_file != gcloud_bundle:
            self.print_warn(f"gcloud is already configured with custom CA: {current_ca_file}")
            
            # Check if the current CA file is writable
            if os.path.exists(current_ca_file) and not self.is_writable(current_ca_file):
                self.print_error(f"Cannot write to current gcloud CA file: {current_ca_file} (permission denied)")
                self.print_warn(f"Will use alternative path: {gcloud_bundle}")
                if not self.is_install_mode():
                    self.print_action(f"Would create new gcloud CA bundle at {gcloud_bundle}")
                # Continue with the new path
            else:
                if not self.is_install_mode():
                    self.print_action("Would ask to update gcloud CA configuration")
                    return
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() != 'y':
                        return
        
        if not self.is_install_mode():
            self.print_action(f"Would create directory: {gcloud_cert_dir}")
            self.print_action(f"Would create gcloud CA bundle at {gcloud_bundle}")
            self.print_action("Would copy system certificates and append Cloudflare certificate")
            self.print_action(f"Would run: gcloud config set core/custom_ca_certs_file {gcloud_bundle}")
        else:
            # Create combined bundle
            self.print_info(f"Creating gcloud CA bundle at {gcloud_bundle}")
            
            # Copy system certificates
            if os.path.exists("/etc/ssl/cert.pem"):
                shutil.copy("/etc/ssl/cert.pem", gcloud_bundle)
            elif os.path.exists("/etc/ssl/certs/ca-certificates.crt"):
                shutil.copy("/etc/ssl/certs/ca-certificates.crt", gcloud_bundle)
            else:
                Path(gcloud_bundle).touch()
            
            # Append Cloudflare certificate
            # Check if certificate already exists in bundle
            if not self.certificate_exists_in_file(CERT_PATH, gcloud_bundle):
                with open(gcloud_bundle, 'a') as f:
                    with open(CERT_PATH, 'r') as cf:
                        f.write(cf.read())
            
            # Configure gcloud
            result = subprocess.run(
                ['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_bundle],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info("gcloud configured successfully")
                # Only run diagnostics in real mode when we actually changed settings
                if needs_setup:
                    self.print_info("Running gcloud diagnostics...")
                    subprocess.run(['gcloud', 'info', '--run-diagnostics'])
            else:
                self.print_error("Failed to configure gcloud")
    
    def setup_java_cert(self):
        """Setup Java certificate."""
        if not self.command_exists('java') and not self.command_exists('keytool'):
            return
        
        # Better error handling for finding JAVA_HOME
        java_home = os.environ.get('JAVA_HOME', '')
        if not java_home and self.command_exists('java'):
            try:
                # First try /usr/libexec/java_home on macOS
                if platform.system() == 'Darwin' and os.path.exists('/usr/libexec/java_home'):
                    result = subprocess.run(['/usr/libexec/java_home'], capture_output=True, text=True)
                    if result.returncode == 0:
                        java_home = result.stdout.strip()
                
                # Fallback to java -XshowSettings
                if not java_home:
                    result = subprocess.run(
                        ['java', '-XshowSettings:properties', '-version'],
                        capture_output=True, text=True, stderr=subprocess.STDOUT
                    )
                    for line in result.stdout.splitlines():
                        if 'java.home' in line:
                            java_home = line.split('=')[1].strip()
                            break
            except Exception as e:
                self.print_debug(f"Error finding JAVA_HOME: {e}")

        if not java_home:
            self.print_warn("Could not determine JAVA_HOME")
            return
        
        cacerts = os.path.join(java_home, "lib/security/cacerts")
        if not os.path.exists(cacerts):
            cacerts = os.path.join(java_home, "jre/lib/security/cacerts")
        
        if not os.path.exists(cacerts):
            self.print_error("Could not find Java cacerts file")
            return
        
        # Check if certificate already exists
        try:
            result = subprocess.run(
                ['keytool', '-list', '-alias', 'cloudflare-zerotrust', '-cacerts', '-storepass', 'changeit'],
                capture_output=True
            )
            if result.returncode == 0 and 'cloudflare-zerotrust' in result.stdout.decode():
                # Certificate already exists, nothing to do
                return
        except:
            pass
        
        self.print_info("Setting up Java certificate...")
        self.print_info(f"Adding certificate to Java keystore: {cacerts}")
        
        if not self.is_install_mode():
            self.print_action(f"Would import certificate to Java keystore: {cacerts}")
            self.print_action(f"Would run: keytool -import -trustcacerts -alias cloudflare-zerotrust -file {CERT_PATH} -cacerts -storepass changeit -noprompt")
        else:
            result = subprocess.run(
                ['keytool', '-import', '-trustcacerts', '-alias', 'cloudflare-zerotrust', 
                 '-file', CERT_PATH, '-cacerts', '-storepass', 'changeit', '-noprompt'],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info("Certificate added to Java keystore successfully")
            else:
                self.print_warn("Failed to add certificate to Java keystore (may require sudo)")
    
    def setup_dbeaver_cert(self):
        """Setup DBeaver certificate."""
        dbeaver_keytool = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/bin/keytool"
        dbeaver_cacerts = "/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
        
        # Check if DBeaver is installed at the default location
        if not os.path.exists(dbeaver_keytool):
            return
        
        # Check if the cacerts file exists
        if not os.path.exists(dbeaver_cacerts):
            self.print_error(f"DBeaver cacerts file not found at: {dbeaver_cacerts}")
            return
        
        # Check if certificate already exists
        try:
            result = subprocess.run(
                [dbeaver_keytool, '-list', '-alias', 'cloudflare-zerotrust', 
                 '-keystore', dbeaver_cacerts, '-storepass', 'changeit'],
                capture_output=True
            )
            if result.returncode == 0 and 'cloudflare-zerotrust' in result.stdout.decode():
                # Certificate already exists, nothing to do
                return
        except:
            pass
        
        self.print_info("Setting up DBeaver certificate...")
        self.print_info("Found DBeaver at default install location")
        
        if not self.is_install_mode():
            self.print_action(f"Would import certificate to DBeaver keystore: {dbeaver_cacerts}")
            self.print_action(f"Would run: {dbeaver_keytool} -import -trustcacerts -alias cloudflare-zerotrust -file {CERT_PATH} -keystore {dbeaver_cacerts} -storepass changeit -noprompt")
        else:
            self.print_info("Adding certificate to DBeaver keystore...")
            result = subprocess.run(
                [dbeaver_keytool, '-import', '-trustcacerts', '-alias', 'cloudflare-zerotrust',
                 '-file', CERT_PATH, '-keystore', dbeaver_cacerts, '-storepass', 'changeit', '-noprompt'],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info("Certificate added to DBeaver keystore successfully")
            else:
                self.print_warn("Failed to add certificate to DBeaver keystore (may require sudo)")
                self.print_warn("You may need to run: sudo ./fuwarp.py --fix")
    
    def setup_wget_cert(self):
        """Setup wget certificate."""
        if not self.command_exists('wget'):
            return
        
        wgetrc_path = os.path.expanduser("~/.wgetrc")
        config_line = f"ca_certificate={CERT_PATH}"
        
        if os.path.exists(wgetrc_path):
            with open(wgetrc_path, 'r') as f:
                content = f.read()
            
            if "ca_certificate=" in content:
                # Check if it's already set to our certificate
                if CERT_PATH in content:
                    return
                
                self.print_info("Setting up wget certificate...")
                self.print_warn(f"wget ca_certificate is already set in {wgetrc_path}")
                
                # Find current setting
                for line in content.splitlines():
                    if line.strip().startswith("ca_certificate="):
                        self.print_info(f"Current setting: {line.strip()}")
                        break
                
                if not self.is_install_mode():
                    self.print_action(f"Would ask to update the ca_certificate in {wgetrc_path}")
                    self.print_action(f"Would set: {config_line}")
                else:
                    response = input("Do you want to update it? (y/N) ")
                    if response.lower() == 'y':
                        # Comment out old entries
                        lines = content.splitlines()
                        new_lines = []
                        for line in lines:
                            if line.strip().startswith("ca_certificate="):
                                new_lines.append(f"#{line}")
                            else:
                                new_lines.append(line)
                        
                        # Add new entry
                        new_lines.append(config_line)
                        
                        # Write back
                        with open(wgetrc_path + '.bak', 'w') as f:
                            f.write(content)
                        with open(wgetrc_path, 'w') as f:
                            f.write('\n'.join(new_lines) + '\n')
                        
                        self.print_info(f"Updated wget configuration in {wgetrc_path}")
                return
        
        # File doesn't exist or doesn't have ca_certificate
        self.print_info("Setting up wget certificate...")
        
        if not self.is_install_mode():
            self.print_action(f"Would add to {wgetrc_path}: {config_line}")
        else:
            self.print_info(f"Adding configuration to {wgetrc_path}")
            with open(wgetrc_path, 'a') as f:
                f.write(f"\n{config_line}\n")
            self.print_info("Added ca_certificate to wget configuration")
    
    def setup_podman_cert(self):
        """Setup Podman certificate."""
        if not self.command_exists('podman'):
            return
        
        self.print_info("Setting up Podman certificate...")
        
        # Check if podman machine exists
        try:
            result = subprocess.run(['podman', 'machine', 'list'], capture_output=True, text=True)
            if 'Currently running' not in result.stdout:
                self.print_warn("No Podman machine is currently running")
                self.print_info("Please start a Podman machine first with: podman machine start")
                return
        except:
            return
        
        if not self.is_install_mode():
            self.print_action("Would copy certificate to Podman VM")
            self.print_action(f"Would run: podman machine ssh 'sudo tee /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem' < {CERT_PATH}")
            self.print_action("Would run: podman machine ssh 'sudo update-ca-trust'")
        else:
            self.print_info("Copying certificate to Podman VM...")
            
            # Copy certificate into Podman VM
            with open(CERT_PATH, 'r') as f:
                cert_content = f.read()
            
            result = subprocess.run(
                ['podman', 'machine', 'ssh', 'sudo tee /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem'],
                input=cert_content, text=True, capture_output=True
            )
            
            if result.returncode == 0:
                # Update CA trust
                result = subprocess.run(
                    ['podman', 'machine', 'ssh', 'sudo update-ca-trust'],
                    capture_output=True
                )
                if result.returncode == 0:
                    self.print_info("Podman certificate installed successfully")
                else:
                    self.print_error("Failed to update CA trust in Podman VM")
            else:
                self.print_error("Failed to copy certificate to Podman VM")
    
    def setup_rancher_cert(self):
        """Setup Rancher certificate."""
        if not self.command_exists('rdctl'):
            return
        
        self.print_info("Setting up Rancher certificate...")
        
        if not self.is_install_mode():
            self.print_action("Would copy certificate to Rancher VM")
            self.print_action(f"Would run: rdctl shell sudo tee /usr/local/share/ca-certificates/cloudflare-warp.pem < {CERT_PATH}")
            self.print_action("Would run: rdctl shell sudo update-ca-certificates")
        else:
            self.print_info("Copying certificate to Rancher VM...")
            
            # Copy certificate into Rancher VM
            with open(CERT_PATH, 'r') as f:
                cert_content = f.read()
            
            result = subprocess.run(
                ['rdctl', 'shell', 'sudo tee /usr/local/share/ca-certificates/cloudflare-warp.pem'],
                input=cert_content, text=True, capture_output=True
            )
            
            if result.returncode == 0:
                # Update CA certificates
                result = subprocess.run(
                    ['rdctl', 'shell', 'sudo update-ca-certificates'],
                    capture_output=True
                )
                if result.returncode == 0:
                    self.print_info("Rancher certificate installed successfully")
                else:
                    self.print_error("Failed to update CA certificates in Rancher VM")
            else:
                self.print_error("Failed to copy certificate to Rancher VM")
    
    def setup_android_emulator_cert(self):
        """Setup Android Emulator certificate."""
        if not self.command_exists('adb') or not self.command_exists('emulator'):
            self.print_info("Android SDK tools not found, skipping Android Emulator setup")
            return
        
        self.print_info("Checking for Android Emulator setup...")
        
        # Check if any emulator is running
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            running_devices = sum(1 for line in result.stdout.splitlines() if 'emulator-' in line)
            
            if running_devices == 0:
                self.print_info("No Android emulator is currently running")
                self.print_info("Please start an emulator with: emulator -avd <your_avd_id> -writable-system -selinux permissive")
                return
        except:
            return
        
        self.print_warn("Android Emulator certificate installation requires a writable system partition")
        self.print_warn("Make sure your emulator was started with -writable-system flag")
        
        if not self.is_install_mode():
            self.print_action("Would restart ADB with root permissions: adb root")
            self.print_action("Would remount system partition: adb remount")
            self.print_action(f"Would push certificate to emulator: adb push {CERT_PATH} /system/etc/security/cacerts/cloudflare-warp.pem")
            self.print_action("Would set permissions: adb shell chmod 644 /system/etc/security/cacerts/cloudflare-warp.pem")
            self.print_action("Would reboot emulator: adb reboot")
        else:
            response = input("Do you want to install the certificate on the running Android emulator? (y/N) ")
            if response.lower() == 'y':
                self.print_info("Installing certificate on Android emulator...")
                
                # Restart ADB with root
                result = subprocess.run(['adb', 'root'], capture_output=True)
                if result.returncode != 0:
                    self.print_error("Failed to restart ADB with root permissions")
                    self.print_info("Make sure your emulator doesn't have Google Play Store")
                    return
                
                # Remount system partition
                result = subprocess.run(['adb', 'remount'], capture_output=True)
                if result.returncode != 0:
                    self.print_error("Failed to remount system partition")
                    self.print_info("Make sure emulator was started with -writable-system flag")
                    return
                
                # Push certificate
                result = subprocess.run(
                    ['adb', 'push', CERT_PATH, '/system/etc/security/cacerts/cloudflare-warp.pem'],
                    capture_output=True
                )
                if result.returncode == 0:
                    # Set permissions
                    subprocess.run(
                        ['adb', 'shell', 'chmod', '644', '/system/etc/security/cacerts/cloudflare-warp.pem'],
                        capture_output=True
                    )
                    self.print_info("Certificate installed. Rebooting emulator...")
                    subprocess.run(['adb', 'reboot'], capture_output=True)
                    self.print_info("Android emulator certificate installed successfully")
                else:
                    self.print_error("Failed to push certificate to emulator")
    
    def setup_colima_cert(self):
        """Setup Colima certificate."""
        if not self.command_exists('colima'):
            return
        
        self.print_info("Setting up Colima certificate...")
        
        # Check if colima machine is running
        try:
            result = subprocess.run(['colima', 'status'], capture_output=True, text=True)
            # Colima outputs status to stderr, not stdout
            status_output = result.stdout + result.stderr
            if 'running' not in status_output.lower():
                self.print_warn("No Colima machine is currently running")
                self.print_info("Please start a Colima machine first with: colima start")
                return
        except:
            return
        
        if not self.is_install_mode():
            self.print_action("Would copy certificate to Colima VM")
            self.print_action(f"Would run: colima ssh -- sudo tee /usr/local/share/ca-certificates/cloudflare-warp.crt < {CERT_PATH}")
            self.print_action("Would run: colima ssh -- sudo update-ca-certificates")
            self.print_action("Would run: colima ssh -- sudo systemctl restart docker")
        else:
            self.print_info("Copying certificate to Colima VM...")
            
            # Copy certificate into Colima VM
            with open(CERT_PATH, 'r') as f:
                cert_content = f.read()
            
            result = subprocess.run(
                ['colima', 'ssh', '--', 'sudo', 'tee', '/usr/local/share/ca-certificates/cloudflare-warp.crt'],
                input=cert_content, text=True, capture_output=True
            )
            
            if result.returncode == 0:
                # Update CA certificates
                result = subprocess.run(
                    ['colima', 'ssh', '--', 'sudo', 'update-ca-certificates'],
                    capture_output=True
                )
                if result.returncode == 0:
                    self.print_info("Certificate installed. Restarting Docker daemon...")
                    # Restart Docker daemon to pick up new certificates
                    result = subprocess.run(
                        ['colima', 'ssh', '--', 'sudo', 'systemctl', 'restart', 'docker'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("Colima certificate installed successfully and Docker daemon restarted")
                    else:
                        self.print_warn("Certificate installed but failed to restart Docker daemon")
                        self.print_info("You may need to manually restart Docker with: colima ssh -- sudo systemctl restart docker")
                else:
                    self.print_error("Failed to update CA certificates in Colima VM")
            else:
                self.print_error("Failed to copy certificate to Colima VM")
    
    def verify_connection(self, tool_name):
        """Verify if a tool can connect through WARP."""
        test_url = "https://www.cloudflare.com"
        result = "UNKNOWN"
        
        self.print_debug(f"Testing {tool_name} connection to {test_url}")
        
        if tool_name == "node":
            if self.command_exists('node'):
                self.print_debug(f"Node.js found at: {shutil.which('node')}")
                self.print_debug(f"NODE_EXTRA_CA_CERTS: {os.environ.get('NODE_EXTRA_CA_CERTS', 'not set')}")
                
                # Test SSL connection
                node_script = f"""
const https = require('https');
https.get('{test_url}', {{headers: {{'User-Agent': 'Mozilla/5.0'}}}}, (res) => {{
    console.error('HTTP Status:', res.statusCode);
    console.error('SSL authorized:', res.socket.authorized);
    // Any HTTP response is OK - we're testing SSL
    process.exit(0);
}}).on('error', (err) => {{
    console.error('Error:', err.message);
    console.error('Error code:', err.code);
    // Only exit with error for SSL issues
    process.exit(err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'CERT_HAS_EXPIRED' ? 1 : 0);
}});
"""
                
                try:
                    proc_result = subprocess.run(
                        ['node', '-e', node_script],
                        capture_output=True, text=True
                    )
                    
                    if proc_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("Node.js test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug("Node.js test failed")
                    
                    if self.is_debug_mode() and proc_result.stderr:
                        self.print_debug(f"Node.js output: {proc_result.stderr}")
                except Exception as e:
                    self.print_debug(f"Node.js test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"
        
        elif tool_name == "python":
            # Check if Python trusts the system Cloudflare WARP certificate
            self.print_info("Checking if Python trusts system Cloudflare WARP certificate...")
            
            try:
                # Create a simple HTTPS request
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                
                # Try to open the URL
                with urllib.request.urlopen(req, timeout=5) as response:
                    self.print_debug(f"Success - HTTP {response.code}")
                    result = "WORKING"
                    
                    # Additional validation - check SSL context
                    context = ssl.create_default_context()
                    self.print_debug(f"Python SSL default verify paths: {ssl.get_default_verify_paths()}")
                    self.print_debug("Python successfully trusts the system Cloudflare WARP certificate")
                    
            except urllib.error.HTTPError as e:
                self.print_debug(f"HTTP Error {e.code} - but SSL worked")
                # HTTP errors (like 403) are OK - we're testing SSL
                result = "WORKING"
            except urllib.error.URLError as e:
                self.print_debug(f"URL Error: {e.reason}")
                # SSL errors mean the cert isn't trusted
                result = "FAILED"
                
                # Check if REQUESTS_CA_BUNDLE or SSL_CERT_FILE would help
                if os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE'):
                    self.print_debug("Python needs environment variables set for certificate trust")
                else:
                    self.print_debug("Python does not trust the system certificate by default")
            except ssl.SSLError as e:
                self.print_debug(f"SSL Error: {e}")
                result = "FAILED"
            except Exception as e:
                self.print_debug(f"Unexpected error: {type(e).__name__}: {e}")
                result = "FAILED"
        
        elif tool_name == "curl":
            if self.command_exists('curl'):
                self.print_debug(f"curl found at: {shutil.which('curl')}")
                
                try:
                    # Check curl version for SecureTransport
                    version_result = subprocess.run(
                        ['curl', '--version'],
                        capture_output=True, text=True
                    )
                    self.print_debug(f"curl version: {version_result.stdout.splitlines()[0]}")
                    
                    # Test connection
                    if self.is_debug_mode():
                        curl_result = subprocess.run(
                            ['curl', '-v', '-s', '-o', '/dev/null', test_url],
                            capture_output=True, text=True
                        )
                    else:
                        curl_result = subprocess.run(
                            ['curl', '-s', '-o', '/dev/null', test_url],
                            capture_output=True
                        )
                    
                    if curl_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("curl test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"curl test failed with exit code: {curl_result.returncode}")
                    
                    if self.is_debug_mode() and curl_result.stderr:
                        # Show relevant SSL info
                        for line in curl_result.stderr.splitlines():
                            if any(keyword in line for keyword in ['SSL', 'certificate', 'TLS']):
                                self.print_debug(f"curl: {line}")
                except Exception as e:
                    self.print_debug(f"curl test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"
        
        elif tool_name == "wget":
            if self.command_exists('wget'):
                self.print_debug(f"wget found at: {shutil.which('wget')}")
                self.print_debug(f"wget config: {os.path.expanduser('~/.wgetrc')}")
                
                try:
                    if self.is_debug_mode():
                        wget_result = subprocess.run(
                            ['wget', '--debug', '-O', '/dev/null', test_url],
                            capture_output=True, text=True
                        )
                    else:
                        wget_result = subprocess.run(
                            ['wget', '-q', '-O', '/dev/null', test_url],
                            capture_output=True
                        )
                    
                    if wget_result.returncode == 0:
                        result = "WORKING"
                        self.print_debug("wget test succeeded")
                    else:
                        result = "FAILED"
                        self.print_debug(f"wget test failed with exit code: {wget_result.returncode}")
                    
                    if self.is_debug_mode() and wget_result.stderr:
                        # Show relevant SSL info
                        for line in wget_result.stderr.splitlines():
                            if any(keyword in line for keyword in ['SSL', 'certificate', 'CA']):
                                self.print_debug(f"wget: {line}")
                except Exception as e:
                    self.print_debug(f"wget test error: {e}")
                    result = "FAILED"
            else:
                result = "NOT_INSTALLED"
        
        self.print_debug(f"Test result for {tool_name}: {result}")
        return result
    
    def check_node_status(self, temp_warp_cert):
        """Check Node.js configuration status."""
        has_issues = False
        if self.command_exists('node'):
            node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
            if node_extra_ca_certs:
                self.print_info(f"  NODE_EXTRA_CA_CERTS is set to: {node_extra_ca_certs}")
                if os.path.exists(node_extra_ca_certs):
                    if self.certificate_exists_in_file(temp_warp_cert, node_extra_ca_certs):
                        self.print_info("  ✓ NODE_EXTRA_CA_CERTS contains current WARP certificate")
                        verify_result = self.verify_connection("node")
                        if verify_result == "WORKING":
                            self.print_info("  ✓ Node.js can connect through WARP")
                        else:
                            self.print_warn("  ✗ Node.js connection test failed")
                            has_issues = True
                    else:
                        self.print_warn("  ✗ NODE_EXTRA_CA_CERTS file exists but doesn't contain current WARP certificate")
                        self.print_action("    Run with --fix to append the certificate to this file")
                        has_issues = True
                else:
                    self.print_warn(f"  ✗ NODE_EXTRA_CA_CERTS points to non-existent file: {node_extra_ca_certs}")
                    has_issues = True
            else:
                self.print_warn("  ✗ NODE_EXTRA_CA_CERTS not configured")
                has_issues = True
            
            # Check npm
            if self.command_exists('npm'):
                try:
                    result = subprocess.run(['npm', 'config', 'get', 'cafile'], capture_output=True, text=True)
                    npm_cafile = result.stdout.strip() if result.returncode == 0 else ""
                    
                    if npm_cafile and npm_cafile not in ["null", "undefined"]:
                        if os.path.exists(npm_cafile):
                            if self.certificate_exists_in_file(temp_warp_cert, npm_cafile):
                                self.print_info("  ✓ npm cafile contains current WARP certificate")
                            else:
                                self.print_warn("  ✗ npm cafile doesn't contain current WARP certificate")
                                has_issues = True
                        else:
                            self.print_warn("  ✗ npm cafile points to non-existent file")
                            has_issues = True
                    else:
                        self.print_warn("  ✗ npm cafile not configured")
                        has_issues = True
                except:
                    pass
        else:
            self.print_info("  - Node.js not installed")
        return has_issues

    def check_python_status(self, temp_warp_cert):
        """Check Python configuration status."""
        has_issues = False
        if self.command_exists('python3') or self.command_exists('python'):
            # First check if Python trusts the system certificate
            python_verify_result = self.verify_connection("python")
            
            if python_verify_result == "WORKING":
                self.print_info("  ✓ Python trusts the system Cloudflare WARP certificate")
                self.print_info("  ✓ Python can connect through WARP without additional configuration")
            else:
                # Python doesn't trust system cert, check environment variables
                python_configured = False
                
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if requests_ca_bundle:
                    self.print_info(f"  REQUESTS_CA_BUNDLE is set to: {requests_ca_bundle}")
                    if os.path.exists(requests_ca_bundle):
                        if self.certificate_exists_in_file(temp_warp_cert, requests_ca_bundle):
                            self.print_info("  ✓ REQUESTS_CA_BUNDLE contains current WARP certificate")
                            python_configured = True
                        else:
                            self.print_warn("  ✗ REQUESTS_CA_BUNDLE file exists but doesn't contain current WARP certificate")
                            self.print_action("    Run with --fix to create a new bundle with both certificates")
                    else:
                        self.print_warn(f"  ✗ REQUESTS_CA_BUNDLE points to non-existent file: {requests_ca_bundle}")
                
                # Also check SSL_CERT_FILE if set
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if ssl_cert_file:
                    self.print_info(f"  SSL_CERT_FILE is set to: {ssl_cert_file}")
                    if os.path.exists(ssl_cert_file):
                        if self.certificate_exists_in_file(temp_warp_cert, ssl_cert_file):
                            self.print_info("  ✓ SSL_CERT_FILE contains current WARP certificate")
                            python_configured = True
                
                if not python_configured:
                    if not requests_ca_bundle and not ssl_cert_file:
                        self.print_warn("  ✗ Python does not trust system certificate by default")
                        self.print_warn("  ✗ No Python certificate environment variables configured")
                        has_issues = True
                    else:
                        has_issues = True
        else:
            self.print_info("  - Python not installed")
        return has_issues

    def check_gcloud_status(self, temp_warp_cert):
        """Check gcloud configuration status."""
        has_issues = False
        if self.command_exists('gcloud'):
            try:
                result = subprocess.run(
                    ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file'],
                    capture_output=True, text=True
                )
                gcloud_ca = result.stdout.strip() if result.returncode == 0 else ""
                
                if gcloud_ca and os.path.exists(gcloud_ca):
                    if self.certificate_exists_in_file(temp_warp_cert, gcloud_ca):
                        self.print_info("  ✓ gcloud configured with current WARP certificate")
                    else:
                        self.print_warn("  ✗ gcloud CA file doesn't contain current WARP certificate")
                        has_issues = True
                else:
                    self.print_warn("  ✗ gcloud not configured with custom CA")
                    has_issues = True
            except:
                self.print_warn("  ✗ Failed to check gcloud configuration")
                has_issues = True
        else:
            self.print_info("  - gcloud not installed (would configure if present)")
        return has_issues

    def check_java_status(self, temp_warp_cert):
        """Check Java configuration status."""
        has_issues = False
        if self.command_exists('java') or self.command_exists('keytool'):
            if self.command_exists('keytool'):
                try:
                    result = subprocess.run(
                        ['keytool', '-list', '-alias', 'cloudflare-zerotrust', '-cacerts', '-storepass', 'changeit'],
                        capture_output=True
                    )
                    if result.returncode == 0 and 'cloudflare-zerotrust' in result.stdout.decode():
                        self.print_info("  ✓ Java keystore contains Cloudflare certificate")
                    else:
                        self.print_warn("  ✗ Java keystore missing Cloudflare certificate")
                        has_issues = True
                except:
                    self.print_warn("  ✗ Failed to check Java keystore")
                    has_issues = True
            else:
                self.print_warn("  ✗ keytool not found")
                has_issues = True
        else:
            self.print_info("  - Java not installed (would configure if present)")
        return has_issues

    def check_dbeaver_status(self, temp_warp_cert):
        """Check DBeaver configuration status."""
        has_issues = False
        dbeaver_app = "/Applications/DBeaver.app"
        if os.path.exists(dbeaver_app):
            dbeaver_keytool = f"{dbeaver_app}/Contents/Eclipse/jre/Contents/Home/bin/keytool"
            dbeaver_cacerts = f"{dbeaver_app}/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
            if os.path.exists(dbeaver_keytool) and os.path.exists(dbeaver_cacerts):
                try:
                    result = subprocess.run(
                        [dbeaver_keytool, '-list', '-alias', 'cloudflare-zerotrust',
                         '-keystore', dbeaver_cacerts, '-storepass', 'changeit'],
                        capture_output=True
                    )
                    if result.returncode == 0 and 'cloudflare-zerotrust' in result.stdout.decode():
                        self.print_info("  ✓ DBeaver keystore contains Cloudflare certificate")
                    else:
                        self.print_warn("  ✗ DBeaver keystore missing Cloudflare certificate")
                        has_issues = True
                except:
                    self.print_warn("  ✗ Failed to check DBeaver keystore")
                    has_issues = True
            else:
                self.print_warn("  ✗ DBeaver JRE not found at expected location")
        else:
            self.print_info("  - DBeaver not installed at /Applications/DBeaver.app")
        return has_issues

    def check_wget_status(self, temp_warp_cert):
        """Check wget configuration status."""
        has_issues = False
        if self.command_exists('wget'):
            wgetrc_path = os.path.expanduser("~/.wgetrc")
            if os.path.exists(wgetrc_path):
                with open(wgetrc_path, 'r') as f:
                    content = f.read()
                if "ca_certificate=" in content and CERT_PATH in content:
                    self.print_info("  ✓ wget configured with Cloudflare certificate")
                    verify_result = self.verify_connection("wget")
                    if verify_result == "WORKING":
                        self.print_info("  ✓ wget can connect through WARP")
                    else:
                        self.print_warn("  ✗ wget connection test failed")
                        has_issues = True
                else:
                    self.print_warn("  ✗ wget not configured with Cloudflare certificate")
                    has_issues = True
            else:
                self.print_warn("  ✗ wget not configured")
                has_issues = True
        else:
            self.print_info("  - wget not installed")
        return has_issues

    def check_podman_status(self, temp_warp_cert):
        """Check Podman configuration status."""
        has_issues = False
        if self.command_exists('podman'):
            try:
                result = subprocess.run(['podman', 'machine', 'list'], capture_output=True, text=True)
                if 'Currently running' in result.stdout:
                    # Check if certificate exists in Podman VM
                    result = subprocess.run(
                        ['podman', 'machine', 'ssh', 'test -f /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("  ✓ Podman VM has Cloudflare certificate installed")
                    else:
                        self.print_warn("  ✗ Podman VM missing Cloudflare certificate")
                        has_issues = True
                else:
                    self.print_info("  - Podman installed but no machine is running")
                    self.print_info("    Start a machine with: podman machine start")
            except:
                self.print_info("  - Failed to check Podman status")
        else:
            self.print_info("  - Podman not installed (would configure VM if present)")
        return has_issues

    def check_rancher_status(self, temp_warp_cert):
        """Check Rancher Desktop configuration status."""
        has_issues = False
        if self.command_exists('rdctl'):
            try:
                # Try to check if Rancher is running
                result = subprocess.run(['rdctl', 'version'], capture_output=True, text=True)
                if 'rdctl' in result.stdout:
                    # Check if certificate exists in Rancher VM
                    result = subprocess.run(
                        ['rdctl', 'shell', 'test -f /usr/local/share/ca-certificates/cloudflare-warp.pem'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("  ✓ Rancher Desktop VM has Cloudflare certificate installed")
                    else:
                        self.print_warn("  ✗ Rancher Desktop VM missing Cloudflare certificate")
                        has_issues = True
                else:
                    self.print_info("  - Rancher Desktop installed but not running")
            except:
                self.print_info("  - Rancher Desktop installed but not running")
        else:
            self.print_info("  - Rancher Desktop not installed (would configure if present)")
        return has_issues

    def check_android_status(self, temp_warp_cert):
        """Check Android Emulator configuration status."""
        has_issues = False
        if self.command_exists('adb') and self.command_exists('emulator'):
            try:
                result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
                running_emulators = sum(1 for line in result.stdout.splitlines() if 'emulator-' in line)
                if running_emulators > 0:
                    self.print_info("  - Android emulator detected (manual installation available)")
                    self.print_info("    Run with --fix to see installation instructions")
                else:
                    self.print_info("  - Android SDK detected but no emulator running")
            except:
                self.print_info("  - Android SDK detected")
        else:
            self.print_info("  - Android SDK not installed (would help configure if present)")
        return has_issues

    def check_colima_status(self, temp_warp_cert):
        """Check Colima configuration status."""
        has_issues = False
        if self.command_exists('colima'):
            try:
                result = subprocess.run(['colima', 'status'], capture_output=True, text=True)
                # Colima outputs status to stderr, not stdout
                status_output = result.stdout + result.stderr
                if 'running' in status_output.lower():
                    # Check if certificate exists in Colima VM
                    result = subprocess.run(
                        ['colima', 'ssh', '--', 'test', '-f', '/usr/local/share/ca-certificates/cloudflare-warp.crt'],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        self.print_info("  ✓ Colima VM has Cloudflare certificate installed")
                    else:
                        self.print_warn("  ✗ Colima VM missing Cloudflare certificate")
                        has_issues = True
                else:
                    self.print_info("  - Colima installed but no machine is running")
                    self.print_info("    Start a machine with: colima start")
            except:
                self.print_info("  - Failed to check Colima status")
        else:
            self.print_info("  - Colima not installed (would configure VM if present)")
        return has_issues

    def check_all_status(self):
        """Check status of all configurations."""
        has_issues = False
        temp_warp_cert = None
        
        self.print_info("Checking Cloudflare WARP Certificate Status")
        self.print_info("===========================================")
        print()
        
        # First, get the current WARP certificate to use for all comparisons
        if self.command_exists('warp-cli'):
            try:
                result = subprocess.run(
                    ['warp-cli', 'certs', '--no-paginate'],
                    capture_output=True, text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tf:
                        tf.write(result.stdout.strip())
                        temp_warp_cert = tf.name
                    
                    self.print_debug("Retrieved WARP certificate for comparison")
                    # Pre-cache fingerprint for the WARP cert
                    self.cert_fingerprint = self.get_cert_fingerprint(temp_warp_cert)
                    self.print_debug(f"WARP certificate fingerprint: {self.cert_fingerprint}")
                else:
                    self.print_error("Failed to retrieve WARP certificate")
                    return
            except Exception as e:
                self.print_error(f"Error retrieving WARP certificate: {e}")
                return
        else:
            self.print_error("warp-cli command not found. Please ensure Cloudflare WARP is installed.")
            return
        
        # Check if WARP is connected
        self.print_status("Cloudflare WARP Connection:")
        if self.command_exists('warp-cli'):
            try:
                result = subprocess.run(['warp-cli', 'status'], capture_output=True, text=True)
                warp_status = result.stdout if result.returncode == 0 else "unknown"
                if "Connected" in warp_status:
                    self.print_info("  ✓ WARP is connected")
                else:
                    self.print_warn("  ✗ WARP is not connected")
                    self.print_action("  Run: warp-cli connect")
                    has_issues = True
            except:
                self.print_error("  ✗ Failed to check WARP status")
                has_issues = True
        else:
            self.print_error("  ✗ warp-cli not found")
            self.print_action("  Install Cloudflare WARP client")
            has_issues = True
        print()
        
        # Check certificate status
        self.print_status("Certificate Status:")
        
        # Check if WARP certificate is valid
        try:
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-checkend', '86400', '-in', temp_warp_cert],
                capture_output=True
            )
            if result.returncode == 0:
                self.print_info("  ✓ WARP certificate is valid")
                
                # Check where the certificate is currently stored
                cert_locations = []
                cert_found = False
                
                # Check common locations
                if os.path.exists(CERT_PATH):
                    with open(CERT_PATH, 'r') as f:
                        existing_cert = f.read()
                    with open(temp_warp_cert, 'r') as f:
                        warp_cert_content = f.read()
                    if existing_cert == warp_cert_content:
                        cert_locations.append(f"    - {CERT_PATH}")
                        cert_found = True
                
                # Check NODE_EXTRA_CA_CERTS
                node_extra_ca_certs = os.environ.get('NODE_EXTRA_CA_CERTS', '')
                if node_extra_ca_certs and os.path.exists(node_extra_ca_certs):
                    if self.certificate_exists_in_file(temp_warp_cert, node_extra_ca_certs):
                        cert_locations.append(f"    - {node_extra_ca_certs} (NODE_EXTRA_CA_CERTS)")
                        cert_found = True
                
                # Check REQUESTS_CA_BUNDLE
                requests_ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE', '')
                if requests_ca_bundle and os.path.exists(requests_ca_bundle):
                    if self.certificate_exists_in_file(temp_warp_cert, requests_ca_bundle):
                        cert_locations.append(f"    - {requests_ca_bundle} (REQUESTS_CA_BUNDLE)")
                        cert_found = True
                
                # Check SSL_CERT_FILE
                ssl_cert_file = os.environ.get('SSL_CERT_FILE', '')
                if ssl_cert_file and os.path.exists(ssl_cert_file):
                    if self.certificate_exists_in_file(temp_warp_cert, ssl_cert_file):
                        cert_locations.append(f"    - {ssl_cert_file} (SSL_CERT_FILE)")
                        cert_found = True
                
                if cert_found:
                    self.print_info("  ✓ WARP certificate found in:")
                    for loc in cert_locations:
                        print(loc)
                else:
                    self.print_warn("  ✗ WARP certificate not found in any configured location")
                    self.print_action("    Run with --fix to install the certificate")
                    has_issues = True
            else:
                self.print_warn("  ✗ WARP certificate is expired or expiring soon")
                has_issues = True
        except:
            self.print_error("  ✗ Failed to check certificate validity")
            has_issues = True
        print()
        
        # Display selected tools info if filtering
        if self.selected_tools:
            selected_tools_info = self.get_selected_tools_info()
            self.print_info(f"Selected tools: {', '.join(selected_tools_info)}")
            print()
        
        # Check each tool
        for tool_key, tool_info in self.tools_registry.items():
            if not self.should_process_tool(tool_key):
                continue
            
            self.print_status(f"{tool_info['name']} Configuration:")
            if tool_info.get('check_func'):
                tool_has_issues = tool_info['check_func'](temp_warp_cert)
                if tool_has_issues:
                    has_issues = True
            print()
        # Check curl configuration if not filtering
        if not self.selected_tools:
            self.print_status("curl Configuration:")
            if self.command_exists('curl'):
                verify_result = self.verify_connection("curl")
                if verify_result == "WORKING":
                    self.print_info("  ✓ curl can connect through WARP")
                    # Check if it's using SecureTransport (macOS system curl)
                    try:
                        result = subprocess.run(['curl', '--version'], capture_output=True, text=True)
                        if 'SecureTransport' in result.stdout:
                            self.print_info("  ✓ Using macOS system curl with SecureTransport (uses system keychain)")
                        elif os.environ.get('CURL_CA_BUNDLE'):
                            self.print_info(f"  ✓ CURL_CA_BUNDLE is set to: {os.environ['CURL_CA_BUNDLE']}")
                    except:
                        pass
                else:
                    if os.environ.get('CURL_CA_BUNDLE'):
                        self.print_info("  ✓ CURL_CA_BUNDLE is set")
                    else:
                        self.print_warn("  ✗ curl connection test failed and CURL_CA_BUNDLE not set")
                        has_issues = True
            else:
                self.print_info("  - curl not installed")
            print()
        # Check Docker configuration if not filtering
        if not self.selected_tools:
            self.print_status("Docker Configuration:")
            if self.command_exists('docker'):
                self.print_info("  - Docker detected")
                self.print_info("    Note: Docker daemon certificate configuration varies by platform")
                self.print_info("    You may need to add certificates to Docker images directly")
            else:
                self.print_info("  - Docker not installed")
            print()
        # Show information about additional tools if not filtering
        if not self.selected_tools:
            self.print_status("Additional Tools (not yet automated):")
            self.print_info("  - RubyGems/Bundler: May work with SSL_CERT_FILE environment variable")
            self.print_info("  - PHP/Composer: May need CURL_CA_BUNDLE and php.ini configuration")
            self.print_info("  - Git: May need 'git config --global http.sslCAInfo' setting")
            self.print_info("  - Firefox: Uses its own certificate store in profile")
            self.print_info("  - Other Homebrew tools: May need individual configuration")
            print()
        
        # Summary
        self.print_info("Summary:")
        self.print_info("========")
        if has_issues:
            self.print_warn("Some configurations need attention.")
            self.print_action("Run './fuwarp.py --fix' to fix the issues")
        else:
            self.print_info("✓ All configured tools are properly set up for Cloudflare WARP")
        print()
        
        # Cleanup
        if temp_warp_cert:
            os.unlink(temp_warp_cert)
    
    def main(self):
        """Main function."""
        try:
            self.print_info("Cloudflare Certificate Installation Script (Python)")
            self.print_info("=================================================")
            
            if self.is_debug_mode():
                self.print_debug(f"Fuwarp version: {VERSION_INFO['version']} (commit: {VERSION_INFO['commit']})")
                self.print_debug(f"Branch: {VERSION_INFO['branch']} | Date: {VERSION_INFO['date']}")
                if VERSION_INFO['dirty']:
                    self.print_debug("Working directory has uncommitted changes")
                self.print_debug(f"Script: Python implementation")
                self.print_debug(f"Running on: {platform.platform()}")
                self.print_debug(f"Python version: {sys.version}")
                self.print_debug(f"Shell: {os.environ.get('SHELL', 'unknown')}")
                self.print_debug(f"PATH: {os.environ.get('PATH', '')}")
                self.print_debug(f"Home directory: {os.path.expanduser('~')}")
                self.print_debug(f"Certificate path: {CERT_PATH}")
                if not self.is_install_mode():
                    self.print_debug("Status mode: Using fast certificate checks")
                else:
                    self.print_debug("Install mode: Using thorough certificate checks")
                if self.selected_tools:
                    self.print_debug(f"Selected tools: {', '.join(self.selected_tools)}")
                print()
            
            # Validate selected tools
            if self.selected_tools:
                invalid_tools = self.validate_selected_tools()
                if invalid_tools:
                    self.print_error(f"Invalid tool selection: {', '.join(invalid_tools)}")
                    self.print_info("Use --list-tools to see available tools and their tags")
                    return 1
                
                # Show which tools will be processed
                selected_info = self.get_selected_tools_info()
                if not selected_info:
                    self.print_warn("No tools match your selection")
                    return 1
            
            if not self.is_install_mode():
                # In status mode, just check current status
                self.check_all_status()
            else:
                self.print_info("Running in FIX mode - changes will be made to your system")
                print()
                
                # Download and verify certificate
                if not self.download_certificate():
                    self.print_error("Failed to download certificate. Exiting.")
                    return 1
                
                # Setup for different environments
                if self.selected_tools:
                    self.print_info(f"Processing selected tools: {', '.join(self.get_selected_tools_info())}")
                    print()
                
                for tool_key, tool_info in self.tools_registry.items():
                    if self.should_process_tool(tool_key):
                        if tool_info.get('setup_func'):
                            tool_info['setup_func']()
                
                # Final message
                print()
                self.print_info("Installation completed!")
                
                if self.shell_modified:
                    self.print_warn("Shell configuration was modified.")
                    self.print_warn("Please reload your shell configuration:")
                    
                    shell_type = self.detect_shell()
                    shell_config = self.get_shell_config(shell_type)
                    
                    if shell_type in ['bash', 'zsh']:
                        self.print_info(f"  source {shell_config}")
                    elif shell_type == 'fish':
                        self.print_info(f"  source {shell_config}")
                    else:
                        self.print_info("  Please restart your shell")
            
            print()
            self.print_info(f"Certificate location: {CERT_PATH}")
            self.print_info("For additional applications, please refer to the documentation.")
            
            return 0  # Success
            
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 130
        except Exception as e:
            self.print_error(f"Unexpected error: {e}")
            if self.is_debug_mode():
                import traceback
                traceback.print_exc()
            return 1


def main():
    # Build version string
    version_str = f"Version: {VERSION_INFO['version']}"
    if VERSION_INFO['commit'] != 'unknown':
        version_str += f" (commit: {VERSION_INFO['commit']})"
    if VERSION_INFO['dirty']:
        version_str += " [modified]"
    
    parser = argparse.ArgumentParser(
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{version_str} | Author: {__author__} | Default: status check only (use --fix to make changes)"
    )
    
    parser.add_argument('--fix', action='store_true',
                        help='Actually make changes (default is status check only)')
    parser.add_argument('--tools', '--tool', action='append', dest='tools',
                        help='Specific tools to check/fix (can be specified multiple times). '
                             'Examples: --tools node --tools python or --tools node-npm,gcloud')
    parser.add_argument('--list-tools', action='store_true',
                        help='List all available tools and their tags')
    parser.add_argument('--debug', '--verbose', action='store_true',
                        help='Show detailed debug information')
    parser.add_argument('--version', action='version',
                        version=f"%(prog)s {VERSION_INFO['version']}")
    
    args = parser.parse_args()
    
    # Handle --list-tools first
    if args.list_tools:
        # Create a temporary instance just to access the registry
        temp_fuwarp = FuwarpPython()
        print("Available tools:")
        for tool_key, tool_info in temp_fuwarp.tools_registry.items():
            tags_str = ', '.join(tool_info['tags'])
            print(f"  {tool_key:<10} - {tool_info['name']:<20} Tags: {tags_str}")
        print("\nExamples: ./fuwarp.py --fix --tools node,python  or  ./fuwarp.py --fix --tools node-npm --tools gcp")
        sys.exit(0)
    
    # Process --tools argument
    selected_tools = []
    if args.tools:
        for tool_arg in args.tools:
            # Split by comma to allow comma-separated lists
            selected_tools.extend([t.strip() for t in tool_arg.split(',') if t.strip()])
    
    # Determine mode
    mode = 'install' if args.fix else 'status'
    
    # Create and run fuwarp instance
    fuwarp = FuwarpPython(mode=mode, debug=args.debug, selected_tools=selected_tools)
    exit_code = fuwarp.main()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
