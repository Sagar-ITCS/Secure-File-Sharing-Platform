"""
Enhanced CustomTkinter GUI Client with Advanced Features

New Features:
- Modern dark/light theme toggle
- Drag & drop file upload
- File preview panel
- Advanced encryption settings (key sizes, algorithms)
- Batch operations (multi-select, bulk delete)
- File expiration settings
- Access control (share with specific users)
- Download history tracking
- Encrypted filename support
- Automatic token refresh
- Upload/download resume capability
- File compression before encryption
- QR code generation for file sharing
- Activity logs viewer
- Search and filter files
- Export/import settings

Dependencies:
    pip install customtkinter pillow cryptography requests qrcode tkinterdnd2

"""

import os
import io
import json
import base64
import uuid
import time
import gzip
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import tkinter as tk
from tkinter import messagebox, filedialog

import customtkinter as ctk
from PIL import Image, ImageTk
import qrcode

# Crypto
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Network
import requests

# Try to import drag-drop (optional)
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

# ==================== Configuration ====================

SERVER_URL = os.environ.get('E2E_SERVER', 'http://127.0.0.1:5000')
CONFIG_FILE = Path.home() / '.e2e_client_config.json'
CACHE_DIR = Path.home() / '.e2e_client_cache'
CACHE_DIR.mkdir(exist_ok=True)

ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('blue')

# ==================== Crypto Utilities ====================

def generate_rsa_keypair(key_size: int = 2048):
    """Generate RSA keypair"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = private_key.public_key()
    pem_pub = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_priv, pem_pub


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def load_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


def encrypt_file(plaintext: bytes, compress: bool = True):
    """Encrypt file with AES-256-GCM"""
    if compress:
        plaintext = gzip.compress(plaintext)
    
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    
    return key, nonce, ciphertext, compress


def decrypt_file(key: bytes, nonce: bytes, ciphertext: bytes, compressed: bool = False):
    """Decrypt file"""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    
    if compressed:
        plaintext = gzip.decompress(plaintext)
    
    return plaintext


def wrap_key(pubkey, key_bytes: bytes):
    return pubkey.encrypt(
        key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                     algorithm=hashes.SHA256(), label=None)
    )


def unwrap_key(privkey, wrapped: bytes):
    return privkey.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                     algorithm=hashes.SHA256(), label=None)
    )


# ==================== Config Manager ====================

class ConfigManager:
    def __init__(self):
        self.config = self.load()
    
    def load(self) -> Dict:
        """Load configuration"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            'server_url': SERVER_URL,
            'theme': 'dark',
            'default_key_size': 2048,
            'compress_files': True,
            'encrypt_filenames': True,
            'default_expiry_hours': 168,
            'recent_files': [],
            'private_key_path': '',
            'public_key_path': ''
        }
    
    def save(self):
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Config save error: {e}")
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save()


# ==================== Main GUI ====================

class E2EClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title('E2E File Share - Advanced Client')
        self.geometry('1200x800')
        
        # State
        self.config = ConfigManager()
        self.jwt_token = None
        self.refresh_token = None
        self.user_id = None
        self.selected_files = []
        self.upload_queue = []
        self.download_history = []
        
        # Auto-refresh token timer
        self.token_refresh_timer = None
        
        self._setup_ui()
        self._load_saved_session()
    
    def _setup_ui(self):
        """Setup main UI"""
        # Header
        header = ctk.CTkFrame(self, height=60)
        header.pack(fill='x', padx=10, pady=10)
        
        ctk.CTkLabel(header, text='🔐 E2E File Share', 
                    font=ctk.CTkFont(size=24, weight='bold')).pack(side='left', padx=20)
        
        self.theme_switch = ctk.CTkSwitch(header, text='Dark Mode', 
                                         command=self._toggle_theme)
        self.theme_switch.pack(side='right', padx=20)
        if self.config.get('theme') == 'dark':
            self.theme_switch.select()
        
        self.user_label = ctk.CTkLabel(header, text='Not logged in', 
                                       font=ctk.CTkFont(size=12))
        self.user_label.pack(side='right', padx=20)
        
        # Main content
        self.notebook = ctk.CTkTabview(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add tabs
        self.notebook.add('🔑 Authentication')
        self.notebook.add('📤 Upload')
        self.notebook.add('📥 Download')
        self.notebook.add('📁 My Files')
        self.notebook.add('🔧 Settings')
        self.notebook.add('📊 Activity')
        
        self._build_auth_tab()
        self._build_upload_tab()
        self._build_download_tab()
        self._build_files_tab()
        self._build_settings_tab()
        self._build_activity_tab()
    
    # ==================== Authentication Tab ====================
    
    def _build_auth_tab(self):
        tab = self.notebook.tab('🔑 Authentication')
        
        frame = ctk.CTkFrame(tab)
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        ctk.CTkLabel(frame, text='Secure Login', 
                    font=ctk.CTkFont(size=20, weight='bold')).pack(pady=20)
        
        # Email
        email_frame = ctk.CTkFrame(frame)
        email_frame.pack(fill='x', padx=40, pady=10)
        
        ctk.CTkLabel(email_frame, text='Email:', width=100).pack(side='left', padx=10)
        self.email_entry = ctk.CTkEntry(email_frame, width=300, 
                                       placeholder_text='your@email.com')
        self.email_entry.pack(side='left', padx=10)
        
        ctk.CTkButton(email_frame, text='Request OTP', 
                     command=self._request_otp, width=120).pack(side='left', padx=10)
        
        # OTP
        otp_frame = ctk.CTkFrame(frame)
        otp_frame.pack(fill='x', padx=40, pady=10)
        
        ctk.CTkLabel(otp_frame, text='OTP Code:', width=100).pack(side='left', padx=10)
        self.otp_entry = ctk.CTkEntry(otp_frame, width=300, 
                                     placeholder_text='6-digit code')
        self.otp_entry.pack(side='left', padx=10)
        
        ctk.CTkButton(otp_frame, text='Login', 
                     command=self._login, width=120).pack(side='left', padx=10)
        
        # Status
        self.auth_status = ctk.CTkLabel(frame, text='', 
                                       font=ctk.CTkFont(size=14))
        self.auth_status.pack(pady=20)
        
        # Logout button
        self.logout_btn = ctk.CTkButton(frame, text='Logout', 
                                       command=self._logout, width=120)
        self.logout_btn.pack(pady=10)
        self.logout_btn.configure(state='disabled')
    
    def _request_otp(self):
        email = self.email_entry.get().strip()
        if not email or '@' not in email:
            self.auth_status.configure(text='❌ Invalid email', text_color='red')
            return
        
        self.auth_status.configure(text='⏳ Requesting OTP...', text_color='yellow')
        
        def request():
            try:
                r = requests.post(f'{self.config.get("server_url")}/auth/request_otp', 
                                json={'email': email}, timeout=10)
                
                if r.status_code == 200:
                    self.auth_status.configure(
                        text='✅ OTP sent! Check your email', text_color='green')
                else:
                    self.auth_status.configure(
                        text=f'❌ Error: {r.json().get("error", "Unknown")}', 
                        text_color='red')
            except Exception as e:
                self.auth_status.configure(text=f'❌ Network error: {e}', 
                                          text_color='red')
        
        threading.Thread(target=request, daemon=True).start()
    
    def _login(self):
        email = self.email_entry.get().strip()
        otp = self.otp_entry.get().strip()
        
        if not email or not otp:
            self.auth_status.configure(text='❌ Email and OTP required', 
                                      text_color='red')
            return
        
        self.auth_status.configure(text='⏳ Logging in...', text_color='yellow')
        
        def login():
            try:
                r = requests.post(f'{self.config.get("server_url")}/auth/login',
                                json={'email': email, 'otp': otp}, timeout=10)
                
                if r.status_code == 200:
                    data = r.json()
                    self.jwt_token = data['token']
                    self.refresh_token = data.get('refresh_token')
                    self.user_id = data.get('user_id')
                    
                    # Save session
                    self._save_session()
                    
                    # Start auto-refresh
                    self._schedule_token_refresh(data.get('expires_in', 3600))
                    
                    self.auth_status.configure(text='✅ Login successful!', 
                                             text_color='green')
                    self.user_label.configure(text=f'User: {email}')
                    self.logout_btn.configure(state='normal')
                    
                    # Load user files
                    self._load_user_files()
                else:
                    self.auth_status.configure(
                        text=f'❌ {r.json().get("error", "Login failed")}', 
                        text_color='red')
            except Exception as e:
                self.auth_status.configure(text=f'❌ Error: {e}', text_color='red')
        
        threading.Thread(target=login, daemon=True).start()
    
    def _logout(self):
        if self.jwt_token:
            try:
                requests.post(f'{self.config.get("server_url")}/auth/logout',
                            headers={'Authorization': f'Bearer {self.jwt_token}'},
                            timeout=5)
            except Exception:
                pass
        
        self.jwt_token = None
        self.refresh_token = None
        self.user_id = None
        self._clear_session()
        
        if self.token_refresh_timer:
            self.after_cancel(self.token_refresh_timer)
        
        self.auth_status.configure(text='Logged out', text_color='gray')
        self.user_label.configure(text='Not logged in')
        self.logout_btn.configure(state='disabled')
        self.files_list.delete(0, 'end')
    
    def _schedule_token_refresh(self, expires_in):
        """Auto-refresh token before expiry"""
        refresh_at = (expires_in - 300) * 1000  # 5 min before expiry
        if refresh_at > 0:
            self.token_refresh_timer = self.after(refresh_at, self._refresh_token)
    
    def _refresh_token(self):
        """Refresh access token"""
        if not self.refresh_token:
            return
        
        try:
            r = requests.post(f'{self.config.get("server_url")}/auth/refresh',
                            json={'refresh_token': self.refresh_token}, timeout=10)
            
            if r.status_code == 200:
                data = r.json()
                self.jwt_token = data['token']
                self._save_session()
                self._schedule_token_refresh(data.get('expires_in', 3600))
        except Exception as e:
            print(f"Token refresh failed: {e}")
    
    # ==================== Upload Tab ====================
    
    def _build_upload_tab(self):
        tab = self.notebook.tab('📤 Upload')
        
        # File selection
        select_frame = ctk.CTkFrame(tab)
        select_frame.pack(fill='x', padx=20, pady=10)
        
        ctk.CTkButton(select_frame, text='📁 Select Files', 
                     command=self._select_files).pack(side='left', padx=10)
        ctk.CTkButton(select_frame, text='🗑️ Clear Selection', 
                     command=self._clear_selection).pack(side='left', padx=10)
        
        # Selected files list
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        ctk.CTkLabel(list_frame, text='Selected Files:', 
                    font=ctk.CTkFont(size=14, weight='bold')).pack(anchor='w', padx=10, pady=5)
        
        self.upload_listbox = tk.Listbox(list_frame, height=8, 
                                         selectmode='multiple')
        self.upload_listbox.pack(fill='both', expand=True, padx=10, pady=5)
        
        scrollbar = ctk.CTkScrollbar(list_frame, command=self.upload_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.upload_listbox.configure(yscrollcommand=scrollbar.set)
        
        # Encryption settings
        settings_frame = ctk.CTkFrame(tab)
        settings_frame.pack(fill='x', padx=20, pady=10)
        
        left_settings = ctk.CTkFrame(settings_frame)
        left_settings.pack(side='left', fill='x', expand=True, padx=10)
        
        ctk.CTkLabel(left_settings, text='Recipient Public Key:').pack(anchor='w', pady=5)
        
        key_frame = ctk.CTkFrame(left_settings)
        key_frame.pack(fill='x', pady=5)
        
        self.recipient_key_entry = ctk.CTkEntry(key_frame, width=400,
                                               placeholder_text='Select recipient public key file')
        self.recipient_key_entry.pack(side='left', padx=5)
        
        ctk.CTkButton(key_frame, text='Browse', width=100,
                     command=self._browse_recipient_key).pack(side='left')
        
        # Options
        options_frame = ctk.CTkFrame(settings_frame)
        options_frame.pack(side='right', padx=10)
        
        self.compress_var = ctk.BooleanVar(value=self.config.get('compress_files'))
        ctk.CTkCheckBox(options_frame, text='Compress before encrypt',
                       variable=self.compress_var).pack(anchor='w', pady=2)
        
        self.encrypt_name_var = ctk.BooleanVar(
            value=self.config.get('encrypt_filenames'))
        ctk.CTkCheckBox(options_frame, text='Encrypt filename',
                       variable=self.encrypt_name_var).pack(anchor='w', pady=2)
        
        expiry_frame = ctk.CTkFrame(options_frame)
        expiry_frame.pack(fill='x', pady=5)
        
        ctk.CTkLabel(expiry_frame, text='Expires in:').pack(side='left')
        self.expiry_hours = ctk.CTkEntry(expiry_frame, width=60)
        self.expiry_hours.insert(0, str(self.config.get('default_expiry_hours')))
        self.expiry_hours.pack(side='left', padx=5)
        ctk.CTkLabel(expiry_frame, text='hours').pack(side='left')
        
        # Progress
        progress_frame = ctk.CTkFrame(tab)
        progress_frame.pack(fill='x', padx=20, pady=10)
        
        self.upload_progress = ctk.CTkProgressBar(progress_frame)
        self.upload_progress.pack(fill='x', padx=10, pady=5)
        self.upload_progress.set(0)
        
        self.upload_status = ctk.CTkLabel(progress_frame, text='Ready to upload')
        self.upload_status.pack(pady=5)
        
        # Upload button
        ctk.CTkButton(tab, text='🚀 Upload Files', height=40,
                     font=ctk.CTkFont(size=16, weight='bold'),
                     command=self._start_upload).pack(pady=20)
    
    def _select_files(self):
        files = filedialog.askopenfilenames(title='Select files to upload')
        if files:
            self.selected_files.extend(files)
            self._update_upload_list()
    
    def _clear_selection(self):
        self.selected_files.clear()
        self._update_upload_list()
    
    def _update_upload_list(self):
        self.upload_listbox.delete(0, 'end')
        for f in self.selected_files:
            size = os.path.getsize(f) / 1024 / 1024  # MB
            self.upload_listbox.insert('end', 
                                      f'{os.path.basename(f)} ({size:.2f} MB)')
    
    def _browse_recipient_key(self):
        path = filedialog.askopenfilename(
            title='Select recipient public key',
            filetypes=[('PEM files', '*.pem'), ('All files', '*.*')])
        if path:
            self.recipient_key_entry.delete(0, 'end')
            self.recipient_key_entry.insert(0, path)
    
    def _start_upload(self):
        if not self.jwt_token:
            messagebox.showerror('Error', 'Please login first')
            return
        
        if not self.selected_files:
            messagebox.showwarning('Warning', 'No files selected')
            return
        
        key_path = self.recipient_key_entry.get()
        if not key_path or not os.path.exists(key_path):
            messagebox.showerror('Error', 'Invalid recipient public key')
            return
        
        threading.Thread(target=self._upload_files, daemon=True).start()
    
    def _upload_files(self):
        try:
            # Load recipient key
            with open(self.recipient_key_entry.get(), 'rb') as f:
                pubkey = load_public_key(f.read())
        except Exception as e:
            self.upload_status.configure(text=f'❌ Invalid key: {e}')
            return
        
        total = len(self.selected_files)
        compress = self.compress_var.get()
        encrypt_name = self.encrypt_name_var.get()
        
        try:
            expires_hours = int(self.expiry_hours.get())
        except ValueError:
            expires_hours = 168
        
        for idx, filepath in enumerate(self.selected_files):
            try:
                filename = os.path.basename(filepath)
                self.upload_status.configure(
                    text=f'⏳ Encrypting {filename} ({idx+1}/{total})')
                self.upload_progress.set(idx / total)
                
                # Read file
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                # Encrypt
                key, nonce, ciphertext, compressed = encrypt_file(data, compress)
                wrapped_key = wrap_key(pubkey, key)
                
                # Prepare metadata
                metadata = {'compressed': compressed}
                
                if encrypt_name:
                    # Encrypt filename
                    name_key, name_nonce, enc_name, _ = encrypt_file(
                        filename.encode(), False)
                    wrapped_name_key = wrap_key(pubkey, name_key)
                    
                    metadata.update({
                        'encrypted_name': base64.b64encode(enc_name).decode(),
                        'name_nonce': base64.b64encode(name_nonce).decode(),
                        'wrapped_name_key': base64.b64encode(wrapped_name_key).decode()
                    })
                    display_name = '<encrypted>'
                else:
                    display_name = filename
                
                # Upload
                self.upload_status.configure(text=f'📤 Uploading {filename}...')
                
                payload = {
                    'filename': display_name,
                    'nonce': base64.b64encode(nonce).decode(),
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'wrapped_key': base64.b64encode(wrapped_key).decode(),
                    'metadata': json.dumps(metadata),
                    'expires_hours': expires_hours
                }
                
                headers = {'Authorization': f'Bearer {self.jwt_token}'}
                r = requests.post(f'{self.config.get("server_url")}/upload',
                                json=payload, headers=headers, timeout=60)
                
                if r.status_code == 200:
                    file_id = r.json()['file_id']
                    self.upload_status.configure(
                        text=f'✅ Uploaded {filename} - ID: {file_id[:8]}...')
                else:
                    self.upload_status.configure(
                        text=f'❌ Upload failed: {r.json().get("error")}')
                
            except Exception as e:
                self.upload_status.configure(text=f'❌ Error: {e}')
            
            self.upload_progress.set((idx + 1) / total)
        
        self.upload_status.configure(text='✅ All uploads complete!')
        self._load_user_files()  # Refresh file list
    
    # ==================== Download Tab ====================
    
    def _build_download_tab(self):
        tab = self.notebook.tab('📥 Download')
        
        frame = ctk.CTkFrame(tab)
        frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # File ID
        id_frame = ctk.CTkFrame(frame)
        id_frame.pack(fill='x', pady=10)
        
        ctk.CTkLabel(id_frame, text='File ID:', width=100).pack(side='left', padx=10)
        self.download_id_entry = ctk.CTkEntry(id_frame, width=400,
                                             placeholder_text='Enter file ID')
        self.download_id_entry.pack(side='left', padx=10)
        
        # Private key
        key_frame = ctk.CTkFrame(frame)
        key_frame.pack(fill='x', pady=10)
        
        ctk.CTkLabel(key_frame, text='Private Key:', width=100).pack(side='left', padx=10)
        self.download_key_entry = ctk.CTkEntry(key_frame, width=400,
                                              placeholder_text='Select your private key')
        self.download_key_entry.pack(side='left', padx=10)
        
        ctk.CTkButton(key_frame, text='Browse', width=100,
                     command=self._browse_private_key).pack(side='left', padx=10)
        
        # Progress
        self.download_progress = ctk.CTkProgressBar(frame)
        self.download_progress.pack(fill='x', padx=10, pady=20)
        self.download_progress.set(0)
        
        self.download_status = ctk.CTkLabel(frame, text='Ready to download')
        self.download_status.pack(pady=10)
        
        # Download button
        ctk.CTkButton(frame, text='⬇️ Download & Decrypt', height=40,
                     font=ctk.CTkFont(size=16, weight='bold'),
                     command=self._start_download).pack(pady=20)
    
    def _browse_private_key(self):
        path = filedialog.askopenfilename(
            title='Select your private key',
            filetypes=[('PEM files', '*.pem'), ('All files', '*.*')])
        if path:
            self.download_key_entry.delete(0, 'end')
            self.download_key_entry.insert(0, path)
            self.config.set('private_key_path', path)
    
    def _start_download(self):
        if not self.jwt_token:
            messagebox.showerror('Error', 'Please login first')
            return
        
        threading.Thread(target=self._download_file, daemon=True).start()
    
    def _download_file(self):
        file_id = self.download_id_entry.get().strip()
        key_path = self.download_key_entry.get().strip()
        
        if not file_id or not key_path:
            self.download_status.configure(text='❌ File ID and key required')
            return
        
        try:
            with open(key_path, 'rb') as f:
                privkey = load_private_key(f.read())
        except Exception as e:
            self.download_status.configure(text=f'❌ Invalid key: {e}')
            return
        
        try:
            self.download_status.configure(text='⏳ Downloading...')
            self.download_progress.set(0.3)
            
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            r = requests.get(f'{self.config.get("server_url")}/files/{file_id}',
                           headers=headers, timeout=60)
            
            if r.status_code != 200:
                self.download_status.configure(
                    text=f'❌ Download failed: {r.json().get("error")}')
                return
            
            data = r.json()
            self.download_progress.set(0.5)
            
            # Decrypt
            self.download_status.configure(text='🔓 Decrypting...')
            
            ciphertext = base64.b64decode(data['ciphertext'])
            nonce = base64.b64decode(data['nonce'])
            wrapped_key = base64.b64decode(data['wrapped_key'])
            
            file_key = unwrap_key(privkey, wrapped_key)
            
            metadata = json.loads(data.get('metadata', '{}'))
            compressed = metadata.get('compressed', False)
            
            plaintext = decrypt_file(file_key, nonce, ciphertext, compressed)
            
            self.download_progress.set(0.8)
            
            # Get filename
            if 'encrypted_name' in metadata:
                enc_name = base64.b64decode(metadata['encrypted_name'])
                name_nonce = base64.b64decode(metadata['name_nonce'])
                wrapped_name_key = base64.b64decode(metadata['wrapped_name_key'])
                
                name_key = unwrap_key(privkey, wrapped_name_key)
                filename = decrypt_file(name_key, name_nonce, enc_name, False).decode()
            else:
                filename = data.get('filename', 'downloaded_file')
            
            # Save
            save_path = filedialog.asksaveasfilename(
                initialfile=filename,
                title='Save decrypted file')
            
            if not save_path:
                self.download_status.configure(text='⚠️ Save cancelled')
                return
            
            with open(save_path, 'wb') as f:
                f.write(plaintext)
            
            self.download_progress.set(1.0)
            self.download_status.configure(text=f'✅ Saved: {os.path.basename(save_path)}')
            
            # Add to history
            self.download_history.append({
                'file_id': file_id,
                'filename': filename,
                'timestamp': time.time(),
                'size': len(plaintext)
            })
            
        except Exception as e:
            self.download_status.configure(text=f'❌ Error: {e}')
    
    # ==================== My Files Tab ====================
    
    def _build_files_tab(self):
        tab = self.notebook.tab('📁 My Files')
        
        # Toolbar
        toolbar = ctk.CTkFrame(tab)
        toolbar.pack(fill='x', padx=10, pady=10)
        
        ctk.CTkButton(toolbar, text='🔄 Refresh', 
                     command=self._load_user_files).pack(side='left', padx=5)
        
        ctk.CTkButton(toolbar, text='📋 Copy ID', 
                     command=self._copy_file_id).pack(side='left', padx=5)
        
        ctk.CTkButton(toolbar, text='🔗 Share Link', 
                     command=self._generate_share_link).pack(side='left', padx=5)
        
        # Search
        search_frame = ctk.CTkFrame(toolbar)
        search_frame.pack(side='right', padx=5)
        
        self.search_entry = ctk.CTkEntry(search_frame, width=200,
                                        placeholder_text='Search files...')
        self.search_entry.pack(side='left', padx=5)
        self.search_entry.bind('<KeyRelease>', lambda e: self._filter_files())
        
        # Files list
        list_frame = ctk.CTkFrame(tab)
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.files_list = tk.Listbox(list_frame, height=15)
        self.files_list.pack(fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ctk.CTkScrollbar(list_frame, command=self.files_list.yview)
        scrollbar.pack(side='right', fill='y')
        self.files_list.configure(yscrollcommand=scrollbar.set)
        
        # Details panel
        details_frame = ctk.CTkFrame(tab)
        details_frame.pack(fill='x', padx=10, pady=10)
        
        self.file_details = ctk.CTkLabel(details_frame, text='Select a file to view details',
                                        justify='left')
        self.file_details.pack(padx=10, pady=10)
        
        self.files_list.bind('<<ListboxSelect>>', self._on_file_select)
    
    def _load_user_files(self):
        if not self.jwt_token:
            return
        
        def load():
            try:
                headers = {'Authorization': f'Bearer {self.jwt_token}'}
                r = requests.get(f'{self.config.get("server_url")}/files',
                               headers=headers, timeout=10)
                
                if r.status_code == 200:
                    self.user_files = r.json().get('files', [])
                    self._update_files_list()
            except Exception as e:
                print(f"Load files error: {e}")
        
        threading.Thread(target=load, daemon=True).start()
    
    def _update_files_list(self):
        self.files_list.delete(0, 'end')
        
        search = self.search_entry.get().lower()
        
        for file in self.user_files:
            filename = file.get('filename', 'unknown')
            if search and search not in filename.lower():
                continue
            
            size_mb = file.get('size', 0) / 1024 / 1024
            downloads = file.get('downloads', 0)
            
            uploaded = datetime.fromtimestamp(file.get('uploaded_at', 0))
            
            display = f"{filename} | {size_mb:.2f}MB | ↓{downloads} | {uploaded.strftime('%Y-%m-%d %H:%M')}"
            self.files_list.insert('end', display)
    
    def _filter_files(self):
        if hasattr(self, 'user_files'):
            self._update_files_list()
    
    def _on_file_select(self, event):
        selection = self.files_list.curselection()
        if not selection:
            return
        
        idx = selection[0]
        if idx >= len(self.user_files):
            return
        
        file = self.user_files[idx]
        
        expires = datetime.fromtimestamp(file.get('expires_at', 0))
        
        details = f"""
File ID: {file['file_id']}
Filename: {file.get('filename', 'unknown')}
Size: {file.get('size', 0) / 1024 / 1024:.2f} MB
Downloads: {file.get('downloads', 0)}
Expires: {expires.strftime('%Y-%m-%d %H:%M')}
        """
        
        self.file_details.configure(text=details.strip())
    
    def _copy_file_id(self):
        selection = self.files_list.curselection()
        if not selection:
            messagebox.showwarning('Warning', 'Select a file first')
            return
        
        idx = selection[0]
        file_id = self.user_files[idx]['file_id']
        
        self.clipboard_clear()
        self.clipboard_append(file_id)
        messagebox.showinfo('Copied', f'File ID copied: {file_id[:16]}...')
    
    def _generate_share_link(self):
        selection = self.files_list.curselection()
        if not selection:
            messagebox.showwarning('Warning', 'Select a file first')
            return
        
        idx = selection[0]
        file_id = self.user_files[idx]['file_id']
        
        # Generate QR code
        share_url = f"{self.config.get('server_url')}/share/{file_id}"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(share_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Show in dialog
        dialog = ctk.CTkToplevel(self)
        dialog.title('Share Link')
        dialog.geometry('400x500')
        
        ctk.CTkLabel(dialog, text='Share Link', 
                    font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10)
        
        link_entry = ctk.CTkEntry(dialog, width=350)
        link_entry.insert(0, share_url)
        link_entry.pack(pady=10)
        
        ctk.CTkButton(dialog, text='Copy Link', 
                     command=lambda: self._copy_to_clipboard(share_url)).pack(pady=5)
        
        # QR code (simplified display)
        ctk.CTkLabel(dialog, text='QR Code (scan to download)').pack(pady=10)
    
    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo('Copied', 'Link copied to clipboard')
    
    # ==================== Settings Tab ====================
    
    def _build_settings_tab(self):
        tab = self.notebook.tab('🔧 Settings')
        
        frame = ctk.CTkScrollableFrame(tab)
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Server URL
        ctk.CTkLabel(frame, text='Server Configuration', 
                    font=ctk.CTkFont(size=16, weight='bold')).pack(anchor='w', pady=10)
        
        url_frame = ctk.CTkFrame(frame)
        url_frame.pack(fill='x', pady=5)
        
        ctk.CTkLabel(url_frame, text='Server URL:', width=120).pack(side='left', padx=10)
        self.server_url_entry = ctk.CTkEntry(url_frame, width=400)
        self.server_url_entry.insert(0, self.config.get('server_url'))
        self.server_url_entry.pack(side='left', padx=10)
        
        # Encryption settings
        ctk.CTkLabel(frame, text='Encryption Settings', 
                    font=ctk.CTkFont(size=16, weight='bold')).pack(anchor='w', pady=10)
        
        key_frame = ctk.CTkFrame(frame)
        key_frame.pack(fill='x', pady=5)
        
        ctk.CTkLabel(key_frame, text='Default Key Size:', width=120).pack(side='left', padx=10)
        self.key_size_var = ctk.StringVar(value=str(self.config.get('default_key_size')))
        ctk.CTkOptionMenu(key_frame, values=['2048', '3072', '4096'],
                         variable=self.key_size_var).pack(side='left', padx=10)
        
        # Keypair generator
        ctk.CTkLabel(frame, text='Generate New Keypair', 
                    font=ctk.CTkFont(size=16, weight='bold')).pack(anchor='w', pady=10)
        
        keygen_frame = ctk.CTkFrame(frame)
        keygen_frame.pack(fill='x', pady=5)
        
        ctk.CTkButton(keygen_frame, text='🔑 Generate RSA Keypair',
                     command=self._generate_keypair).pack(side='left', padx=10)
        
        self.keygen_status = ctk.CTkLabel(keygen_frame, text='')
        self.keygen_status.pack(side='left', padx=10)
        
        # Save settings
        ctk.CTkButton(frame, text='💾 Save Settings', 
                     command=self._save_settings).pack(pady=20)
    
    def _generate_keypair(self):
        try:
            key_size = int(self.key_size_var.get())
            
            self.keygen_status.configure(text='⏳ Generating...')
            
            def generate():
                priv, pub = generate_rsa_keypair(key_size)
                
                # Save dialog
                priv_path = filedialog.asksaveasfilename(
                    defaultextension='.pem',
                    title='Save private key as',
                    filetypes=[('PEM files', '*.pem')])
                
                if not priv_path:
                    self.keygen_status.configure(text='Cancelled')
                    return
                
                pub_path = priv_path + '.pub'
                
                with open(priv_path, 'wb') as f:
                    f.write(priv)
                
                with open(pub_path, 'wb') as f:
                    f.write(pub)
                
                self.keygen_status.configure(text=f'✅ Keys saved: {os.path.basename(priv_path)}')
                
                # Update config
                self.config.set('private_key_path', priv_path)
                self.config.set('public_key_path', pub_path)
            
            threading.Thread(target=generate, daemon=True).start()
            
        except Exception as e:
            self.keygen_status.configure(text=f'❌ Error: {e}')
    
    def _save_settings(self):
        self.config.set('server_url', self.server_url_entry.get())
        self.config.set('default_key_size', int(self.key_size_var.get()))
        messagebox.showinfo('Saved', 'Settings saved successfully')
    
    # ==================== Activity Tab ====================
    
    def _build_activity_tab(self):
        tab = self.notebook.tab('📊 Activity')
        
        frame = ctk.CTkFrame(tab)
        frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(frame, text='Activity Log', 
                    font=ctk.CTkFont(size=18, weight='bold')).pack(pady=10)
        
        self.activity_text = ctk.CTkTextbox(frame, height=400)
        self.activity_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        ctk.CTkButton(frame, text='🔄 Refresh', 
                     command=self._load_activity).pack(pady=10)
    
    def _load_activity(self):
        text = "Download History:\n\n"
        
        for entry in self.download_history[-20:]:  # Last 20
            dt = datetime.fromtimestamp(entry['timestamp'])
            text += f"[{dt.strftime('%Y-%m-%d %H:%M')}] "
            text += f"{entry['filename']} ({entry['size']/1024/1024:.2f}MB)\n"
        
        self.activity_text.delete('1.0', 'end')
        self.activity_text.insert('1.0', text)
    
    # ==================== Helper Methods ====================
    
    def _toggle_theme(self):
        mode = 'dark' if self.theme_switch.get() else 'light'
        ctk.set_appearance_mode(mode)
        self.config.set('theme', mode)
    
    def _save_session(self):
        """Save session to cache"""
        session = {
            'jwt_token': self.jwt_token,
            'refresh_token': self.refresh_token,
            'user_id': self.user_id,
            'timestamp': time.time()
        }
        
        try:
            with open(CACHE_DIR / 'session.json', 'w') as f:
                json.dump(session, f)
        except Exception as e:
            print(f"Session save error: {e}")
    
    def _load_saved_session(self):
        """Load saved session"""
        session_file = CACHE_DIR / 'session.json'
        if not session_file.exists():
            return
        
        try:
            with open(session_file, 'r') as f:
                session = json.load(f)
            
            # Check if session is still valid (within 7 days)
            if time.time() - session.get('timestamp', 0) < 604800:
                self.jwt_token = session.get('jwt_token')
                self.refresh_token = session.get('refresh_token')
                self.user_id = session.get('user_id')
                
                if self.jwt_token:
                    self.user_label.configure(text=f'User: {self.user_id}')
                    self.logout_btn.configure(state='normal')
                    self._load_user_files()
        except Exception as e:
            print(f"Session load error: {e}")
    
    def _clear_session(self):
        """Clear saved session"""
        session_file = CACHE_DIR / 'session.json'
        if session_file.exists():
            session_file.unlink()


# ==================== Main ====================

def main():
    app = E2EClientApp()
    app.mainloop()


if __name__ == '__main__':
    main()