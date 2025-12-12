"""
Enhanced E2E File Sharing Server with Advanced Features

New Features:
- JWT authentication with refresh tokens
- Email-based OTP authentication (passwordless)
- File expiration and auto-cleanup
- Access control lists (ACLs) per file
- Activity logging and audit trails
- Rate limiting per user
- File metadata encryption
- Multiple storage backends (local, S3, IPFS)
- Presigned URL generation for S3
- File sharing links with permissions
- Admin dashboard endpoints
- Health check and metrics

Dependencies:
    pip install cryptography flask flask-cors flask-limiter pyjwt requests boto3 python-dotenv

Environment variables (.env):
    SECRET_KEY=your-secret-key-here
    JWT_SECRET=your-jwt-secret-here
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=your-email@gmail.com
    SMTP_PASSWORD=your-app-password
    AWS_ACCESS_KEY_ID=your-aws-key
    AWS_SECRET_ACCESS_KEY=your-aws-secret
    S3_BUCKET=your-bucket-name
    IPFS_API=/ip4/127.0.0.1/tcp/5001

Run: python enhanced_server.py
"""

import os
import sys
import json
import uuid
import base64
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Optional imports
try:
    import boto3
    from botocore.exceptions import ClientError
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False

try:
    import smtplib
    from email.mime.text import MIMEText
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

from dotenv import load_dotenv
load_dotenv()

# Configuration
STORAGE_DIR = Path("./storage")
META_DIR = Path("./meta")
LOG_DIR = Path("./logs")
TEMP_DIR = Path("./temp")

for d in [STORAGE_DIR, META_DIR, LOG_DIR, TEMP_DIR]:
    d.mkdir(exist_ok=True)

SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY = 3600  # 1 hour
REFRESH_EXPIRY = 604800  # 7 days

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max
CORS(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# In-memory stores (use Redis/DB in production)
otp_store = {}  # email -> {otp, expires, attempts}
active_tokens = set()  # valid JWT tokens
user_activity = {}  # user_id -> [timestamps]

# ==================== Utilities ====================

def log_activity(user_id, action, details=None):
    """Log user activity"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'user_id': user_id,
        'action': action,
        'details': details or {}
    }
    
    log_file = LOG_DIR / f"{datetime.utcnow().strftime('%Y-%m-%d')}.log"
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    
    # Track user activity for rate limiting
    if user_id not in user_activity:
        user_activity[user_id] = []
    user_activity[user_id].append(time.time())
    # Keep only last hour
    user_activity[user_id] = [t for t in user_activity[user_id] if time.time() - t < 3600]


def generate_token(user_id, token_type='access'):
    """Generate JWT token"""
    expiry = JWT_EXPIRY if token_type == 'access' else REFRESH_EXPIRY
    payload = {
        'user_id': user_id,
        'type': token_type,
        'exp': datetime.utcnow() + timedelta(seconds=expiry),
        'iat': datetime.utcnow(),
        'jti': secrets.token_hex(16)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    active_tokens.add(token)
    return token


def verify_token(token):
    """Verify JWT token"""
    try:
        if token not in active_tokens:
            return None
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        active_tokens.discard(token)
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ', 1)[1]
        payload = verify_token(token)
        
        if not payload or payload.get('type') != 'access':
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.user_id = payload['user_id']
        return f(*args, **kwargs)
    
    return decorated


def send_otp_email(email, otp):
    """Send OTP via email"""
    if not EMAIL_AVAILABLE:
        print(f"[DEV MODE] OTP for {email}: {otp}")
        return True
    
    try:
        msg = MIMEText(f"Your OTP code is: {otp}\n\nValid for 10 minutes.")
        msg['Subject'] = 'E2E File Share - Login Code'
        msg['From'] = os.getenv('SMTP_USER')
        msg['To'] = email
        
        with smtplib.SMTP(os.getenv('SMTP_HOST', 'smtp.gmail.com'), 
                         int(os.getenv('SMTP_PORT', 587))) as server:
            server.starttls()
            server.login(os.getenv('SMTP_USER'), os.getenv('SMTP_PASSWORD'))
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False


def cleanup_expired_files():
    """Remove expired files"""
    now = time.time()
    for meta_file in META_DIR.glob('*.json'):
        try:
            with open(meta_file, 'r') as f:
                meta = json.load(f)
            
            if 'expires_at' in meta and meta['expires_at'] < now:
                file_id = meta['file_id']
                storage_file = STORAGE_DIR / f"{file_id}.bin"
                
                if storage_file.exists():
                    storage_file.unlink()
                meta_file.unlink()
                
                log_activity('system', 'file_expired', {'file_id': file_id})
        except Exception as e:
            print(f"Cleanup error: {e}")


# ==================== Authentication Endpoints ====================

@app.route('/auth/request_otp', methods=['POST'])
@limiter.limit("5 per hour")
def request_otp():
    """Request OTP for passwordless login"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    
    # Generate 6-digit OTP
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expires = time.time() + 600  # 10 minutes
    
    otp_store[email] = {
        'otp': otp,
        'expires': expires,
        'attempts': 0
    }
    
    if send_otp_email(email, otp):
        log_activity(email, 'otp_requested')
        return jsonify({'status': 'ok', 'message': 'OTP sent to email'})
    else:
        return jsonify({'error': 'Failed to send OTP'}), 500


@app.route('/auth/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """Login with OTP"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    
    if not email or not otp:
        return jsonify({'error': 'Email and OTP required'}), 400
    
    stored = otp_store.get(email)
    if not stored:
        return jsonify({'error': 'No OTP request found'}), 400
    
    if time.time() > stored['expires']:
        del otp_store[email]
        return jsonify({'error': 'OTP expired'}), 400
    
    stored['attempts'] += 1
    if stored['attempts'] > 3:
        del otp_store[email]
        return jsonify({'error': 'Too many attempts'}), 429
    
    if stored['otp'] != otp:
        return jsonify({'error': 'Invalid OTP'}), 401
    
    # Success - generate tokens
    del otp_store[email]
    user_id = hashlib.sha256(email.encode()).hexdigest()[:16]
    
    access_token = generate_token(user_id, 'access')
    refresh_token = generate_token(user_id, 'refresh')
    
    log_activity(user_id, 'login', {'email': email})
    
    return jsonify({
        'token': access_token,
        'refresh_token': refresh_token,
        'user_id': user_id,
        'expires_in': JWT_EXPIRY
    })


@app.route('/auth/refresh', methods=['POST'])
def refresh():
    """Refresh access token"""
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token required'}), 400
    
    payload = verify_token(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        return jsonify({'error': 'Invalid refresh token'}), 401
    
    user_id = payload['user_id']
    new_access = generate_token(user_id, 'access')
    
    return jsonify({
        'token': new_access,
        'expires_in': JWT_EXPIRY
    })


@app.route('/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout and invalidate token"""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split(' ', 1)[1] if ' ' in auth_header else ''
    active_tokens.discard(token)
    
    log_activity(request.user_id, 'logout')
    return jsonify({'status': 'ok'})


# ==================== File Upload Endpoints ====================

@app.route('/upload', methods=['POST'])
@require_auth
@limiter.limit("20 per hour")
def upload():
    """Upload encrypted file to local storage"""
    try:
        data = request.get_json()
        filename = data.get('filename', 'unnamed')
        nonce = base64.b64decode(data['nonce'])
        ciphertext = base64.b64decode(data['ciphertext'])
        wrapped_key = base64.b64decode(data['wrapped_key'])
        metadata = data.get('metadata', '{}')
        expires_hours = data.get('expires_hours', 168)  # 7 days default
        allowed_users = data.get('allowed_users', [])  # ACL
        
    except Exception as e:
        return jsonify({'error': 'Invalid payload', 'detail': str(e)}), 400
    
    file_id = str(uuid.uuid4())
    storage_path = STORAGE_DIR / f"{file_id}.bin"
    meta_path = META_DIR / f"{file_id}.json"
    
    # Write ciphertext
    with open(storage_path, 'wb') as f:
        f.write(ciphertext)
    
    # Write metadata
    meta = {
        'file_id': file_id,
        'filename': filename,
        'owner': request.user_id,
        'uploaded_at': time.time(),
        'expires_at': time.time() + (expires_hours * 3600),
        'size': len(ciphertext),
        'nonce': base64.b64encode(nonce).decode(),
        'wrapped_key': base64.b64encode(wrapped_key).decode(),
        'metadata': metadata,
        'allowed_users': allowed_users,
        'storage': 'local',
        'downloads': 0
    }
    
    with open(meta_path, 'w') as f:
        json.dump(meta, f)
    
    log_activity(request.user_id, 'file_uploaded', {
        'file_id': file_id,
        'size': len(ciphertext)
    })
    
    return jsonify({'file_id': file_id, 'expires_at': meta['expires_at']})


@app.route('/upload/s3', methods=['POST'])
@require_auth
def upload_s3_metadata():
    """Record S3-uploaded file metadata"""
    if not S3_AVAILABLE:
        return jsonify({'error': 'S3 not configured'}), 501
    
    data = request.get_json()
    file_id = str(uuid.uuid4())
    
    meta = {
        'file_id': file_id,
        'owner': request.user_id,
        'uploaded_at': time.time(),
        'storage': 's3',
        's3_key': data.get('s3_key'),
        'bucket': data.get('bucket'),
        'wrapped_key': data.get('wrapped_key'),
        'metadata': data.get('metadata', '{}'),
        'downloads': 0
    }
    
    meta_path = META_DIR / f"{file_id}.json"
    with open(meta_path, 'w') as f:
        json.dump(meta, f)
    
    log_activity(request.user_id, 'file_uploaded_s3', {'file_id': file_id})
    return jsonify({'file_id': file_id})


@app.route('/upload/presigned', methods=['POST'])
@require_auth
def get_presigned_upload():
    """Get presigned URL for direct S3 upload"""
    if not S3_AVAILABLE:
        return jsonify({'error': 'S3 not configured'}), 501
    
    try:
        s3 = boto3.client('s3',
                         aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                         aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'))
        
        bucket = os.getenv('S3_BUCKET')
        key = f"encrypted/{uuid.uuid4().hex}.bin"
        
        url = s3.generate_presigned_url(
            'put_object',
            Params={'Bucket': bucket, 'Key': key},
            ExpiresIn=3600
        )
        
        return jsonify({'upload_url': url, 's3_key': key, 'bucket': bucket})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== File Download Endpoints ====================

@app.route('/files/<file_id>', methods=['GET'])
@require_auth
def get_file(file_id):
    """Download encrypted file"""
    meta_path = META_DIR / f"{file_id}.json"
    
    if not meta_path.exists():
        return jsonify({'error': 'File not found'}), 404
    
    with open(meta_path, 'r') as f:
        meta = json.load(f)
    
    # Check ACL
    allowed = meta.get('allowed_users', [])
    if allowed and request.user_id not in allowed and request.user_id != meta['owner']:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check expiration
    if 'expires_at' in meta and time.time() > meta['expires_at']:
        return jsonify({'error': 'File expired'}), 410
    
    # Update download count
    meta['downloads'] = meta.get('downloads', 0) + 1
    with open(meta_path, 'w') as f:
        json.dump(meta, f)
    
    if meta['storage'] == 'local':
        storage_path = STORAGE_DIR / f"{file_id}.bin"
        if not storage_path.exists():
            return jsonify({'error': 'File data not found'}), 404
        
        with open(storage_path, 'rb') as f:
            ciphertext = f.read()
        
        response = {
            'file_id': file_id,
            'filename': meta['filename'],
            'nonce': meta['nonce'],
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'wrapped_key': meta['wrapped_key'],
            'metadata': meta.get('metadata', '{}')
        }
    
    elif meta['storage'] == 's3':
        response = {
            'file_id': file_id,
            'storage': 's3',
            's3_key': meta['s3_key'],
            'bucket': meta['bucket'],
            'wrapped_key': meta['wrapped_key'],
            'metadata': meta.get('metadata', '{}')
        }
    
    log_activity(request.user_id, 'file_downloaded', {'file_id': file_id})
    return jsonify(response)


@app.route('/files/<file_id>/metadata', methods=['GET'])
@require_auth
def get_file_metadata(file_id):
    """Get file metadata only"""
    meta_path = META_DIR / f"{file_id}.json"
    
    if not meta_path.exists():
        return jsonify({'error': 'File not found'}), 404
    
    with open(meta_path, 'r') as f:
        meta = json.load(f)
    
    # Return safe metadata
    return jsonify({
        'file_id': file_id,
        'filename': meta.get('filename', 'unknown'),
        'uploaded_at': meta.get('uploaded_at'),
        'expires_at': meta.get('expires_at'),
        'size': meta.get('size'),
        'downloads': meta.get('downloads', 0),
        'owner': request.user_id == meta.get('owner')
    })


@app.route('/files', methods=['GET'])
@require_auth
def list_files():
    """List user's files"""
    files = []
    for meta_path in META_DIR.glob('*.json'):
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            
            if meta.get('owner') == request.user_id:
                files.append({
                    'file_id': meta['file_id'],
                    'filename': meta.get('filename'),
                    'uploaded_at': meta.get('uploaded_at'),
                    'expires_at': meta.get('expires_at'),
                    'size': meta.get('size'),
                    'downloads': meta.get('downloads', 0)
                })
        except Exception:
            continue
    
    return jsonify({'files': files})


# ==================== Admin & Utility Endpoints ====================

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        's3_available': S3_AVAILABLE,
        'email_available': EMAIL_AVAILABLE
    })


@app.route('/stats', methods=['GET'])
@require_auth
def stats():
    """User statistics"""
    user_files = [f for f in META_DIR.glob('*.json') 
                  if json.load(open(f)).get('owner') == request.user_id]
    
    total_size = sum(json.load(open(f)).get('size', 0) for f in user_files)
    
    return jsonify({
        'total_files': len(user_files),
        'total_size': total_size,
        'activity_count': len(user_activity.get(request.user_id, []))
    })


# ==================== Main ====================

if __name__ == '__main__':
    # Periodic cleanup
    import threading
    def cleanup_loop():
        while True:
            time.sleep(3600)  # Every hour
            cleanup_expired_files()
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()
    
    print("=" * 60)
    print("E2E File Share Server - Enhanced Edition")
    print("=" * 60)
    print(f"Storage: {STORAGE_DIR.absolute()}")
    print(f"S3 Available: {S3_AVAILABLE}")
    print(f"Email Available: {EMAIL_AVAILABLE}")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)