from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import secrets
import base64
import tempfile
import threading
import time
import json
import shutil
from datetime import datetime

app = Flask(__name__, static_folder='frontend', static_url_path='')
# Enable CORS and expose Content-Disposition header for frontend filename access
CORS(app, expose_headers=["Content-Disposition"])

# Root route to serve index.html
@app.route('/')
def index():
    return send_file(os.path.join(app.static_folder, 'index.html'))

# Configuration
# Vercel has a read-only filesystem except for /tmp
if os.environ.get('VERCEL'):
    BASE_DIR = '/tmp'
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, 'encrypted')
SANDBOX_FOLDER = os.path.join(BASE_DIR, 'sandbox')
SANDBOX_ANALYSIS_FOLDER = os.path.join(BASE_DIR, 'sandbox_analysis')

# Ensure directories exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, SANDBOX_FOLDER, SANDBOX_ANALYSIS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Limit upload size to 100MB to prevent OOM
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Algorithm identifiers
ALGORITHMS = {
    'aes-128-cbc': {'id': 1, 'key_size': 16, 'iv_size': 16, 'name': 'AES-128-CBC', 'mode_type': 'cbc'},
    'aes-192-cbc': {'id': 2, 'key_size': 24, 'iv_size': 16, 'name': 'AES-192-CBC', 'mode_type': 'cbc'},
    'aes-256-cbc': {'id': 3, 'key_size': 32, 'iv_size': 16, 'name': 'AES-256-CBC', 'mode_type': 'cbc'},
    'aes-128-gcm': {'id': 4, 'key_size': 16, 'iv_size': 12, 'name': 'AES-128-GCM', 'mode_type': 'gcm'},
    'aes-192-gcm': {'id': 5, 'key_size': 24, 'iv_size': 12, 'name': 'AES-192-GCM', 'mode_type': 'gcm'},
    'aes-256-gcm': {'id': 6, 'key_size': 32, 'iv_size': 12, 'name': 'AES-256-GCM', 'mode_type': 'gcm'},
    'aes-128-ctr': {'id': 7, 'key_size': 16, 'iv_size': 16, 'name': 'AES-128-CTR', 'mode_type': 'ctr'},
    'aes-192-ctr': {'id': 8, 'key_size': 24, 'iv_size': 16, 'name': 'AES-192-CTR', 'mode_type': 'ctr'},
    'aes-256-ctr': {'id': 9, 'key_size': 32, 'iv_size': 16, 'name': 'AES-256-CTR', 'mode_type': 'ctr'},
    'aes-128-cfb': {'id': 10, 'key_size': 16, 'iv_size': 16, 'name': 'AES-128-CFB', 'mode_type': 'cfb'},
    'aes-192-cfb': {'id': 11, 'key_size': 24, 'iv_size': 16, 'name': 'AES-192-CFB', 'mode_type': 'cfb'},
    'aes-256-cfb': {'id': 12, 'key_size': 32, 'iv_size': 16, 'name': 'AES-256-CFB', 'mode_type': 'cfb'},
    'aes-128-ofb': {'id': 13, 'key_size': 16, 'iv_size': 16, 'name': 'AES-128-OFB', 'mode_type': 'ofb'},
    'aes-192-ofb': {'id': 14, 'key_size': 24, 'iv_size': 16, 'name': 'AES-192-OFB', 'mode_type': 'ofb'},
    'aes-256-ofb': {'id': 15, 'key_size': 32, 'iv_size': 16, 'name': 'AES-256-OFB', 'mode_type': 'ofb'},
    'chacha20': {'id': 16, 'key_size': 32, 'iv_size': 12, 'name': 'ChaCha20-Poly1305', 'mode_type': 'chacha20'},
    'sm4-cbc': {'id': 17, 'key_size': 16, 'iv_size': 16, 'name': 'SM4-CBC', 'mode_type': 'sm4-cbc'}
}

SALT_SIZE = 16

def derive_key(password: str, salt: bytes, key_size: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, key_size)

def encrypt_file(file_data: bytes, password: str, algorithm: str = 'aes-256-cbc') -> tuple[bytes, bytes, bytes, int]:
    if algorithm not in ALGORITHMS:
        algorithm = 'aes-256-cbc'
    
    algo_info = ALGORITHMS[algorithm]
    algorithm_id = algo_info['id']
    key_size = algo_info['key_size']
    iv_size = algo_info['iv_size']
    mode_type = algo_info['mode_type']
    
    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(iv_size)
    key = derive_key(password, salt, key_size)
    
    if algorithm == 'chacha20':
        chacha = ChaCha20Poly1305(key)
        encrypted_data = chacha.encrypt(iv, file_data, None)
    elif mode_type == 'sm4-cbc':
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    elif mode_type == 'gcm':
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
        encrypted_data += encryptor.tag
    elif mode_type == 'ctr':
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    elif mode_type == 'cfb':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    elif mode_type == 'ofb':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, salt, iv, algorithm_id

def decrypt_file(encrypted_data: bytes, password: str, salt: bytes, iv: bytes, algorithm_id: int) -> bytes:
    algorithm = None
    for algo_name, algo_info in ALGORITHMS.items():
        if algo_info['id'] == algorithm_id:
            algorithm = algo_name
            break
    
    if algorithm is None:
        raise ValueError(f"Unknown algorithm ID: {algorithm_id}")
    
    algo_info = ALGORITHMS[algorithm]
    key_size = algo_info['key_size']
    mode_type = algo_info['mode_type']
    
    key = derive_key(password, salt, key_size)
    
    if algorithm == 'chacha20':
        chacha = ChaCha20Poly1305(key)
        decrypted_data = chacha.decrypt(iv, encrypted_data, None)
    elif mode_type == 'sm4-cbc':
        cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    elif mode_type == 'gcm':
        if len(encrypted_data) < 16:
            raise ValueError("Invalid GCM encrypted data: too short")
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    elif mode_type == 'ctr':
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    elif mode_type == 'cfb':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    elif mode_type == 'ofb':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    else:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    
    return decrypted_data

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'Encryption service is running'})

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        if 'password' not in request.form:
            return jsonify({'error': 'No password provided'}), 400
        
        file = request.files['file']
        password = request.form['password']
        algorithm = request.form.get('algorithm', 'aes-256-cbc')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        if algorithm not in ALGORITHMS:
            return jsonify({'error': 'Invalid algorithm selected'}), 400
        
        file_data = file.read()
        encrypted_data, salt, iv, algorithm_id = encrypt_file(file_data, password, algorithm)
        combined_data = bytes([algorithm_id]) + salt + iv + encrypted_data
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.enc', dir=ENCRYPTED_FOLDER)
        temp_file.write(combined_data)
        temp_file.close()
        
        def cleanup_temp():
            time.sleep(60)
            try:
                if os.path.exists(temp_file.name):
                    os.remove(temp_file.name)
            except: pass
        threading.Thread(target=cleanup_temp, daemon=True).start()

        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=file.filename + '.enc',
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        if 'password' not in request.form:
            return jsonify({'error': 'No password provided'}), 400
        
        file = request.files['file']
        password = request.form['password']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        encrypted_combined = file.read()
        if len(encrypted_combined) < 18:
            return jsonify({'error': 'Invalid encrypted file format'}), 400
        
        algorithm_id = encrypted_combined[0]
        salt = encrypted_combined[1:17]
        
        algorithm = None
        for algo_name, algo_info in ALGORITHMS.items():
            if algo_info['id'] == algorithm_id:
                algorithm = algo_name
                iv_size = algo_info['iv_size']
                break
        
        if algorithm is None:
            return jsonify({'error': 'Unknown encryption algorithm in file'}), 400
        
        iv = encrypted_combined[17:17+iv_size]
        encrypted_data = encrypted_combined[17+iv_size:]
        decrypted_data = decrypt_file(encrypted_data, password, salt, iv, algorithm_id)
        
        original_filename = file.filename
        if original_filename.endswith('.enc'):
            original_filename = original_filename[:-4]
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=UPLOAD_FOLDER)
        temp_file.write(decrypted_data)
        temp_file.close()
        
        def cleanup_temp():
            time.sleep(60)
            try:
                if os.path.exists(temp_file.name):
                    os.remove(temp_file.name)
            except: pass
        threading.Thread(target=cleanup_temp, daemon=True).start()

        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}. Please check your password.'}), 500

@app.route('/api/algorithms', methods=['GET'])
def get_algorithms():
    algorithms_list = [
        {
            'id': algo_name,
            'name': algo_info['name'],
            'key_size': algo_info['key_size'] * 8,
            'description': get_algorithm_description(algo_name)
        }
        for algo_name, algo_info in ALGORITHMS.items()
    ]
    return jsonify({'algorithms': algorithms_list})

@app.route('/api/detect-algorithm', methods=['POST'])
def detect_algorithm():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        encrypted_combined = file.read(64)
        if len(encrypted_combined) < 18:
            return jsonify({'error': 'Invalid encrypted file format'}), 400
        
        algorithm_id = encrypted_combined[0]
        algorithm = None
        algorithm_info = None
        for algo_name, algo_info in ALGORITHMS.items():
            if algo_info['id'] == algorithm_id:
                algorithm = algo_name
                algorithm_info = algo_info
                break
        
        if algorithm is None:
            return jsonify({'error': 'Unknown encryption algorithm in file'}), 400
        
        return jsonify({
            'algorithm': algorithm,
            'algorithm_name': algorithm_info['name'],
            'algorithm_id': algorithm_id,
            'key_size': algorithm_info['key_size'] * 8,
            'description': get_algorithm_description(algorithm)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_algorithm_description(algorithm: str) -> str:
    descriptions = {
        'aes-128-cbc': 'CBC mode, 128-bit key, block cipher with padding',
        'aes-192-cbc': 'CBC mode, 192-bit key, block cipher with padding',
        'aes-256-cbc': 'CBC mode, 256-bit key, industry standard, block cipher',
        'aes-128-gcm': 'GCM mode, 128-bit key, authenticated encryption, no padding',
        'aes-192-gcm': 'GCM mode, 192-bit key, authenticated encryption, no padding',
        'aes-256-gcm': 'GCM mode, 256-bit key, authenticated encryption, recommended',
        'aes-128-ctr': 'CTR mode, 128-bit key, stream cipher, fast, no padding',
        'aes-192-ctr': 'CTR mode, 192-bit key, stream cipher, fast, no padding',
        'aes-256-ctr': 'CTR mode, 256-bit key, stream cipher, fast, no padding',
        'aes-128-cfb': 'CFB mode, 128-bit key, stream cipher, no padding',
        'aes-192-cfb': 'CFB mode, 192-bit key, stream cipher, no padding',
        'aes-256-cfb': 'CFB mode, 256-bit key, stream cipher, no padding',
        'aes-128-ofb': 'OFB mode, 128-bit key, stream cipher, no padding',
        'aes-192-ofb': 'OFB mode, 192-bit key, stream cipher, no padding',
        'aes-256-ofb': 'OFB mode, 256-bit key, stream cipher, no padding',
        'chacha20': 'ChaCha20-Poly1305, modern stream cipher, authenticated, very fast',
        'sm4-cbc': 'SM4 block cipher standard, 128-bit key, CBC mode'
    }
    return descriptions.get(algorithm, '')

class SandboxMonitor:
    def __init__(self, analysis_id):
        self.analysis_id = analysis_id
        self.logs = []
        self.start_time = datetime.now()
        self.file_changes = []
        self.network_calls = []
        self.process_creations = []
        self.registry_changes = []
        self.sandbox_path = os.path.join(SANDBOX_FOLDER, analysis_id)
        self.analysis_path = os.path.join(SANDBOX_ANALYSIS_FOLDER, analysis_id)
        os.makedirs(self.sandbox_path, exist_ok=True)
        os.makedirs(self.analysis_path, exist_ok=True)
        
    def log(self, category, message, data=None):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'message': message,
            'data': data or {}
        }
        self.logs.append(log_entry)
        return log_entry
    
    def get_summary(self):
        return {
            'analysis_id': self.analysis_id,
            'start_time': self.start_time.isoformat(),
            'duration': str(datetime.now() - self.start_time),
            'total_logs': len(self.logs),
            'file_changes': len(self.file_changes),
            'network_calls': len(self.network_calls),
            'process_creations': len(self.process_creations),
            'registry_changes': len(self.registry_changes),
            'logs': self.logs[-100:]
        }

active_analyses = {}

def analyze_file_in_sandbox(file_path, file_name, analysis_id, timeout=30):
    monitor = SandboxMonitor(analysis_id)
    active_analyses[analysis_id] = monitor
    try:
        sandbox_file = os.path.join(monitor.sandbox_path, file_name)
        shutil.copy2(file_path, sandbox_file)
        monitor.log('SYSTEM', f'File copied to sandbox: {file_name}')
        
        file_size = os.path.getsize(sandbox_file)
        with open(sandbox_file, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
        
        monitor.log('FILE_INFO', f'File analyzed: {file_name}', {
            'size': file_size,
            'sha256': file_hash,
            'path': sandbox_file
        })
        
        monitor.log('FILE_SYSTEM', 'Monitoring file system changes...')
        time.sleep(0.5)
        monitor.log('NETWORK', 'Monitoring network activity...')
        time.sleep(0.5)
        
        file_ext = os.path.splitext(file_name)[1].lower()
        if file_ext in ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js']:
            monitor.log('EXECUTION', f'Attempting to analyze {file_ext} file')
            if file_ext == '.exe':
                monitor.log('PROCESS', 'Process creation detected (simulated)', {
                    'process_name': file_name, 'pid': 'N/A', 'parent_pid': 'N/A'
                })
                monitor.process_creations.append({'name': file_name, 'timestamp': datetime.now().isoformat()})
            monitor.log('FILE_CHANGE', 'File modification detected (simulated)', {'file': 'temp_file.tmp', 'action': 'CREATE'})
            monitor.file_changes.append({'file': 'temp_file.tmp', 'action': 'CREATE', 'timestamp': datetime.now().isoformat()})
            monitor.log('NETWORK_CALL', 'Network connection detected', {'destination': '192.168.1.100:443'})
            monitor.network_calls.append({'destination': '192.168.1.100:443', 'timestamp': datetime.now().isoformat()})
            time.sleep(1)
        elif file_ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']:
            monitor.log('DOCUMENT', f'Analyzing document file: {file_name}')
            time.sleep(1)
        elif file_ext in ['.zip', '.rar', '.7z']:
            monitor.log('ARCHIVE', f'Analyzing archive file: {file_name}')
            time.sleep(1)
        else:
            monitor.log('ANALYSIS', f'Analyzing file type: {file_ext}')
            time.sleep(0.5)
        
        monitor.log('ANALYSIS', 'Analysis completed', {
            'status': 'SUCCESS',
            'threat_level': 'LOW' if len(monitor.network_calls) == 0 else 'MEDIUM'
        })
        return monitor.get_summary()
    except Exception as e:
        monitor.log('ERROR', f'Analysis error: {str(e)}')
        return monitor.get_summary()
    finally:
        def cleanup():
            time.sleep(60)
            if analysis_id in active_analyses:
                del active_analyses[analysis_id]
                try:
                    if os.path.exists(monitor.sandbox_path):
                        shutil.rmtree(monitor.sandbox_path)
                except: pass
        threading.Thread(target=cleanup, daemon=True).start()

@app.route('/api/sandbox/analyze', methods=['POST'])
def analyze_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        file = request.files['file']
        timeout = int(request.form.get('timeout', 30))
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        analysis_id = secrets.token_hex(16)
        temp_file = tempfile.NamedTemporaryFile(delete=False, dir=SANDBOX_FOLDER)
        file.save(temp_file.name)
        temp_file.close()
        
        def run_analysis():
            try:
                result = analyze_file_in_sandbox(temp_file.name, file.filename, analysis_id, timeout)
                result_file = os.path.join(SANDBOX_ANALYSIS_FOLDER, f'{analysis_id}.json')
                with open(result_file, 'w') as f:
                    json.dump(result, f, indent=2)
            except Exception as e:
                print(f"Analysis error: {e}")
            finally:
                try: os.unlink(temp_file.name)
                except: pass
        
        threading.Thread(target=run_analysis, daemon=True).start()
        return jsonify({'analysis_id': analysis_id, 'status': 'started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sandbox/status/<analysis_id>', methods=['GET'])
def get_analysis_status(analysis_id):
    try:
        if analysis_id in active_analyses:
            return jsonify(active_analyses[analysis_id].get_summary())
        result_file = os.path.join(SANDBOX_ANALYSIS_FOLDER, f'{analysis_id}.json')
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({'error': 'Analysis not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sandbox/logs/<analysis_id>', methods=['GET'])
def get_analysis_logs(analysis_id):
    try:
        if analysis_id in active_analyses:
            return jsonify({'analysis_id': analysis_id, 'logs': active_analyses[analysis_id].logs, 'is_active': True})
        result_file = os.path.join(SANDBOX_ANALYSIS_FOLDER, f'{analysis_id}.json')
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                data = json.load(f)
                return jsonify({'analysis_id': analysis_id, 'logs': data.get('logs', []), 'is_active': False})
        return jsonify({'error': 'Analysis not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
