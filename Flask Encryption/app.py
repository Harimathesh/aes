from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from Crypto.Cipher import AES
import base64
import os
import io
import json
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

# -------------------- USER MANAGEMENT --------------------

USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

if not os.path.exists(USER_FILE):
    save_users({"admin": {"password": "1234", "role": "admin"}})

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/index')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    users = load_users()
    
    if username in users and users[username]["password"] == password:
        session.update({'logged_in': True, 'username': username, 'role': users[username].get("role", "user")})
        return jsonify({"success": True, "redirect": url_for('index')})
    return jsonify({"success": False, "error": "Invalid Username or Password ❌"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

# -------------------- TEXT ENCRYPTION/DECRYPTION --------------------

MAX_TEXT_SIZE = 10 * 1024 * 1024  # 10MB

@app.route('/encrypt-text', methods=['POST'])
def encrypt_text():
    try:
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json()
            text = data.get('text', '')
            key_size = int(data.get('key_size', 256))
        else:
            text = request.form.get('text', '')
            key_size = int(request.form.get('key_size', 256))
        
        # Validate input
        if not text:
            return jsonify({"success": False, "error": "No text provided"}), 400
        
        if len(text.encode('utf-8')) > MAX_TEXT_SIZE:
            return jsonify({"success": False, "error": f"Text too large (max {MAX_TEXT_SIZE//1024//1024}MB)"}), 400
        
        # Generate key and encrypt
        key = os.urandom(key_size // 8)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        
        # Return single combined string for easier handling
        encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        return jsonify({
            "success": True,
            "encrypted": encrypted,
            "key": key_b64,
            "input_type": detect_input_type(text)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def detect_input_type(text):
    """Detect the type of input text"""
    try:
        json.loads(text)
        return "json"
    except:
        pass
    
    if re.match(r'^\s*[\w-]+\s*:\s*.+', text):  # Simple YAML detection
        return "yaml"
    
    if re.match(r'^\s*<\?xml|<[a-zA-Z]', text):  # XML detection
        return "xml"
    
    if '=' in text and '\n' in text:  # Config file detection
        return "config"
    
    return "text"

@app.route('/decrypt-text', methods=['POST'])
def decrypt_text():
    try:
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json()
            encrypted = data.get('encrypted', '')
            key = data.get('key', '')
        else:
            encrypted = request.form.get('encrypted', '')
            key = request.form.get('key', '')
        
        if not encrypted or not key:
            return jsonify({"success": False, "error": "Missing encrypted data or key"}), 400
        
        # Decode components
        key_bytes = base64.b64decode(key.encode('utf-8'))
        encrypted_bytes = base64.b64decode(encrypted.encode('utf-8'))
        nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
        
        # Decrypt
        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        
        return jsonify({
            "success": True,
            "decrypted": decrypted,
            "input_type": detect_input_type(decrypted)
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Decryption failed: {str(e)}"}), 400

# -------------------- IMAGE ENCRYPTION/DECRYPTION --------------------

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
MAX_IMAGE_SIZE = 20 * 1024 * 1024  # 20MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/encrypt-image', methods=['POST'])
def encrypt_image():
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "error": "No image provided"}), 400
        
        image_file = request.files['image']
        key_size = int(request.form.get('key_size', 256))
        
        if not allowed_file(image_file.filename):
            return jsonify({"success": False, "error": f"Invalid image format. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"}), 400
        
        # Check file size
        image_file.seek(0, os.SEEK_END)
        file_size = image_file.tell()
        image_file.seek(0)
        
        if file_size > MAX_IMAGE_SIZE:
            return jsonify({"success": False, "error": f"Image too large (max {MAX_IMAGE_SIZE//1024//1024}MB)"}), 400
        
        # Encrypt
        key = os.urandom(key_size // 8)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(image_file.read())
        
        # Return as single combined string
        encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        return jsonify({
            "success": True,
            "encrypted": encrypted,
            "key": key_b64,
            "original_filename": image_file.filename,
            "original_size": file_size
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/decrypt-image', methods=['POST'])
def decrypt_image():
    try:
        # Accept both JSON and form data
        if request.is_json:
            data = request.get_json()
            encrypted = data.get('encrypted', '')
            key = data.get('key', '')
        else:
            encrypted = request.form.get('encrypted', '')
            key = request.form.get('key', '')
        
        if not encrypted or not key:
            return jsonify({"success": False, "error": "Missing encrypted data or key"}), 400
        
        # Decode components
        key_bytes = base64.b64decode(key.encode('utf-8'))
        encrypted_bytes = base64.b64decode(encrypted.encode('utf-8'))
        nonce, tag, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:32], encrypted_bytes[32:]
        
        # Decrypt
        cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Determine content type
        content_type = 'image/jpeg'
        if encrypted_bytes[0:4] == b'\x89PNG':
            content_type = 'image/png'
        elif encrypted_bytes[0:3] == b'GIF':
            content_type = 'image/gif'
        elif encrypted_bytes[0:2] == b'BM':
            content_type = 'image/bmp'
        elif encrypted_bytes[0:4] == b'RIFF' and encrypted_bytes[8:12] == b'WEBP':
            content_type = 'image/webp'
        
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype=content_type,
            as_attachment=False
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"Image decryption failed: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(debug=True)