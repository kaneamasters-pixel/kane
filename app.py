import sqlite3, bcrypt, jwt, json, os, re
from flask import Flask, request, jsonify, render_template, make_response, send_from_directory
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
SECRET = os.environ.get('JWT_SECRET', 'meditation-secret-key-change-in-prod-2024')
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'db.sqlite')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE REFERENCES users(id),
            name TEXT,
            answers TEXT,
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sessions_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            completed_at TEXT DEFAULT (datetime('now'))
        );
    ''')
    conn.commit()
    conn.close()

def make_token(user_id):
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token') or request.headers.get('Authorization','').replace('Bearer ','')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=['HS256'])
            request.user_id = data['user_id']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    body = request.get_json()
    email = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Valid email required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_db()
        cur = conn.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, pw_hash))
        user_id = cur.lastrowid
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An account with this email already exists'}), 400
    token = make_token(user_id)
    resp = make_response(jsonify({'ok': True, 'token': token}))
    resp.set_cookie('token', token, httponly=True, samesite='Lax', max_age=30*24*3600)
    return resp

@app.route('/api/login', methods=['POST'])
def login():
    body = request.get_json()
    email = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Incorrect email or password'}), 401
    token = make_token(user['id'])
    resp = make_response(jsonify({'ok': True, 'token': token}))
    resp.set_cookie('token', token, httponly=True, samesite='Lax', max_age=30*24*3600)
    return resp

@app.route('/api/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('token')
    return resp

@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    conn = get_db()
    user = conn.execute('SELECT id, email, created_at FROM users WHERE id = ?', (request.user_id,)).fetchone()
    profile = conn.execute('SELECT name, answers, updated_at FROM profiles WHERE user_id = ?', (request.user_id,)).fetchone()
    count = conn.execute('SELECT COUNT(*) as c FROM sessions_log WHERE user_id = ?', (request.user_id,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user['id'],
        'email': user['email'],
        'created_at': user['created_at'],
        'profile': {
            'name': profile['name'] if profile else None,
            'answers': json.loads(profile['answers']) if profile and profile['answers'] else None,
            'updated_at': profile['updated_at'] if profile else None
        },
        'session_count': count['c']
    })

@app.route('/api/profile', methods=['POST'])
@require_auth
def save_profile():
    body = request.get_json()
    name = body.get('name', '')
    answers = json.dumps(body.get('answers', {}))
    conn = get_db()
    existing = conn.execute('SELECT id FROM profiles WHERE user_id = ?', (request.user_id,)).fetchone()
    if existing:
        conn.execute('UPDATE profiles SET name=?, answers=?, updated_at=datetime("now") WHERE user_id=?', (name, answers, request.user_id))
    else:
        conn.execute('INSERT INTO profiles (user_id, name, answers) VALUES (?, ?, ?)', (request.user_id, name, answers))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/session', methods=['POST'])
@require_auth
def log_session():
    conn = get_db()
    conn.execute('INSERT INTO sessions_log (user_id) VALUES (?)', (request.user_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/sessions', methods=['GET'])
@require_auth
def get_sessions():
    conn = get_db()
    rows = conn.execute('SELECT completed_at FROM sessions_log WHERE user_id = ? ORDER BY completed_at DESC LIMIT 30', (request.user_id,)).fetchall()
    conn.close()
    return jsonify({'sessions': [r['completed_at'] for r in rows]})

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5050)))
