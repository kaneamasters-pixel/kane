import os, bcrypt, jwt, json, re
from flask import Flask, request, jsonify, render_template, make_response
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
SECRET = os.environ.get('JWT_SECRET', 'meditation-secret-key-change-in-prod-2024')
DATABASE_URL = os.environ.get('DATABASE_URL', '')

def get_db():
    if DATABASE_URL:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn, 'pg'
    else:
        import sqlite3
        db_path = os.path.join(os.path.dirname(__file__), 'data', 'db.sqlite')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn, 'sqlite'

def init_db():
    conn, mode = get_db()
    cur = conn.cursor()
    if mode == 'pg':
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS profiles (
            id SERIAL PRIMARY KEY, user_id INTEGER UNIQUE REFERENCES users(id),
            name TEXT, answers TEXT, vision TEXT, plan_days INTEGER DEFAULT 7,
            updated_at TIMESTAMP DEFAULT NOW())''')
        cur.execute('''CREATE TABLE IF NOT EXISTS sessions_log (
            id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id),
            day_number INTEGER DEFAULT 1, duration_seconds INTEGER DEFAULT 0,
            takeaway TEXT, completed_at TIMESTAMP DEFAULT NOW())''')
        # Add missing columns if upgrading from old schema
        for col, defn in [('vision','TEXT'), ('plan_days','INTEGER DEFAULT 7')]:
            try:
                cur.execute(f'ALTER TABLE profiles ADD COLUMN IF NOT EXISTS {col} {defn}')
            except: pass
        for col, defn in [('day_number','INTEGER DEFAULT 1'),('duration_seconds','INTEGER DEFAULT 0'),('takeaway','TEXT')]:
            try:
                cur.execute(f'ALTER TABLE sessions_log ADD COLUMN IF NOT EXISTS {col} {defn}')
            except: pass
    else:
        cur.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE REFERENCES users(id),
                name TEXT, answers TEXT, vision TEXT, plan_days INTEGER DEFAULT 7,
                updated_at TEXT DEFAULT (datetime('now')));
            CREATE TABLE IF NOT EXISTS sessions_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id),
                day_number INTEGER DEFAULT 1, duration_seconds INTEGER DEFAULT 0,
                takeaway TEXT, completed_at TEXT DEFAULT (datetime('now')));
        ''')
    conn.commit(); conn.close()

def fetchone(cur, mode):
    row = cur.fetchone()
    if row is None: return None
    if mode == 'pg':
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))
    return dict(row)

def fetchall(cur, mode):
    rows = cur.fetchall()
    if mode == 'pg':
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in rows]
    return [dict(r) for r in rows]

def ph(mode): return '%s' if mode == 'pg' else '?'

def make_token(user_id):
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=30)}
    return jwt.encode(payload, SECRET, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (request.cookies.get('token') or 
                 request.headers.get('Authorization','').replace('Bearer ','').strip())
        if not token: return jsonify({'error': 'Unauthorized'}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=['HS256'])
            request.user_id = data['user_id']
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index(): return render_template('index.html')

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
        conn, mode = get_db(); cur = conn.cursor()
        if mode == 'pg':
            cur.execute(f'INSERT INTO users (email, password_hash) VALUES ({ph(mode)},{ph(mode)}) RETURNING id', (email, pw_hash))
            user_id = cur.fetchone()[0]
        else:
            cur.execute('INSERT INTO users (email, password_hash) VALUES (?,?)', (email, pw_hash))
            user_id = cur.lastrowid
        conn.commit(); conn.close()
    except Exception as e:
        if 'unique' in str(e).lower() or 'UNIQUE' in str(e):
            return jsonify({'error': 'An account with this email already exists'}), 400
        return jsonify({'error': 'Registration failed'}), 500
    token = make_token(user_id)
    resp = make_response(jsonify({'ok': True, 'token': token}))
    resp.set_cookie('token', token, httponly=False, samesite='Lax', max_age=30*24*3600, path='/')
    return resp

@app.route('/api/login', methods=['POST'])
def login():
    body = request.get_json()
    email = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    conn, mode = get_db(); cur = conn.cursor()
    cur.execute(f'SELECT * FROM users WHERE email = {ph(mode)}', (email,))
    user = fetchone(cur, mode); conn.close()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Incorrect email or password'}), 401
    token = make_token(user['id'])
    resp = make_response(jsonify({'ok': True, 'token': token}))
    resp.set_cookie('token', token, httponly=False, samesite='Lax', max_age=30*24*3600, path='/')
    return resp

@app.route('/api/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('token'); return resp

@app.route('/api/me', methods=['GET'])
@require_auth
def me():
    try:
        conn, mode = get_db(); cur = conn.cursor()
        cur.execute(f'SELECT id, email, created_at FROM users WHERE id = {ph(mode)}', (request.user_id,))
        user = fetchone(cur, mode)
        cur.execute(f'SELECT name, answers, vision, plan_days, updated_at FROM profiles WHERE user_id = {ph(mode)}', (request.user_id,))
        profile = fetchone(cur, mode)
        cur.execute(f'SELECT COUNT(*) as c FROM sessions_log WHERE user_id = {ph(mode)}', (request.user_id,))
        row = cur.fetchone(); count = row[0] if row else 0
        conn.close()
        if not user: return jsonify({'error': 'Not found'}), 404
        return jsonify({
            'id': user['id'], 'email': user['email'], 'created_at': str(user['created_at']),
            'profile': {
                'name': profile['name'] if profile else None,
                'answers': json.loads(profile['answers']) if profile and profile.get('answers') else None,
                'vision': profile.get('vision') if profile else None,
                'plan_days': profile.get('plan_days') or 7 if profile else 7,
                'updated_at': str(profile['updated_at']) if profile and profile.get('updated_at') else None
            },
            'session_count': count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['POST'])
@require_auth
def save_profile():
    body = request.get_json()
    name = body.get('name', '')
    answers = json.dumps(body.get('answers', {}))
    vision = body.get('vision', '')
    plan_days = body.get('plan_days', 7)
    conn, mode = get_db(); cur = conn.cursor()
    cur.execute(f'SELECT id FROM profiles WHERE user_id = {ph(mode)}', (request.user_id,))
    existing = cur.fetchone()
    if existing:
        if mode == 'pg':
            cur.execute('UPDATE profiles SET name=%s, answers=%s, vision=%s, plan_days=%s, updated_at=NOW() WHERE user_id=%s',
                       (name, answers, vision, plan_days, request.user_id))
        else:
            cur.execute('UPDATE profiles SET name=?, answers=?, vision=?, plan_days=?, updated_at=datetime("now") WHERE user_id=?',
                       (name, answers, vision, plan_days, request.user_id))
    else:
        cur.execute(f'INSERT INTO profiles (user_id, name, answers, vision, plan_days) VALUES ({ph(mode)},{ph(mode)},{ph(mode)},{ph(mode)},{ph(mode)})',
                   (request.user_id, name, answers, vision, plan_days))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/session', methods=['POST'])
@require_auth
def log_session():
    body = request.get_json() or {}
    day_number = body.get('day_number', 1)
    duration_seconds = body.get('duration_seconds', 0)
    takeaway = body.get('takeaway', '')
    conn, mode = get_db(); cur = conn.cursor()
    cur.execute(f'INSERT INTO sessions_log (user_id, day_number, duration_seconds, takeaway) VALUES ({ph(mode)},{ph(mode)},{ph(mode)},{ph(mode)})',
               (request.user_id, day_number, duration_seconds, takeaway))
    conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.route('/api/sessions', methods=['GET'])
@require_auth
def get_sessions():
    conn, mode = get_db(); cur = conn.cursor()
    cur.execute(f'SELECT day_number, duration_seconds, takeaway, completed_at FROM sessions_log WHERE user_id = {ph(mode)} ORDER BY completed_at DESC LIMIT 90', (request.user_id,))
    rows = fetchall(cur, mode); conn.close()
    return jsonify({'sessions': [{'day': r['day_number'], 'duration': r['duration_seconds'], 'takeaway': r['takeaway'], 'completed_at': str(r['completed_at'])} for r in rows]})

@app.route('/api/leaderboard', methods=['GET'])
@require_auth
def leaderboard():
    conn, mode = get_db(); cur = conn.cursor()
    if mode == 'pg':
        cur.execute('''SELECT u.id, p.name, u.email,
            COUNT(s.id) as total_sessions,
            COALESCE(MAX(s.day_number),0) as current_day,
            COALESCE(SUM(s.duration_seconds),0) as total_time,
            MAX(s.completed_at) as last_session
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            LEFT JOIN sessions_log s ON s.user_id = u.id
            GROUP BY u.id, p.name, u.email
            ORDER BY current_day DESC, total_sessions DESC LIMIT 50''')
    else:
        cur.execute('''SELECT u.id, p.name, u.email,
            COUNT(s.id) as total_sessions,
            COALESCE(MAX(s.day_number),0) as current_day,
            COALESCE(SUM(s.duration_seconds),0) as total_time,
            MAX(s.completed_at) as last_session
            FROM users u
            LEFT JOIN profiles p ON p.user_id = u.id
            LEFT JOIN sessions_log s ON s.user_id = u.id
            GROUP BY u.id
            ORDER BY current_day DESC, total_sessions DESC LIMIT 50''')
    rows = fetchall(cur, mode); conn.close()
    me_id = request.user_id
    result = []
    for i, r in enumerate(rows):
        display_name = r['name'] or r['email'].split('@')[0]
        result.append({
            'rank': i+1, 'name': display_name, 'is_me': r['id'] == me_id,
            'current_day': r['current_day'], 'total_sessions': r['total_sessions'],
            'total_time': r['total_time'], 'last_session': str(r['last_session']) if r['last_session'] else None
        })
    return jsonify({'leaderboard': result})

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5050)))
