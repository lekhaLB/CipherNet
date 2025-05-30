import socket
import threading
import json
import sqlite3
import bcrypt
import secrets

# ---------- Database Setup ----------


def create_user_table():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def register_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    return result and bcrypt.checkpw(password.encode(), result[0])


# ---------- Session Management ----------
active_sessions = {}  # token -> username


def generate_session(username):
    token = secrets.token_hex(16)
    active_sessions[token] = username
    print(f"[+] Session started for {username} -> Token: {token}")
    return token


def validate_session(token):
    return active_sessions.get(token)


# ---------- Socket Server Setup ----------
HOST = '127.0.0.1'
PORT = 5555


def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    session_token = None

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                message = json.loads(data.decode())
                print(f"[{addr}] Received: {message}")
            except json.JSONDecodeError:
                conn.send(json.dumps({'status': 'invalid_json'}).encode())
                continue

            action = message.get('action')

            if action == 'login':
                username = message.get('username')
                password = message.get('password')
                if username and password and authenticate_user(username, password):
                    session_token = generate_session(username)
                    conn.send(json.dumps(
                        {'status': 'ok', 'session': session_token}).encode())
                else:
                    conn.send(json.dumps({'status': 'fail'}).encode())

            elif action == 'message':
                token = message.get('session')
                content = message.get('content')
                user = validate_session(token)
                if user:
                    print(f"[{user}] Message: {content}")
                    conn.send(json.dumps({'status': 'received'}).encode())
                else:
                    conn.send(json.dumps({'status': 'unauthorized'}).encode())

            elif message['action'] == 'register':
                username = message.get('username')
                password = message.get('password')
                if username and password:
                    success = register_user(username, password)
                    if success:
                        conn.send(json.dumps(
                            {'status': 'registered'}).encode())
                    else:
                        conn.send(json.dumps({'status': 'exists'}).encode())
                else:
                    conn.send(json.dumps({'status': 'fail'}).encode())

            else:
                conn.send(json.dumps({'status': 'unknown_command'}).encode())

    except Exception as e:
        print(f"[-] Error handling {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")


def start_server():
    create_user_table()

    # Safe conditional registration
    if not authenticate_user('testuser', 'password123'):
        register_user('testuser', 'password123')

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Server started on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(
            target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
