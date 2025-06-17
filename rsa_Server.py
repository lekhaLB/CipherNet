import socket
import threading
import json
import sqlite3
import bcrypt
import secrets
import base64  # For encoding/decoding public keys and encrypted data

# ---------- Database Setup ----------
DATABASE_NAME = 'users.db'


def create_user_table():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    # public_key will store the Base64 encoded PEM public key string
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key TEXT -- Stores Base64 encoded PEM public key
        )
    ''')
    conn.commit()
    conn.close()


def register_user(username, password, public_key_b64):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute(
            'INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
            (username, hashed, public_key_b64)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def authenticate_user(username, password):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    return result and bcrypt.checkpw(password.encode(), result[0])

# NEW: Functions for public key management


def store_public_key(username, public_key_b64):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('UPDATE users SET public_key = ? WHERE username = ?',
              (public_key_b64, username))
    conn.commit()
    conn.close()
    print(f"[DB] Updated public key for {username}")


def get_public_key_b64(username):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


def get_all_public_keys_b64():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT username, public_key FROM users')
    results = c.fetchall()
    conn.close()
    public_keys_data = {}
    for username, public_key_b64 in results:
        if public_key_b64:  # Ensure key exists
            public_keys_data[username] = public_key_b64
    return public_keys_data


# ---------- Session Management ----------
active_sessions = {}  # token -> username
# username -> client_socket (Tracks online users and their connections)
online_users = {}


def generate_session(username, client_socket):
    token = secrets.token_hex(16)
    active_sessions[token] = username
    online_users[username] = client_socket
    print(f"[+] Session started for {username} -> Token: {token}")
    return token


def invalidate_session(token):
    """Invalidates a session token and removes the user from online_users."""
    if token in active_sessions:
        username = active_sessions.pop(token)
        if username in online_users:
            del online_users[username]
        print(f"[-] Session ended for {username}")
        return username
    return None


def validate_session(token):
    return active_sessions.get(token)

# ---------- Server Communication Helpers ----------


# def send_json(client_socket, data):
#     """Helper to send JSON data to a client."""
#     try:
#         json_data = json.dumps(data)
#         # Add a fixed-size header with message length (e.g., 8 bytes)
#         # This helps the client know how much data to expect for the JSON
#         message_length = len(json_data.encode('utf-8'))
#         header = f"{message_length:<8}".encode(
#             'utf-8')  # Left-align, pad with spaces
#         client_socket.sendall(header + json_data.encode('utf-8'))
#     except Exception as e:
#         print(f"Error sending data to client: {e}")
def send_json(client_socket, data):
    """Helper to send JSON data to a client."""
    try:
        json_data = json.dumps(data)
        message_length = len(json_data.encode('utf-8'))
        header = f"{message_length:<8}".encode(
            'utf-8')  # Left-align, pad with spaces

        print(
            f"[SERVER] Preparing to send JSON. Length: {message_length}. Header: {header!r}")
        print(f"[SERVER] JSON data: {json_data}")

        client_socket.sendall(header + json_data.encode('utf-8'))
        print("[SERVER] Data sent successfully.")
    except Exception as e:
        print(f"[SERVER ERROR] Error sending data to client: {e}")

# Modified to use length-prefixing for reliable message framing


def recv_json(client_socket):
    """Helper to receive JSON data from a client using length-prefixing."""
    try:
        # Read the 8-byte header
        header_bytes = client_socket.recv(8)
        if not header_bytes:
            return None  # Connection closed

        header_str = header_bytes.decode('utf-8').strip()
        message_length = int(header_str)

        full_message_bytes = b''
        bytes_received = 0
        while bytes_received < message_length:
            chunk = client_socket.recv(
                min(message_length - bytes_received, 4096))
            if not chunk:
                return None  # Connection closed unexpectedly
            full_message_bytes += chunk
            bytes_received += len(chunk)

        return json.loads(full_message_bytes.decode('utf-8'))
    except ValueError:  # If header is not a valid int
        print("Invalid message length header received.")
        return None
    except json.JSONDecodeError:
        print("Malformed JSON received.")
        return None
    except Exception as e:
        print(f"Error receiving data: {e}")
        return None


def broadcast_online_users_list():
    """Sends the current list of online users to all connected clients."""
    online_usernames = list(online_users.keys())
    message = {
        'action': 'online_users_list',
        'users': online_usernames
    }
    for client_socket in list(online_users.values()):
        send_json(client_socket, message)


# ---------- Socket Server Setup ----------
HOST = '127.0.0.1'
PORT = 5555


def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    current_session_token = None
    current_username = None

    try:
        while True:
            message = recv_json(conn)
            if message is None:  # Client disconnected or malformed message
                break

            print(
                f"[{addr}] Received: {message.get('action')} from {message.get('username') or message.get('from')}")

            action = message.get('action')

            if action == 'login':
                username = message.get('username')
                password = message.get('password')
                # Client sends its public key on login
                public_key_b64 = message.get('public_key')

                if username and password and authenticate_user(username, password):
                    if username in online_users and online_users[username] != conn:
                        send_json(
                            conn, {'status': 'fail', 'message': 'User already logged in elsewhere.'})
                        continue

                    current_session_token = generate_session(username, conn)
                    current_username = username

                    # Store/update the public key received from the client
                    if public_key_b64:
                        store_public_key(username, public_key_b64)

                    all_pks = get_all_public_keys_b64()  # Get all public keys for client caching

                    send_json(conn, {
                        'status': 'ok',
                        'session': current_session_token,
                        'username': username,
                        'public_keys': all_pks  # Send all public keys
                    })
                    broadcast_online_users_list()
                else:
                    send_json(conn, {'status': 'fail',
                              'message': 'Invalid credentials'})

            elif action == 'register':
                username = message.get('username')
                password = message.get('password')
                # Receive Base64 encoded PEM public key
                public_key_b64 = message.get('public_key')

                if username and password and public_key_b64:
                    success = register_user(username, password, public_key_b64)
                    if success:
                        send_json(conn, {'status': 'registered',
                                  'message': 'Registration successful'})
                    else:
                        send_json(conn, {'status': 'exists',
                                  'message': 'Username already exists'})
                else:
                    send_json(conn, {
                              'status': 'fail', 'message': 'Username, password, and public key required'})

            elif action == 'logout':
                token_to_invalidate = message.get('session')
                if token_to_invalidate and token_to_invalidate == current_session_token:
                    if invalidate_session(token_to_invalidate):
                        send_json(conn, {'status': 'logged_out',
                                  'message': 'Successfully logged out.'})
                        broadcast_online_users_list()
                        break
                    else:
                        send_json(conn, {'status': 'fail',
                                  'message': 'Session invalid.'})
                else:
                    send_json(
                        conn, {'status': 'fail', 'message': 'No active session or invalid token.'})

            elif action == 'message':
                token = message.get('session')
                recipient = message.get('recipient')
                encrypted_content_b64 = message.get(
                    'encrypted_content')  # Base64 encoded
                encrypted_aes_key_b64 = message.get(
                    'encrypted_aes_key')  # Base64 encoded

                sender_username = validate_session(token)

                if sender_username and sender_username == current_username:
                    if not recipient or not encrypted_content_b64 or not encrypted_aes_key_b64:
                        send_json(conn, {
                                  'status': 'fail', 'message': 'Missing recipient, encrypted_content, or encrypted_aes_key'})
                        continue

                    if recipient in online_users:
                        recipient_socket = online_users[recipient]
                        chat_message = {
                            'action': 'chat_message',
                            'from': sender_username,
                            'to': recipient,
                            'encrypted_content': encrypted_content_b64,
                            'encrypted_aes_key': encrypted_aes_key_b64
                        }
                        send_json(recipient_socket, chat_message)
                    else:
                        send_json(conn, {
                                  'status': 'fail', 'message': f'User "{recipient}" is offline or does not exist.'})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid or expired session'})

            elif action == 'get_online_users':
                token = message.get('session')
                user = validate_session(token)
                if user and user == current_username:
                    online_usernames = list(online_users.keys())
                    users_for_client = [
                        u for u in online_usernames if u != user]
                    send_json(
                        conn, {'action': 'online_users_list', 'users': users_for_client})
                else:
                    send_json(conn, {
                              'status': 'unauthorized', 'message': 'Invalid session to get online users'})

            elif action == 'get_public_keys':
                token = message.get('session')
                requester_username = validate_session(token)
                usernames_to_get = message.get('usernames', [])

                if requester_username and requester_username == current_username:
                    requested_pks = {}
                    for u in usernames_to_get:
                        pk_b64 = get_public_key_b64(u)
                        if pk_b64:
                            requested_pks[u] = pk_b64
                    send_json(
                        conn, {'action': 'public_keys_response', 'public_keys': requested_pks})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid session to get public keys'})

            else:
                send_json(conn, {'status': 'unknown_command',
                          'message': 'Unknown action'})

    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
    finally:
        if current_session_token:
            if active_sessions.get(current_session_token) == current_username:
                if current_username in online_users and online_users[current_username] == conn:
                    del online_users[current_username]
                del active_sessions[current_session_token]
                print(
                    f"[-] Cleaned up session for {current_username} on disconnect.")
                broadcast_online_users_list()
        conn.close()
        print(f"[-] Disconnected {addr}")


def start_server():
    create_user_table()

    # Create dummy users for testing if they don't exist.
    # Note: Their public keys will be added/updated when clients log in/register.
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    users_to_add = [('testuser', 'password123'),
                    ('user2', 'password123'), ('user3', 'password123')]
    for username, password in users_to_add:
        c.execute('SELECT username FROM users WHERE username=?', (username,))
        if not c.fetchone():
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            c.execute('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
                      (username, hashed, None))  # Public key starts as NULL
            print(
                f"[*] Registered '{username}' with password '{password}' (for testing).")
    conn.commit()
    conn.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
