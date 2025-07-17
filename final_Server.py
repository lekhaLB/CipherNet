import socket
import threading
import json
import sqlite3
import bcrypt
import secrets
import base64

# ---------- Database Setup ----------
DATABASE_NAME = 'users.db'


def create_user_table():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key TEXT -- Stores Base64 encoded PEM public key
        )
    ''')
    # New tables for group chat
    c.execute('''
        CREATE TABLE IF NOT EXISTS groups_ (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            creator_username TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            username TEXT,
            -- Stores the group's secret AES key, encrypted with this member's RSA public key
            encrypted_group_secret_key_b64 TEXT NOT NULL, 
            PRIMARY KEY (group_id, username),
            FOREIGN KEY (group_id) REFERENCES groups_(id) ON DELETE CASCADE,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
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
        if public_key_b64:
            public_keys_data[username] = public_key_b64
    return public_keys_data

# NEW: Group functions


def create_group_db(group_name, creator_username, members_with_encrypted_keys):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO groups_ (name, creator_username) VALUES (?, ?)',
                  (group_name, creator_username))
        group_id = c.lastrowid  # Get the ID of the newly created group

        for member_username, encrypted_key_b64 in members_with_encrypted_keys.items():
            c.execute('INSERT INTO group_members (group_id, username, encrypted_group_secret_key_b64) VALUES (?, ?, ?)',
                      (group_id, member_username, encrypted_key_b64))
        conn.commit()
        print(
            f"[DB] Group '{group_name}' (ID: {group_id}) created by {creator_username} with members: {list(members_with_encrypted_keys.keys())}")
        return group_id
    except sqlite3.IntegrityError as e:
        print(f"[DB Error] Could not create group {group_name}: {e}")
        conn.rollback()
        return None
    finally:
        conn.close()


def get_group_members(group_id):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT username FROM group_members WHERE group_id = ?', (group_id,))
    members = [row[0] for row in c.fetchall()]
    conn.close()
    return members


def get_user_groups(username):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''
        SELECT g.id, g.name, g.creator_username
        FROM groups_ g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.username = ?
    ''', (username,))
    groups_data = [{'id': row[0], 'name': row[1], 'creator': row[2]}
                   for row in c.fetchall()]
    conn.close()
    return groups_data


def get_encrypted_group_key_for_member(group_id, username):
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('''
        SELECT encrypted_group_secret_key_b64
        FROM group_members
        WHERE group_id = ? AND username = ?
    ''', (group_id, username))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


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


def send_json(client_socket, data):
    """Helper to send JSON data to a client."""
    try:
        json_data = json.dumps(data)
        message_length = len(json_data.encode('utf-8'))
        header = f"{message_length:<8}".encode('utf-8')
        client_socket.sendall(header + json_data.encode('utf-8'))
    except Exception as e:
        print(f"Error sending data to client: {e}")


def recv_json(client_socket):
    """Helper to receive JSON data from a client using length-prefixing."""
    try:
        header_bytes = client_socket.recv(8)
        if not header_bytes:
            return None

        header_str = header_bytes.decode('utf-8').strip()
        message_length = int(header_str)

        full_message_bytes = b''
        bytes_received = 0
        while bytes_received < message_length:
            chunk = client_socket.recv(
                min(message_length - bytes_received, 4096))
            if not chunk:
                return None
            full_message_bytes += chunk
            bytes_received += len(chunk)

        return json.loads(full_message_bytes.decode('utf-8'))
    except ValueError:
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
            if message is None:
                break

            action = message.get('action')
            if current_username:
                print(f"[{addr}] Received: {action} from {current_username}")
            else:
                print(
                    f"[{addr}] Received: {action} (pre-auth) {message.get('username')}")

            if action == 'login':
                username = message.get('username')
                password = message.get('password')
                public_key_b64 = message.get('public_key')

                if username and password and authenticate_user(username, password):
                    if username in online_users and online_users[username] != conn:
                        send_json(
                            conn, {'status': 'fail', 'message': 'User already logged in elsewhere.'})
                        continue

                    current_session_token = generate_session(username, conn)
                    current_username = username

                    if public_key_b64:
                        store_public_key(username, public_key_b64)

                    all_pks = get_all_public_keys_b64()
                    # NEW: Get user's groups on login
                    user_groups = get_user_groups(current_username)

                    send_json(conn, {
                        'status': 'ok',
                        'session': current_session_token,
                        'username': username,
                        'public_keys': all_pks,
                        'user_groups': user_groups  # Send user's groups
                    })
                    broadcast_online_users_list()
                else:
                    send_json(conn, {'status': 'fail',
                              'message': 'Invalid credentials'})

            elif action == 'register':
                username = message.get('username')
                password = message.get('password')
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
                sender_username = validate_session(token)
                recipient = message.get('recipient')
                encrypted_content = message.get('encrypted_content')
                encrypted_aes_key = message.get('encrypted_aes_key')
                self_destruct = message.get('self_destruct', False)
                destruct_after = message.get('destruct_after', 0)

                if sender_username and sender_username == current_username:
                    if not all([recipient, encrypted_content, encrypted_aes_key]):
                        send_json(
                            conn, {'status': 'fail', 'message': 'Missing message details.'})
                        continue

                    if recipient in online_users:
                        recipient_socket = online_users[recipient]

                        relay_message = {
                            'action': 'chat_message',
                            'from': sender_username,
                            'encrypted_content': encrypted_content,
                            'encrypted_aes_key': encrypted_aes_key,
                            'self_destruct': self_destruct,
                            'destruct_after': destruct_after
                        }

                        send_json(recipient_socket, relay_message)
                        send_json(
                            conn, {'status': 'ok', 'message': f'Message sent to {recipient}.'})
                    else:
                        send_json(conn, {
                                  'status': 'fail', 'message': f'User \"{recipient}\" is offline or does not exist.'})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid session to send message.'})

            elif action == 'group_message':
                token = message.get('session')
                sender_username = validate_session(token)
                group_id = message.get('group_id')
                encrypted_content = message.get('encrypted_content')
                encrypted_message_aes_key = message.get(
                    'encrypted_message_aes_key')
                self_destruct = message.get('self_destruct', False)
                destruct_after = message.get('destruct_after', 0)

                if sender_username and sender_username == current_username:
                    group_members = get_group_members(group_id)
                    if group_members:
                        relay_message = {
                            'action': 'group_chat_message',
                            'from': sender_username,
                            'group_id': group_id,
                            'encrypted_content': encrypted_content,
                            'encrypted_message_aes_key': encrypted_message_aes_key,
                            'self_destruct': self_destruct,
                            'destruct_after': destruct_after
                        }
                        for member_username in group_members:
                            if member_username in online_users and member_username != sender_username:
                                member_socket = online_users[member_username]
                                send_json(member_socket, relay_message)
                        send_json(
                            conn, {'status': 'ok', 'message': f'Group message sent to {group_id}.'})
                    else:
                        send_json(conn, {'status': 'fail',
                                         'message': 'Group not found.'})
                else:
                    send_json(conn, {
                        'status': 'unauthorized', 'message': 'Invalid session to send group message.'})

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

            elif action == 'create_group':  # NEW: Create Group action
                token = message.get('session')
                creator_username = validate_session(token)
                group_name = message.get('group_name')
                # Dictionary of {member_username: RSA_encrypted_GROUP_SECRET_KEY_b64}
                members_with_encrypted_keys = message.get(
                    'members_with_encrypted_keys')

                if creator_username and creator_username == current_username and group_name and members_with_encrypted_keys:
                    group_id = create_group_db(
                        group_name, creator_username, members_with_encrypted_keys)
                    if group_id:
                        send_json(conn, {'status': 'ok', 'action': 'group_created',
                                  'group_id': group_id, 'group_name': group_name})
                        # Notify all members that a new group was created, so they can fetch their key
                        group_members_list = list(
                            members_with_encrypted_keys.keys())
                        for member_username in group_members_list:
                            # Don't send back to creator, they already know
                            if member_username in online_users and online_users[member_username] != conn:
                                send_json(online_users[member_username], {
                                    'action': 'new_group_notification',
                                    'group_id': group_id,
                                    'group_name': group_name,
                                    'creator': creator_username
                                })
                    else:
                        send_json(conn, {
                                  'status': 'fail', 'message': 'Failed to create group. Group name might exist.'})
                else:
                    send_json(conn, {
                              'status': 'unauthorized', 'message': 'Invalid session or missing group details.'})

            elif action == 'get_my_groups':  # NEW: Get user's groups action
                token = message.get('session')
                username = validate_session(token)
                if username and username == current_username:
                    user_groups = get_user_groups(username)
                    send_json(
                        conn, {'action': 'my_groups_list', 'groups': user_groups})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid session to get groups.'})

            elif action == 'get_encrypted_group_key':  # NEW: Get specific encrypted group key for a member
                token = message.get('session')
                username = validate_session(token)
                group_id = message.get('group_id')
                if username and username == current_username and group_id:
                    encrypted_group_secret_key_b64 = get_encrypted_group_key_for_member(
                        group_id, username)
                    if encrypted_group_secret_key_b64:
                        send_json(conn, {'action': 'encrypted_group_key_response',
                                         'group_id': group_id,
                                         'encrypted_group_secret_key_b64': encrypted_group_secret_key_b64})
                    else:
                        send_json(conn, {
                                  'status': 'fail', 'message': 'Group key not found for this user in this group.'})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid session or group ID.'})

            # --- FILE SHARING HANDLERS ---
            elif action == 'file':
                token = message.get('session')
                sender_username = validate_session(token)
                recipient = message.get('recipient')
                filename = message.get('filename')
                filedata = message.get('filedata')
                if sender_username and sender_username == current_username:
                    if recipient in online_users:
                        relay = {
                            "action": "file_message",
                            "from": sender_username,
                            "filename": filename,
                            "filedata": filedata
                        }
                        send_json(online_users[recipient], relay)
                        send_json(
                            conn, {'status': 'ok', 'message': f'File sent to {recipient}.'})
                    else:
                        send_json(conn, {
                            'status': 'fail', 'message': f'User \"{recipient}\" is offline or does not exist.'})
                else:
                    send_json(conn, {'status': 'unauthorized',
                                     'message': 'Invalid session to send file.'})

            elif action == 'group_file':
                token = message.get('session')
                sender_username = validate_session(token)
                group_id = message.get('group_id')
                filename = message.get('filename')
                filedata = message.get('filedata')
                if sender_username and sender_username == current_username:
                    group_members = get_group_members(group_id)
                    if group_members:
                        relay = {
                            "action": "group_file_message",
                            "from": sender_username,
                            "group_id": group_id,
                            "filename": filename,
                            "filedata": filedata
                        }
                        for member in group_members:
                            if member in online_users and member != sender_username:
                                send_json(online_users[member], relay)
                        send_json(
                            conn, {'status': 'ok', 'message': f'File sent to group {group_id}.'})
                    else:
                        send_json(conn, {'status': 'fail',
                                         'message': 'Group not found.'})
                else:
                    send_json(conn, {
                        'status': 'unauthorized', 'message': 'Invalid session to send group file.'})
            # --- END FILE SHARING HANDLERS ---

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

    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    users_to_add = [('testuser', 'password123'),
                    ('user2', 'password123'), ('user3', 'password123')]
    for username, password in users_to_add:
        c.execute('SELECT username FROM users WHERE username=?', (username,))
        if not c.fetchone():
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            c.execute('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
                      (username, hashed, None))
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
