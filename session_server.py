import socket
import threading
import json
import sqlite3
import bcrypt
import secrets

# ---------- Database Setup ----------
DATABASE_NAME = 'users.db'  # Define database name for consistency


def create_user_table():
    conn = sqlite3.connect(DATABASE_NAME)
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
    conn = sqlite3.connect(DATABASE_NAME)
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
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()
    return result and bcrypt.checkpw(password.encode(), result[0])


# ---------- Session Management ----------
active_sessions = {}  # token -> username
# username -> client_socket (NEW: Tracks online users and their connections)
online_users = {}


def generate_session(username, client_socket):
    token = secrets.token_hex(16)
    active_sessions[token] = username
    online_users[username] = client_socket  # NEW: Add user to online_users
    print(f"[+] Session started for {username} -> Token: {token}")
    return token


def invalidate_session(token):
    """Invalidates a session token and removes the user from online_users."""
    if token in active_sessions:
        username = active_sessions.pop(token)  # Remove from active sessions
        if username in online_users:  # If the user is currently marked as online
            # This is the corrected line: no comparison with 'client_socket'
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
        client_socket.send(json.dumps(data).encode('utf-8'))
    except Exception as e:
        print(f"Error sending data to client: {e}")


def broadcast_online_users_list():
    """Sends the current list of online users to all connected clients."""
    online_usernames = list(online_users.keys())
    # Prepare the message for broadcasting
    message = {
        'action': 'online_users_list',
        'users': online_usernames
    }
    json_message = json.dumps(message).encode('utf-8')

    # Iterate over a copy of the values to avoid RuntimeError during dictionary modification
    for client_socket in list(online_users.values()):
        try:
            client_socket.send(json_message)
        except Exception as e:
            # If sending fails, the client probably disconnected.
            # It will be cleaned up in handle_client's finally block.
            print(
                f"Warning: Could not broadcast to a client socket. Error: {e}")


# ---------- Socket Server Setup ----------
HOST = '127.0.0.1'
PORT = 5555


def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    current_session_token = None
    current_username = None  # Keep track of the username for this connection

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break  # Client disconnected

            try:
                message = json.loads(data.decode('utf-8'))  # Decode with utf-8
                print(f"[{addr}] Received: {message}")
            except json.JSONDecodeError:
                send_json(conn, {'status': 'invalid_json',
                          'message': 'Malformed JSON received'})
                continue

            action = message.get('action')

            if action == 'login':
                username = message.get('username')
                password = message.get('password')
                if username and password and authenticate_user(username, password):
                    # Check if user is already logged in from another place
                    if username in online_users and online_users[username] != conn:
                        send_json(
                            conn, {'status': 'fail', 'message': 'User already logged in elsewhere.'})
                        continue

                    current_session_token = generate_session(
                        username, conn)  # Pass client socket
                    current_username = username
                    send_json(
                        conn, {'status': 'ok', 'session': current_session_token, 'username': username})
                    broadcast_online_users_list()  # Notify all clients of new online user
                else:
                    send_json(conn, {'status': 'fail',
                              'message': 'Invalid credentials'})

            elif action == 'register':
                username = message.get('username')
                password = message.get('password')
                if username and password:
                    success = register_user(username, password)
                    if success:
                        send_json(conn, {'status': 'registered',
                                  'message': 'Registration successful'})
                    else:
                        send_json(conn, {'status': 'exists',
                                  'message': 'Username already exists'})
                else:
                    send_json(
                        conn, {'status': 'fail', 'message': 'Username and password required'})

            elif action == 'logout':  # NEW: Handle logout action
                token_to_invalidate = message.get('session')
                # Ensure it's this connection's session
                if token_to_invalidate and token_to_invalidate == current_session_token:
                    if invalidate_session(token_to_invalidate):
                        send_json(conn, {'status': 'logged_out',
                                  'message': 'Successfully logged out.'})
                        broadcast_online_users_list()  # Notify all clients
                        break  # Exit loop, client will disconnect
                    else:
                        send_json(conn, {'status': 'fail',
                                  'message': 'Session invalid.'})
                else:
                    send_json(
                        conn, {'status': 'fail', 'message': 'No active session or invalid token.'})

            elif action == 'message':  # MODIFIED: One-to-one message handling
                token = message.get('session')
                recipient = message.get('recipient')  # NEW: Recipient field
                content = message.get('content')

                sender_username = validate_session(token)

                if sender_username and sender_username == current_username:  # Ensure the sender is who they claim to be
                    if not recipient or not content:
                        send_json(
                            conn, {'status': 'fail', 'message': 'Missing recipient or content'})
                        continue

                    if recipient in online_users:
                        recipient_socket = online_users[recipient]
                        chat_message = {
                            'action': 'chat_message',  # NEW: Specific action type for chat messages
                            'from': sender_username,
                            'to': recipient,
                            'content': content
                        }
                        send_json(recipient_socket, chat_message)
                        # Optional: Send a confirmation back to the sender if needed
                        # send_json(conn, {'status': 'sent', 'message': f'Message sent to {recipient}'})
                    else:
                        send_json(conn, {
                                  'status': 'fail', 'message': f'User "{recipient}" is offline or does not exist.'})
                else:
                    send_json(conn, {'status': 'unauthorized',
                              'message': 'Invalid or expired session'})

            elif action == 'get_online_users':  # NEW: Action to get online users list
                token = message.get('session')
                user = validate_session(token)
                if user and user == current_username:
                    online_usernames = list(online_users.keys())
                    # Exclude the requesting user from their own list
                    users_for_client = [
                        u for u in online_usernames if u != user]
                    send_json(
                        conn, {'action': 'online_users_list', 'users': users_for_client})
                else:
                    send_json(conn, {
                              'status': 'unauthorized', 'message': 'Invalid session to get online users'})

            else:
                send_json(conn, {'status': 'unknown_command',
                          'message': 'Unknown action'})

    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
    finally:
        # Clean up on disconnect or error
        if current_session_token:
            # Check if the session token is still valid for this connection before invalidating
            if active_sessions.get(current_session_token) == current_username:
                if current_username in online_users and online_users[current_username] == conn:
                    # Remove from online users
                    del online_users[current_username]
                # Remove from active sessions
                del active_sessions[current_session_token]
                print(
                    f"[-] Cleaned up session for {current_username} on disconnect.")
                broadcast_online_users_list()  # Notify others about user going offline
        conn.close()
        print(f"[-] Disconnected {addr}")


def start_server():
    create_user_table()

    # Safe conditional registration (for testing)
    if not authenticate_user('testuser', 'password123'):
        register_user('testuser', 'password123')
        print("[*] Registered 'testuser' with password 'password123' (for testing).")
    if not authenticate_user('user2', 'password123'):
        register_user('user2', 'password123')
        print("[*] Registered 'user2' with password 'password123' (for testing).")
    if not authenticate_user('user3', 'password123'):
        register_user('user3', 'password123')
        print("[*] Registered 'user3' with password 'password123' (for testing).")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                      1)  # Allows reusing the address
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

# import socket
# import threading
# import json
# import sqlite3
# import bcrypt
# import secrets

# # ---------- Database Setup ----------


# def create_user_table():
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('''
#         CREATE TABLE IF NOT EXISTS users (
#             username TEXT PRIMARY KEY,
#             password_hash TEXT NOT NULL
#         )
#     ''')
#     conn.commit()
#     conn.close()


# def register_user(username, password):
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
#     try:
#         c.execute(
#             'INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed))
#         conn.commit()
#         conn.close()
#         return True
#     except sqlite3.IntegrityError:
#         conn.close()
#         return False


# def authenticate_user(username, password):
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
#     result = c.fetchone()
#     conn.close()
#     return result and bcrypt.checkpw(password.encode(), result[0])


# # ---------- Session Management ----------
# active_sessions = {}  # token -> username


# def generate_session(username):
#     token = secrets.token_hex(16)
#     active_sessions[token] = username
#     print(f"[+] Session started for {username} -> Token: {token}")
#     return token


# def validate_session(token):
#     return active_sessions.get(token)


# # ---------- Socket Server Setup ----------
# HOST = '127.0.0.1'
# PORT = 5555


# def handle_client(conn, addr):
#     print(f"[+] New connection from {addr}")
#     session_token = None

#     try:
#         while True:
#             data = conn.recv(4096)
#             if not data:
#                 break

#             try:
#                 message = json.loads(data.decode())
#                 print(f"[{addr}] Received: {message}")
#             except json.JSONDecodeError:
#                 conn.send(json.dumps({'status': 'invalid_json'}).encode())
#                 continue

#             action = message.get('action')

#             if action == 'login':
#                 username = message.get('username')
#                 password = message.get('password')
#                 if username and password and authenticate_user(username, password):
#                     session_token = generate_session(username)
#                     conn.send(json.dumps(
#                         {'status': 'ok', 'session': session_token}).encode())
#                 else:
#                     conn.send(json.dumps({'status': 'fail'}).encode())

#             elif action == 'message':
#                 token = message.get('session')
#                 content = message.get('content')
#                 user = validate_session(token)
#                 if user:
#                     print(f"[{user}] Message: {content}")
#                     conn.send(json.dumps({'status': 'received'}).encode())
#                 else:
#                     conn.send(json.dumps({'status': 'unauthorized'}).encode())

#             elif message['action'] == 'register':
#                 username = message.get('username')
#                 password = message.get('password')
#                 if username and password:
#                     success = register_user(username, password)
#                     if success:
#                         conn.send(json.dumps(
#                             {'status': 'registered'}).encode())
#                     else:
#                         conn.send(json.dumps({'status': 'exists'}).encode())
#                 else:
#                     conn.send(json.dumps({'status': 'fail'}).encode())

#             else:
#                 conn.send(json.dumps({'status': 'unknown_command'}).encode())

#     except Exception as e:
#         print(f"[-] Error handling {addr}: {e}")
#     finally:
#         conn.close()
#         print(f"[-] Disconnected {addr}")


# def start_server():
#     create_user_table()

#     # Safe conditional registration
#     if not authenticate_user('testuser', 'password123'):
#         register_user('testuser', 'password123')

#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind((HOST, PORT))
#     server.listen()
#     print(f"[*] Server started on {HOST}:{PORT}")

#     while True:
#         conn, addr = server.accept()
#         thread = threading.Thread(
#             target=handle_client, args=(conn, addr), daemon=True)
#         thread.start()


# if __name__ == "__main__":
#     start_server()
