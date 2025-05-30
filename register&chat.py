import socket
import json
import threading

HOST = '127.0.0.1'
PORT = 5555


def register():
    username = input("Choose username: ").strip()
    password = input("Choose password: ").strip()
    # For registration, we'll send a 'register' action to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        message = {
            'action': 'register',
            'username': username,
            'password': password
        }
        sock.send(json.dumps(message).encode())
        response = json.loads(sock.recv(1024).decode())
        if response.get('status') == 'ok':
            print("Registration successful!")
        else:
            print(
                f"Registration failed: {response.get('reason', 'Unknown error')}")


def login():
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    message = {
        'action': 'login',
        'username': username,
        'password': password
    }
    sock.send(json.dumps(message).encode())
    response = json.loads(sock.recv(1024).decode())
    if response.get('status') == 'ok':
        print("Login successful!")
        session_token = response.get('session')
        return sock, session_token, username
    else:
        print("Login failed. Check username/password.")
        sock.close()
        return None, None, None


def listen_for_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("Disconnected from server.")
                break
            msg = json.loads(data.decode())
            if msg.get('action') == 'message':
                sender = msg.get('from')
                content = msg.get('content')
                print(f"\n[{sender}]: {content}\n> ", end='', flush=True)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


def chat(sock, session_token, username):
    threading.Thread(target=listen_for_messages,
                     args=(sock,), daemon=True).start()

    print("Type your messages below. Type '/quit' to exit.")
    while True:
        message = input("> ").strip()
        if message == '/quit':
            print("Exiting chat...")
            sock.close()
            break
        if not message:
            continue

        # Build chat message packet
        msg_packet = {
            'action': 'message',
            'session': session_token,
            'content': message,
            'from': username
        }
        try:
            sock.send(json.dumps(msg_packet).encode())
            # Optionally, you could wait for 'received' confirmation
        except Exception as e:
            print(f"Error sending message: {e}")
            break


def main():
    print("Welcome to CipherNet Chat Client")
    print("1. Register")
    print("2. Login")
    choice = input("Select option (1/2): ").strip()

    if choice == '1':
        register()
    elif choice == '2':
        sock, session_token, username = login()
        if sock:
            chat(sock, session_token, username)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
