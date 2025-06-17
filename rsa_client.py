import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import socket
import threading
import json
import sqlite3
import os
import base64

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.exceptions import InvalidTag  # For GCM decryption errors

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
CLIENT_DB_NAME = 'client_keys.db'

# --- Cryptography Helpers ---


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key (256 bits = 32 bytes)
        salt=salt,
        iterations=480000,  # Increased iterations for stronger key derivation
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

# Encrypts the user's private RSA key using AES-256 GCM with a password-derived key


def encrypt_private_key(private_key_pem_bytes, password):
    salt = os.urandom(16)  # For PBKDF2
    key_for_aes = derive_key(password, salt)
    nonce = os.urandom(12)  # For AES GCM

    cipher = Cipher(algorithms.AES(key_for_aes),
                    modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(private_key_pem_bytes) + encryptor.finalize()
    tag = encryptor.tag

    # Store salt, nonce, ciphertext, and tag together
    combined_encrypted_data = salt + nonce + ciphertext + tag
    return base64.b64encode(combined_encrypted_data).decode('utf-8')

# Decrypts the user's private RSA key


def decrypt_private_key(encrypted_data_b64, password):
    combined_encrypted_data = base64.b64decode(encrypted_data_b64)

    salt = combined_encrypted_data[:16]
    nonce = combined_encrypted_data[16:28]  # 12 bytes nonce
    ciphertext = combined_encrypted_data[28:-16]  # Tag is last 16 bytes
    tag = combined_encrypted_data[-16:]

    key_for_aes = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key_for_aes), modes.GCM(
        nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    plain_private_key_pem_bytes = decryptor.update(
        ciphertext) + decryptor.finalize()
    return plain_private_key_pem_bytes


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Export keys to PEM format as bytes
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        # No encryption here, we'll encrypt it with user's password
        encryption_algorithm=NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, private_key_pem, public_key_pem

# For AES GCM authenticated encryption of messages


def encrypt_message_aes(message_bytes, aes_key):
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

# For AES GCM authenticated decryption of messages


def decrypt_message_aes(nonce, ciphertext, tag, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return plain_text_bytes


class ChatClient:
    def __init__(self, master):
        self.master = master
        self.running = False
        self.master.title("CipherNet: Secure Chat App")
        self.session_token = None
        self.username = None
        self.current_recipient = None

        # Cryptography attributes
        # Holds the cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey object
        self.private_key = None
        # Holds the cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey object
        self.public_key = None
        # username -> cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey object
        self.public_keys_cache = {}
        self.user_password = None  # Temporarily store during login for private key decryption

        self.setup_local_db()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))
        except ConnectionRefusedError:
            messagebox.showerror(
                "Error", "Could not connect to server. Make sure the server is running.")
            self.master.destroy()
            return
        except Exception as e:
            messagebox.showerror(
                "Error", f"An unexpected error occurred during connection: {e}")
            self.master.destroy()
            return

        self.build_login_screen()

    def setup_local_db(self):
        conn = sqlite3.connect(CLIENT_DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS local_keys (
                username TEXT PRIMARY KEY,
                private_key_encrypted TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def store_local_private_key(self, username, encrypted_private_key_b64):
        conn = sqlite3.connect(CLIENT_DB_NAME)
        c = conn.cursor()
        try:
            c.execute('INSERT OR REPLACE INTO local_keys (username, private_key_encrypted) VALUES (?, ?)',
                      (username, encrypted_private_key_b64))
            conn.commit()
            print(f"Private key for {username} stored locally.")
        except Exception as e:
            print(f"Error storing local private key: {e}")
        finally:
            conn.close()

    def get_local_private_key_data(self, username):
        conn = sqlite3.connect(CLIENT_DB_NAME)
        c = conn.cursor()
        c.execute(
            'SELECT private_key_encrypted FROM local_keys WHERE username = ?', (username,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else None

    # Helper to send JSON messages with length prefixing
    def send_json(self, data):
        try:
            json_data = json.dumps(data)
            message_length = len(json_data.encode('utf-8'))
            header = f"{message_length:<8}".encode('utf-8')
            self.sock.sendall(header + json_data.encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")
            raise  # Re-raise to be caught by calling method for logout

    # Helper to receive JSON messages with length prefixing
    # def recv_json(self):
    #     try:
    #         header_bytes = self.sock.recv(8)
    #         if not header_bytes:
    #             return None

    #         header_str = header_bytes.decode('utf-8').strip()
    #         message_length = int(header_str)

    #         full_message_bytes = b''
    #         bytes_received = 0
    #         while bytes_received < message_length:
    #             chunk = self.sock.recv(
    #                 min(message_length - bytes_received, 4096))
    #             if not chunk:
    #                 return None
    #             full_message_bytes += chunk
    #             bytes_received += len(full_message_bytes)

    #         return json.loads(full_message_bytes.decode('utf-8'))
    #     except ValueError:
    #         print("Invalid message length header received.")
    #         return None
    #     except json.JSONDecodeError:
    #         print("Malformed JSON received.")
    #         return None
    #     except Exception as e:
    #         print(f"Error receiving data: {e}")
    #         return None
    def recv_json(self):
        try:
            print("[CLIENT] Attempting to receive 8-byte header...")
            header_bytes = self.sock.recv(8)
            print(
                f"[CLIENT] Received header_bytes: {header_bytes!r} (length: {len(header_bytes)})")

            if not header_bytes:
                print("[CLIENT] Server closed connection during header receive.")
                return None  # Connection closed

            header_str = header_bytes.decode('utf-8').strip()
            print(f"[CLIENT] Decoded header_str: '{header_str}'")

            message_length = int(header_str)
            print(f"[CLIENT] Expected message length: {message_length} bytes")

            full_message_bytes = b''
            bytes_received = 0
            while bytes_received < message_length:
                chunk = self.sock.recv(
                    min(message_length - bytes_received, 4096))
                if not chunk:
                    print(
                        "[CLIENT] Server closed connection unexpectedly during message body receive.")
                    return None  # Connection closed unexpectedly
                full_message_bytes += chunk
                bytes_received += len(chunk)

            print(
                f"[CLIENT] Received full message (bytes_received: {bytes_received}). Decoding JSON...")
            return json.loads(full_message_bytes.decode('utf-8'))
        except ValueError:  # If header is not a valid int
            print(
                f"[CLIENT ERROR] Invalid message length header received. Header was: {header_bytes!r}")
            return None
        except json.JSONDecodeError:
            print(
                f"[CLIENT ERROR] Malformed JSON received. Message body was: {full_message_bytes!r}")
            return None
        except Exception as e:
            print(f"[CLIENT ERROR] Error receiving data: {e}")
            return None

    def build_login_screen(self):
        self.clear_window()
        tk.Label(self.master, text="Login", font=("Arial", 18)).pack(pady=10)
        self.user_entry = tk.Entry(self.master, width=30)
        self.user_entry.pack(pady=5)
        self.user_entry.insert(0, "Username")

        self.pass_entry = tk.Entry(self.master, width=30, show="*")
        self.pass_entry.pack(pady=5)
        self.pass_entry.insert(0, "Password")

        tk.Button(self.master, text="Login", command=self.login).pack(pady=10)
        tk.Button(self.master, text="Register",
                  command=self.build_register_screen).pack()

    def build_register_screen(self):
        self.clear_window()
        tk.Label(self.master, text="Register",
                 font=("Arial", 18)).pack(pady=10)
        self.reg_user_entry = tk.Entry(self.master, width=30)
        self.reg_user_entry.pack(pady=5)
        self.reg_user_entry.insert(0, "Username")

        self.reg_pass_entry = tk.Entry(self.master, width=30, show="*")
        self.reg_pass_entry.pack(pady=5)
        self.reg_pass_entry.insert(0, "Password")

        tk.Button(self.master, text="Register",
                  command=self.register).pack(pady=10)
        tk.Button(self.master, text="Back to Login",
                  command=self.build_login_screen).pack()

    def build_chat_screen(self):
        self.clear_window()

        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        users_frame = tk.Frame(main_frame, bd=2, relief=tk.GROOVE)
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        tk.Label(users_frame, text="Online Users",
                 font=("Arial", 10, "bold")).pack(pady=5)
        self.online_users_listbox = tk.Listbox(
            users_frame, width=20, height=15)
        self.online_users_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.online_users_listbox.bind(
            '<<ListboxSelect>>', self.select_recipient)

        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.recipient_label = tk.Label(
            chat_frame, text="Select a user to chat with", font=("Arial", 12, "bold"))
        self.recipient_label.pack(pady=5)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, state='disabled', width=50, height=15)
        self.chat_display.pack(pady=10, fill=tk.BOTH, expand=True)

        message_input_frame = tk.Frame(chat_frame)
        message_input_frame.pack(pady=5, fill=tk.X)

        self.message_entry = tk.Entry(message_input_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.message_entry.bind(
            "<Return>", lambda event=None: self.send_message())
        tk.Button(message_input_frame, text="Send",
                  command=self.send_message).pack(side=tk.LEFT, padx=5)

        tk.Button(chat_frame, text="Logout", command=self.logout).pack(
            pady=5, side=tk.RIGHT, padx=5)

        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # This will trigger public key fetching when online_users_list is received
        self.request_online_users()

    def select_recipient(self, event=None):
        selected_indices = self.online_users_listbox.curselection()
        if selected_indices:
            index = selected_indices[0]
            selected_username = self.online_users_listbox.get(index)

            # Request public key if not in cache
            if selected_username not in self.public_keys_cache:
                self.request_public_keys([selected_username])

            self.current_recipient = selected_username
            self.recipient_label.config(
                text=f"Chatting with: {self.current_recipient}")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
        else:
            self.current_recipient = None
            self.recipient_label.config(text="Select a user to chat with")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')

    def login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        self.username = username
        self.user_password = password  # Keep password in memory for private key decryption

        public_key_pem_b64 = None
        private_key_encrypted_b64 = self.get_local_private_key_data(username)

        if private_key_encrypted_b64:
            # User has an existing key pair locally
            try:
                private_key_pem_bytes = decrypt_private_key(
                    private_key_encrypted_b64, password)
                self.private_key = load_pem_private_key(
                    private_key_pem_bytes, password=None, backend=default_backend())
                self.public_key = self.private_key.public_key()
                public_key_pem_bytes = self.public_key.public_bytes(
                    encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
                )
                public_key_pem_b64 = base64.b64encode(
                    public_key_pem_bytes).decode('utf-8')
                print(f"Loaded existing private key for {username}.")
            except InvalidTag:
                messagebox.showerror("Decryption Error",
                                     "Incorrect password for private key.")
                print(
                    "Private key decryption failed due to invalid tag (wrong password or corrupted data).")
                self.user_password = None
                return
            except Exception as e:
                messagebox.showerror("Decryption Error",
                                     f"Failed to decrypt private key: {e}")
                print(f"Private key decryption error: {e}")
                self.user_password = None
                return
        else:
            # First time login or key pair not found, generate new keys
            self.private_key, self.public_key, private_key_pem_bytes, public_key_pem_bytes = generate_rsa_key_pair()
            encrypted_pk_b64 = encrypt_private_key(
                private_key_pem_bytes, password)
            self.store_local_private_key(username, encrypted_pk_b64)
            public_key_pem_b64 = base64.b64encode(
                public_key_pem_bytes).decode('utf-8')
            print(f"Generated and stored new key pair for {username}.")

        # Now send the login request to the server, including the public key
        message = {
            'action': 'login',
            'username': username,
            'password': password,
            'public_key': public_key_pem_b64  # Send Base64 encoded PEM public key
        }
        try:
            self.send_json(message)
            response = self.recv_json()

            if response and response.get('status') == 'ok':
                self.session_token = response['session']
                self.username = response['username']

                # Cache all public keys received from the server
                for user, pk_pem_b64 in response.get('public_keys', {}).items():
                    try:
                        pk_pem_bytes = base64.b64decode(pk_pem_b64)
                        self.public_keys_cache[user] = load_pem_public_key(
                            pk_pem_bytes, backend=default_backend())
                    except Exception as e:
                        print(
                            f"Error loading public key for {user} into cache: {e}")

                self.build_chat_screen()
            else:
                messagebox.showerror("Login Failed", response.get(
                    'message', "Invalid credentials"))
                self.user_password = None  # Clear password on failed login
        except ConnectionResetError:
            messagebox.showerror("Connection Error",
                                 "Server disconnected unexpectedly.")
            self.master.destroy()
        except Exception as e:
            messagebox.showerror(
                "Login Error", f"An error occurred during login: {e}")
        finally:
            # self.user_password is intentionally kept for the session duration to decrypt incoming messages.
            pass

    def register(self):
        username = self.reg_user_entry.get()
        password = self.reg_pass_entry.get()
        if not username or not password:
            messagebox.showwarning(
                "Input Error", "Username and password are required.")
            return

        # Generate new key pair for registration
        private_key, public_key, private_key_pem_bytes, public_key_pem_bytes = generate_rsa_key_pair()

        # Encrypt and store private key locally using the provided password
        encrypted_pk_b64 = encrypt_private_key(private_key_pem_bytes, password)
        self.store_local_private_key(username, encrypted_pk_b64)

        # Prepare public key for sending to server
        public_key_pem_b64 = base64.b64encode(
            public_key_pem_bytes).decode('utf-8')

        message = {
            'action': 'register',
            'username': username,
            'password': password,
            'public_key': public_key_pem_b64  # Send Base64 encoded PEM public key
        }
        try:
            self.send_json(message)
            response = self.recv_json()

            if response and response.get('status') == 'registered':
                messagebox.showinfo(
                    "Success", "Registration successful! Please login.")
                self.build_login_screen()
            elif response and response.get('status') == 'exists':
                messagebox.showerror("Error", "Username already exists.")
            else:
                messagebox.showerror("Error", response.get(
                    'message', "Registration failed."))
        except ConnectionResetError:
            messagebox.showerror("Connection Error",
                                 "Server disconnected unexpectedly.")
            self.master.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Error during registration: {e}")

    def send_message(self):
        if not self.current_recipient:
            messagebox.showwarning(
                "No Recipient", "Please select a user to chat with from the 'Online Users' list.")
            return

        content = self.message_entry.get()
        if not content.strip():
            return

        recipient_public_key = self.public_keys_cache.get(
            self.current_recipient)
        if not recipient_public_key:
            messagebox.showerror(
                "Encryption Error", f"Public key for {self.current_recipient} not found in cache. Please select the user again or wait for list refresh.")
            # Optionally, request the key again here
            self.request_public_keys([self.current_recipient])
            return

        try:
            # 1. Generate ephemeral AES key
            aes_key = os.urandom(32)  # AES-256 (32 bytes)

            # 2. Encrypt message with AES key using AES-GCM
            nonce, encrypted_content_bytes, tag = encrypt_message_aes(
                content.encode('utf-8'), aes_key)
            # Combine nonce, ciphertext, and tag for transmission
            combined_aes_encrypted_data = nonce + encrypted_content_bytes + tag
            encrypted_content_b64 = base64.b64encode(
                combined_aes_encrypted_data).decode('utf-8')

            # 3. Encrypt AES key with recipient's RSA public key using OAEP padding
            encrypted_aes_key_bytes = recipient_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_aes_key_b64 = base64.b64encode(
                encrypted_aes_key_bytes).decode('utf-8')

        except Exception as e:
            messagebox.showerror("Encryption Failed",
                                 f"Could not encrypt message: {e}")
            print(f"Encryption failed: {e}")
            return

        message = {
            'action': 'message',
            'session': self.session_token,
            'recipient': self.current_recipient,
            'encrypted_content': encrypted_content_b64,
            'encrypted_aes_key': encrypted_aes_key_b64
        }
        try:
            self.send_json(message)
            self.insert_message_to_chat(
                f"You to {self.current_recipient}: {content}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            self.master.after(0, self.logout)

    def insert_message_to_chat(self, message):
        self.master.after(0, self._insert_message_gui, message)

    def _insert_message_gui(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def update_online_users_list(self, users_list):
        self.master.after(0, self._update_online_users_gui, users_list)

    def _update_online_users_gui(self, users_list):
        self.online_users_listbox.delete(0, tk.END)
        filtered_users_list = [u for u in users_list if u != self.username]
        for user in filtered_users_list:
            self.online_users_listbox.insert(tk.END, user)

        # Request public keys for any new users that aren't in cache
        new_users_to_fetch_pk = [
            u for u in filtered_users_list if u not in self.public_keys_cache]
        if new_users_to_fetch_pk:
            print(
                f"Requesting public keys for new users: {new_users_to_fetch_pk}")
            self.request_public_keys(new_users_to_fetch_pk)

        if self.current_recipient and self.current_recipient in filtered_users_list:
            try:
                idx = filtered_users_list.index(self.current_recipient)
                self.online_users_listbox.selection_set(idx)
                self.online_users_listbox.activate(idx)
            except ValueError:
                pass
        elif self.current_recipient and self.current_recipient not in filtered_users_list:
            self.current_recipient = None
            self.recipient_label.config(text="Select a user to chat with")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')

    def request_online_users(self):
        message = {
            'action': 'get_online_users',
            'session': self.session_token
        }
        try:
            self.send_json(message)
        except Exception as e:
            print(f"Error requesting online users: {e}")
            self.master.after(0, self.logout)

    def request_public_keys(self, usernames):
        if not usernames:
            return
        message = {
            'action': 'get_public_keys',
            'session': self.session_token,
            'usernames': usernames
        }
        try:
            self.send_json(message)
        except Exception as e:
            print(f"Error requesting public keys: {e}")

    def receive_messages(self):
        while self.running:
            try:
                msg = self.recv_json()
                if msg is None:
                    print(
                        "Server disconnected gracefully or malformed message received.")
                    self.master.after(0, lambda: messagebox.showerror(
                        "Connection Error", "Server disconnected."))
                    self.master.after(0, self.logout)
                    break

                if msg.get('action') == 'chat_message':
                    sender = msg.get('from', 'Unknown')
                    encrypted_content_b64 = msg.get('encrypted_content')
                    encrypted_aes_key_b64 = msg.get('encrypted_aes_key')

                    if not self.private_key:
                        print("Error: Private key not loaded for decryption.")
                        self.insert_message_to_chat(
                            f"[{sender}]: (Decryption failed - private key missing)")
                        continue
                    if not self.user_password:
                        print(
                            "Error: User password not in memory for private key decryption.")
                        self.insert_message_to_chat(
                            f"[{sender}]: (Decryption failed - password missing)")
                        continue

                    # Default in case of failure
                    content = "(Decryption Failed)"
                    try:
                        # 1. Decrypt AES key with own RSA private key
                        encrypted_aes_key_bytes = base64.b64decode(
                            encrypted_aes_key_b64)
                        aes_key = self.private_key.decrypt(
                            encrypted_aes_key_bytes,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )

                        # 2. Decrypt message content with recovered AES key
                        combined_aes_encrypted_data = base64.b64decode(
                            encrypted_content_b64)
                        nonce = combined_aes_encrypted_data[:12]
                        ciphertext = combined_aes_encrypted_data[12:-16]
                        tag = combined_aes_encrypted_data[-16:]

                        decrypted_content_bytes = decrypt_message_aes(
                            nonce, ciphertext, tag, aes_key)
                        content = decrypted_content_bytes.decode('utf-8')

                    except InvalidTag:
                        print(
                            f"Decryption failed for message from {sender}: InvalidTag (likely corrupted message or wrong key)")
                        content = "(Decryption Failed: Message Integrity Compromised)"
                    except Exception as e:
                        print(
                            f"Decryption failed for message from {sender}: {e}")
                        content = "(Decryption Failed)"

                    if sender == self.current_recipient:
                        self.insert_message_to_chat(f"{sender}: {content}")
                    else:
                        print(
                            f"New message from {sender} (not current recipient): {content}")
                        # Example of notification:
                        self.master.after(0, lambda: self.master.bell())

                elif msg.get('action') == 'online_users_list':
                    users = msg.get('users', [])
                    self.update_online_users_list(users)

                elif msg.get('action') == 'public_keys_response':
                    for user, pk_pem_b64 in msg.get('public_keys', {}).items():
                        try:
                            pk_pem_bytes = base64.b64decode(pk_pem_b64)
                            self.public_keys_cache[user] = load_pem_public_key(
                                pk_pem_bytes, backend=default_backend())
                            print(f"Cached public key for {user}")
                        except Exception as e:
                            print(
                                f"Error loading public key for {user} from server response: {e}")

                elif msg.get('status') == 'error':
                    error_message = msg.get(
                        'message', 'An unknown error occurred on the server.')
                    self.master.after(0, lambda: messagebox.showerror(
                        "Server Error", error_message))

            except ConnectionResetError:
                print("Server closed the connection unexpectedly.")
                self.master.after(0, lambda: messagebox.showerror(
                    "Connection Error", "Server closed the connection unexpectedly."))
                self.master.after(0, self.logout)
                break
            except Exception as e:
                if self.running:
                    print(f"Error in receive_messages thread: {e}")
                    self.master.after(0, lambda: messagebox.showerror(
                        "Receive Error", f"An error occurred while receiving messages: {e}"))
                break

    def logout(self):
        self.running = False
        if self.sock and self.session_token:
            try:
                logout_msg = {
                    'action': 'logout',
                    'session': self.session_token
                }
                self.send_json(logout_msg)
            except Exception as e:
                print(f"Error sending logout message: {e}")

        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except OSError as e:
                print(f"Error during socket shutdown/close: {e}")
            except Exception as e:
                print(f"Unexpected error closing socket: {e}")

        # Reset client state variables
        self.sock = None
        self.session_token = None
        self.username = None
        self.current_recipient = None
        self.private_key = None
        self.public_key = None
        self.public_keys_cache = {}
        self.user_password = None  # IMPORTANT: Clear the password from memory on logout

        # Reinitialize connection and go back to login screen
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))
        except ConnectionRefusedError:
            messagebox.showerror(
                "Error", "Could not reconnect to server after logout. Server might be down.")
            self.master.destroy()
            return
        except Exception as e:
            messagebox.showerror(
                "Error", f"An unexpected error occurred during reconnection: {e}")
            self.master.destroy()
            return

        self.build_login_screen()

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()


# Main application setup
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("600x450")
    app = ChatClient(root)

    def on_closing():
        if app.running:
            app.logout()
        else:
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
