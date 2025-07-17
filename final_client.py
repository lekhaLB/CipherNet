import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
from tkinter import ttk  # For Treeview or similar for user selection
import socket
import threading
import json
import sqlite3
import os
import base64
# To store chat history per conversation/group
from collections import defaultdict

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.exceptions import InvalidTag  # For GCM decryption errors
from functools import partial
from tkinter import filedialog

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

    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, private_key_pem, public_key_pem


def encrypt_message_aes(message_bytes, aes_key):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


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
        self.current_recipient = None  # For 1-on-1 chat
        self.current_group_id = None  # For group chat
        self.chat_mode = '1-on-1'     # '1-on-1' or 'group'

        self.private_key = None
        self.public_key = None
        self.public_keys_cache = {}  # username -> PublicKey object
        self.user_password = None

        self.setup_local_db()
        self.self_destruct_var = tk.BooleanVar(value=False)
        self.self_destruct_time = tk.IntVar(value=5)  # default 5 seconds

        # NEW: Store group chat history and group keys
        self.group_chat_histories = defaultdict(
            list)  # group_id -> list of messages
        self.one_on_one_chat_histories = defaultdict(
            list)  # username -> list of messages
        self.my_groups = []  # List of {'id', 'name', 'creator'} dicts
        # group_id -> decrypted_group_secret_key (bytes)
        self.my_group_secret_keys = {}

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
        c.execute('''
            CREATE TABLE IF NOT EXISTS client_groups (
                group_id INTEGER PRIMARY KEY,
                group_name TEXT NOT NULL,
                group_secret_key_encrypted_b64 TEXT NOT NULL
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

    def store_local_group_key(self, group_id, group_name, encrypted_group_secret_key_b64):
        conn = sqlite3.connect(CLIENT_DB_NAME)
        c = conn.cursor()
        try:
            c.execute('INSERT OR REPLACE INTO client_groups (group_id, group_name, group_secret_key_encrypted_b64) VALUES (?, ?, ?)',
                      (group_id, group_name, encrypted_group_secret_key_b64))
            conn.commit()
            print(
                f"Group key for group '{group_name}' (ID: {group_id}) stored locally.")
        except Exception as e:
            print(f"Error storing local group key: {e}")
        finally:
            conn.close()

    def get_local_group_key_data(self, group_id):
        conn = sqlite3.connect(CLIENT_DB_NAME)
        c = conn.cursor()
        c.execute(
            'SELECT group_secret_key_encrypted_b64 FROM client_groups WHERE group_id = ?', (group_id,))
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
            raise

    # Helper to receive JSON messages with length prefixing
    def recv_json(self):
        try:
            header_bytes = self.sock.recv(8)
            if not header_bytes:
                return None

            header_str = header_bytes.decode('utf-8').strip()
            message_length = int(header_str)

            full_message_bytes = b''
            bytes_received = 0
            while bytes_received < message_length:
                chunk = self.sock.recv(
                    min(message_length - bytes_received, 4096))
                if not chunk:
                    return None
                full_message_bytes += chunk
                bytes_received += len(full_message_bytes)

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

        # Left Panel for Online Users and Groups
        left_panel = tk.Frame(main_frame, bd=2, relief=tk.GROOVE)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        # Online Users Section
        tk.Label(left_panel, text="Online Users",
                 font=("Arial", 10, "bold")).pack(pady=5)
        self.online_users_listbox = tk.Listbox(left_panel, width=20, height=8)
        self.online_users_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.online_users_listbox.bind(
            '<<ListboxSelect>>', self.select_1on1_recipient)

        # Create Group Button
        tk.Button(left_panel, text="Create Group",
                  command=self.create_group_dialog).pack(pady=5)

        # My Groups Section
        tk.Label(left_panel, text="My Groups", font=(
            "Arial", 10, "bold")).pack(pady=5)
        self.groups_listbox = tk.Listbox(left_panel, width=20, height=8)
        self.groups_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.groups_listbox.bind('<<ListboxSelect>>', self.select_group)

        # Right Panel for Chat Display and Input
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.recipient_label = tk.Label(
            chat_frame, text="Select a user or group to chat with", font=("Arial", 12, "bold"))
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

        # --- Self-destructing message controls ---
        tk.Checkbutton(
            message_input_frame, text="Self-Destruct",
            variable=self.self_destruct_var
        ).pack(side=tk.LEFT, padx=2)
        tk.Label(message_input_frame, text="After (s):").pack(side=tk.LEFT)
        tk.Entry(
            message_input_frame, textvariable=self.self_destruct_time, width=3
        ).pack(side=tk.LEFT, padx=2)
        # --- End controls ---

        tk.Button(message_input_frame, text="Send",
                  command=self.send_message).pack(side=tk.LEFT, padx=5)

        tk.Button(chat_frame, text="Logout", command=self.logout).pack(
            pady=5, side=tk.RIGHT, padx=5)

        # Add the send file button
        tk.Button(message_input_frame, text="Send File",
                  command=self.send_file).pack(side=tk.LEFT, padx=5)

        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.request_online_users()
        self.request_my_groups()  # NEW: Request user's groups on chat screen load

    def select_1on1_recipient(self, event=None):
        selected_indices = self.online_users_listbox.curselection()
        if selected_indices:
            # Clear group selection
            self.groups_listbox.selection_clear(0, tk.END)

            index = selected_indices[0]
            selected_username = self.online_users_listbox.get(index)

            if selected_username == self.username:  # Prevent chatting with self
                messagebox.showwarning(
                    "Invalid Selection", "Cannot chat with yourself. Please select another user.")
                self.online_users_listbox.selection_clear(0, tk.END)
                self.current_recipient = None
                self.current_group_id = None
                self.recipient_label.config(
                    text="Select a user or group to chat with")
                self.chat_display.config(state='normal')
                self.chat_display.delete(1.0, tk.END)
                self.chat_display.config(state='disabled')
                return

            if selected_username not in self.public_keys_cache:
                self.request_public_keys([selected_username])

            self.current_recipient = selected_username
            self.current_group_id = None
            self.chat_mode = '1-on-1'
            self.recipient_label.config(
                text=f"Chatting with: {self.current_recipient}")
            self.load_chat_history()
        else:
            self.current_recipient = None
            self.recipient_label.config(
                text="Select a user or group to chat with")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')

    def select_group(self, event=None):
        selected_indices = self.groups_listbox.curselection()
        if selected_indices:
            # Clear 1-on-1 selection
            self.online_users_listbox.selection_clear(0, tk.END)

            index = selected_indices[0]
            selected_group_name = self.groups_listbox.get(index)

            selected_group_info = next(
                (g for g in self.my_groups if g['name'] == selected_group_name), None)

            if selected_group_info:
                group_id = selected_group_info['id']
                if group_id not in self.my_group_secret_keys:
                    # Request the encrypted group key from the server
                    self.request_encrypted_group_key(group_id)
                    messagebox.showinfo(
                        "Fetching Group Key", "Fetching group key. Please wait a moment before sending messages.")

                self.current_group_id = group_id
                self.current_recipient = None  # Ensure 1-on-1 is cleared
                self.chat_mode = 'group'
                self.recipient_label.config(
                    text=f"Group Chat: {selected_group_name}")
                self.load_chat_history()
            else:
                self.current_group_id = None
                self.recipient_label.config(
                    text="Select a user or group to chat with")
                self.chat_display.config(state='normal')
                self.chat_display.delete(1.0, tk.END)
                self.chat_display.config(state='disabled')

    def load_chat_history(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        if self.chat_mode == '1-on-1' and self.current_recipient:
            history = self.one_on_one_chat_histories[self.current_recipient]
            for msg in history:
                self.chat_display.insert(tk.END, msg + "\n")
        elif self.chat_mode == 'group' and self.current_group_id:
            history = self.group_chat_histories[self.current_group_id]
            for msg in history:
                self.chat_display.insert(tk.END, msg + "\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        self.username = username
        self.user_password = password

        public_key_pem_b64 = None
        private_key_encrypted_b64 = self.get_local_private_key_data(username)

        if private_key_encrypted_b64:
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
                messagebox.showerror(
                    "Decryption Error", "Incorrect password for private key. Please check your password.")
                self.user_password = None
                return
            except Exception as e:
                messagebox.showerror("Decryption Error",
                                     f"Failed to decrypt private key: {e}")
                self.user_password = None
                return
        else:
            self.private_key, self.public_key, private_key_pem_bytes, public_key_pem_bytes = generate_rsa_key_pair()
            encrypted_pk_b64 = encrypt_private_key(
                private_key_pem_bytes, password)
            self.store_local_private_key(username, encrypted_pk_b64)
            public_key_pem_b64 = base64.b64encode(
                public_key_pem_bytes).decode('utf-8')
            print(f"Generated and stored new key pair for {username}.")

        message = {
            'action': 'login',
            'username': username,
            'password': password,
            'public_key': public_key_pem_b64
        }
        try:
            self.send_json(message)
            response = self.recv_json()

            if response and response.get('status') == 'ok':
                self.session_token = response['session']
                self.username = response['username']

                for user, pk_pem_b64 in response.get('public_keys', {}).items():
                    try:
                        pk_pem_bytes = base64.b64decode(pk_pem_b64)
                        self.public_keys_cache[user] = load_pem_public_key(
                            pk_pem_bytes, backend=default_backend())
                    except Exception as e:
                        print(
                            f"Error loading public key for {user} into cache: {e}")

                # Load user's groups and decrypt their keys
                server_groups = response.get('user_groups', [])
                self.my_groups = server_groups  # Store list of group info
                for group_info in server_groups:
                    group_id = group_info['id']
                    # Attempt to load and decrypt group key from local DB
                    encrypted_group_secret_key_b64 = self.get_local_group_key_data(
                        group_id)
                    if encrypted_group_secret_key_b64:
                        try:
                            # Decrypt group secret key using own RSA private key
                            encrypted_key_bytes = base64.b64decode(
                                encrypted_group_secret_key_b64)
                            decrypted_group_secret_key = self.private_key.decrypt(
                                encrypted_key_bytes,
                                padding.OAEP(
                                    mgf=padding.MGF1(
                                        algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            self.my_group_secret_keys[group_id] = decrypted_group_secret_key
                            print(
                                f"Decrypted group secret key for group {group_info['name']} (ID: {group_id})")
                        except Exception as e:
                            print(
                                f"Failed to decrypt group key for group {group_info['name']}: {e}")
                            messagebox.showwarning(
                                "Group Key Error", f"Failed to decrypt key for group {group_info['name']}. You might not be able to read messages.")
                    else:
                        print(
                            f"No local group key found for group {group_info['name']} (ID: {group_id}).")
                        # This would happen if user joins a group and then clears local DB, or created group on another client.
                        # For now, if no local key, cannot decrypt. Could add mechanism to request from server again if needed.

                self.build_chat_screen()
            else:
                messagebox.showerror("Login Failed", response.get(
                    'message', "Invalid credentials"))
                self.user_password = None
        except ConnectionResetError:
            messagebox.showerror("Connection Error",
                                 "Server disconnected unexpectedly.")
            self.master.destroy()
        except Exception as e:
            messagebox.showerror(
                "Login Error", f"An error occurred during login: {e}")
        finally:
            pass  # user_password kept for session

    def register(self):
        username = self.reg_user_entry.get()
        password = self.reg_pass_entry.get()
        if not username or not password:
            messagebox.showwarning(
                "Input Error", "Username and password are required.")
            return

        private_key, public_key, private_key_pem_bytes, public_key_pem_bytes = generate_rsa_key_pair()

        encrypted_pk_b64 = encrypt_private_key(private_key_pem_bytes, password)
        self.store_local_private_key(username, encrypted_pk_b64)

        public_key_pem_b64 = base64.b64encode(
            public_key_pem_bytes).decode('utf-8')

        message = {
            'action': 'register',
            'username': username,
            'password': password,
            'public_key': public_key_pem_b64
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
        content = self.message_entry.get()
        if not content.strip():
            return

        # Self-destructing message options
        self_destruct = self.self_destruct_var.get()
        destruct_after = self.self_destruct_time.get() if self_destruct else None

        if self.chat_mode == '1-on-1':
            if not self.current_recipient:
                messagebox.showwarning(
                    "No Recipient", "Please select a user to chat with from the 'Online Users' list.")
                return
            self._send_1on1_message(content, self_destruct, destruct_after)
        elif self.chat_mode == 'group':
            if not self.current_group_id:
                messagebox.showwarning(
                    "No Group Selected", "Please select a group to chat in from the 'My Groups' list.")
                return
            self._send_group_message(content, self_destruct, destruct_after)
        else:
            messagebox.showerror(
                "Chat Mode Error", "Invalid chat mode selected.")

        self.message_entry.delete(0, tk.END)

    def _send_1on1_message(self, content, self_destruct=False, destruct_after=None):
        recipient_public_key = self.public_keys_cache.get(
            self.current_recipient)
        if not recipient_public_key:
            messagebox.showerror(
                "Encryption Error", f"Public key for {self.current_recipient} not found in cache. Cannot encrypt message.")
            self.request_public_keys([self.current_recipient])
            return

        try:
            aes_key = os.urandom(32)
            content = self.message_entry.get()  # Get the message from the entry
            print(f"Plaintext Message: {content}")

            nonce, encrypted_content_bytes, tag = encrypt_message_aes(
                content.encode('utf-8'), aes_key)
            combined_aes_encrypted_data = nonce + encrypted_content_bytes + tag
            # Show the encrypted message
            print(f"Ciphertext: {combined_aes_encrypted_data}")
            encrypted_content_b64 = base64.b64encode(
                combined_aes_encrypted_data).decode('utf-8')

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
            print(f"1-on-1 Encryption failed: {e}")
            return

        message = {
            'action': 'message',
            'session': self.session_token,
            'recipient': self.current_recipient,
            'encrypted_content': encrypted_content_b64,
            'encrypted_aes_key': encrypted_aes_key_b64,
            'self_destruct': self_destruct,
            'destruct_after': destruct_after
        }
        try:
            self.send_json(message)
            display_message = f"You to {self.current_recipient}: {content}"
            self.insert_message_to_chat(display_message)
            self.one_on_one_chat_histories[self.current_recipient].append(
                display_message)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            self.master.after(0, self.logout)

    def _send_group_message(self, content, self_destruct=False, destruct_after=None):
        group_secret_key = self.my_group_secret_keys.get(self.current_group_id)
        if not group_secret_key:
            messagebox.showerror(
                "Encryption Error", f"Group key for selected group not available. Cannot send message.")
            return

        try:
            # Generate ephemeral AES key for this message
            message_aes_key = os.urandom(32)
            content = self.message_entry.get()  # Get the message from the entry
            print(f"Plaintext Message: {content}")

            # Encrypt message content with message's AES key
            nonce_msg, encrypted_content_bytes, tag_msg = encrypt_message_aes(
                content.encode('utf-8'), message_aes_key)
            combined_aes_encrypted_data = nonce_msg + encrypted_content_bytes + tag_msg
            # Show the encrypted message
            print(f"Ciphertext: {combined_aes_encrypted_data}")
            encrypted_content_b64 = base64.b64encode(
                combined_aes_encrypted_data).decode('utf-8')

            # Encrypt message's AES key with the group's secret key
            nonce_key, encrypted_message_aes_key_bytes, tag_key = encrypt_message_aes(
                message_aes_key, group_secret_key)
            combined_encrypted_key_data = nonce_key + \
                encrypted_message_aes_key_bytes + tag_key
            encrypted_message_aes_key_b64 = base64.b64encode(
                combined_encrypted_key_data).decode('utf-8')

        except Exception as e:
            messagebox.showerror("Encryption Failed",
                                 f"Could not encrypt group message: {e}")
            print(f"Group Encryption failed: {e}")
            return

        message = {
            'action': 'group_message',
            'session': self.session_token,
            'group_id': self.current_group_id,
            'encrypted_content': encrypted_content_b64,
            'encrypted_message_aes_key': encrypted_message_aes_key_b64,
            'self_destruct': self_destruct,
            'destruct_after': destruct_after
        }
        try:
            self.send_json(message)
            display_message = f"You to Group {self._get_group_name(self.current_group_id)}: {content}"
            self.insert_message_to_chat(display_message)
            self.group_chat_histories[self.current_group_id].append(
                display_message)
        except Exception as e:
            messagebox.showerror(
                "Send Error", f"Failed to send group message: {e}")
            self.master.after(0, self.logout)

    # Function to handle sending files
    def send_file(self):
        if self.chat_mode == '1-on-1' and not self.current_recipient:
            messagebox.showwarning(
                "No Recipient", "Select a user to send a file.")
            return
        if self.chat_mode == 'group' and not self.current_group_id:
            messagebox.showwarning(
                "No Group", "Select a group to send a file.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        file_b64 = base64.b64encode(file_bytes).decode('utf-8')

        msg = {
            "action": "file" if self.chat_mode == '1-on-1' else "group_file",
            "session": self.session_token,
            "filename": filename,
            "filedata": file_b64,
        }

        if self.chat_mode == '1-on-1':
            msg["recipient"] = self.current_recipient
        else:
            msg["group_id"] = self.current_group_id

        self.send_json(msg)

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

        new_users_to_fetch_pk = [
            u for u in filtered_users_list if u not in self.public_keys_cache]
        if new_users_to_fetch_pk:
            print(
                f"Requesting public keys for new users: {new_users_to_fetch_pk}")
            self.request_public_keys(new_users_to_fetch_pk)

        # Retain selection if current_recipient is still online and 1-on-1 mode
        if self.chat_mode == '1-on-1' and self.current_recipient and self.current_recipient in filtered_users_list:
            try:
                idx = filtered_users_list.index(self.current_recipient)
                self.online_users_listbox.selection_set(idx)
                self.online_users_listbox.activate(idx)
            except ValueError:
                pass
        # Deselect if current_recipient went offline
        elif self.chat_mode == '1-on-1' and self.current_recipient and self.current_recipient not in filtered_users_list:
            self.current_recipient = None
            self.recipient_label.config(
                text="Select a user or group to chat with")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
        # If in group mode, ensure 1-on-1 list is clear of selection
        elif self.chat_mode == 'group':
            self.online_users_listbox.selection_clear(0, tk.END)

    def update_groups_list(self, groups_list):
        self.master.after(0, self._update_groups_gui, groups_list)

    def _update_groups_gui(self, groups_list):
        self.groups_listbox.delete(0, tk.END)
        self.my_groups = groups_list  # Update internal list
        for group in groups_list:
            self.groups_listbox.insert(tk.END, group['name'])

        # Retain selection if current_group is still active and in group mode
        if self.chat_mode == 'group' and self.current_group_id:
            try:
                # Find group by ID, then get its name, then find its index in the listbox
                current_group_name = next(
                    (g['name'] for g in self.my_groups if g['id'] == self.current_group_id), None)
                if current_group_name:
                    idx = self.groups_listbox.get(
                        0, tk.END).index(current_group_name)
                    self.groups_listbox.selection_set(idx)
                    self.groups_listbox.activate(idx)
                else:  # Group might have been deleted or user removed from it
                    self.current_group_id = None
                    self.recipient_label.config(
                        text="Select a user or group to chat with")
                    self.chat_display.config(state='normal')
                    self.chat_display.delete(1.0, tk.END)
                    self.chat_display.config(state='disabled')
            except ValueError:  # Group not found in listbox
                pass
        # If in 1-on-1 mode, ensure group list is clear of selection
        elif self.chat_mode == '1-on-1':
            self.groups_listbox.selection_clear(0, tk.END)

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

    def request_my_groups(self):
        message = {
            'action': 'get_my_groups',
            'session': self.session_token
        }
        try:
            self.send_json(message)
        except Exception as e:
            print(f"Error requesting my groups: {e}")

    def request_encrypted_group_key(self, group_id):
        message = {
            'action': 'get_encrypted_group_key',
            'session': self.session_token,
            'group_id': group_id
        }
        try:
            self.send_json(message)
        except Exception as e:
            print(f"Error requesting encrypted group key: {e}")

    def create_group_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Create New Group")
        dialog.transient(self.master)  # Make dialog on top of main window
        dialog.grab_set()  # Make dialog modal
        dialog.geometry("300x400")

        tk.Label(dialog, text="Group Name:").pack(pady=5)
        group_name_entry = tk.Entry(dialog, width=30)
        group_name_entry.pack(pady=5)

        tk.Label(dialog, text="Select Members:").pack(pady=5)
        # Create a Listbox with extended selection for multiple users
        members_listbox = tk.Listbox(
            dialog, selectmode=tk.MULTIPLE, width=30, height=10)
        members_listbox.pack(pady=5)

        # Populate with current online users (excluding self)
        current_online_users = [u for u in self.online_users_listbox.get(
            0, tk.END) if u != self.username]
        for user in current_online_users:
            members_listbox.insert(tk.END, user)
        # Select self by default
        members_listbox.insert(tk.END, self.username)
        # Select the last added item (self)
        members_listbox.selection_set(tk.END)

        def on_create():
            group_name = group_name_entry.get().strip()
            selected_indices = members_listbox.curselection()
            selected_members = [members_listbox.get(
                i) for i in selected_indices]

            if not group_name:
                messagebox.showwarning(
                    "Input Error", "Group name cannot be empty.", parent=dialog)
                return
            if len(selected_members) < 1:  # Must have at least 1 member (self)
                messagebox.showwarning(
                    "Input Error", "Please select at least one member (yourself).", parent=dialog)
                return
            if self.username not in selected_members:
                messagebox.showwarning(
                    "Input Error", "You must be a member of the group you create.", parent=dialog)
                return

            self._create_group(group_name, selected_members)
            dialog.destroy()

        tk.Button(dialog, text="Create", command=on_create).pack(
            side=tk.LEFT, padx=10, pady=10)
        tk.Button(dialog, text="Cancel", command=dialog.destroy).pack(
            side=tk.RIGHT, padx=10, pady=10)

    def _create_group(self, group_name, selected_members):
        if not self.private_key:
            messagebox.showerror(
                "Error", "Your private key is not loaded. Cannot create group securely.")
            return

        # Generate the long-lived group AES key (32 bytes for AES-256)
        group_secret_key = os.urandom(32)

        members_with_encrypted_keys = {}
        # Encrypt the group_secret_key for each member with their RSA public key
        for member_username in selected_members:
            member_public_key = self.public_keys_cache.get(member_username)
            if not member_public_key:
                messagebox.showwarning(
                    "Missing Public Key", f"Public key for {member_username} not found. Cannot add to group. Please ensure they have logged in previously.")
                continue  # Skip this member if PK not available

            try:
                encrypted_group_secret_key_bytes = member_public_key.encrypt(
                    group_secret_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                members_with_encrypted_keys[member_username] = base64.b64encode(
                    encrypted_group_secret_key_bytes).decode('utf-8')
            except Exception as e:
                print(f"Error encrypting group key for {member_username}: {e}")
                messagebox.showerror(
                    "Encryption Error", f"Failed to encrypt group key for {member_username}.")
                return  # Abort group creation if any member key fails encryption

        if self.username not in members_with_encrypted_keys:
            messagebox.showerror(
                "Error", "You must be included in the group you create.")
            return

        message = {
            'action': 'create_group',
            'session': self.session_token,
            'group_name': group_name,
            'members_with_encrypted_keys': members_with_encrypted_keys
        }
        try:
            self.send_json(message)
            # The server will respond with 'group_created' which is handled in receive_messages
        except Exception as e:
            messagebox.showerror("Group Creation Error",
                                 f"Failed to send group creation request: {e}")
            self.master.after(0, self.logout)

    def _get_group_name(self, group_id):
        for group in self.my_groups:
            if group['id'] == group_id:
                return group['name']
        return f"Group ID {group_id}"

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

                action = msg.get('action')

                if action == 'chat_message':  # One-on-one message
                    sender = msg.get('from', 'Unknown')
                    encrypted_content_b64 = msg.get('encrypted_content')
                    encrypted_aes_key_b64 = msg.get('encrypted_aes_key')

                    if not self.private_key:
                        print("Error: Private key not loaded for decryption.")
                        self.insert_message_to_chat(
                            f"[{sender}]: (Decryption failed - private key missing)")
                        continue

                    content = "(Decryption Failed)"
                    try:
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

                    display_message = f"{sender}: {content}"
                    self.one_on_one_chat_histories[sender].append(
                        display_message)
                    if sender == self.current_recipient and self.chat_mode == '1-on-1':
                        self.insert_message_to_chat(display_message)
                        # --- Self-destruct logic ---
                        if msg.get('self_destruct'):
                            seconds = msg.get('destruct_after', 5)
                            self.master.after(
                                seconds * 1000,
                                lambda: self._remove_last_message_from_chat(
                                    '1-on-1', sender)
                            )
                    else:
                        print(
                            f"New 1-on-1 message from {sender} (not current recipient): {content}")
                        self.master.after(0, lambda: self.master.bell())

                elif action == 'group_chat_message':  # NEW: Group chat message
                    group_id = msg.get('group_id')
                    sender = msg.get('from', 'Unknown')
                    encrypted_content_b64 = msg.get('encrypted_content')
                    encrypted_message_aes_key_b64 = msg.get(
                        'encrypted_message_aes_key')

                    group_secret_key = self.my_group_secret_keys.get(group_id)
                    if not group_secret_key:
                        print(
                            f"Error: Group secret key not available for group {group_id}. Cannot decrypt message.")
                        display_message = f"[{self._get_group_name(group_id)}] {sender}: (Decryption failed - group key missing)"
                        self.group_chat_histories[group_id].append(
                            display_message)
                        if group_id == self.current_group_id and self.chat_mode == 'group':
                            self.insert_message_to_chat(display_message)
                            # --- Self-destruct logic ---
                            if msg.get('self_destruct'):
                                seconds = msg.get('destruct_after', 5)
                                self.master.after(
                                    seconds * 1000,
                                    lambda: self._remove_last_message_from_chat(
                                        'group', group_id)
                                )
                        self.master.after(0, lambda: self.master.bell())
                        continue

                    content = "(Decryption Failed)"
                    try:
                        # 1. Decrypt message's ephemeral AES key with the group's secret key
                        combined_encrypted_key_data = base64.b64decode(
                            encrypted_message_aes_key_b64)
                        nonce_key = combined_encrypted_key_data[:12]
                        encrypted_message_aes_key_bytes = combined_encrypted_key_data[12:-16]
                        tag_key = combined_encrypted_key_data[-16:]

                        message_aes_key = decrypt_message_aes(
                            nonce_key, encrypted_message_aes_key_bytes, tag_key, group_secret_key)

                        # 2. Decrypt message content with message's AES key
                        combined_aes_encrypted_data = base64.b64decode(
                            encrypted_content_b64)
                        nonce_msg = combined_aes_encrypted_data[:12]
                        ciphertext = combined_aes_encrypted_data[12:-16]
                        tag_msg = combined_aes_encrypted_data[-16:]

                        decrypted_content_bytes = decrypt_message_aes(
                            nonce_msg, ciphertext, tag_msg, message_aes_key)
                        content = decrypted_content_bytes.decode('utf-8')

                    except InvalidTag:
                        print(
                            f"Group message decryption failed for {sender} in group {group_id}: InvalidTag (corrupted message or wrong key)")
                        content = "(Decryption Failed: Message Integrity Compromised)"
                    except Exception as e:
                        print(
                            f"Group message decryption failed for {sender} in group {group_id}: {e}")
                        content = "(Decryption Failed)"

                    display_message = f"[{self._get_group_name(group_id)}] {sender}: {content}"
                    self.group_chat_histories[group_id].append(display_message)
                    if group_id == self.current_group_id and self.chat_mode == 'group':
                        self.insert_message_to_chat(display_message)
                    else:
                        print(
                            f"New group message from {sender} in group {self._get_group_name(group_id)} (not current): {content}")
                        self.master.after(0, lambda: self.master.bell())

                    # --- FILE SHARING HANDLING ---
                elif action == 'file_message':
                    sender = msg.get('from')
                    filename = msg.get('filename')
                    filedata = msg.get('filedata')
                    display_message = f"{sender} sent a file: {filename}"
                    self._insert_file_message_to_chat(
                        display_message, filename, filedata, mode='1-on-1', key=sender)
                elif action == 'group_file_message':
                    sender = msg.get('from')
                    group_id = msg.get('group_id')
                    filename = msg.get('filename')
                    filedata = msg.get('filedata')
                    display_message = f"[{self._get_group_name(group_id)}] {sender} sent a file: {filename}"
                    self._insert_file_message_to_chat(
                        display_message, filename, filedata, mode='group', key=group_id)
                # --- END FILE SHARING HANDLING ---

                elif action == 'online_users_list':
                    users = msg.get('users', [])
                    self.update_online_users_list(users)

                elif action == 'public_keys_response':
                    for user, pk_pem_b64 in msg.get('public_keys', {}).items():
                        try:
                            pk_pem_bytes = base64.b64decode(pk_pem_b64)
                            self.public_keys_cache[user] = load_pem_public_key(
                                pk_pem_bytes, backend=default_backend())
                            print(f"Cached public key for {user}")
                        except Exception as e:
                            print(
                                f"Error loading public key for {user} from server response: {e}")

                elif action == 'group_created':  # NEW: Group created notification
                    group_id = msg.get('group_id')
                    group_name = msg.get('group_name')
                    messagebox.showinfo(
                        "Group Created", f"Group '{group_name}' created successfully with ID: {group_id}")
                    self.request_my_groups()  # Refresh group list

                    # If this client was the creator, they already have the group_secret_key.
                    # The server will send a 'new_group_notification' to other members.
                    # For the creator, the group_secret_key is generated and temporarily in memory
                    # and should be stored locally here using the password.
                    # This is handled in _create_group by generating and encrypting it for self and other members,
                    # but it needs to be stored on the client side too for future sessions.
                    # This specific part of storage is done during _create_group
                    # if this client is the creator, the group_secret_key_encrypted_b64 is already saved locally
                    # when the create_group_dialog successfully sends it.

                elif action == 'new_group_notification':  # NEW: Other members get notification
                    group_id = msg.get('group_id')
                    group_name = msg.get('group_name')
                    creator = msg.get('creator')
                    messagebox.showinfo(
                        "New Group!", f"You've been added to group '{group_name}' created by {creator}.")
                    self.request_my_groups()  # Refresh group list

                elif action == 'my_groups_list':  # NEW: List of groups user is in
                    groups_data = msg.get('groups', [])
                    self.update_groups_list(groups_data)

                elif action == 'encrypted_group_key_response':  # NEW: Encrypted group key received
                    group_id = msg.get('group_id')
                    encrypted_group_secret_key_b64 = msg.get(
                        'encrypted_group_secret_key_b64')
                    if encrypted_group_secret_key_b64 and self.private_key and self.user_password:
                        try:
                            # Decrypt group secret key using own RSA private key
                            encrypted_key_bytes = base64.b64decode(
                                encrypted_group_secret_key_b64)
                            decrypted_group_secret_key = self.private_key.decrypt(
                                encrypted_key_bytes,
                                padding.OAEP(
                                    mgf=padding.MGF1(
                                        algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            self.my_group_secret_keys[group_id] = decrypted_group_secret_key
                            group_name = self._get_group_name(group_id)
                            self.store_local_group_key(
                                group_id, group_name, encrypted_group_secret_key_b64)
                            print(
                                f"Decrypted and stored group secret key for group {group_name} (ID: {group_id})")
                            messagebox.showinfo(
                                "Group Key Ready", f"Group key for '{group_name}' loaded successfully. You can now chat.")
                            # If this was the currently selected group, reload chat history to enable sending
                            if self.current_group_id == group_id and self.chat_mode == 'group':
                                self.load_chat_history()  # Re-enable sending now that key is ready
                        except Exception as e:
                            print(
                                f"Failed to decrypt group key from server response for group {group_id}: {e}")
                            messagebox.showwarning(
                                "Group Key Error", f"Failed to decrypt key for group ID {group_id}. Check your password or try again.")
                    else:
                        print(
                            f"Received encrypted group key but unable to decrypt or private key/password missing.")
                        messagebox.showwarning(
                            "Group Key Error", "Received group key but cannot decrypt it.")

                elif msg.get('status') == 'error' or msg.get('status') == 'fail':
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

    def _remove_last_message_from_chat(self, mode, key):
        # Remove last message from chat display and history
        if mode == '1-on-1':
            history = self.one_on_one_chat_histories[key]
        else:
            history = self.group_chat_histories[key]
        if history:
            history.pop()
            self.load_chat_history()

    # Helper function to insert file messages into the chat display
    def _insert_file_message_to_chat(self, display_message, filename, filedata, mode, key):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, display_message + " ")
        btn = tk.Button(self.chat_display, text="Save", padx=2, pady=0,
                        command=partial(self._save_file, filename, filedata))
        self.chat_display.window_create(tk.END, window=btn)
        self.chat_display.insert(tk.END, "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')
        # Save to history for reload
        if mode == '1-on-1':
            self.one_on_one_chat_histories[key].append(
                (display_message, filename, filedata))
        else:
            self.group_chat_histories[key].append(
                (display_message, filename, filedata))

    # Helper function to save files
    def _save_file(self, filename, filedata):
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(base64.b64decode(filedata))
            messagebox.showinfo("File Saved", f"Saved file to {save_path}")

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

        self.sock = None
        self.session_token = None
        self.username = None
        self.current_recipient = None
        self.current_group_id = None
        self.chat_mode = '1-on-1'
        self.private_key = None
        self.public_key = None
        self.public_keys_cache = {}
        self.user_password = None  # IMPORTANT: Clear the password from memory on logout
        self.my_groups = []
        self.my_group_secret_keys = {}
        self.group_chat_histories.clear()
        self.one_on_one_chat_histories.clear()

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
    root.geometry("600x600")  # Increased size for new elements
    app = ChatClient(root)

    def on_closing():
        if app.running:
            app.logout()
        else:
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
