import socket
import threading
import json
import os
import base64
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, filedialog
from tkinter import ttk
from collections import defaultdict
from functools import partial

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_public_key, load_pem_private_key

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key(private_key_pem_bytes, password):
    salt = os.urandom(16)
    key_for_aes = derive_key(password, salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_for_aes),
                    modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(private_key_pem_bytes) + encryptor.finalize()
    tag = encryptor.tag
    combined_encrypted_data = salt + nonce + ciphertext + tag
    return base64.b64encode(combined_encrypted_data).decode('utf-8')


def decrypt_private_key(encrypted_data_b64, password):
    combined_encrypted_data = base64.b64decode(encrypted_data_b64)
    salt = combined_encrypted_data[:16]
    nonce = combined_encrypted_data[16:28]
    ciphertext = combined_encrypted_data[28:-16]
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
    tag = encryptor.tag
    return nonce, ciphertext, tag


def decrypt_message_aes(nonce, ciphertext, tag, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("CipherNet Secure Chat")
        self.sock = None
        self.session_token = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self.public_keys = {}
        self.my_groups = []
        self.group_keys = {}
        self.current_recipient = None
        self.current_group_id = None
        self.chat_mode = '1-on-1'
        self.one_on_one_chat_histories = defaultdict(list)
        self.group_chat_histories = defaultdict(list)
        self.self_destruct_var = tk.BooleanVar(value=False)
        self.self_destruct_time = tk.IntVar(value=5)
        self.running = False
        self.build_login_screen()

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((SERVER_HOST, SERVER_PORT))

    def send_json(self, data):
        try:
            json_data = json.dumps(data)
            message_length = len(json_data.encode('utf-8'))
            header = f"{message_length:<8}".encode('utf-8')
            self.sock.sendall(header + json_data.encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")

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
                bytes_received += len(chunk)
            return json.loads(full_message_bytes.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None

    def build_login_screen(self):
        self.clear_window()
        frame = tk.Frame(self.master)
        frame.pack(padx=20, pady=20)
        tk.Label(frame, text="CipherNet Secure Chat",
                 font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(frame, text="Username:").pack()
        self.username_entry = tk.Entry(frame)
        self.username_entry.pack()
        tk.Label(frame, text="Password:").pack()
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.pack()
        tk.Button(frame, text="Login", command=self.login).pack(pady=5)
        tk.Button(frame, text="Register", command=self.register).pack(pady=5)

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning(
                "Input Error", "Please enter both username and password.")
            return
        self.connect()
        self.username = username
        key_file = f"{username}_private.pem"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                encrypted_private_key_b64 = f.read().decode('utf-8')
            try:
                private_key_pem = decrypt_private_key(
                    encrypted_private_key_b64, password)
                self.private_key = load_pem_private_key(
                    private_key_pem, password=None, backend=default_backend())
                self.public_key = self.private_key.public_key()
            except Exception as e:
                messagebox.showerror(
                    "Key Error", f"Failed to decrypt private key: {e}")
                return
        else:
            self.private_key, self.public_key, private_key_pem, public_key_pem = generate_rsa_key_pair()
            encrypted_private_key_b64 = encrypt_private_key(
                private_key_pem, password)
            with open(key_file, "w") as f:
                f.write(encrypted_private_key_b64)
        public_key_b64 = base64.b64encode(
            self.public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        ).decode('utf-8')
        login_data = {
            'action': 'login',
            'username': username,
            'password': password,
            'public_key': public_key_b64
        }
        self.send_json(login_data)
        response = self.recv_json()
        if response and response.get('status') == 'ok':
            self.session_token = response['session']
            self.public_keys = response.get('public_keys', {})
            self.my_groups = response.get('user_groups', [])
            self.build_chat_screen()
        else:
            messagebox.showerror("Login Failed", response.get(
                'message', 'Unknown error'))
            self.sock.close()

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning(
                "Input Error", "Please enter both username and password.")
            return
        self.private_key, self.public_key, private_key_pem, public_key_pem = generate_rsa_key_pair()
        encrypted_private_key_b64 = encrypt_private_key(
            private_key_pem, password)
        key_file = f"{username}_private.pem"
        with open(key_file, "w") as f:
            f.write(encrypted_private_key_b64)
        public_key_b64 = base64.b64encode(public_key_pem).decode('utf-8')
        self.connect()
        register_data = {
            'action': 'register',
            'username': username,
            'password': password,
            'public_key': public_key_b64
        }
        self.send_json(register_data)
        response = self.recv_json()
        if response and response.get('status') == 'registered':
            messagebox.showinfo("Registration Successful",
                                "You can now log in.")
            self.sock.close()
        else:
            messagebox.showerror("Registration Failed",
                                 response.get('message', 'Unknown error'))
            self.sock.close()

    def build_chat_screen(self):
        self.clear_window()
        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        left_panel = tk.Frame(main_frame, bd=2, relief=tk.GROOVE)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        tk.Label(left_panel, text="Online Users",
                 font=("Arial", 10, "bold")).pack(pady=5)
        self.online_users_listbox = tk.Listbox(left_panel, width=20, height=8)
        self.online_users_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.online_users_listbox.bind(
            '<<ListboxSelect>>', self.select_1on1_recipient)
        tk.Button(left_panel, text="Create Group",
                  command=self.create_group_dialog).pack(pady=5)
        tk.Label(left_panel, text="My Groups", font=(
            "Arial", 10, "bold")).pack(pady=5)
        self.groups_listbox = tk.Listbox(left_panel, width=20, height=8)
        self.groups_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.groups_listbox.bind('<<ListboxSelect>>', self.select_group)
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
        tk.Checkbutton(
            message_input_frame, text="Self-Destruct",
            variable=self.self_destruct_var
        ).pack(side=tk.LEFT, padx=2)
        tk.Label(message_input_frame, text="After (s):").pack(side=tk.LEFT)
        tk.Entry(
            message_input_frame, textvariable=self.self_destruct_time, width=3
        ).pack(side=tk.LEFT, padx=2)
        tk.Button(message_input_frame, text="Send",
                  command=self.send_message).pack(side=tk.LEFT, padx=5)
        tk.Button(message_input_frame, text="Send File",
                  command=self.send_file).pack(side=tk.LEFT, padx=5)
        tk.Button(chat_frame, text="Logout", command=self.logout).pack(
            pady=5, side=tk.RIGHT, padx=5)
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.request_online_users()
        self.request_my_groups()

    def request_online_users(self):
        self.send_json({'action': 'get_online_users',
                       'session': self.session_token})

    def request_my_groups(self):
        self.send_json({'action': 'get_my_groups',
                       'session': self.session_token})

    def select_1on1_recipient(self, event):
        selection = self.online_users_listbox.curselection()
        if selection:
            recipient = self.online_users_listbox.get(selection[0])
            self.current_recipient = recipient
            self.chat_mode = '1-on-1'
            self.recipient_label.config(text=f"Chatting with: {recipient}")
            self.load_chat_history()

    def select_group(self, event):
        selection = self.groups_listbox.curselection()
        if selection:
            idx = selection[0]
            group = self.my_groups[idx]
            self.current_group_id = group['id']
            self.chat_mode = 'group'
            self.recipient_label.config(text=f"Group: {group['name']}")
            self.load_chat_history()

    def load_chat_history(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        if self.chat_mode == '1-on-1' and self.current_recipient:
            for entry in self.one_on_one_chat_histories[self.current_recipient]:
                if isinstance(entry, tuple):
                    display_message, filename, filedata = entry
                    self.chat_display.insert(tk.END, display_message + " ")
                    btn = tk.Button(self.chat_display, text="Save", padx=2, pady=0,
                                    command=partial(self._save_file, filename, filedata))
                    self.chat_display.window_create(tk.END, window=btn)
                    self.chat_display.insert(tk.END, "\n")
                else:
                    self.chat_display.insert(tk.END, entry + "\n")
        elif self.chat_mode == 'group' and self.current_group_id:
            for entry in self.group_chat_histories[self.current_group_id]:
                if isinstance(entry, tuple):
                    display_message, filename, filedata = entry
                    self.chat_display.insert(tk.END, display_message + " ")
                    btn = tk.Button(self.chat_display, text="Save", padx=2, pady=0,
                                    command=partial(self._save_file, filename, filedata))
                    self.chat_display.window_create(tk.END, window=btn)
                    self.chat_display.insert(tk.END, "\n")
                else:
                    self.chat_display.insert(tk.END, entry + "\n")
        self.chat_display.config(state='disabled')

    def insert_message_to_chat(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def send_message(self):
        content = self.message_entry.get()
        if not content.strip():
            return
        self_destruct = self.self_destruct_var.get()
        destruct_after = self.self_destruct_time.get() if self_destruct else 0
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
        self.message_entry.focus_set()

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

    def _send_1on1_message(self, content, self_destruct=False, destruct_after=0):
        recipient_pk_b64 = self.public_keys.get(self.current_recipient)
        if not recipient_pk_b64:
            messagebox.showerror("Encryption Error",
                                 "Recipient's public key not found.")
            return
        recipient_pk = load_pem_public_key(base64.b64decode(
            recipient_pk_b64), backend=default_backend())
        aes_key = os.urandom(32)
        nonce, ciphertext, tag = encrypt_message_aes(
            content.encode('utf-8'), aes_key)
        encrypted_content = base64.b64encode(
            nonce + ciphertext + tag).decode('utf-8')
        encrypted_aes_key = recipient_pk.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        encrypted_aes_key_b64 = base64.b64encode(
            encrypted_aes_key).decode('utf-8')
        message = {
            'action': 'message',
            'session': self.session_token,
            'recipient': self.current_recipient,
            'encrypted_content': encrypted_content,
            'encrypted_aes_key': encrypted_aes_key_b64,
            'self_destruct': self_destruct,
            'destruct_after': destruct_after
        }
        self.send_json(message)

    def _send_group_message(self, content, self_destruct=False, destruct_after=0):
        group_id = self.current_group_id
        group_key = self.group_keys.get(group_id)
        if not group_key:
            messagebox.showerror("Encryption Error", "Group key not found.")
            return
        aes_key = os.urandom(32)
        nonce, ciphertext, tag = encrypt_message_aes(
            content.encode('utf-8'), aes_key)
        encrypted_content = base64.b64encode(
            nonce + ciphertext + tag).decode('utf-8')
        encrypted_message_aes_key = base64.b64encode(aes_key).decode('utf-8')
        message = {
            'action': 'group_message',
            'session': self.session_token,
            'group_id': group_id,
            'encrypted_content': encrypted_content,
            'encrypted_message_aes_key': encrypted_message_aes_key,
            'self_destruct': self_destruct,
            'destruct_after': destruct_after
        }
        self.send_json(message)

    def receive_messages(self):
        while self.running:
            try:
                msg = self.recv_json()
                if msg is None:
                    self.master.after(0, lambda: messagebox.showerror(
                        "Connection Error", "Server disconnected."))
                    self.master.after(0, self.logout)
                    break
                action = msg.get('action')
                if action == 'online_users_list':
                    users = msg.get('users', [])
                    self.online_users_listbox.delete(0, tk.END)
                    for user in users:
                        if user != self.username:
                            self.online_users_listbox.insert(tk.END, user)
                elif action == 'my_groups_list':
                    self.my_groups = msg.get('groups', [])
                    self.groups_listbox.delete(0, tk.END)
                    for group in self.my_groups:
                        self.groups_listbox.insert(tk.END, group['name'])
                elif action == 'chat_message':
                    sender = msg.get('from')
                    encrypted_content = msg.get('encrypted_content')
                    encrypted_aes_key_b64 = msg.get('encrypted_aes_key')
                    try:
                        encrypted_aes_key = base64.b64decode(
                            encrypted_aes_key_b64)
                        aes_key = self.private_key.decrypt(
                            encrypted_aes_key,
                            padding.OAEP(mgf=padding.MGF1(
                                algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        data = base64.b64decode(encrypted_content)
                        nonce = data[:12]
                        tag = data[-16:]
                        ciphertext = data[12:-16]
                        content = decrypt_message_aes(
                            nonce, ciphertext, tag, aes_key).decode('utf-8')
                    except Exception as e:
                        content = "[Decryption failed]"
                    display_message = f"{sender}: {content}"
                    self.one_on_one_chat_histories[sender].append(
                        display_message)
                    if sender == self.current_recipient and self.chat_mode == '1-on-1':
                        self.insert_message_to_chat(display_message)
                        if msg.get('self_destruct'):
                            seconds = msg.get('destruct_after', 5)
                            self.master.after(
                                seconds * 1000,
                                lambda: self._remove_last_message_from_chat(
                                    '1-on-1', sender)
                            )
                elif action == 'group_chat_message':
                    sender = msg.get('from')
                    group_id = msg.get('group_id')
                    encrypted_content = msg.get('encrypted_content')
                    encrypted_message_aes_key_b64 = msg.get(
                        'encrypted_message_aes_key')
                    try:
                        aes_key = base64.b64decode(
                            encrypted_message_aes_key_b64)
                        data = base64.b64decode(encrypted_content)
                        nonce = data[:12]
                        tag = data[-16:]
                        ciphertext = data[12:-16]
                        content = decrypt_message_aes(
                            nonce, ciphertext, tag, aes_key).decode('utf-8')
                    except Exception as e:
                        content = "[Decryption failed]"
                    display_message = f"[{self._get_group_name(group_id)}] {sender}: {content}"
                    self.group_chat_histories[group_id].append(display_message)
                    if group_id == self.current_group_id and self.chat_mode == 'group':
                        self.insert_message_to_chat(display_message)
                        if msg.get('self_destruct'):
                            seconds = msg.get('destruct_after', 5)
                            self.master.after(
                                seconds * 1000,
                                lambda: self._remove_last_message_from_chat(
                                    'group', group_id)
                            )
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
                elif action == 'new_group_notification':
                    self.request_my_groups()
                elif action == 'encrypted_group_key_response':
                    group_id = msg.get('group_id')
                    encrypted_group_secret_key_b64 = msg.get(
                        'encrypted_group_secret_key_b64')
                    try:
                        encrypted_group_secret_key = base64.b64decode(
                            encrypted_group_secret_key_b64)
                        group_key = self.private_key.decrypt(
                            encrypted_group_secret_key,
                            padding.OAEP(mgf=padding.MGF1(
                                algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        self.group_keys[group_id] = group_key
                    except Exception as e:
                        print(
                            f"Failed to decrypt group key for group {group_id}: {e}")
            except Exception as e:
                print(f"Error in receive_messages: {e}")
                break

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

    def _save_file(self, filename, filedata):
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(base64.b64decode(filedata))
            messagebox.showinfo("File Saved", f"Saved file to {save_path}")

    def _get_group_name(self, group_id):
        for group in self.my_groups:
            if str(group['id']) == str(group_id):
                return group['name']
        return f"Group ID {group_id}"

    def _remove_last_message_from_chat(self, mode, key):
        if mode == '1-on-1':
            history = self.one_on_one_chat_histories[key]
        else:
            history = self.group_chat_histories[key]
        if history:
            history.pop()
            self.load_chat_history()

    def logout(self):
        self.running = False
        if self.session_token:
            try:
                self.send_json(
                    {'action': 'logout', 'session': self.session_token})
            except Exception as e:
                print(f"Error sending logout message: {e}")
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.session_token = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self.public_keys = {}
        self.my_groups = []
        self.group_keys = {}
        self.current_recipient = None
        self.current_group_id = None
        self.chat_mode = '1-on-1'
        self.one_on_one_chat_histories.clear()
        self.group_chat_histories.clear()
        self.build_login_screen()

    def create_group_dialog(self):
        group_name = simpledialog.askstring(
            "Create Group", "Enter group name:")
        if not group_name:
            return
        selected_indices = self.online_users_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning(
                "No Members", "Select at least one user to add to the group.")
            return
        members = [self.online_users_listbox.get(i) for i in selected_indices]
        members.append(self.username)
        group_secret_key = os.urandom(32)
        members_with_encrypted_keys = {}
        for member in members:
            pk_b64 = self.public_keys.get(member)
            if not pk_b64:
                continue
            pk = load_pem_public_key(base64.b64decode(
                pk_b64), backend=default_backend())
            encrypted_group_key = pk.encrypt(
                group_secret_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )
            members_with_encrypted_keys[member] = base64.b64encode(
                encrypted_group_key).decode('utf-8')
        message = {
            'action': 'create_group',
            'session': self.session_token,
            'group_name': group_name,
            'members_with_encrypted_keys': members_with_encrypted_keys
        }
        self.send_json(message)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
