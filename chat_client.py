# import tkinter as tk
# from tkinter import messagebox, scrolledtext
# import socket
# import threading
# import json

# SERVER_HOST = '127.0.0.1'
# SERVER_PORT = 5555


# class ChatClient:
#     def __init__(self, master):
#         self.master = master
#         self.master.title("Secure Chat App")
#         self.session_token = None
#         self.username = None
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((SERVER_HOST, SERVER_PORT))
#         except:
#             messagebox.showerror("Error", "Could not connect to server.")
#             self.master.destroy()

#         self.build_login_screen()

#     def build_login_screen(self):
#         self.clear_window()
#         tk.Label(self.master, text="Login", font=("Arial", 18)).pack(pady=10)
#         self.user_entry = tk.Entry(self.master, width=30)
#         self.user_entry.pack(pady=5)
#         self.user_entry.insert(0, "Username")

#         self.pass_entry = tk.Entry(self.master, width=30, show="*")
#         self.pass_entry.pack(pady=5)
#         self.pass_entry.insert(0, "Password")

#         tk.Button(self.master, text="Login", command=self.login).pack(pady=10)
#         tk.Button(self.master, text="Register",
#                   command=self.build_register_screen).pack()

#     def build_register_screen(self):
#         self.clear_window()
#         tk.Label(self.master, text="Register",
#                  font=("Arial", 18)).pack(pady=10)
#         self.reg_user_entry = tk.Entry(self.master, width=30)
#         self.reg_user_entry.pack(pady=5)
#         self.reg_user_entry.insert(0, "Username")

#         self.reg_pass_entry = tk.Entry(self.master, width=30, show="*")
#         self.reg_pass_entry.pack(pady=5)
#         self.reg_pass_entry.insert(0, "Password")

#         tk.Button(self.master, text="Register",
#                   command=self.register).pack(pady=10)
#         tk.Button(self.master, text="Back to Login",
#                   command=self.build_login_screen).pack()

#     def build_chat_screen(self):
#         self.clear_window()
#         tk.Label(self.master, text=f"Logged in as {self.username}", font=(
#             "Arial", 12)).pack()
#         self.chat_display = scrolledtext.ScrolledText(
#             self.master, state='disabled', width=50, height=15)
#         self.chat_display.pack(pady=10)
#         self.message_entry = tk.Entry(self.master, width=40)
#         self.message_entry.pack(side=tk.LEFT, padx=5, pady=5)
#         tk.Button(self.master, text="Send", command=self.send_message).pack(
#             side=tk.LEFT, padx=5)
#         threading.Thread(target=self.receive_messages, daemon=True).start()

#     def login(self):
#         username = self.user_entry.get()
#         password = self.pass_entry.get()
#         self.username = username
#         message = {
#             'action': 'login',
#             'username': username,
#             'password': password
#         }
#         self.sock.send(json.dumps(message).encode())
#         response = json.loads(self.sock.recv(1024).decode())
#         if response.get('status') == 'ok':
#             self.session_token = response['session']
#             self.build_chat_screen()
#         else:
#             messagebox.showerror("Login Failed", "Invalid credentials")

#     def register(self):
#         username = self.reg_user_entry.get()
#         password = self.reg_pass_entry.get()
#         # Send to server or use a separate admin tool for registration
#         messagebox.showinfo(
#             "Note", "Registration must be handled server-side.\nAsk admin to add user.")
#         self.build_login_screen()

#     def send_message(self):
#         content = self.message_entry.get()
#         if not content.strip():
#             return
#         message = {
#             'action': 'message',
#             'session': self.session_token,
#             'content': content
#         }
#         self.sock.send(json.dumps(message).encode())
#         self.message_entry.delete(0, tk.END)

#     def receive_messages(self):
#         while True:
#             try:
#                 data = self.sock.recv(4096)
#                 if not data:
#                     break
#                 msg = json.loads(data.decode())
#                 if msg.get('status') == 'received':
#                     continue  # confirmation
#                 self.chat_display.config(state='normal')
#                 self.chat_display.insert(
#                     tk.END, f"{msg.get('from', 'Server')}: {msg.get('content')}\n")
#                 self.chat_display.config(state='disabled')
#                 self.chat_display.see(tk.END)
#             except:
#                 break

#     def clear_window(self):
#         for widget in self.master.winfo_children():
#             widget.destroy()


# if __name__ == "__main__":
#     root = tk.Tk()
#     root.geometry("400x400")
#     app = ChatClient(root)
#     root.mainloop()


import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import json

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555


class ChatClient:
    def __init__(self, master):
        self.master = master
        self.running = False
        self.master.title("CipherNet: Secure Chat App")
        self.session_token = None
        self.username = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))
        except:
            messagebox.showerror("Error", "Could not connect to server.")
            self.master.destroy()

        self.build_login_screen()

    def initialize_connection(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))
        except:
            messagebox.showerror("Error", "Could not connect to server.")
            self.master.destroy()

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
        tk.Label(self.master, text=f"Logged in as {self.username}", font=(
            "Arial", 12)).pack()
        self.chat_display = scrolledtext.ScrolledText(
            self.master, state='disabled', width=50, height=15)
        self.chat_display.pack(pady=10)
        self.message_entry = tk.Entry(self.master, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=5, pady=5)
        tk.Button(self.master, text="Send", command=self.send_message).pack(
            side=tk.LEFT, padx=5)

        # Logout button
        tk.Button(self.master, text="Logout", command=self.logout).pack(
            side=tk.RIGHT, padx=5, pady=5)

        # Flag to control receive_messages thread
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def login(self):
        username = self.user_entry.get()
        password = self.pass_entry.get()
        self.username = username
        message = {
            'action': 'login',
            'username': username,
            'password': password
        }
        self.sock.send(json.dumps(message).encode())
        response = json.loads(self.sock.recv(1024).decode())
        if response.get('status') == 'ok':
            self.session_token = response['session']
            self.build_chat_screen()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    def register(self):
        username = self.reg_user_entry.get()
        password = self.reg_pass_entry.get()
        if not username or not password:
            messagebox.showwarning(
                "Input Error", "Username and password are required.")
            return

        message = {
            'action': 'register',
            'username': username,
            'password': password
        }
        try:
            self.sock.send(json.dumps(message).encode())
            response = json.loads(self.sock.recv(1024).decode())
            if response.get('status') == 'registered':
                messagebox.showinfo(
                    "Success", "Registration successful! Please login.")
                self.build_login_screen()
            elif response.get('status') == 'exists':
                messagebox.showerror("Error", "Username already exists.")
            else:
                messagebox.showerror("Error", "Registration failed.")
        except Exception as e:
            messagebox.showerror("Error", f"Error during registration: {e}")

    def send_message(self):
        content = self.message_entry.get()
        if not content.strip():
            return
        message = {
            'action': 'message',
            'session': self.session_token,
            'content': content
        }
        self.sock.send(json.dumps(message).encode())
        self.message_entry.delete(0, tk.END)

    def receive_messages(self):
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                msg = json.loads(data.decode())
                if msg.get('status') == 'received':
                    continue  # confirmation
                self.chat_display.config(state='normal')
                self.chat_display.insert(
                    tk.END, f"{msg.get('from', 'Server')}: {msg.get('content')}\n")
                self.chat_display.config(state='disabled')
                self.chat_display.see(tk.END)
            except:
                break

    def logout(self):
        if self.sock and self.session_token:
            try:
                logout_msg = {
                    'action': 'logout',
                    'session': self.session_token
                }
                self.sock.send(json.dumps(logout_msg).encode())
                response = json.loads(self.sock.recv(1024).decode())
                if response.get('status') == 'logged_out':
                    messagebox.showinfo("Logout", "Successfully logged out.")
                else:
                    messagebox.showwarning(
                        "Logout", "Logout failed or session invalid.")
            except Exception as e:
                messagebox.showerror(
                    "Logout Error", f"Error during logout: {e}")

        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except:
                pass
        self.sock = None
        self.session_token = None
        self.username = None
        self.initialize_connection()
        self.build_login_screen()

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("400x400")
    app = ChatClient(root)
    root.mainloop()
