import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
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
        # New: Stores the username of the user being chatted with
        self.current_recipient = None

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

        # Start a dedicated thread for receiving messages after successful login
        # No need for a separate 'initial_receiver_thread' anymore, the main receive_messages
        # thread will handle all incoming server communications once built_chat_screen is shown.
        # However, to avoid a race condition where login response isn't received,
        # we'll handle login/register responses synchronously first.

        self.build_login_screen()

    # The _initial_receive_handler is not strictly needed as login/register responses
    # are handled synchronously in their respective methods.
    # We remove the call to it for clarity and simplicity.

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

        # Main Frame for layout
        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left Panel for Online Users
        users_frame = tk.Frame(main_frame, bd=2, relief=tk.GROOVE)
        users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        tk.Label(users_frame, text="Online Users",
                 font=("Arial", 10, "bold")).pack(pady=5)
        self.online_users_listbox = tk.Listbox(
            users_frame, width=20, height=15)
        self.online_users_listbox.pack(padx=5, pady=5, fill=tk.Y, expand=True)
        self.online_users_listbox.bind(
            '<<ListboxSelect>>', self.select_recipient)

        # Right Panel for Chat Display and Input
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.recipient_label = tk.Label(
            chat_frame, text="Select a user to chat with", font=("Arial", 12, "bold"))
        self.recipient_label.pack(pady=5)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, state='disabled', width=50, height=15)
        self.chat_display.pack(pady=10, fill=tk.BOTH, expand=True)

        # Message input area
        message_input_frame = tk.Frame(chat_frame)
        message_input_frame.pack(pady=5, fill=tk.X)

        self.message_entry = tk.Entry(message_input_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        self.message_entry.bind(
            "<Return>", lambda event=None: self.send_message())  # Bind Enter key
        tk.Button(message_input_frame, text="Send",
                  command=self.send_message).pack(side=tk.LEFT, padx=5)

        # Logout button
        tk.Button(chat_frame, text="Logout", command=self.logout).pack(
            pady=5, side=tk.RIGHT, padx=5)

        # Flag to control receive_messages thread
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Request online users list immediately after building chat screen
        self.request_online_users()

    def select_recipient(self, event=None):
        selected_indices = self.online_users_listbox.curselection()
        if selected_indices:
            index = selected_indices[0]
            self.current_recipient = self.online_users_listbox.get(index)
            self.recipient_label.config(
                text=f"Chatting with: {self.current_recipient}")
            self.chat_display.config(state='normal')
            # Clear chat display when changing recipient
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
        self.username = username  # Store username after successful login attempt
        message = {
            'action': 'login',
            'username': username,
            'password': password
        }
        try:
            self.sock.send(json.dumps(message).encode('utf-8'))
            # Use a larger buffer for responses
            response_data = self.sock.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            if response.get('status') == 'ok':
                self.session_token = response['session']
                # The server might send the 'username' back for confirmation, if so, use it.
                # Otherwise, rely on self.username set earlier.
                if 'username' in response:
                    self.username = response['username']
                self.build_chat_screen()
            else:
                messagebox.showerror("Login Failed", response.get(
                    'message', "Invalid credentials"))
        except ConnectionResetError:
            messagebox.showerror("Connection Error",
                                 "Server disconnected unexpectedly.")
            self.master.destroy()
        except json.JSONDecodeError:
            messagebox.showerror(
                "Error", "Received malformed response from server.")
        except Exception as e:
            messagebox.showerror(
                "Login Error", f"An error occurred during login: {e}")

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
            self.sock.send(json.dumps(message).encode('utf-8'))
            response_data = self.sock.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            if response.get('status') == 'registered':
                messagebox.showinfo(
                    "Success", "Registration successful! Please login.")
                self.build_login_screen()
            elif response.get('status') == 'exists':
                messagebox.showerror("Error", "Username already exists.")
            else:
                messagebox.showerror("Error", response.get(
                    'message', "Registration failed."))
        except ConnectionResetError:
            messagebox.showerror("Connection Error",
                                 "Server disconnected unexpectedly.")
            self.master.destroy()
        except json.JSONDecodeError:
            messagebox.showerror(
                "Error", "Received malformed response from server.")
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

        message = {
            'action': 'message',
            'session': self.session_token,
            'recipient': self.current_recipient,  # NEW: specify recipient
            'content': content
        }
        try:
            self.sock.send(json.dumps(message).encode('utf-8'))
            # Display own message immediately
            self.insert_message_to_chat(
                f"You to {self.current_recipient}: {content}")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            # Consider logging out if connection is lost
            self.master.after(0, self.logout)

    def insert_message_to_chat(self, message):
        # Use master.after to ensure GUI updates happen on the main thread
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
        for user in users_list:
            # Ensure the user doesn't see themselves in the online users list
            if user != self.username:
                self.online_users_listbox.insert(tk.END, user)

        # Re-select the current recipient if they are still online
        if self.current_recipient and self.current_recipient in users_list:
            try:
                # Find the index of the current recipient in the *displayed* list
                # (which excludes self.username)
                displayed_users = [u for u in users_list if u != self.username]
                if self.current_recipient in displayed_users:
                    idx = displayed_users.index(self.current_recipient)
                    self.online_users_listbox.selection_set(idx)
                    self.online_users_listbox.activate(idx)
            except ValueError:
                pass  # Recipient might have just gone offline right after list update
        elif self.current_recipient and self.current_recipient not in users_list:
            # If current recipient went offline, deselect and clear chat
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
            self.sock.send(json.dumps(message).encode('utf-8'))
        except Exception as e:
            print(f"Error requesting online users: {e}")
            # If this fails, the connection might be broken.
            self.master.after(0, self.logout)

    def receive_messages(self):
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("Server disconnected gracefully.")
                    self.master.after(0, lambda: messagebox.showerror(
                        "Connection Error", "Server disconnected."))
                    # Force logout on server disconnect
                    self.master.after(0, self.logout)
                    break

                msg = json.loads(data.decode('utf-8'))

                # Handle different message types from the server
                if msg.get('action') == 'chat_message':
                    sender = msg.get('from', 'Unknown')
                    content = msg.get('content', '')
                    # Only display if the message is from the currently selected recipient
                    if sender == self.current_recipient:
                        self.insert_message_to_chat(f"{sender}: {content}")
                    # Optional: Add a visual cue (e.g., notification) for messages from other users
                    else:
                        print(
                            f"New message from {sender} (not current recipient): {content}")
                        # Example of notification:
                        # self.master.after(0, lambda: self.master.bell()) # Play a sound
                        # self.master.after(0, lambda: messagebox.showinfo("New Message", f"New message from {sender}"))

                elif msg.get('action') == 'online_users_list':
                    users = msg.get('users', [])
                    self.update_online_users_list(users)

                elif msg.get('status') == 'error':
                    # Handle errors sent from the server (e.g., 'User offline')
                    error_message = msg.get(
                        'message', 'An unknown error occurred on the server.')
                    self.master.after(0, lambda: messagebox.showerror(
                        "Server Error", error_message))

                # Add more conditions for other message types (e.g., group chat, file transfer) later

            except json.JSONDecodeError:
                print(
                    f"Received malformed JSON from server: {data.decode('utf-8')}")
                self.master.after(0, lambda: messagebox.showerror(
                    "Data Error", "Received malformed data from server."))
            except ConnectionResetError:
                print("Server closed the connection unexpectedly.")
                self.master.after(0, lambda: messagebox.showerror(
                    "Connection Error", "Server closed the connection unexpectedly."))
                self.master.after(0, self.logout)
                break
            except Exception as e:
                if self.running:  # Only report error if client is still supposed to be running
                    print(f"Error in receive_messages thread: {e}")
                    self.master.after(0, lambda: messagebox.showerror(
                        "Receive Error", f"An error occurred while receiving messages: {e}"))
                break  # Exit the loop on error

    def logout(self):
        # Set running to False FIRST to stop the receive_messages thread cleanly
        self.running = False

        if self.sock and self.session_token:
            try:
                logout_msg = {
                    'action': 'logout',
                    'session': self.session_token
                }
                self.sock.send(json.dumps(logout_msg).encode('utf-8'))
                # Give server a moment to process logout message if needed, but not strictly necessary
                # as server will eventually detect disconnect.
            except Exception as e:
                print(f"Error sending logout message: {e}")

        # Close socket properly
        if self.sock:
            try:
                # Use shutdown to signal intent to close, then close
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except OSError as e:  # Catch "socket not connected" or similar if already closed/disconnected
                print(f"Error during socket shutdown/close: {e}")
            except Exception as e:
                print(f"Unexpected error closing socket: {e}")

        # Reset client state variables
        self.sock = None
        self.session_token = None
        self.username = None
        self.current_recipient = None

        # Reinitialize connection and go back to login screen
        # Create a new socket for the next connection attempt
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
    root.geometry("600x450")  # Adjust size for new layout
    app = ChatClient(root)
    # Handle window close event to ensure clean logout

    def on_closing():
        if app.running:  # If chat screen is active
            app.logout()
        else:  # If on login/register screen, just destroy
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

# # import tkinter as tk
# # from tkinter import messagebox, scrolledtext
# # import socket
# # import threading
# # import json

# # SERVER_HOST = '127.0.0.1'
# # SERVER_PORT = 5555


# # class ChatClient:
# #     def __init__(self, master):
# #         self.master = master
# #         self.master.title("Secure Chat App")
# #         self.session_token = None
# #         self.username = None
# #         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #         try:
# #             self.sock.connect((SERVER_HOST, SERVER_PORT))
# #         except:
# #             messagebox.showerror("Error", "Could not connect to server.")
# #             self.master.destroy()

# #         self.build_login_screen()

# #     def build_login_screen(self):
# #         self.clear_window()
# #         tk.Label(self.master, text="Login", font=("Arial", 18)).pack(pady=10)
# #         self.user_entry = tk.Entry(self.master, width=30)
# #         self.user_entry.pack(pady=5)
# #         self.user_entry.insert(0, "Username")

# #         self.pass_entry = tk.Entry(self.master, width=30, show="*")
# #         self.pass_entry.pack(pady=5)
# #         self.pass_entry.insert(0, "Password")

# #         tk.Button(self.master, text="Login", command=self.login).pack(pady=10)
# #         tk.Button(self.master, text="Register",
# #                   command=self.build_register_screen).pack()

# #     def build_register_screen(self):
# #         self.clear_window()
# #         tk.Label(self.master, text="Register",
# #                  font=("Arial", 18)).pack(pady=10)
# #         self.reg_user_entry = tk.Entry(self.master, width=30)
# #         self.reg_user_entry.pack(pady=5)
# #         self.reg_user_entry.insert(0, "Username")

# #         self.reg_pass_entry = tk.Entry(self.master, width=30, show="*")
# #         self.reg_pass_entry.pack(pady=5)
# #         self.reg_pass_entry.insert(0, "Password")

# #         tk.Button(self.master, text="Register",
# #                   command=self.register).pack(pady=10)
# #         tk.Button(self.master, text="Back to Login",
# #                   command=self.build_login_screen).pack()

# #     def build_chat_screen(self):
# #         self.clear_window()
# #         tk.Label(self.master, text=f"Logged in as {self.username}", font=(
# #             "Arial", 12)).pack()
# #         self.chat_display = scrolledtext.ScrolledText(
# #             self.master, state='disabled', width=50, height=15)
# #         self.chat_display.pack(pady=10)
# #         self.message_entry = tk.Entry(self.master, width=40)
# #         self.message_entry.pack(side=tk.LEFT, padx=5, pady=5)
# #         tk.Button(self.master, text="Send", command=self.send_message).pack(
# #             side=tk.LEFT, padx=5)
# #         threading.Thread(target=self.receive_messages, daemon=True).start()

# #     def login(self):
# #         username = self.user_entry.get()
# #         password = self.pass_entry.get()
# #         self.username = username
# #         message = {
# #             'action': 'login',
# #             'username': username,
# #             'password': password
# #         }
# #         self.sock.send(json.dumps(message).encode())
# #         response = json.loads(self.sock.recv(1024).decode())
# #         if response.get('status') == 'ok':
# #             self.session_token = response['session']
# #             self.build_chat_screen()
# #         else:
# #             messagebox.showerror("Login Failed", "Invalid credentials")

# #     def register(self):
# #         username = self.reg_user_entry.get()
# #         password = self.reg_pass_entry.get()
# #         # Send to server or use a separate admin tool for registration
# #         messagebox.showinfo(
# #             "Note", "Registration must be handled server-side.\nAsk admin to add user.")
# #         self.build_login_screen()

# #     def send_message(self):
# #         content = self.message_entry.get()
# #         if not content.strip():
# #             return
# #         message = {
# #             'action': 'message',
# #             'session': self.session_token,
# #             'content': content
# #         }
# #         self.sock.send(json.dumps(message).encode())
# #         self.message_entry.delete(0, tk.END)

# #     def receive_messages(self):
# #         while True:
# #             try:
# #                 data = self.sock.recv(4096)
# #                 if not data:
# #                     break
# #                 msg = json.loads(data.decode())
# #                 if msg.get('status') == 'received':
# #                     continue  # confirmation
# #                 self.chat_display.config(state='normal')
# #                 self.chat_display.insert(
# #                     tk.END, f"{msg.get('from', 'Server')}: {msg.get('content')}\n")
# #                 self.chat_display.config(state='disabled')
# #                 self.chat_display.see(tk.END)
# #             except:
# #                 break

# #     def clear_window(self):
# #         for widget in self.master.winfo_children():
# #             widget.destroy()


# # if __name__ == "__main__":
# #     root = tk.Tk()
# #     root.geometry("400x400")
# #     app = ChatClient(root)
# #     root.mainloop()


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
#         self.running = False
#         self.master.title("CipherNet: Secure Chat App")
#         self.session_token = None
#         self.username = None
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((SERVER_HOST, SERVER_PORT))
#         except:
#             messagebox.showerror("Error", "Could not connect to server.")
#             self.master.destroy()

#         self.build_login_screen()

#     def initialize_connection(self):
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((SERVER_HOST, SERVER_PORT))
#         except:
#             messagebox.showerror("Error", "Could not connect to server.")
#             self.master.destroy()

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

#         # Logout button
#         tk.Button(self.master, text="Logout", command=self.logout).pack(
#             side=tk.RIGHT, padx=5, pady=5)

#         # Flag to control receive_messages thread
#         self.running = True
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
#         if not username or not password:
#             messagebox.showwarning(
#                 "Input Error", "Username and password are required.")
#             return

#         message = {
#             'action': 'register',
#             'username': username,
#             'password': password
#         }
#         try:
#             self.sock.send(json.dumps(message).encode())
#             response = json.loads(self.sock.recv(1024).decode())
#             if response.get('status') == 'registered':
#                 messagebox.showinfo(
#                     "Success", "Registration successful! Please login.")
#                 self.build_login_screen()
#             elif response.get('status') == 'exists':
#                 messagebox.showerror("Error", "Username already exists.")
#             else:
#                 messagebox.showerror("Error", "Registration failed.")
#         except Exception as e:
#             messagebox.showerror("Error", f"Error during registration: {e}")

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
#         while self.running:
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

#     def logout(self):
#         if self.sock and self.session_token:
#             try:
#                 logout_msg = {
#                     'action': 'logout',
#                     'session': self.session_token
#                 }
#                 self.sock.send(json.dumps(logout_msg).encode())
#                 response = json.loads(self.sock.recv(1024).decode())
#                 if response.get('status') == 'logged_out':
#                     messagebox.showinfo("Logout", "Successfully logged out.")
#                 else:
#                     messagebox.showwarning(
#                         "Logout", "Logout failed or session invalid.")
#             except Exception as e:
#                 messagebox.showerror(
#                     "Logout Error", f"Error during logout: {e}")

#         self.running = False
#         if self.sock:
#             try:
#                 self.sock.shutdown(socket.SHUT_RDWR)
#                 self.sock.close()
#             except:
#                 pass
#         self.sock = None
#         self.session_token = None
#         self.username = None
#         self.initialize_connection()
#         self.build_login_screen()

#     def clear_window(self):
#         for widget in self.master.winfo_children():
#             widget.destroy()


# if __name__ == "__main__":
#     root = tk.Tk()
#     root.geometry("400x400")
#     app = ChatClient(root)
#     root.mainloop()
