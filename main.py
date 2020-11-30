#!/usr/bin/python3.9
# -*-coding:Utf-8 -*
from tkinter import *  # pylint: disable=unused-wildcard-import
from data_managing import Data_managing
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import json


class Interface(Frame):

    """Notre fenêtre principale.
    Tous les widgets sont stockés comme attributs de cette fenêtre."""

    def __init__(self, windows, **kwargs):
        # Top frame
        Frame.__init__(self, windows, width=1500, height=1100, **kwargs)
        self.pack(fill=BOTH)
        self.password = ""
        self.salt = ""
        self.logs = Label(self, text="")
        self.logs.pack(fill=BOTH, expand=False)
        self.fernet_key = ""
        if self.is_new_account():
            self.display_register_frame()
        elif not self.is_new_account():
            self.display_login_frame()
        # Bottom Frame
        self.exit_button = Button(windows, text="Exit", command=self.quit)
        self.exit_button.pack(side="bottom")

    def display_login_frame(self):
        ## Body frame
        self.frame_login = Frame(windows)
        self.frame_login.pack(fill=BOTH, expand=True)
        self.message = Label(
            self.frame_login, text="Enter password:", justify="left", anchor=W
        )
        self.message.pack(side="top", fill=X)
        #### Child login frame
        self.password_input = StringVar()
        self.input_entry_password = Entry(
            self.frame_login, textvariable=self.password_input, width=30, show="*"
        )
        self.input_entry_password.pack()
        self.connect_button = Button(
            self.frame_login, text="Connect", command=self.connect
        )
        self.connect_button.pack(side="bottom")

    def display_register_frame(self):
        ## Body frame
        self.frame_register = Frame(windows)
        self.frame_register.pack(fill=BOTH, expand=True)
        self.message = Label(
            self.frame_register, text="Enter password:", justify="left", anchor=W
        )
        self.message.pack(side="top", fill=X)
        #### Child login frame
        # password input
        password_input = StringVar()
        input_entry_password = Entry(
            self.frame_register, textvariable=password_input, width=30, show="*"
        )
        input_entry_password.pack()
        # password confirm input
        self.message_confirm = Label(
            self.frame_register,
            text="Enter password confirmation:",
            justify="left",
            anchor=W,
        )
        self.message_confirm.pack(side="top", fill=X)
        password_confirm_input = StringVar()
        input_entry_password = Entry(
            self.frame_register,
            textvariable=password_confirm_input,
            width=30,
            show="*",
        )
        input_entry_password.pack()
        # Register button
        register_button = Button(
            self.frame_register,
            text="Register",
            command=(
                lambda: self.is_register_pass_valid(
                    password_input.get(), password_confirm_input.get()
                )
            ),
        )
        register_button.pack(side="bottom")

    def connect(self):
        input_pass = self.password_input.get()
        input_pass = "password"  # TODO to delete
        if self.is_password_valid(input_pass):

            self.logs["text"] = "You're logged."
            self.logs["fg"] = "black"
            self.display_connected_frame()
        else:
            self.logs["text"] = "Wrong password."
            self.logs["fg"] = "red"

    def is_password_valid(self, password: str):
        from base64 import b64decode
        import hashlib

        data = self.get_connect_id()
        byte_salt = b64decode(data["salt"].encode())
        byte_password = password.encode()
        enc_password = hashlib.sha224(byte_password + byte_salt).hexdigest()
        if enc_password == data["unlock_password"]:
            self.salt = byte_salt
            self.fernet_key = self.create_fernet_key(password, byte_salt)
            return True
        return False

    def display_connected_frame(self):
        # Create data display
        self.frame_login.destroy()
        self.frame_connected = Frame(windows)
        self.frame_connected.pack(fill=BOTH, expand=True)
        # Create class data managing
        data_manage = Data_managing(
            self.fernet_key, self.password, self.frame_connected
        )
        data_manage.display_add_new_account()
        data_manage.display_account_info()

    def get_connect_id(self):
        import json

        with open("./main_id.json") as data_file:
            data = json.load(data_file)
            return data

    def create_fernet_key(self, password: str, salt: bytes):

        password = password.encode()  # Convert to type bytes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

        f = Fernet(key)
        return f

    def is_new_account(self):
        try:
            with open("main_id.json", "r") as f:
                data = json.load(f)
                if data["unlock_password"] != "" and data["salt"] != "":
                    print("Account found")
                    return False
                print("Some errors has occured in loading ID of account")
                return True

        except:
            print("No account was found")
            return True

    def is_register_pass_valid(self, password: str, password_confim: str):
        self.log = ""

        def check_pass(password, password_confim):
            log = ""
            if len(password) < 8:
                log += "\nPassword length < 8"

            if password != password_confim:
                log += "\nConfirm password doesn't match password"
            if log == "":
                return True
            else:
                self.log = "Incorrect register password." + log
                return False

        if check_pass(password, password_confim):
            self.logs["text"] = ""
            self.create_new_user(password)
            return True
        else:
            self.logs["text"] = self.log
            self.logs["fg"] = "red"
            return False

    def create_new_user(self, password: str):
        import os
        import hashlib
        from base64 import b64encode

        try:
            salt = os.urandom(16)
            self.salt = salt
            self.password = password
            self.fernet_key = self.create_fernet_key(password, salt)
            password = password.encode()
            enc_password = hashlib.sha224(password + salt).hexdigest()
            # To store byte salt in Json we need to convert it yo str
            str_salt = b64encode(salt).decode("utf8")

            data = {"unlock_password": enc_password, "salt": str_salt}

            with open("./main_id.json", "w") as data_file:
                json.dump(data, data_file, ensure_ascii=False, indent=4)
            self.logs["text"] = "User created"
            self.logs["fg"] = "black"
            self.frame_register.destroy()
            self.display_login_frame()
        except Exception as e:
            self.logs["text"] = "Error in creating User"
            self.logs["fg"] = "red"
            print(e)
            try:
                os.remove("./main_id.json")
            except:
                pass


windows = Tk()
interface = Interface(windows)

interface.mainloop()
interface.destroy()