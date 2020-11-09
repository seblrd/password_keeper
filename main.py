#!/usr/bin/python3.9
# -*-coding:Utf-8 -*
from tkinter import *


class Interface(Frame):

    """Notre fenêtre principale.
    Tous les widgets sont stockés comme attributs de cette fenêtre."""

    def __init__(self, windows, **kwargs):
        # Top frame
        Frame.__init__(self, windows, width=1500, height=1100, **kwargs)
        self.pack(fill=BOTH)

        self.logs = Label(self, text="")
        self.logs.pack()
        self.display_login_frame()
        # Bottom Frame
        self.exit_button = Button(windows, text="Exit", command=self.quit)
        self.exit_button.pack(side="bottom")

    def display_login_frame(self):
        ## Body frame
        self.frame_login = Frame(windows)
        self.frame_login.pack()
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

    def connect(self):
        input_pass = self.password_input.get()
        if self.is_password_valid(input_pass):
            self.logs["text"] = "You're logged."
            self.logs["fg"] = "black"
            self.display_data_frame()
        else:
            self.logs["text"] = "Wrong password."
            self.logs["fg"] = "red"

    def is_password_valid(self, password):
        bdd_password = self.get_password()
        if password == bdd_password:
            return True
        return False

    def display_data_frame(self):
        # Create data display
        self.frame_login.destroy()
        self.frame_data = Frame(windows)
        self.frame_data.pack()
        self.message = Label(
            self.frame_data, text="Enter the name of account:", justify="left", anchor=W
        )
        self.message.pack(side="top", fill=X)
        self.account_name = StringVar()
        self.entry_account = Entry(
            self.frame_data, textvariable=self.account_name, width=30
        )
        self.entry_account.pack()
        self.button_search = Button(self.frame_data, text="Search", command=self.search)
        self.button_search.pack(side="bottom")

        # Display data account
        self.display_account_info(self.frame_data)

    def display_account_info(self, parent_frame):
        # Get stored data
        account_infos = self.get_account_data()
        # Display each element
        for element in account_infos:
            data_elem = account_infos[element]
            data_id = "id: {0}".format(data_elem["id"])
            data_pass = "password: {0}".format(data_elem["password"])
            frame_element = Frame(parent_frame, bg="grey", bd=3)
            frame_element.pack(fill=X)
            # Name of the account ex: Steam, youtube, ...
            account_name = Label(
                frame_element, text=element, justify="left", anchor=W, font=(12)
            )
            account_name.pack(side="top", fill=X)
            # Id of the account
            frame_id = Frame(frame_element)
            frame_id.pack(side="top", fill=X)
            account_id = Label(frame_id, text=data_id, justify="left", anchor=W)
            account_id.pack(side="left", fill=X)
            self.button_copy_to_clipboard(data_elem["id"], frame_id)
            # Pass of the account
            frame_password = Frame(frame_element)
            frame_password.pack(side="top", fill=X)
            account_password = Label(
                frame_password, text=data_pass, justify="left", anchor=W
            )
            account_password.pack(side="left", fill=X)
            self.button_copy_to_clipboard(data_elem["password"], frame_password)

    def get_account_data(self):
        import json

        with open("./data.json") as data_file:
            data = json.load(data_file)
            return data["account_infos"]

    def get_password(self):
        import json

        with open("./data.json") as data_file:
            data = json.load(data_file)
            return data["unlock_password"]

    def search(self):
        print(self.account_name.get(), type(self.account_name.get()))

    def button_copy_to_clipboard(self, str_to_copy: str, parent_frame):
        def copy_to_clipboard(str_to_copy):
            self.clipboard_clear()
            self.clipboard_append(str(str_to_copy))
            print(str_to_copy)

        copy_str = Button(
            parent_frame, text="Copy", command=copy_to_clipboard(str_to_copy)
        )
        copy_str.pack(side="right")


windows = Tk()
interface = Interface(windows)

interface.mainloop()
interface.destroy()