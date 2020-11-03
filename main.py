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
        
        ## Body frame
        self.frame_login = Frame(windows)
        self.frame_login.pack()
        self.message = Label(self.frame_login, text="Enter password:", justify="left",anchor=W)
        self.message.pack(side="top",fill=X)
        #### Child login frame
        self.password_input = StringVar()
        self.input_entry_password = Entry(self.frame_login, textvariable=self.password_input, width=30, show="*")
        self.input_entry_password.pack()
        self.connect_button = Button(self.frame_login, text="Connect", command=self.connect)
        self.connect_button.pack(side="bottom")

        # Bottom Frame
        self.exit_button = Button(windows, text="Exit", command=self.quit)
        self.exit_button.pack(side="bottom")

    def connect(self):
        input_pass = self.password_input.get()
        if self.is_password_valid(input_pass):
            self.logs["text"] = "You're logged."
            self.logs["fg"] = "black"
            self.data_display()
        else:
            self.logs["text"] = "Wrong password."
            self.logs["fg"] = "red"
    def is_password_valid(self, password):
        bdd_password= ""
        if password == bdd_password:
            return True
        return False
    def data_display(self):
        
        self.frame_login.destroy()
        self.frame_data = Frame(windows)
        self.frame_data.pack()
        self.message = Label(self.frame_data, text="Enter the name of account:", justify="left",anchor=W)
        self.message.pack(side="top",fill=X)
        self.account_name = StringVar()
        self.entry_account = Entry(self.frame_data, textvariable=self.account_name, width=30)
        self.entry_account.pack()
        self.button_search = Button(self.frame_data, text="Search", command=self.search)
        self.button_search.pack(side="bottom")

        # Display data account
        self.display_account_info()

    def display_account_info(self):
        account_infos = self.account_data()
        for element in account_infos:
            print(element)

    def account_data(self):
        import json
        with open('./data.json') as data_file:
            data = json.load(data_file)
        return data["account_infos"]
    def search(self):
        print(self.account_name.get(), type(self.account_name.get()))

windows = Tk()
interface = Interface(windows)

interface.mainloop()
interface.destroy()