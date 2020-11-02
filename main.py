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
        frame_login = Frame(windows)
        frame_login.pack()
        self.message = Label(frame_login, text="Enter password:", justify="left",anchor=W)
        self.message.pack(side="top",fill=X)
        #### Child login frame
        self.password_input = StringVar()
        self.input_entry_password = Entry(frame_login, textvariable=self.password_input, width=30)
        self.input_entry_password.pack()
        self.connect_button = Button(frame_login, text="Connect", command=self.connect)
        self.connect_button.pack(side="bottom")

        # Bottom Frame
        self.exit_button = Button(windows, text="Exit", command=self.quit)
        self.exit_button.pack(side="bottom")

    def connect(self):
        input_pass = self.password_input.get()
        if self.is_password_valid(input_pass):
            self.logs["text"] = "You're logged."
        else:
            self.logs["text"] = "Wrong password."
            self.logs["fg"] = "red"
        print("you're in {0}".format(self.password_input.get()))
    def is_password_valid(self, password):
        bdd_password= "ok"
        if password == bdd_password:
            return True
        return False
windows = Tk()
interface = Interface(windows)

interface.mainloop()
interface.destroy()