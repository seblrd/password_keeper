from tkinter import *  # pylint: disable=unused-wildcard-import
from tkinter import messagebox
import json


class Data_managing(Frame):
    def __init__(self, fernet_key, account_password, parent_frame):
        self.account_data = {}
        self.fernet_key = fernet_key
        self.account_password = account_password
        self.parent_frame = parent_frame

    def display_add_new_account(self):
        self.display = False

        def display_on_clic(parent_frame):
            if self.display == False:
                self.add_new_account(parent_frame)
                self.display = True
            elif self.display == True:
                self.frame_displayed.destroy()
                self.display = False

        self.frame_new_account = Frame(self.parent_frame)
        self.frame_new_account.pack(side="top", fill=BOTH)
        self.button_display_add_account = Button(
            self.frame_new_account,
            text="Add new account",
            command=(lambda: display_on_clic(self.frame_new_account)),
        )
        self.button_display_add_account.pack()

    def display_account_info(self):
        # Get stored data
        self.frame_account_infos = Frame(self.parent_frame)
        self.frame_account_infos.pack(fill=BOTH, expand=True)

        scrollbar = Scrollbar(self.frame_account_infos, orient="vertical")
        canvas_child = Canvas(self.frame_account_infos, yscrollcommand=scrollbar.set)
        scrollbar.config(command=canvas_child.yview)
        scrollbar.pack(side=RIGHT, fill=Y, expand=True)
        canvas_child.config(yscrollcommand=scrollbar.set)
        canvas_child.pack(side=LEFT, fill=BOTH, expand=True)

        frame_child = Frame(self.frame_account_infos)
        frame_child.pack(fill=BOTH, expand=True)
        canvas_child.create_window(0, 0, window=frame_child)

        # Getting data to display
        account_infos = self.get_account_data()
        self.account_data = account_infos
        # Display each element
        for element in account_infos:
            data_elem = account_infos[element]
            data_id = "id: {0}".format(data_elem["id"])
            data_pass = "password: {0}".format(data_elem["password"])

            self.frame_element = Frame(frame_child, bg="grey", bd=3)
            self.frame_element.pack(fill=BOTH, expand=True)

            # Name of the account ex: Steam, youtube, ...
            frame_account_name = Frame(self.frame_element)
            frame_account_name.pack(side=TOP, fill=BOTH)
            account_name = Label(
                frame_account_name,
                text=element,
                justify="left",
                anchor=NW,
                font=(12),
                height=2,
            )
            account_name.pack(side="left", fill=X)
            ## Edit / Delete button
            button_delete = Button(
                frame_account_name,
                text="Delete",
                command=(lambda: self.delete_account(element)),
            )
            button_delete.pack(side="right", anchor="ne")
            # Id of the account
            frame_id = Frame(self.frame_element)
            frame_id.pack(side="top", fill=X)
            account_id = Label(frame_id, text=data_id, justify="left", anchor=W)
            account_id.pack(side="left", fill=X)
            self.button_copy_to_clipboard(data_elem["id"], frame_id)
            # Pass of the account
            frame_password = Frame(self.frame_element)
            frame_password.pack(side="top", fill=X)
            account_password = Label(
                frame_password, text=data_pass, justify="left", anchor=W
            )
            account_password.pack(side="left", fill=X)
            self.button_copy_to_clipboard(data_elem["password"], frame_password)

        self.frame_account_infos.update()
        canvas_child.config(scrollregion=canvas_child.bbox("all"))

    def get_account_data(self):
        def decrypt_data(byte_to_decode: bytes):
            f = self.fernet_key
            decrypted = f.decrypt(byte_to_decode)
            return decrypted

        with open("data.encrypted", "rb") as f:
            data = f.read()
            data = decrypt_data(data).decode()
            data = json.loads(data)
            return data

    def button_copy_to_clipboard(self, str_to_copy: str, parent_frame):
        def copy_to_clipboard(str_to_copy):
            self.clipboard_clear()
            self.clipboard_append(str(str_to_copy))

        self.copy_str = Button(
            parent_frame, text="Copy", command=(lambda: copy_to_clipboard(str_to_copy))
        )
        self.copy_str.pack(side="right")

    def add_new_account(self, parent_frame):
        self.frame_displayed = Frame(parent_frame, bd=10)
        self.frame_displayed.pack(side="top", fill=X, expand=False)

        label_account_name = Label(
            self.frame_displayed, text="Account Name:", justify="left", anchor=W
        )
        label_account_name.pack()
        # Account Name input
        self.account_name = StringVar()
        self.entry_account_name = Entry(
            self.frame_displayed, textvariable=self.account_name, width=30
        )
        self.entry_account_name.pack()
        # Account Id input
        label_account_id = Label(
            self.frame_displayed, text="Account id:", justify="left", anchor=W
        )
        label_account_id.pack()
        self.account_id = StringVar()
        self.entry_account_id = Entry(
            self.frame_displayed, textvariable=self.account_id, width=30
        )
        self.entry_account_id.pack()
        # Account Password input
        label_account_password = Label(
            self.frame_displayed, text="Account password:", justify="left", anchor=W
        )
        label_account_password.pack()
        self.account_password = StringVar()
        self.entry_account_password = Entry(
            self.frame_displayed, textvariable=self.account_password, width=30
        )
        self.entry_account_password.pack()
        # Add new account
        self.button_add_account = Button(
            self.frame_displayed,
            text="Add",
            command=(
                lambda: self.store_new_account(
                    self.account_name.get(),
                    self.account_id.get(),
                    self.account_password.get(),
                )
            ),
        )
        self.button_add_account.pack(side="bottom")

        # Separe frame
        label_account_password = Label(
            self.frame_displayed, text="----------------", justify="left", anchor=W
        )
        label_account_password.pack()

    def store_new_account(self, name: str, id: str, password: str):
        data_to_store = self.account_data
        name = name.capitalize()
        data_to_store[name] = {"id": id, "password": password}

        def encrypt_data(data_to_store: dict):
            data_to_store = json.dumps(data_to_store).encode("utf-8")
            f = self.fernet_key
            encrypt = f.encrypt(data_to_store)
            return encrypt

        enc = encrypt_data(data_to_store)
        with open("data.encrypted", "wb") as f:
            f.write(enc)

        self.refresh_data_display()

    def delete_data(self, account_name: str):
        updated_data = self.account_data
        del updated_data[account_name]

        def encrypt_data(data_to_store: dict):
            data_to_store = json.dumps(data_to_store).encode("utf-8")
            f = self.fernet_key
            encrypt = f.encrypt(data_to_store)
            return encrypt

        enc = encrypt_data(updated_data)
        with open("data.encrypted", "wb") as f:
            f.write(enc)
        self.account_data = updated_data
        self.refresh_data_display()

    def refresh_data_display(self):
        self.frame_account_infos.destroy()
        self.display_account_info()

    def delete_account(self, account_name):
        msg_box = messagebox.askquestion(
            "Delete account {0}".format(account_name),
            "Are you sure you want delete this account?",
        )
        if msg_box == "yes":
            self.delete_data(account_name)
            print("deleted")
        else:
            print("cancelled")
