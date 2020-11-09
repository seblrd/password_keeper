# -*-coding:Utf-8 -*
import json

data = {}
data["unlock_password"] = ""
data["account_infos"] = {
    "ubi": {"id": "mon_id_ubi", "password": "password$£_ubi"},
    "steam": {"id": "mon_id_steam", "password": "password_steam"},
}
with open("data.json", "w") as outfile:
    json.dump(data, outfile, ensure_ascii=False, indent=4)


class Data:
    def __init__(self):
        self.data = {}

    def add_new_account(self, account: str, id: str, password: str):
        self.data[account] = {"id": id, "password": password}

    def edit_account(self, account: str, id: str = "", password: str = ""):
        print("ok")