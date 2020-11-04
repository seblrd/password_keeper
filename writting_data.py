# -*-coding:Utf-8 -*
import json

data = {}
data["unlock_password"] = "1234"
data["account_infos"] = {
    "ubi": {"id": "mon_id", "password": "password$£"},
    "steam": {"id": "mon_id", "password": "password"},
}
with open("data.json", "w") as outfile:
    json.dump(data, outfile, ensure_ascii=False, indent=4)


class Password_data:
    def __init__(self):
        self.data = {}

    def add_new_account(self, account: str, id: str, password: str):
        self.data[account] = {"id": id, "password": password}

    def edit_account(self, account: str, id: str = "", password: str = ""):
        print("ok")