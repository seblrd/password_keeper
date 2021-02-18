from cx_Freeze import setup, Executable

setup(
    name="Password Keeper",
    version="0.4",
    description="Save your password",
    executables=[Executable("main.py")],
)
# run cmd: "deploy.py build" to create new .exe file
