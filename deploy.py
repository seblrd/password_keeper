from cx_Freeze import setup, Executable

setup(
    name="Password Keeper",
    version="0.3",
    description="Save your password",
    executables=[Executable("main.py")],
)