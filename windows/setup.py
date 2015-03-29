import sys
from cx_Freeze import setup, Executable

include_files = [
    "README.txt",
    "LICENSE.txt",
    "ydcmd.cfg",
    "ca-root.crt"   # http://curl.haxx.se/docs/caextract.html
]

build_exe_options = {
    "packages"      : ["os"],
    "excludes"      : ["tkinter"],
    "include_files" : include_files
}

setup (
    name        = "ydcmd",
    version     = "1.9",
    description = "Command line client for Yandex.Disk",
    options     = { "build_exe": build_exe_options },
    executables = [ Executable("ydcmd.py", base = None) ]
)
