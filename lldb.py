# lldb_messages.py

import subprocess

TARGET = "/System/Applications/Messages.app/Contents/MacOS/Messages"


def run_lldb():
    cmd = [
        "lldb",
        TARGET,
    ]

    subprocess.run(cmd)


if __name__ == "__main__":
    run_lldb()
