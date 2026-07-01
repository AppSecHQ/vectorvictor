# Intentionally vulnerable — Cycode SAST branch-scan verification probe.
# Clear taint: argv source -> critical sinks (OS command / SQL / code injection).
import os
import sys
import sqlite3
import subprocess


def process(user_input, sql_input):
    # CWE-78 OS command injection
    os.system("echo " + user_input)
    subprocess.call("ls -la " + user_input, shell=True)

    # CWE-89 SQL injection
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + sql_input + "'")

    # CWE-95 code injection
    eval(user_input)


if __name__ == "__main__":
    process(sys.argv[1], sys.argv[2])