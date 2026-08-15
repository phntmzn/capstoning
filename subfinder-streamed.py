import subprocess

domain = "example.com"

subprocess.run([
    "subfinder",
    "-d", domain,
    "-silent"
])
