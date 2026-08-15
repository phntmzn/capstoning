# subfinder_wrapper.py

import subprocess
import sys


def run_subfinder(domain: str):
    cmd = [
        "subfinder",
        "-d", domain,
        "-silent"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        subdomains = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        return subdomains

    except FileNotFoundError:
        print("Error: subfinder is not installed or not in PATH.")
        sys.exit(1)

    except subprocess.CalledProcessError as e:
        print("subfinder failed:")
        print(e.stderr)
        sys.exit(e.returncode)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} example.com")
        sys.exit(1)

    domain = sys.argv[1]

    results = run_subfinder(domain)

    print(f"\nFound {len(results)} subdomains:\n")

    for subdomain in results:
        print(subdomain)
