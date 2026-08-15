# package_security.py

import subprocess
from pathlib import Path


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def analyze_package(path: str):
    """
    Perform basic macOS package security checks.
    """

    package = Path(path)

    if not package.exists():
        raise FileNotFoundError(package)

    # --------------------------------------------------------
    # Check the stapled notarization ticket.
    # --------------------------------------------------------

    stapler = run_command([
        "xcrun",
        "stapler",
        "validate",
        str(package),
    ])

    # --------------------------------------------------------
    # Ask Gatekeeper to assess the package as an installer.
    # --------------------------------------------------------

    gatekeeper = run_command([
        "spctl",
        "--assess",
        "--verbose=4",
        "--type",
        "install",
        str(package),
    ])

    return {
        "package": str(package),
        "notarization_ticket": stapler,
        "gatekeeper": gatekeeper,
    }


if __name__ == "__main__":

    target = "/path/to/Installer.pkg"

    try:
        report = analyze_package(target)

        print("Package:")
        print(report["package"])

        print("\n--- Notarization ---")

        if report["notarization_ticket"]["success"]:
            print("[+] Stapled notarization ticket is valid")
        else:
            print("[-] No valid stapled ticket detected")

        print(
            report["notarization_ticket"]["stdout"]
            or report["notarization_ticket"]["stderr"]
        )

        print("\n--- Gatekeeper ---")

        if report["gatekeeper"]["success"]:
            print("[+] Gatekeeper accepted the installer")
        else:
            print("[-] Gatekeeper rejected the installer")

        print(
            report["gatekeeper"]["stdout"]
            or report["gatekeeper"]["stderr"]
        )

    except Exception as error:
        print("Error:", error)
