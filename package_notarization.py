# package_notarization.py

import subprocess
from pathlib import Path


def check_notarization(package_path: str) -> bool:
    """
    Check whether a macOS package has a valid notarization ticket.

    Uses Apple's supported `stapler validate` command rather than
    calling the private SecAssessmentTicketLookup API directly.

    Returns:
        True  -> valid notarization ticket found
        False -> ticket missing or validation failed
    """

    package = Path(package_path)

    # Make sure the supplied path exists.
    if not package.exists():
        raise FileNotFoundError(
            f"Package not found: {package}"
        )

    # --------------------------------------------------------
    # xcrun stapler validate <package>
    #
    # `stapler` checks the notarization ticket associated with
    # the package.
    # --------------------------------------------------------

    command = [
        "xcrun",
        "stapler",
        "validate",
        str(package),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    # Combine stdout and stderr because stapler may report
    # useful diagnostic information through either stream.
    output = (
        result.stdout +
        result.stderr
    ).strip()

    print(output)

    # stapler returns success when ticket validation succeeds.
    return result.returncode == 0


if __name__ == "__main__":

    target = "/path/to/Installer.pkg"

    try:
        notarized = check_notarization(target)

        print()

        if notarized:
            print("[+] Package has a valid notarization ticket")
        else:
            print("[-] Package notarization could not be validated")

    except FileNotFoundError as error:
        print("Error:", error)
