# detect_diskarbitration.py

from pathlib import Path
from macho_dependencies import extract_dependencies


INTERESTING_DEPENDENCIES = {
    "DiskArbitration.framework": "External disk / volume interaction",
    "Security.framework": "Keychain / security APIs",
    "Network.framework": "Networking capability",
    "IOKit.framework": "Hardware / device interaction",
}


def analyze_dependencies(path: str):
    """
    Inspect a Mach-O's direct dependencies and highlight
    frameworks that may indicate interesting capabilities.

    This is static analysis only. The binary is never executed.
    """

    dependencies = extract_dependencies(Path(path))

    print(f"\nAnalyzing: {path}")
    print("-" * 70)

    for dependency in dependencies:
        dep_path = dependency["path"]

        print(dep_path)

        for name, description in INTERESTING_DEPENDENCIES.items():
            if name in dep_path:
                print(f"    [!] Interesting: {description}")


if __name__ == "__main__":
    target = "/path/to/binary"

    try:
        analyze_dependencies(target)

    except Exception as error:
        print("Error:", error)
