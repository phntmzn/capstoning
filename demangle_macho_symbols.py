# demangle_macho_symbols.py

import subprocess
from pathlib import Path


def get_symbols(binary_path: str):
    """
    Extract symbols from a Mach-O binary using nm.
    """

    binary = Path(binary_path)

    if not binary.exists():
        raise FileNotFoundError(binary)

    result = subprocess.run(
        ["nm", str(binary)],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.splitlines()


def demangle(symbol: str) -> str:
    """
    Demangle one C++ symbol using Apple's c++filt.
    """

    result = subprocess.run(
        ["c++filt", symbol],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


def analyze(binary_path: str):
    for line in get_symbols(binary_path):
        parts = line.split()

        if not parts:
            continue

        symbol = parts[-1]

        # Mach-O C++ symbols commonly start with _Z.
        if symbol.startswith("_Z"):
            print(f"{symbol}")
            print(f"    -> {demangle(symbol)}")


if __name__ == "__main__":
    analyze("/path/to/MachO")
