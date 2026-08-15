# disk_api_scan.py

from pathlib import Path


DISK_ARBITRATION_APIS = [
    b"DASessionCreate",
    b"DARegisterDiskAppearedCallback",
    b"DADiskCopyDescription",
    b"kDADiskDescriptionVolumeNameKey",
]


def scan_disk_apis(path: str):
    """
    Look for DiskArbitration-related API names in a binary.

    Finding a string does not prove the API is called,
    but it is useful for malware triage.
    """

    data = Path(path).read_bytes()

    print(f"Scanning: {path}")

    found = []

    for api in DISK_ARBITRATION_APIS:
        if api in data:
            name = api.decode()
            found.append(name)
            print(f"[+] Found: {name}")

    if not found:
        print("[-] No known DiskArbitration API names found")

    return found


if __name__ == "__main__":
    scan_disk_apis("/path/to/binary")
