# macho_dependencies.py
import struct
from pathlib import Path


# ------------------------------------------------------------
# Mach-O constants
# ------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF

LC_LOAD_DYLIB = 0x0000000C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023


DYLIB_COMMANDS = {
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}


# ------------------------------------------------------------
# Errors
# ------------------------------------------------------------

class MachOError(Exception):
    pass


# ------------------------------------------------------------
# Parser
# ------------------------------------------------------------

def extract_dependencies(path):
    """
    Extract direct dynamic-library dependencies from a
    64-bit little-endian Mach-O binary.

    This does not execute the binary.

    It only reads Mach-O load commands such as:

        LC_LOAD_DYLIB
        LC_LOAD_WEAK_DYLIB
        LC_REEXPORT_DYLIB
        LC_LOAD_UPWARD_DYLIB
    """

    path = Path(path)

    # Read the entire binary into memory.
    data = path.read_bytes()

    # A mach_header_64 is 32 bytes.
    if len(data) < 32:
        raise MachOError("File is too small to contain a Mach-O header")

    # --------------------------------------------------------
    # Parse the Mach-O magic value
    # --------------------------------------------------------

    magic = struct.unpack_from("<I", data, 0)[0]

    if magic != MH_MAGIC_64:
        raise MachOError(
            f"Unsupported Mach-O magic: 0x{magic:08X}"
        )

    # --------------------------------------------------------
    # mach_header_64
    #
    # struct mach_header_64 {
    #     uint32_t magic;
    #     cpu_type_t cputype;
    #     cpu_subtype_t cpusubtype;
    #     uint32_t filetype;
    #     uint32_t ncmds;
    #     uint32_t sizeofcmds;
    #     uint32_t flags;
    #     uint32_t reserved;
    # };
    # --------------------------------------------------------

    (
        magic,
        cpu_type,
        cpu_subtype,
        file_type,
        ncmds,
        sizeofcmds,
        flags,
        reserved,
    ) = struct.unpack_from("<IIIIIIII", data, 0)

    print(f"Mach-O: {path}")
    print(f"CPU type:     0x{cpu_type:08X}")
    print(f"Load commands: {ncmds}")
    print(f"Command bytes: {sizeofcmds}")

    dependencies = []

    # Load commands begin immediately after mach_header_64.
    offset = 32

    # --------------------------------------------------------
    # Walk every load command
    # --------------------------------------------------------

    for _ in range(ncmds):

        # Every load command begins with:
        #
        # struct load_command {
        #     uint32_t cmd;
        #     uint32_t cmdsize;
        # };
        if offset + 8 > len(data):
            raise MachOError("Truncated load command")

        cmd, cmdsize = struct.unpack_from(
            "<II",
            data,
            offset,
        )

        # Reject malformed load commands.
        if cmdsize < 8:
            raise MachOError(
                f"Invalid load command size: {cmdsize}"
            )

        command_end = offset + cmdsize

        if command_end > len(data):
            raise MachOError(
                "Load command extends beyond end of file"
            )

        # ----------------------------------------------------
        # Check whether this command references a dylib.
        # ----------------------------------------------------

        if cmd in DYLIB_COMMANDS:

            # dylib_command layout:
            #
            # struct dylib_command {
            #     uint32_t cmd;
            #     uint32_t cmdsize;
            #
            #     struct dylib {
            #         uint32_t name.offset;
            #         uint32_t timestamp;
            #         uint32_t current_version;
            #         uint32_t compatibility_version;
            #     } dylib;
            # };
            #
            # The name offset is located 8 bytes into the
            # dylib_command.
            if cmdsize < 24:
                raise MachOError(
                    "Malformed dylib_command"
                )

            name_offset = struct.unpack_from(
                "<I",
                data,
                offset + 8,
            )[0]

            # name_offset is relative to the start of the
            # dylib_command, not the start of the file.
            name_start = offset + name_offset

            if (
                name_offset >= cmdsize
                or name_start >= command_end
            ):
                raise MachOError(
                    "Invalid dylib name offset"
                )

            # Find the terminating NULL byte.
            name_end = data.find(
                b"\x00",
                name_start,
                command_end,
            )

            if name_end == -1:
                raise MachOError(
                    "Unterminated dylib name"
                )

            dependency = data[
                name_start:name_end
            ].decode(
                "utf-8",
                errors="replace",
            )

            dependencies.append({
                "path": dependency,
                "command": cmd,
            })

        # Advance to the next load command.
        offset += cmdsize

    return dependencies


# ------------------------------------------------------------
# Command-name helper
# ------------------------------------------------------------

def command_name(cmd):
    names = {
        LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
        LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
        LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
        LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
    }

    return names.get(
        cmd,
        f"UNKNOWN_0x{cmd:08X}",
    )


# ------------------------------------------------------------
# Example
# ------------------------------------------------------------

if __name__ == "__main__":

    target = (
        "/Applications/Safari.app/"
        "Contents/MacOS/Safari"
    )

    try:
        dependencies = extract_dependencies(target)

        print("\nDependencies:")

        for dep in dependencies:
            print(
                f"{command_name(dep['command']):22} "
                f"{dep['path']}"
            )

    except (OSError, MachOError) as error:
        print("Error:", error)
