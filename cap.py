import struct
from capstone import *

path = "/System/Applications/Messages.app/Contents/MacOS/Messages"

# --------------------------------------------------
# Read file
# --------------------------------------------------

with open(path, "rb") as f:
    raw = f.read()

# --------------------------------------------------
# Constants
# --------------------------------------------------

FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

# --------------------------------------------------
# Detect/extract ARM64 slice
# --------------------------------------------------

magic_be = struct.unpack_from(">I", raw, 0)[0]
magic_le = struct.unpack_from("<I", raw, 0)[0]

data = None

if magic_be == FAT_MAGIC or magic_le == FAT_CIGAM:
    nfat_arch = struct.unpack_from(">I", raw, 4)[0]

    print(f"Universal binary with {nfat_arch} architectures")

    arch_offset = 8

    for i in range(nfat_arch):
        cputype, cpusubtype, offset, size, align = struct.unpack_from(
            ">IIIII",
            raw,
            arch_offset
        )

        if cputype == CPU_TYPE_X86_64:
            arch_name = "x86_64"
        elif cputype == CPU_TYPE_ARM64:
            arch_name = "arm64"
        else:
            arch_name = f"unknown(0x{cputype:x})"

        print(
            f"arch {i}: "
            f"{arch_name} "
            f"cpu=0x{cputype:x} "
            f"offset=0x{offset:x} "
            f"size=0x{size:x}"
        )

        if cputype == CPU_TYPE_ARM64:
            print()
            print(f"Using ARM64 slice at file offset 0x{offset:x}")

            data = raw[offset:offset + size]

            break

        arch_offset += 20

    if data is None:
        raise RuntimeError("ARM64 slice not found")

else:
    data = raw


# --------------------------------------------------
# Validate thin ARM64 Mach-O
# --------------------------------------------------

if len(data) < 32:
    raise RuntimeError("Mach-O data is too small")

magic = struct.unpack_from("<I", data, 0)[0]

if magic != MH_MAGIC_64:
    raise RuntimeError(
        f"Unexpected thin Mach-O magic: 0x{magic:08x}"
    )

print("ARM64 Mach-O slice loaded successfully")
print()


# --------------------------------------------------
# Read mach_header_64
# --------------------------------------------------

(
    magic,
    cputype,
    cpusubtype,
    filetype,
    ncmds,
    sizeofcmds,
    flags,
    reserved
) = struct.unpack_from(
    "<IiiIIIII",
    data,
    0
)

print("=== MACH-O HEADER ===")
print(f"CPU type      : 0x{cputype:x}")
print(f"CPU subtype   : 0x{cpusubtype:x}")
print(f"File type     : 0x{filetype:x}")
print(f"Load commands : {ncmds}")
print(f"Commands size : 0x{sizeofcmds:x}")
print(f"Flags         : 0x{flags:x}")
print()


# --------------------------------------------------
# Locate sections
# --------------------------------------------------

cmd_offset = 32

text_offset = None
text_size = None
text_addr = None

sections = []

print("=== SECTIONS ===")

for command_index in range(ncmds):

    if cmd_offset + 8 > len(data):
        raise RuntimeError(
            f"Load command {command_index} extends past file"
        )

    cmd, cmdsize = struct.unpack_from(
        "<II",
        data,
        cmd_offset
    )

    if cmdsize < 8:
        raise RuntimeError(
            f"Invalid load command size: {cmdsize}"
        )

    if cmd_offset + cmdsize > len(data):
        raise RuntimeError(
            f"Load command {command_index} is out of bounds"
        )

    if cmd == LC_SEGMENT_64:

        (
            _cmd,
            _cmdsize,
            segname_raw,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            segflags
        ) = struct.unpack_from(
            "<II16sQQQQiiII",
            data,
            cmd_offset
        )

        segname = segname_raw.rstrip(b"\x00").decode(
            "utf-8",
            errors="replace"
        )

        section_offset = cmd_offset + 72

        for section_index in range(nsects):

            if section_offset + 80 > len(data):
                raise RuntimeError(
                    "Section table extends past file"
                )

            (
                sectname_raw,
                sect_segname_raw,
                addr,
                size,
                offset,
                align,
                reloff,
                nreloc,
                section_flags,
                reserved1,
                reserved2,
                reserved3
            ) = struct.unpack_from(
                "<16s16sQQIIIIIIII",
                data,
                section_offset
            )

            sectname = sectname_raw.rstrip(b"\x00").decode(
                "utf-8",
                errors="replace"
            )

            sect_segname = sect_segname_raw.rstrip(b"\x00").decode(
                "utf-8",
                errors="replace"
            )

            sections.append(
                {
                    "segment": sect_segname,
                    "section": sectname,
                    "addr": addr,
                    "size": size,
                    "offset": offset,
                    "flags": section_flags,
                }
            )

            print(
                f"{sect_segname},{sectname}: "
                f"offset=0x{offset:x} "
                f"addr=0x{addr:x} "
                f"size=0x{size:x}"
            )

            if (
                sect_segname == "__TEXT"
                and sectname == "__text"
            ):
                text_offset = offset
                text_size = size
                text_addr = addr

            section_offset += 80

    cmd_offset += cmdsize


# --------------------------------------------------
# Verify __TEXT,__text
# --------------------------------------------------

if text_offset is None:
    raise RuntimeError(
        "__TEXT,__text section not found"
    )

if text_offset + text_size > len(data):
    raise RuntimeError(
        "__TEXT,__text extends past ARM64 slice"
    )

print()
print("=== CODE SECTION ===")
print(f"File offset : 0x{text_offset:x}")
print(f"VM address  : 0x{text_addr:x}")
print(f"Size        : 0x{text_size:x}")
print()


# --------------------------------------------------
# Prepare Capstone
# --------------------------------------------------

code = data[
    text_offset:
    text_offset + text_size
]

md = Cs(
    CS_ARCH_ARM64,
    CS_MODE_ARM
)

md.detail = False


# --------------------------------------------------
# Disassemble
# --------------------------------------------------

print("=== DISASSEMBLY ===")

instruction_count = 0
function_count = 0

for insn in md.disasm(
    code,
    text_addr
):

    instruction_count += 1

    # ARM64e function prologue heuristic
    if insn.mnemonic in (
        "pacibsp",
        "paciasp"
    ):
        function_count += 1

        print()
        print(
            f"--- probable function "
            f"#{function_count} "
            f"@ 0x{insn.address:x} ---"
        )

    print(
        f"0x{insn.address:016x}: "
        f"{insn.mnemonic:<10} "
        f"{insn.op_str}"
    )


# --------------------------------------------------
# Summary
# --------------------------------------------------

print()
print("=== SUMMARY ===")
print(
    f"Instructions decoded : "
    f"{instruction_count}"
)

print(
    f"Probable functions    : "
    f"{function_count}"
)

print(
    f"__text start          : "
    f"0x{text_addr:x}"
)

print(
    f"__text end            : "
    f"0x{text_addr + text_size:x}"
)

print()
print("Done.")
