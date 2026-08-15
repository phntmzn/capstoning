import struct
from capstone import *

path = "/System/Applications/Messages.app/Contents/MacOS/Messages"

with open(path, "rb") as f:
    raw = f.read()

FAT_CIGAM = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF

CPU_TYPE_ARM64 = 0x0100000C

magic_be = struct.unpack_from(">I", raw, 0)[0]
magic_le = struct.unpack_from("<I", raw, 0)[0]

# --------------------------------------------------
# Extract ARM64 slice if this is a universal binary
# --------------------------------------------------

if magic_le == FAT_CIGAM or magic_be == 0xCAFEBABE:
    nfat_arch = struct.unpack_from(">I", raw, 4)[0]

    print(f"Universal binary with {nfat_arch} architectures")

    arch_offset = 8
    data = None

    for i in range(nfat_arch):
        cputype, cpusubtype, offset, size, align = struct.unpack_from(
            ">IIIII",
            raw,
            arch_offset
        )

        print(
            f"arch {i}: "
            f"cpu=0x{cputype:x} "
            f"offset=0x{offset:x} "
            f"size=0x{size:x}"
        )

        if cputype == CPU_TYPE_ARM64:
            print(f"Using ARM64 slice at file offset 0x{offset:x}")
            data = raw[offset:offset + size]
            break

        arch_offset += 20

    if data is None:
        raise RuntimeError("ARM64 slice not found")

else:
    data = raw


# --------------------------------------------------
# Parse thin Mach-O
# --------------------------------------------------

magic = struct.unpack_from("<I", data, 0)[0]

if magic != MH_MAGIC_64:
    raise RuntimeError(f"Unexpected thin Mach-O magic: 0x{magic:08x}")
# --------------------------------------------------
# Locate __TEXT,__text
# --------------------------------------------------

LC_SEGMENT_64 = 0x19

(
    magic,
    cputype,
    cpusubtype,
    filetype,
    ncmds,
    sizeofcmds,
    flags,
    reserved
) = struct.unpack_from("<IiiIIIII", data, 0)

print(f"Load commands: {ncmds}")

cmd_offset = 32

text_offset = None
text_size = None
text_addr = None

for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, cmd_offset)

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

        for _ in range(nsects):
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


if text_offset is None:
    raise RuntimeError("__TEXT,__text not found")

print()
print("=== CODE SECTION ===")
print(f"offset : 0x{text_offset:x}")
print(f"addr   : 0x{text_addr:x}")
print(f"size   : 0x{text_size:x}")


# --------------------------------------------------
# Disassemble ARM64 code
# --------------------------------------------------

code = data[text_offset:text_offset + text_size]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

MAX_INSTRUCTIONS = 300

print()
print("=== DISASSEMBLY ===")

for i, insn in enumerate(md.disasm(code, text_addr)):
    print(
        f"0x{insn.address:016x}: "
        f"{insn.mnemonic:<10} "
        f"{insn.op_str}"
    )

    if i + 1 >= MAX_INSTRUCTIONS:
        break
    
print("ARM64 Mach-O slice loaded successfully")
