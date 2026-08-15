import ctypes
import ctypes.util
import os


# ------------------------------------------------------------
# macOS CPU architecture constants
# ------------------------------------------------------------

# x86_64 / Intel CPU type.
CPU_TYPE_X86_64 = 0x01000007

# arm64 / Apple Silicon CPU type.
CPU_TYPE_ARM64 = 0x0100000C

# Process flag used by macOS to indicate that a process
# is being translated by Rosetta 2.
#
# This constant comes from <sys/proc.h>.
P_TRANSLATED = 0x00020000


# ------------------------------------------------------------
# Load the macOS C standard library
# ------------------------------------------------------------

# Find the system C library.
libc_path = ctypes.util.find_library("c")

# Load libc so Python can call native macOS APIs such as:
#
#   sysctlnametomib()
#   sysctl()
#
# use_errno=True allows us to retrieve errno when a call fails.
libc = ctypes.CDLL(libc_path, use_errno=True)


# ------------------------------------------------------------
# Configure sysctlnametomib()
# ------------------------------------------------------------

# C declaration:
#
# int sysctlnametomib(
#     const char *name,
#     int *mibp,
#     size_t *sizep
# );
#
# This converts a human-readable sysctl name such as:
#
#     "sysctl.proc_cputype"
#
# into its numeric Management Information Base (MIB) array.

libc.sysctlnametomib.argtypes = [
    ctypes.c_char_p,                  # sysctl name
    ctypes.POINTER(ctypes.c_int),     # output MIB array
    ctypes.POINTER(ctypes.c_size_t),  # number of MIB components
]

# sysctlnametomib() returns an int:
#
#   0  = success
#  -1  = failure
libc.sysctlnametomib.restype = ctypes.c_int


# ------------------------------------------------------------
# Configure sysctl()
# ------------------------------------------------------------

# C declaration:
#
# int sysctl(
#     int *name,
#     u_int namelen,
#     void *oldp,
#     size_t *oldlenp,
#     void *newp,
#     size_t newlen
# );
#
# sysctl() queries kernel information using the numeric MIB
# created by sysctlnametomib().

libc.sysctl.argtypes = [
    ctypes.POINTER(ctypes.c_int),     # MIB array
    ctypes.c_uint,                    # number of MIB components
    ctypes.c_void_p,                  # buffer receiving the result
    ctypes.POINTER(ctypes.c_size_t),  # result buffer size
    ctypes.c_void_p,                  # new value (unused here)
    ctypes.c_size_t,                  # new value size
]

libc.sysctl.restype = ctypes.c_int


# ------------------------------------------------------------
# Get raw CPU type for a process
# ------------------------------------------------------------

def get_process_cpu_type(pid: int) -> int:
    """
    Query macOS for the CPU type associated with a process.

    Examples of values returned:

        CPU_TYPE_X86_64
        CPU_TYPE_ARM64

    Parameters
    ----------
    pid:
        Process ID to inspect.

    Returns
    -------
    int
        Raw macOS cpu_type_t value.
    """

    # Allocate enough room for the numeric sysctl MIB.
    #
    # "sysctl.proc_cputype" produces a base MIB and the
    # process ID is appended to that MIB afterward.
    mib = (ctypes.c_int * 4)()

    # The initial number of MIB components expected for
    # sysctl.proc_cputype.
    mib_len = ctypes.c_size_t(3)

    # --------------------------------------------------------
    # Step 1:
    # Convert "sysctl.proc_cputype" into a numeric MIB.
    # --------------------------------------------------------

    result = libc.sysctlnametomib(
        b"sysctl.proc_cputype",
        mib,
        ctypes.byref(mib_len),
    )

    # A return value other than zero means the system call failed.
    if result != 0:
        errno = ctypes.get_errno()

        raise OSError(
            errno,
            f"sysctlnametomib failed for PID {pid}"
        )

    # Make sure there is still room in our array for the PID.
    if mib_len.value >= len(mib):
        raise RuntimeError(
            "Unexpected sysctl MIB length"
        )

    # --------------------------------------------------------
    # Step 2:
    # Append the target PID to the MIB.
    # --------------------------------------------------------

    # Example conceptual MIB:
    #
    #     [CTL_SYSCTL, ..., PROC_CPUTYPE, PID]
    #
    # The PID tells macOS which process we want to inspect.
    mib[mib_len.value] = pid

    # Increase the number of valid MIB elements now that the
    # process ID has been added.
    mib_len.value += 1

    # --------------------------------------------------------
    # Step 3:
    # Prepare storage for the returned cpu_type_t value.
    # --------------------------------------------------------

    cpu_type = ctypes.c_int()

    # sysctl() requires the size of the destination buffer.
    cpu_type_size = ctypes.c_size_t(
        ctypes.sizeof(cpu_type)
    )

    # --------------------------------------------------------
    # Step 4:
    # Query macOS for the process CPU type.
    # --------------------------------------------------------

    result = libc.sysctl(
        mib,                           # numeric MIB
        mib_len.value,                 # MIB length
        ctypes.byref(cpu_type),        # destination buffer
        ctypes.byref(cpu_type_size),   # destination size
        None,                          # no new value
        0,                             # no new value size
    )

    # If sysctl fails, retrieve errno and raise an exception.
    if result != 0:
        errno = ctypes.get_errno()

        raise OSError(
            errno,
            f"sysctl failed for PID {pid}"
        )

    # Return the raw CPU type integer.
    return cpu_type.value


# ------------------------------------------------------------
# Convert the CPU type into a readable architecture name
# ------------------------------------------------------------

def get_architecture(pid: int) -> str:
    """
    Return a readable architecture name for the supplied PID.

    Possible results include:

        Intel
        Apple Silicon
        Unknown (...)
    """

    # Query the raw cpu_type_t value first.
    cpu_type = get_process_cpu_type(pid)

    # --------------------------------------------------------
    # Intel / x86_64
    # --------------------------------------------------------

    if cpu_type == CPU_TYPE_X86_64:
        return "Intel"

    # --------------------------------------------------------
    # Apple Silicon / arm64
    # --------------------------------------------------------

    if cpu_type == CPU_TYPE_ARM64:
        return "Apple Silicon"

    # --------------------------------------------------------
    # Unknown architecture
    # --------------------------------------------------------

    # "& 0xffffffff" ensures the value is displayed as an
    # unsigned 32-bit hexadecimal number.
    return (
        f"Unknown "
        f"(cpu_type=0x{cpu_type & 0xffffffff:08x})"
    )


# ------------------------------------------------------------
# Test
# ------------------------------------------------------------

if __name__ == "__main__":

    # Get the PID of this Python interpreter.
    pid = os.getpid()

    print("PID:", pid)

    # Determine whether this Python process is being reported
    # by macOS as Intel or Apple Silicon.
    print(
        "Architecture:",
        get_architecture(pid)
    )
