#
# ida_kernelcache/kernel.py
# Brandon Azad
#
# The kernel module holds functions and global variables pertaining to the kernel as a whole. No
# prior initialization via ida_kernelcache is necessary.
#
import plistlib

import idc
import idautils
import idaapi

from . import ida_utilities as idau
from . import kplist

_log = idau.make_log(0, __name__)


def find_kernel_base():
    """Find the kernel base."""
    base = idaapi.get_fileregion_ea(0)
    if base != 0xFFFFFFFFFFFFFFFF:
        return base
    seg = [seg for seg in map(idaapi.get_segm_by_name, ["__TEXT.HEADER", "__TEXT:HEADER"]) if seg]
    if not seg:
        raise RuntimeError("unable to find kernel base")
    return seg[0].start_ea


base = find_kernel_base()
"""The kernel base address (the address of the main kernel Mach-O header)."""


def _find_prelink_info_segments():
    """Find all candidate __PRELINK_INFO segments (or sections).

    We try to identify any IDA segments with __PRELINK_INFO in the name so that this function will
    work both before and after automatic rename. A more reliable method would be parsing the
    Mach-O.
    """
    segments = []
    # Gather a list of all the possible segments.
    for seg in idautils.Segments():
        name = idc.get_segm_name(seg)
        if "__PRELINK_INFO" in name or name == "__info":
            segments.append(seg)
    if len(segments) < 1:
        _log(0, "Could not find any __PRELINK_INFO segment candidates")
    elif len(segments) > 1:
        _log(1, "Multiple segment names contain __PRELINK_INFO: {}", [idc.get_segm_name(seg) for seg in segments])
    return segments


def parse_prelink_info():
    """Find and parse the kernel __PRELINK_INFO dictionary."""
    segments = _find_prelink_info_segments()

    for segment in segments:
        seg_start = idc.get_segm_start(segment)
        seg_end = idc.get_segm_end(segment)

        # prelink_info_string = idc.get_strlit_contents(segment)
        prelink_info_string = idc.get_bytes(seg_start, seg_end - seg_start)
        if prelink_info_string != None:
            if prelink_info_string[:5] == b"<dict":
                prelink_info_string = prelink_info_string.replace(b"\x00", b"")
                prelink_info_string = prelink_info_string.decode()

                prelink_info = kplist.kplist_parse(prelink_info_string)
                if prelink_info:
                    return prelink_info
            elif prelink_info_string.startswith(b'<?xml version="1.0"'):
                return plistlib.loads((prelink_info_string.rstrip(b"\x00")))
    _log(0, "Could not find __PRELINK_INFO")
    return None


prelink_info = parse_prelink_info()
"""The kernel __PRELINK_INFO dictionary."""

KC_11_NORMAL = "11-normal"
KC_12_MERGED = "12-merged"


def _get_kernelcache_format():
    # once upon a time every KEXT had it's GOT ...
    if any(idc.get_segm_name(seg).endswith("__got") for seg in idautils.Segments()):
        return KC_11_NORMAL
    return KC_12_MERGED


kernelcache_format = _get_kernelcache_format()
