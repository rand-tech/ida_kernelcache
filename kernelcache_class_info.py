#
# kernelcache_class_info.py
# Brandon Azad
#
# Collect information about C++ classes in a kernelcache.
#

from ida_utilities import *

from collections import defaultdict

from kernelcache_ida_segments import (kernelcache_kext)
from kernelcache_vtable_utilities import (VTABLE_OFFSET, kernelcache_vtable_length)

_log_level = 1

def _log_ok(level):
    return level <= _log_level

def _log(level, fmt, *args):
    if _log_ok(level):
        print 'kernelcache_class_info: ' + fmt.format(*args)

# IDK where IDA defines these.
_MEMOP_PREINDEX  = 0x20
_MEMOP_POSTINDEX = 0x80

_MEMOP_WBINDEX   = _MEMOP_PREINDEX | _MEMOP_POSTINDEX

class _Regs(object):
    """A set of registers for _emulate_arm64."""

    class _Unknown:
        """A wrapper class indicating that the value is unknown."""
        def __add__(self, other):
            return _Regs.Unknown
        def __radd__(self, other):
            return _Regs.Unknown
        def __nonzero__(self):
            return False

    _reg_names = idautils.GetRegisterList()
    Unknown = _Unknown()

    def __init__(self):
        self.clearall()

    def clearall(self):
        self._regs = {}

    def clear(self, reg):
        try:
            del self._regs[self._reg(reg)]
        except KeyError:
            pass

    def _reg(self, reg):
        if type(reg) is int:
            reg = _Regs._reg_names[reg]
        return reg

    def __getitem__(self, reg):
        try:
            return self._regs[self._reg(reg)]
        except:
            return _Regs.Unknown

    def __setitem__(self, reg, value):
        if value is None or value is _Regs.Unknown:
            self.clear(reg)
        else:
            self._regs[self._reg(reg)] = value & 0xffffffffffffffff

def _emulate_arm64(start, end, on_BL=None, on_RET=None):
    """A very basic partial Arm64 emulator that does just enough to find OSMetaClass
    information."""
    # Super basic emulation.
    reg = _Regs()
    def load(addr, dtyp):
        if not addr:
            return None
        if dtyp == idaapi.dt_qword:
            size = 8
        elif dtyp == idaapi.dt_dword:
            size = 4
        else:
            return None
        return read_word(addr, size)
    def cleartemps():
        for t in ['X{}'.format(i) for i in range(0, 19)]:
            reg.clear(t)
    for insn in Instructions(start, end):
        _log(11, 'Processing instruction {:#x}', insn.ea)
        mnem = insn.get_canon_mnem()
        if mnem == 'ADRP' or mnem == 'ADR':
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'ADD' and insn.Op2.type == idc.o_reg and insn.Op3.type == idc.o_imm:
            reg[insn.Op1.reg] = reg[insn.Op2.reg] + insn.Op3.value
        elif mnem == 'NOP':
            pass
        elif mnem == 'MOV' and insn.Op2.type == idc.o_imm:
            reg[insn.Op1.reg] = insn.Op2.value
        elif mnem == 'MOV' and insn.Op2.type == idc.o_reg:
            reg[insn.Op1.reg] = reg[insn.Op2.reg]
        elif mnem == 'RET':
            if on_RET:
                on_RET(reg)
            break
        elif (mnem == 'STP' or mnem == 'LDP') and insn.Op3.type == idc.o_displ:
            if insn.auxpref & _MEMOP_WBINDEX:
                reg[insn.Op3.reg] = reg[insn.Op3.reg] + insn.Op3.addr
            if mnem == 'LDP':
                reg.clear(insn.Op1.reg)
                reg.clear(insn.Op2.reg)
        elif (mnem == 'STR' or mnem == 'LDR') and not insn.auxpref & _MEMOP_WBINDEX:
            if mnem == 'LDR':
                if insn.Op2.type == idc.o_displ:
                    reg[insn.Op1.reg] = load(reg[insn.Op2.reg] + insn.Op2.addr, insn.Op1.dtyp)
                else:
                    reg.clear(insn.Op1.reg)
        elif mnem == 'BL' and insn.Op1.type == idc.o_near:
            if on_BL:
                on_BL(insn.Op1.addr, reg)
            cleartemps()
        else:
            _log(10, 'Unrecognized instruction at address {:#x}', insn.ea)
            reg.clearall()

class _OneToOneMapFactory(object):
    """A factory to extract the largest one-to-one submap."""

    def __init__(self):
        self._as_to_bs = defaultdict(set)
        self._bs_to_as = defaultdict(set)

    def add_link(self, a, b):
        """Add a link between the two objects."""
        self._as_to_bs[a].add(b)
        self._bs_to_as[b].add(a)

    def _make_unique_oneway(self, xs_to_ys, ys_to_xs, bad_x=None):
        """Internal helper to make one direction unique."""
        for x, ys in xs_to_ys.items():
            if len(ys) != 1:
                if bad_x:
                    bad_x(x, ys)
                del xs_to_ys[x]
                for y in ys:
                    del ys_to_xs[y]

    def _build_oneway(self, xs_to_ys):
        """Build a one-way mapping after pruning."""
        x_to_y = dict()
        for x, ys in xs_to_ys.items():
            x_to_y[x] = next(iter(ys))
        return x_to_y

    def build(self, bad_a=None, bad_b=None):
        """Extract the smallest one-to-one submap."""
        as_to_bs = dict(self._as_to_bs)
        bs_to_as = dict(self._bs_to_as)
        self._make_unique_oneway(as_to_bs, bs_to_as, bad_a)
        self._make_unique_oneway(bs_to_as, as_to_bs, bad_b)
        return self._build_oneway(as_to_bs)

class ClassInfo(object):
    """Information about a C++ class in a kernelcache."""

    def __init__(self, classname, metaclass, vtable, class_size, superclass_name, meta_superclass):
        self.superclass      = None
        self.classname       = classname
        self.metaclass       = metaclass
        self.vtable          = vtable
        self.class_size      = class_size
        self.superclass_name = superclass_name
        self.meta_superclass = meta_superclass

    def __repr__(self):
        def hex(x):
            if x is None:
                return repr(None)
            return '{:#x}'.format(x)
        return 'ClassInfo({!r}, {}, {}, {}, {!r}, {})'.format(
                self.classname, hex(self.metaclass), hex(self.vtable),
                self.class_size, self.superclass_name, hex(self.meta_superclass))

def _process_mod_init_func_for_metaclasses(func, found_metaclass):
    """Process a function from the __mod_init_func section for OSMetaClass information."""
    _log(4, 'Processing function {}', idc.GetFunctionName(func))
    def on_BL(addr, reg):
        X0, X1, X3 = reg['X0'], reg['X1'], reg['X3']
        if not (X0 and X1 and X3):
            return
        _log(5, 'Have call to {:#x}({:#x}, {:#x}, ?, {:#x})', addr, X0, X1, X3)
        # OSMetaClass::OSMetaClass(this, className, superclass, classSize)
        if not idc.SegName(X1).endswith("__TEXT.__cstring") or not idc.SegName(X0):
            return
        found_metaclass(X0, idc.GetString(X1), X3, reg['X2'] or None)
    _emulate_arm64(func, idc.FindFuncEnd(func), on_BL=on_BL)

def _process_mod_init_func_section_for_metaclasses(segstart, found_metaclass):
    """Process a __mod_init_func section for OSMetaClass information."""
    segend = idc.SegEnd(segstart)
    for func in ReadWords(segstart, segend):
        _process_mod_init_func_for_metaclasses(func, found_metaclass)

def _collect_metaclasses():
    """Collect OSMetaClass information from all kexts in the kernelcache."""
    # Collect associations from class names to metaclass instances and vice versa.
    metaclass_to_classname_builder = _OneToOneMapFactory()
    metaclass_to_class_size      = dict()
    metaclass_to_meta_superclass = dict()
    def found_metaclass(metaclass, classname, class_size, meta_superclass):
        metaclass_to_classname_builder.add_link(metaclass, classname)
        metaclass_to_class_size[metaclass]      = class_size
        metaclass_to_meta_superclass[metaclass] = meta_superclass
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('__DATA_CONST.__mod_init_func'):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_mod_init_func_section_for_metaclasses(ea, found_metaclass)
    # Filter out any class name (and its associated metaclasses) that has multiple metaclasses.
    # This can happen when multiple kexts define a class but only one gets loaded.
    def bad_classname(classname, metaclasses):
        _log(0, 'Class {} has multiple metaclasses: {}', classname,
                ', '.join(['{:#x}'.format(mc) for mc in metaclasses]))
    # Filter out any metaclass (and its associated class names) that has multiple class names. I
    # have no idea why this would happen.
    def bad_metaclass(metaclass, classnames):
        _log(0, 'Metaclass {:#x} has multiple classes: {}', metaclass,
                ', '.join(classnames))
    # Return the final dictionary of metaclass info.
    metaclass_to_classname = metaclass_to_classname_builder.build(bad_metaclass, bad_classname)
    metaclass_info = dict()
    for metaclass, classname in metaclass_to_classname.items():
        meta_superclass = metaclass_to_meta_superclass[metaclass]
        superclass_name = metaclass_to_classname.get(meta_superclass, None)
        metaclass_info[metaclass] = ClassInfo(classname, metaclass, None,
                metaclass_to_class_size[metaclass], superclass_name, meta_superclass)
    return metaclass_info

_VTABLE_GETMETACLASS    = VTABLE_OFFSET + 7
_MAX_GETMETACLASS_INSNS = 3

def _get_vtable_metaclass(vtable_addr, metaclass_info):
    """Simulate the getMetaClass method of the vtable and check if it returns an OSMetaClass."""
    getMetaClass = read_word(vtable_addr + _VTABLE_GETMETACLASS * WORD_SIZE)
    def on_RET(reg):
        on_RET.ret = reg['X0']
    on_RET.ret = None
    _emulate_arm64(getMetaClass, getMetaClass + WORD_SIZE * _MAX_GETMETACLASS_INSNS, on_RET=on_RET)
    if on_RET.ret in metaclass_info:
        return on_RET.ret

def _process_const_section_for_vtables(segstart, metaclass_info, found_vtable):
    """Process a __const section to search for virtual method tables."""
    segend = idc.SegEnd(segstart)
    addr = segstart
    while addr < segend:
        possible, length = kernelcache_vtable_length(addr, segend, scan=True)
        if possible:
            metaclass = _get_vtable_metaclass(addr, metaclass_info)
            if metaclass:
                _log(4, 'Vtable at address {:#x} has metaclass {:#x}', addr, metaclass)
                found_vtable(metaclass, addr)
        addr += length * WORD_SIZE

def _collect_vtables(metaclass_info):
    """Use OSMetaClass information to search for virtual method tables."""
    all_vtables = set()
    # Build a mapping from OSMetaClass instances to virtual method tables.
    metaclass_to_vtable_builder = _OneToOneMapFactory()
    def found_vtable(metaclass, vtable):
        all_vtables.add(vtable)
        if kernelcache_kext(metaclass) == kernelcache_kext(vtable):
            metaclass_to_vtable_builder.add_link(metaclass, vtable)
    for ea in idautils.Segments():
        segname = idc.SegName(ea)
        if not segname.endswith('__DATA_CONST.__const'):
            continue
        _log(2, 'Processing segment {}', segname)
        _process_const_section_for_vtables(ea, metaclass_info, found_vtable)
    # If a metaclass has multiple vtables, that's really weird, unless the metaclass is
    # OSMetaClass's metaclass. In that case all OSMetaClass subclasses will have their vtables
    # refer back to OSMetaClass's metaclass.
    # TODO: Right now we don't do anything special for this case.
    def bad_metaclass(metaclass, vtables):
        vtinfo = ['{:#x}'.format(vt) for vt in vtables]
        _log(0, 'Metaclass {:#x} ({}) has multiple vtables: {}', metaclass,
                metaclass_info[metaclass].classname, ', '.join(vtinfo))
    # If a vtable has multiple metaclasses, that's really weird.
    def bad_vtable(vtable, metaclasses):
        mcinfo = ['{:#x} ({})'.format(mc, metaclass_info[mc].classname) for mc in metaclasses]
        _log(0, 'Vtable {:#x} has multiple metaclasses: {}', vtable, ', '.join(mcinfo))
    metaclass_to_vtable = metaclass_to_vtable_builder.build(bad_metaclass, bad_vtable)
    # Print a list of the metaclasses that have been eliminated.
    if _log_ok(1):
        original  = set(metaclass_info.keys())
        remaining = set(metaclass_to_vtable.keys())
        _log(1, 'Eliminated classes:')
        for metaclass in original.difference(remaining):
            _log(1, '\t{:#x}  {}', metaclass, metaclass_info[metaclass].classname)
    # The resulting mapping may have fewer metaclasses than metaclass_info.
    class_info = dict()
    for metaclass, vtable in metaclass_to_vtable.items():
        classinfo = metaclass_info[metaclass]
        # Add the vtable, which we didn't have earlier.
        classinfo.vtable = vtable
        # If this class's superclass is still live, set its superclass field. This is safe since
        # this is the last filtering operation.
        if classinfo.meta_superclass in metaclass_to_vtable:
            classinfo.superclass = metaclass_info[classinfo.meta_superclass]
        class_info[classinfo.classname] = classinfo
    return class_info, all_vtables

def _check_filetype(filetype):
    """Checks that the filetype is compatible before trying to process it."""
    return 'Mach-O' in filetype and 'ARM64' in filetype

def _collect_class_info():
    """Collect information about C++ classes defined in a kernelcache."""
    filetype = idaapi.get_file_type_name()
    if not _check_filetype(filetype):
        _log(-1, 'Bad file type "{}"', filetype)
        return None
    _log(1, 'Collecting information about OSMetaClass instances')
    metaclass_info = _collect_metaclasses()
    if not metaclass_info:
        _log(-1, 'Could not collect OSMetaClass instances')
        return None
    _log(1, 'Searching for virtual method tables')
    class_info, all_vtables = _collect_vtables(metaclass_info)
    if not class_info:
        _log(-1, 'Could not collect virtual method tables')
        return None
    _log(1, 'Done')
    return class_info, all_vtables

kernelcache_class_info = dict()
"""A global map from class names to ClassInfo objects. See kernelcache_collect_class_info()."""

kernelcache_vtables = set()
"""A global set of all identified virtual method tables in the kernel."""

def kernelcache_collect_class_info():
    """Collect information about C++ classes defined in a kernelcache.

    This function searches through an iOS kernelcache for information about the C++ classes defined
    in it. It returns a dictionary that maps the C++ class names to a ClassInfo object containing
    metainformation about the class.

    The result of this function call is cached in the kernelcache_class_info global dictionary. If
    this dictionary is nonempty, this function will return its value rather than re-examining the
    kernelcache. To force re-evaluation of this function, clear the kernelcache_class_info
    dictionary with kernelcache_class_info.clear().

    This function also collects the set of all virtual method tables identified in the kernelcache,
    even if the corresponding class could not be identified. This set is stored in the
    kernelcache_vtables set.

    Only Arm64 is supported at this time.

    Only top-level classes are processed. Information about nested classes is not collected.
    """
    global kernelcache_class_info
    if not kernelcache_class_info:
        result = _collect_class_info()
        if result is not None:
            class_info, all_vtables = result
            kernelcache_class_info.update(class_info)
            kernelcache_vtables.update(all_vtables)
    return kernelcache_class_info

