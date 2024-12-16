#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.


from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
global unwind
unwind = 1





####################
import io, os, ctypes, mmap
import ctypes.util
from enum import IntEnum
from typing import Optional, Sequence, Mapping, Tuple
from elftools.common.utils import preserve_stream_pos
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationHandler
from elftools.elf.sections import Symbol, SymbolTableSection
from elftools.elf.descriptions import describe_reloc_type
from qiling import Qiling
from qiling.os.memory import QlMemoryManager
from qiling.os.linux.function_hook import *
from qiling.arch.arm64 import QlArchARM64
from qiling.core_struct import QlCoreStructs
from memhax.constants import memory

MAP_FILE            = 0x00000000
MAP_SHARED          = 0x00000001
MAP_PRIVATE         = 0x00000002

MAP_FIXED           = 0x00000010
MAP_ANONYMOUS       = 0x00000020
MAP_GROWSDOWN       = 0x00000100
MAP_DENYWRITE       = 0x00000800
MAP_EXECUTABLE      = 0x00001000
MAP_LOCKED          = 0x00002000
MAP_NORESERVE       = 0x00004000
MAP_POPULATE        = 0x00008000
MAP_NONBLOCK        = 0x00010000
MAP_STACK           = 0x00020000
MAP_HUGETLB         = 0x00040000
MAP_SYNC            = 0x00080000
MAP_FIXED_NOREPLACE = 0x00100000
MAP_UNINITIALIZED   = 0x04000000

SHN_UNDEF	= 0

PF_X=0x1
PF_W=0x2
PF_R=0x4

PROT_NONE = 0
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
PROT_ALL = 7

PT_DYNAMIC      = 2
DT_NULL         = 0
DT_NEEDED         = 1
DT_PLTRELSZ     = 2
DT_PLTGOT         = 3
DT_HASH         = 4
DT_STRTAB         = 5
DT_SYMTAB         = 6
DT_RELA         = 7
DT_RELASZ         = 8
DT_RELAENT         = 9
DT_STRSZ         = 10
DT_SYMENT         = 11
DT_INIT         = 12
DT_FINI         = 13
DT_SONAME         = 14
DT_RPATH         = 15
DT_SYMBOLIC     = 16
DT_REL             = 17
DT_RELSZ         = 18
DT_RELENT         = 19
DT_PLTREL         = 20
DT_DEBUG         = 21
DT_TEXTREL         = 22
DT_JMPREL         = 23
DT_BIND_NOW     = 24
DT_INIT_ARRAY     = 25
DT_FINI_ARRAY     = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_RUNPATH         = 29
DT_FLAGS         = 30
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
DT_ENCODING     = 32
DT_GNU_HASH        = 0x6ffffef5




DT_MIPS_LOCAL_GOTNO = 0x7000000a
DT_MIPS_SYMTABNO = 0x70000011
DT_MIPS_GOTSYM = 0x70000013


FLAG_LINKED           = 0x00000001
FLAG_EXE              = 0x00000004 # The main executable
FLAG_LINKER           = 0x00000010 # The linker itself
FLAG_GNU_HASH         = 0x00000040 # uses gnu hash
FLAG_MAPPED_BY_CALLER = 0x00000080 # the map is reserved by the caller and should not be unmapped
FLAG_NEW_SOINFO       = 0x40000000 # new soinfo format
SOINFO_VERSION        = 3

STB_LOCAL   = 0
STB_GLOBAL  = 1
STB_WEAK    = 2

# /* Processor specific relocation types */
R_ARM_NONE		= 0
R_ARM_PC24		= 1
R_ARM_ABS32		= 2
R_ARM_REL32		= 3
R_ARM_PC13		= 4
R_ARM_ABS16		= 5
R_ARM_ABS12		= 6
R_ARM_THM_ABS5		= 7
R_ARM_ABS8		= 8
R_ARM_SBREL32		= 9
R_ARM_THM_PC22		= 10
R_ARM_THM_PC8		= 11
R_ARM_AMP_VCALL9	= 12
R_ARM_SWI24		= 13
R_ARM_THM_SWI8		= 14
R_ARM_XPC25		= 15
R_ARM_THM_XPC22		= 16

#20-31 are reserved for ARM Linux.
R_ARM_COPY		= 20
R_ARM_GLOB_DAT		= 21
R_ARM_JUMP_SLOT		= 22
R_ARM_RELATIVE		= 23
R_ARM_GOTOFF		= 24
R_ARM_GOTPC		= 25
R_ARM_GOT32		= 26
R_ARM_PLT32		= 27
R_ARM_CALL		= 28
R_ARM_JUMP24		= 29
R_ARM_THM_JUMP24    = 30
R_ARM_BASE_ABS		= 31
R_ARM_ALU_PCREL_7_0 = 32
R_ARM_ALU_PCREL_15_8    = 33
R_ARM_ALU_PCREL_23_15   = 34
R_ARM_ALU_SBREL_11_0    = 35
R_ARM_ALU_SBREL_19_12   = 36
R_ARM_ALU_SBREL_27_20   = 37	
R_ARM_TARGET1		= 38
R_ARM_SBREL31		= 39	
R_ARM_V4BX		= 40
R_ARM_TARGET2		= 41
R_ARM_PREL31		= 42
R_ARM_MOVW_ABS_NC   = 43
R_ARM_MOVT_ABS		= 44
R_ARM_MOVW_PREL_NC  = 45
R_ARM_MOVT_PREL		= 46
R_ARM_THM_MOVW_ABS_NC   = 47
R_ARM_THM_MOVT_ABS  = 48
R_ARM_THM_MOVW_PREL_NC  = 49
R_ARM_THM_MOVT_PREL = 50

R_AARCH64_ABS64               = 257
R_AARCH64_ABS32               = 258
R_AARCH64_ABS16               = 259
R_AARCH64_PREL64              = 260
R_AARCH64_PREL32              = 261
R_AARCH64_PREL16              = 262
R_AARCH64_MOVW_UABS_G0        = 263
R_AARCH64_MOVW_UABS_G0_NC     = 264
R_AARCH64_MOVW_UABS_G1        = 265
R_AARCH64_MOVW_UABS_G1_NC     = 266
R_AARCH64_MOVW_UABS_G2        = 267
R_AARCH64_MOVW_UABS_G2_NC     = 268
R_AARCH64_MOVW_UABS_G3        = 269
R_AARCH64_MOVW_SABS_G0        = 270
R_AARCH64_MOVW_SABS_G1        = 271
R_AARCH64_MOVW_SABS_G2        = 272
R_AARCH64_LD_PREL_LO19        = 273
R_AARCH64_ADR_PREL_LO21       = 274
R_AARCH64_ADR_PREL_PG_HI21    = 275
R_AARCH64_ADR_PREL_PG_HI21_NC = 276
R_AARCH64_ADD_ABS_LO12_NC     = 277
R_AARCH64_LDST8_ABS_LO12_NC   = 278
R_AARCH64_TSTBR14             = 279
R_AARCH64_CONDBR19            = 280
R_AARCH64_JUMP26              = 282
R_AARCH64_CALL26              = 283
R_AARCH64_LDST16_ABS_LO12_NC  = 284
R_AARCH64_LDST32_ABS_LO12_NC  = 285
R_AARCH64_LDST64_ABS_LO12_NC  = 286
R_AARCH64_LDST128_ABS_LO12_NC = 299
R_AARCH64_MOVW_PREL_G0        = 287
R_AARCH64_MOVW_PREL_G0_NC     = 288
R_AARCH64_MOVW_PREL_G1        = 289
R_AARCH64_MOVW_PREL_G1_NC     = 290
R_AARCH64_MOVW_PREL_G2        = 291
R_AARCH64_MOVW_PREL_G2_NC     = 292
R_AARCH64_MOVW_PREL_G3        = 293

R_AARCH64_COPY                  = 1024
R_AARCH64_GLOB_DAT              = 1025    #/* Create GOT entry.  */
R_AARCH64_JUMP_SLOT             = 1026    #/* Create PLT entry.  */
R_AARCH64_RELATIVE              = 1027    #/* Adjust by program base.  */
R_AARCH64_TLS_TPREL64           = 1030
R_AARCH64_TLS_DTPREL32          = 1031
R_AARCH64_IRELATIVE             = 1032

R_GENERIC_JUMP_SLOT  = R_AARCH64_JUMP_SLOT
R_GENERIC_GLOB_DAT   = R_AARCH64_GLOB_DAT
R_GENERIC_RELATIVE   = R_AARCH64_RELATIVE
R_GENERIC_IRELATIVE  = R_AARCH64_IRELATIVE

UNWIND_SAMPLE_STACK_USER = 0x4000 
UNWIND_EVENT_SIZE = 16672
UNWIND_RGS_CNT = 33
PAGE_SIZE = 0x1000

PAGE_START  = lambda addr: (addr & ~(PAGE_SIZE - 1))
PAGE_END    = lambda addr: ((addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
PAGE_OFFSET = lambda addr: (addr % PAGE_SIZE)
LOGI = lambda *args :print("[INFO ]", *args)
LOGD = lambda *args :print("[DEBUG]", *args)
LOGE = lambda *args :print("[ERROR]", *args)

# 加载 libc
libc = ctypes.CDLL("libc.so.6")

# 定义 mmap 函数的参数和返回值类型
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
# 定义 munmap 函数的参数
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]  # 设置参数类型
libc.memcpy.restype = ctypes.c_void_p  # 设置返回值类型

class ELF_Phdr:
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align

class ELF32_Phdr(ELF_Phdr):
    Phdr_SIZE = 4 * 8
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Phdr_SIZE:
            raise

        fmt = '<IIIIIIII' if endian == 0 else '>IIIIIIII'

        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(fmt, buf)
        super(ELF32_Phdr, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)

class ELF64_Phdr(ELF_Phdr):
    Phdr_SIZE = 8 * 7
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Phdr_SIZE:
            raise
        
        fmt = '<IIQQQQQQ' if endian == 0 else '>IIQQQQQQ'

        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(fmt, buf)
        super(ELF64_Phdr, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)
        
class ELF_Dyn:
    def __init__(self, d_tag, d_un):
        self.d_tag = d_tag
        self.d_un = d_un

class ELF32_Dyn(ELF_Dyn):
    Dyn_SIZE = 4 * 2
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Dyn_SIZE:
            raise
        
        fmt = '<iI' if endian == 0 else '>iI'

        d_tag, d_un = struct.unpack(fmt, buf)
        super(ELF32_Dyn, self).__init__(d_tag, d_un)

class ELF64_Dyn(ELF_Dyn):
    Dyn_SIZE = 8 * 2
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Dyn_SIZE:
            raise
        
        fmt = '<qQ' if endian == 0 else '>qQ'

        d_tag, d_un = struct.unpack(fmt, buf)
        super(ELF64_Dyn, self).__init__(d_tag, d_un)

class ELF_Rel:
    def __init__(self, r_offset, r_info):
        self.r_offset = r_offset
        self.r_info = r_info

class ELF32_Rel(ELF_Rel):
    Rel_SIZE = 4 * 2
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rel_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<II' if endian == 0 else '>II'

        r_offset, r_info = struct.unpack(self.fmt, buf)
        super(ELF32_Rel, self).__init__(r_offset, r_info)

    @property
    def r_type(self):
        return self.r_info & 0xff

    @property
    def r_sym(self):
        return self.r_info >> 8
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info)

class ELF64_Rel(ELF_Rel):
    Rel_SIZE = 8 * 2
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rel_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<QQ' if endian == 0 else '>QQ'

        r_offset, r_info = struct.unpack(self.fmt, buf)
        super(ELF64_Rel, self).__init__(r_offset, r_info)

    @property
    def r_type(self):
        return self.r_info & 0xffffffff
        
    @property
    def r_sym(self):
        return self.r_info >> 32
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info)


class ELF_Rela:
    def __init__(self, r_offset, r_info, r_addend):
        self.r_offset = r_offset
        self.r_info = r_info
        self.r_addend = r_addend

class ELF32_Rela(ELF_Rela):
    Rela_SIZE = 4 * 3
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rela_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<IIi' if endian == 0 else '>IIi'

        r_offset, r_info, r_addend = struct.unpack(self.fmt, buf)
        super(ELF32_Rela, self).__init__(r_offset, r_info, r_addend)

    @property
    def r_type(self):
        return self.r_info & 0xff

    @property
    def r_sym(self):
        return self.r_info >> 8
    
    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info, self.r_addend)

class ELF64_Rela(ELF_Rela):
    Rela_SIZE = 8 * 3
    def __init__(self, buf, endian = 0, ptr = None):
        if len(buf) != self.Rela_SIZE:
            raise
        
        self.ptr = ptr
        self.fmt = '<QQq' if endian == 0 else '>QQq'

        r_offset, r_info, r_addend = struct.unpack(self.fmt, buf)
        super(ELF64_Rela, self).__init__(r_offset, r_info, r_addend)

    @property
    def r_type(self):
        return self.r_info & 0xffffffff
        
    @property
    def r_sym(self):
        return self.r_info >> 32

    def pack(self):
        return struct.pack(self.fmt, self.r_offset, self.r_info, self.r_addend)

class ELF_Sym:
    def __init__(self, st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx):
        self.st_name = st_name
        self.st_value = st_value
        self.st_size = st_size
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx

class ELF32_Sym(ELF_Sym):
    Sym_SIZE = 4 * 4
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Sym_SIZE:
            raise
        
        self.fmt = '<IIIBBH' if endian == 0 else '>IIIBBH'

        st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx = struct.unpack(self.fmt, buf)
        super(ELF32_Sym, self).__init__(st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx)
    
    def pack(self):
        struct.pack(self.fmt ,self.st_name ,self.st_value ,self.st_size ,self.st_info ,self.st_other ,self.st_shndx)

class ELF64_Sym(ELF_Sym):
    Sym_SIZE = 8 * 3
    def __init__(self, buf, endian = 0):
        if len(buf) != self.Sym_SIZE:
            raise
        
        self.fmt = '<IBBHQQ' if endian == 0 else '>IBBHQQ'

        st_name ,st_info ,st_other ,st_shndx ,st_value ,st_size = struct.unpack(self.fmt, buf)
        super(ELF64_Sym, self).__init__(st_name ,st_value ,st_size ,st_info ,st_other ,st_shndx)
    
    def pack(self):
        struct.pack(self.fmt ,self.st_name ,self.st_info ,self.st_other ,self.st_shndx ,self.st_value ,self.st_size)

class ELF_Symtab:
    def __init__(self, ql, symtab, endian = 0):
        self.ql = ql
        self.symtab = symtab
        self.endian = endian

        self.symclass = ELF32_Sym if self.ql.arch.bits == 32 else ELF64_Sym
    
    def __getitem__(self, idx):
        buf = self.ql.mem.read(self.symtab + idx * self.symclass.Sym_SIZE, self.symclass.Sym_SIZE)
        return self.symclass(buf, self.endian)

    def __setitem__(self, idx, sym):
        self.ql.mem.write(self.symtab + idx * self.symclass.Sym_SIZE, sym.pack())

class ELF_Strtab:
    def __init__(self, strtab):
        self.strtab = bytes(strtab)
    
    def __getitem__(self, idx):
        return self.strtab[idx: self.strtab.index(b'\x00', idx)]

class MemUtil:
    @staticmethod
    def read(addr, size):
        # buf = bytearray(size)
        # ctypes.memmove(buf, ctypes.cast(addr, ctypes.POINTER(ctypes.c_char)), size)
        
        buf = ctypes.string_at(ctypes.cast(addr, ctypes.POINTER(ctypes.c_char)), size)
        return buf 
        # data = None
        # with memory(addr) as mem:
        #     data = mem.read(size)
        # return data
    
    @staticmethod
    def readU64(addr):
        buf = MemUtil.read(addr, 8)
        value = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint64)).contents.value
        return value

    @staticmethod
    def write(addr, buf):
        libc.memcpy(addr, buf, ctypes.sizeof(buf))

    @staticmethod
    def writeU64(addr, value):
        value_ctypes = ctypes.c_uint64(value)
        # 使用 ctypes.string_at 获取指定地址的指针
        # 这里我们使用 ctypes.cast 将地址转换为指向 c_uint64 的指针
        ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_uint64))
        # 将值写入指定的内存地址
        ptr.contents = value_ctypes

class FakeQiling(QlCoreStructs):
    mem:MemUtil
    arch:QlArchARM64
    def __init__(self):
        super().__init__(QL_ENDIAN.EL, bit=64)
        self.mem = MemUtil()
        self.arch = QlArchARM64(ql=None)


UINT32 = lambda x: x&0xFFFFFFFF

def elf_hash(name):
    h = 0 
    for c in name:
        h = UINT32(h << 4) + c
        h = UINT32(h)
        g = UINT32(h & 0xf0000000)
        h = h^g
        g = UINT32(g >> 24)
        h = h^g
    return h

def gnu_hash(name):
    h = 5381
    for c in name:
        tmp = UINT32(h << 5) + c
        tmp = UINT32(tmp)
        h = UINT32(h + tmp)
    return h

class AndroidElf:
    ql:FakeQiling
    load_bias_:int 
    _ELFFile: ELFFile
    def __init__(self, ql = FakeQiling()):
        self.name = None
        self.ql = ql
        self.flags = 0
        self.dynamic = None
        
        self.nbucket = None
        self.nchain = None
        self.bucket = None
        self.chain = None

        self.gnu_nbucket = None
        self.gnu_symbias = None
        self.gnu_maskwords = None
        self.gnu_shift2 = None
        self.gnu_bloom_filter = None
        self.gnu_bucket = None
        self.gnu_chain = None

        self.init_func = None
        self.fini_func = None

        self.init_array = None
        self.init_array_count = 0

        self.finit_array = None
        self.finit_array_count = 0

        self.preinit_array = None
        self.preinit_array_count = 0

        self.has_text_relocations = False
        self.has_DT_SYMBOLIC = False
        self.so_needed = []

        self.strtab = None
        self.strtab_size = None

        self.symtab = None
        self.syment = ELF32_Sym.Sym_SIZE if ql.arch.bits == 32 else ELF64_Sym.Sym_SIZE

        self.plt_rel_size = None
        self.plt_rel = None
        self.plt_rel_type = DT_REL if ql.arch.bits == 32 else DT_RELA

        self.rela = None
        self.rela_size = None
        self.relaent = ELF32_Rela.Rela_SIZE if ql.arch.bits == 32 else ELF64_Rela.Rela_SIZE

        self.rel = None
        self.rel_size = None
        self.relent = ELF32_Rel.Rel_SIZE if ql.arch.bits == 32 else ELF64_Rel.Rel_SIZE

        self.plt_got = None
        self.mips_local_gotno = None
        self.mips_symtabno = None
        self.mips_gotsym = None

        self.rel_list = []
        self.endian = 0 if ql.arch.endian == QL_ENDIAN.EL else 1

    def parse_dynamic64(self):
        # typedef struct
        # {
        # Elf64_Sxword    d_tag;            /* Dynamic entry type */
        # union
        #     {
        #     Elf64_Xword d_val;        /* Integer value */
        #     Elf64_Addr d_ptr;            /* Address value */
        #     } d_un;
        # } Elf64_Dyn;

        # /* 64-bit ELF base types. */
        # typedef uint64_t Elf64_Addr;
        # typedef uint16_t Elf64_Half;
        # typedef int16_t     Elf64_SHalf;
        # typedef uint64_t Elf64_Off;
        # typedef int32_t     Elf64_Sword;
        # typedef uint32_t Elf64_Word;
        # typedef uint64_t Elf64_Xword;
        # typedef int64_t  Elf64_Sxword;


        Dsize = ELF64_Dyn.Dyn_SIZE
        idx = 0

        while True:
            address = self.load_bias_ + self.dynamic["p_vaddr"] + idx * Dsize
            buf = self.ql.mem.read(address, Dsize)
            D = ELF64_Dyn(buf, self.endian)
            yield D
            idx += 1
            if D.d_tag == DT_NULL:
                break
        return
    
    def gnu_lookup(self, symbol_name, vi, symbol_index):
        hash = gnu_hash(symbol_name)
        h2 = UINT32(hash >> self.gnu_shift2)

        bloom_mask_bits = 8*8; 
        word_num = (hash / bloom_mask_bits) & self.gnu_maskwords
        bloom_word = self.gnu_bloom_filter[word_num];

        symbol_index = 0

        # // test against bloom filter
        if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0):
            return True

        # // bloom test says "probably yes"...
        n = self.gnu_bucket[hash % self.gnu_nbucket]

        if (n == 0):
            return True

        # // lookup versym for the version definition in this library
        # // note the difference between "version is not requested" (vi == nullptr)
        # // and "version not found". In the first case verneed is kVersymNotNeeded
        # // which implies that the default version can be accepted; the second case results in
        # // verneed = 1 (kVersymGlobal) and implies that we should ignore versioned symbols
        # // for this library and consider only *global* ones.
        # ElfW(Versym) verneed = 0;
        if (!find_verdef_version_index(this, vi, &verneed)) {
            return false;
        }

        while 1:
            ElfW(Sym)* s = symtab_ + n;
            const ElfW(Versym)* verdef = get_versym(n);
            // skip hidden versions when verneed == kVersymNotNeeded (0)
            if (verneed == kVersymNotNeeded && is_versym_hidden(verdef)) {
                continue;
            }
            if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
                check_symbol_version(verneed, verdef) &&
                strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
                is_symbol_global_and_defined(this, s)) {
                TRACE_TYPE(LOOKUP, "FOUND %s in %s (%p) %zd",
                    symbol_name.get_name(), get_realpath(), reinterpret_cast<void*>(s->st_value),
                    static_cast<size_t>(s->st_size));
                *symbol_index = n;
                return true;
            }
            if ((self.gnu_chain[n] & 1) == 0):
                break
            n = n + 1

        return true

    def find_symbol_by_name(self, symbol_name, vi, symbol):
        symbol_index = 0
        success = gnu_lookup(symbol_name, vi, symbol_index) if is_gnu_hash() else elf_lookup(symbol_name, vi, symbol_index)

        if (success):
          symbol = None if symbol_index == 0 else self.symtab[symbol_index]
        return success;


class VersionTracker:
    def get_version_info(self, source_symver):
        if (source_symver < 2 ||
            source_symver >= version_infos.size() ||
            version_infos[source_symver].name == nullptr) {
            return nullptr;
        }

        return &version_infos[source_symver];

class AndroidLinker:
    """
    参考的旧版本: http://androidxref.com/4.4.4_r1/xref/bionic/linker/linker.cpp
    """
    load_regions: Sequence[Tuple[int, int, int]] = []
    solist = {}
    LD_LIBRARY_PATH = ["/system/lib64"]

    def __init__(self):
        self.ql = FakeQiling()

    def do_dlopen(self, elfPath):
        so = self.find_library(elfPath)
        if so == None:
            LOGE(f"can't load module {eilfPath}")
        so.CallConstructors()

    def find_library(self, elfPath, load_address: int = 0, argv: Sequence[str] = [], env: Mapping[str, str] = {}):
        so_name = elfPath.split(os.path.sep)[-1]
        if so_name in self.solist:
            return self.solist[so_name]
        
        elf = self.load_library(elfPath)
        if elf == None:
            return None
        
        self.soinfo_link_image(elf)
        self.solist[so_name] = elf

        return elf

    def load_library(self, elfPath, load_address=0):
        path = elfPath
        if os.path.sep not in elfPath:
            for libDir in AndroidLinker.LD_LIBRARY_PATH:
                path = os.path.join(libDir, elfPath)
                if os.path.exists(path):
                    break
        if not os.path.exists(path): return None
        LOGD(f"loading {path}")
        elf = AndroidElf()
        infile =  open(path, 'rb')
        fstream = io.BytesIO(infile.read())
        elffile = ELFFile(fstream)
        elf._ELFFile = elffile
        
        # get list of loadable segments; these segments will be loaded to memory
        load_segments = sorted(elffile.iter_segments(type='PT_LOAD'), key=lambda s: s['p_vaddr'])

        mem_start = PAGE_START(load_segments[0]['p_vaddr'])
        mem_end   = PAGE_END(load_segments[-1]['p_vaddr'] + load_segments[-1]['p_memsz'])

        # entry_point = load_address + elffile['e_entry']
        start  = libc.mmap(load_address, mem_end - mem_start, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        load_bias_  = start - mem_start
        elf.load_bias_ = load_bias_

        # iterate over loadable segments
        for phdr in load_segments:
            seg_start = phdr['p_vaddr'] + load_bias_
            seg_end   = seg_start + phdr['p_memsz']
            seg_page_start = PAGE_START(seg_start)
            seg_page_end   = PAGE_END(seg_end)
            #计算该PT_LOAD段在内存中对应文件的结束位置
            seg_file_end   = seg_start + phdr["p_filesz"]
            #文件中的偏移
            file_start = phdr["p_offset"]
            file_end   = file_start + phdr["p_filesz"]

            file_page_start = PAGE_START(file_start);
            file_length = file_end - file_page_start;
            #将该PT_LOAD段的实际内容页对齐后映射到内存中
            flag = phdr["p_flags"]
            seg_addr = libc.mmap(seg_page_start, file_length, flag, MAP_FIXED|MAP_PRIVATE, infile.fileno(),file_page_start);
            #如果该段的权限可写且该段指定的文件大小并不是页边界对齐的，就要对页内没有文件与之对应的区域置0
            if ((flag & PF_W) != 0 and PAGE_OFFSET(seg_file_end) > 0):
                libc.memset(seg_file_end, 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
            #如果该段指定的内存大小超出了文件映射的页面，就要对多出的页进行匿名映射
            #防止出现Bus error的情况
            if (seg_page_end > seg_file_end):
                libc.mmap(seg_file_end, seg_page_end - seg_file_end, 
                            flag, 
                            MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                            -1,
                            0)
                
            # print(f'map seg:{seg_start:x} - {seg_end:x}')
        infile.close()

        #异常相关
        # (void) phdr_table_get_arm_exidx(phdr, phnum, base,
                                    # &si->ARM_exidx, &si->ARM_exidx_count);

        #符号
        elf.dynamic = next(elffile.iter_segments(type='PT_DYNAMIC'))
        return elf


    #参考 http://androidxref.com/8.0.0_r4/xref/bionic/linker/linker.cpp#2871
    def soinfo_link_image(self, elf:AndroidElf):
        
        version_tracker = VersionTracker()
        version_tracker.init()

        for d in elf.parse_dynamic64():
            # LOGD(f"Dynamic d_tag:{d.d_tag}")
            if d.d_tag == DT_NULL:
                break
            if d.d_tag ==  DT_SONAME:
                elf.name = d.d_un
            elif d.d_tag == DT_HASH:
                elf.nbucket = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un, elf.ql.arch.pointersize))
                elf.nchain = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize, elf.ql.arch.pointersize))
                elf.bucket = elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 2, elf.ql.arch.pointersize * elf.nbucket)
                elf.chain = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 2 + elf.ql.arch.pointersize * elf.nbucket, elf.ql.arch.pointersize))
                pass
            elif d.d_tag == DT_GNU_HASH:
                elf.gnu_nbucket = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un, elf.ql.arch.pointersize))
                elf.gnu_symbias = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize, elf.ql.arch.pointersize))
                elf.gnu_maskwords = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 2, elf.ql.arch.pointersize))
                elf.gnu_shift2 = elf.ql.unpack(elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 3, elf.ql.arch.pointersize))
                elf.gnu_bloom_filter = elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 4, elf.gnu_maskwords)
                elf.gnu_bucket = elf.ql.mem.read(elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 4 + elf.gnu_maskwords, elf.ql.arch.pointersize * elf.gnu_nbucket)
                elf.gnu_chain = elf.load_bias_ + d.d_un + elf.ql.arch.pointersize * 4 + elf.gnu_maskwords + elf.ql.arch.pointersize * elf.gnu_nbucket - elf.ql.arch.pointersize * elf.gnu_symbias
                elf.flags |= FLAG_GNU_HASH
            elif d.d_tag == DT_STRTAB:
                elf.strtab = d.d_un + elf.load_bias_
            elif d.d_tag == DT_STRSZ:
                elf.strtab_size = d.d_un
            elif d.d_tag == DT_SYMTAB:
                elf.symtab = d.d_un + elf.load_bias_
            elif d.d_tag == DT_SYMENT:
                if d.d_un != elf.syment:
                    raise
            elif d.d_tag == DT_PLTREL:
                if d.d_un != elf.plt_rel_type:
                    # FIXME: I don't why it is a error
                    # but it is triggered in riscv32
                    pass
            elif d.d_tag == DT_PLTRELSZ:
                elf.plt_rel_size = d.d_un
            elif d.d_tag == DT_JMPREL:
                elf.plt_rel = d.d_un + elf.load_bias_
            elif d.d_tag == DT_PLTGOT:
                elf.plt_got = d.d_un

            elif d.d_tag == DT_RELA:
                elf.rela = d.d_un + elf.load_bias_
            elif d.d_tag == DT_RELASZ:
                elf.rela_size = d.d_un
            elif d.d_tag == DT_RELAENT:
                if elf.relaent != d.d_un:
                    raise

            elif d.d_tag == DT_REL:
                elf.rel = d.d_un + elf.load_bias_
            elif d.d_tag == DT_RELSZ:
                elf.rel_size = d.d_un
            elif d.d_tag == DT_RELENT:
                if elf.relent != d.d_un:
                    raise



            elif d.d_tag == DT_MIPS_LOCAL_GOTNO:
                elf.mips_local_gotno = d.d_un
            elif d.d_tag == DT_MIPS_SYMTABNO:
                elf.mips_symtabno = d.d_un
            elif d.d_tag == DT_MIPS_GOTSYM:
                elf.mips_gotsym = d.d_un
            
            elif d.d_tag ==  DT_INIT:
                elf.init_func = d.d_un + elf.load_bias_
                LOGD(f"constructors (DT_INIT) found at {elf.init_func:x}");
            elif d.d_tag ==  DT_FINI:
                elf.fini_func = d.d_un + elf.load_bias_
                LOGD(f"destructors (DT_FINI) found at {elf.fini_func:x}");
            elif d.d_tag ==  DT_INIT_ARRAY:
                elf.init_array = d.d_un + elf.load_bias_
            elif d.d_tag == DT_INIT_ARRAYSZ:
                # 64位是8字节,32位是4字节
                if elf.ql.arch.bits == 64:
                    elf.init_array_count = (d.d_un / 8) 
                elif elf.ql.arch.bits == 32:
                    elf.init_array_count = (d.d_un / 4) 
            elif d.d_tag ==  DT_FINI_ARRAY:
                elf.fini_array = d.d_un + elf.load_bias_
            elif d.d_tag ==  DT_FINI_ARRAYSZ:
                # 64位是8字节,32位是4字节
                if elf.ql.arch.bits == 64:
                    elf.finit_array_count = (d.d_un / 8) 
                elif elf.ql.arch.bits == 32:
                    elf.finit_array_count = (d.d_un / 4) 
            elif d.d_tag ==  DT_PREINIT_ARRAY:
                #也是初始化函数，但是跟init.array不同，这个段大多只出现在可执行文件中，在So中我选择了忽略
                elf.preinit_array = d.d_un + elf.load_bias_
            elif d.d_tag ==  DT_PREINIT_ARRAYSZ:
                # 64位是8字节,32位是4字节
                if elf.ql.arch.bits == 64:
                    elf.preinit_array_count = (d.d_un / 8) 
                elif elf.ql.arch.bits == 32:
                    elf.preinit_array_count = (d.d_un / 4) 
            elif d.d_tag ==  DT_TEXTREL:
                elf.has_text_relocations = True
            elif d.d_tag ==  DT_SYMBOLIC:
                elf.has_DT_SYMBOLIC = True

            elif d.d_tag ==  DT_NEEDED:
                #先读取,后面再处理
                elf.so_needed.append(d.d_un)
            else:
                LOGE(f"unknow d_tag: {d.d_tag:x}")
                pass
            
        if elf.strtab != None and elf.strtab_size != None:
            elf.strtab = ELF_Strtab(elf.ql.mem.read(elf.strtab, elf.strtab_size))
        
        if elf.rela != None and elf.rela_size != None:
            rela_buf = elf.ql.mem.read(elf.rela, elf.rela_size)
            rela_ptr = elf.rela
            if elf.ql.arch.bits == 32:
                elf.rela = [ELF32_Rela(rela_buf[_ * elf.relaent : (_ + 1) * elf.relaent], elf.endian, rela_ptr + _ * elf.relaent) for _ in range(elf.rela_size // elf.relaent)]
            elif elf.ql.arch.bits == 64:
                elf.rela = [ELF64_Rela(rela_buf[_ * elf.relaent : (_ + 1) * elf.relaent], elf.endian, rela_ptr + _ * elf.relaent) for _ in range(elf.rela_size // elf.relaent)]
        
        if elf.rel != None and elf.rel_size != None:
            rel_buf = elf.ql.mem.read(elf.rel, elf.rel_size)
            rel_ptr = elf.rel
            if elf.ql.arch.bits == 32:
                elf.rel = [ELF32_Rel(rel_buf[_ * elf.relent : (_ + 1) * elf.relent], elf.endian, rel_ptr + _ * elf.relent) for _ in range(elf.rel_size // elf.relent)]
            elif elf.ql.arch.bits == 64:
                elf.rel = [ELF64_Rel(rel_buf[_ * elf.relent : (_ + 1) * elf.relent], elf.endian, rel_ptr + _ * elf.relent) for _ in range(elf.rel_size // elf.relent)]

        if elf.plt_rel != None and elf.plt_rel_size != None:
            plt_rel_buf = elf.ql.mem.read(elf.plt_rel, elf.plt_rel_size)
            plt_rel_ptr = elf.plt_rel
            if elf.plt_rel_type == DT_REL:
                if elf.ql.arch.bits == 32:
                    elf.plt_rel = [ELF32_Rel(plt_rel_buf[_ * elf.relent : (_ + 1) * elf.relent], elf.endian, plt_rel_ptr + _ * elf.relent) for _ in range(elf.plt_rel_size // elf.relent)]
                elif elf.ql.arch.bits == 64:
                    elf.plt_rel = [ELF64_Rel(plt_rel_buf[_ * elf.relent : (_ + 1) * elf.relent], elf.endian, plt_rel_ptr + _ * elf.relent) for _ in range(elf.plt_rel_size // elf.relent)]
            else:
                if elf.ql.arch.bits == 32:
                    elf.plt_rel = [ELF32_Rela(plt_rel_buf[_ * elf.relaent : (_ + 1) * elf.relaent], elf.endian, plt_rel_ptr + _ * elf.relaent) for _ in range(elf.plt_rel_size // elf.relaent)]
                elif elf.ql.arch.bits == 64:
                    elf.plt_rel = [ELF64_Rela(plt_rel_buf[_ * elf.relaent : (_ + 1) * elf.relaent], elf.endian, plt_rel_ptr + _ * elf.relaent) for _ in range(elf.plt_rel_size // elf.relaent)]
        
        if elf.symtab != None:
            elf.symtab = ELF_Symtab(elf.ql, elf.symtab, elf.endian)

        if elf.strtab != None:
            newList= []
            for i in range(len(elf.so_needed)):
                d_un = elf.so_needed[i]
                #先读取,后面再处理
                library_name = elf.strtab[d_un].decode('utf-8')
                newList.append(library_name)
            elf.so_needed = newList

            elf.name = elf.strtab[elf.name].decode('utf-8')

        # 至此，Dynamic段的信息就解析完毕了，其中想表达的信息也被处理后放到了soinfo中，后面直接就可以拿来用了

        # 再次遍历Dynamic段处理依赖
        for so in elf.so_needed:
            self.find_library(library_name)

        # 处理重定位
        if isinstance(elf.plt_rel, list):
            LOGD("[ relocating {elf.name} plt ]")
            if (self.soinfo_relocate(elf, elf.plt_rel, elf.so_needed)):
                return False
            

        if isinstance(elf.rel, list):
            LOGD("[ relocating %s ]" % elf.name )
            if (self.soinfo_relocate(elf, elf.rel, elf.so_needed)):
                return False

        #设置soinfo的LINKED标志，表示已进行链接
        # si->flags |= FLAG_LINKED;
        LOGD("[ finished linking %s ]" % elf.name)

    # def lookup_version_info(version_tracker, sym, sym_name, vi):
    #     const ElfW(Versym)* sym_ver_ptr = get_versym(sym);
    #     ElfW(Versym) sym_ver = sym_ver_ptr == nullptr ? 0 : *sym_ver_ptr;
    
    #     if (sym_ver != VER_NDX_LOCAL && sym_ver != VER_NDX_GLOBAL) {
    #         *vi = version_tracker.get_version_info(sym_ver);
    
    #         if (vi == None):
    #             return false
            
    #     else:
    #         # there is no version info
    #         vi = None
    #     return True

    def soinfo_relocate(self, elf, rel_list:list, needed):
        ELF64_R_TYPE = lambda info: (info & 0xffffffff)
        ELF64_R_SYM = lambda info: ((info) >> 32)

        #拿到符号表和字符串表，定义一些变量
        # Elf32_Sym* symtab = si->symtab;
        # const char* strtab = si->strtab;
        # Elf32_Sym* s;
        # Elf32_Rel* start = rel;
        # soinfo* lsi;

        load_bias = elf.load_bias_

        symtab = elf.symtab
        strtab = elf.strtab

        lsi = None
        
        for idx in range(len(rel_list)):
            rel = rel_list[idx]
            # 重定位类型
            type = ELF64_R_TYPE(rel.r_info)
            # 重定位符号
            sym = ELF64_R_SYM(rel.r_info)
            # 计算需要重定位的地址
            reloc = rel.r_offset + elf.load_bias_
            sym_addr = 0
            sym_name = None
            addend = rel.r_addend

            LOGD("Processing '%s' relocation at index %d" % (elf.name, idx))
            # R_*_NONE
            if (type == 0):continue
            if (sym != 0):
                # 如果sym不为0，说明重定位需要用到符号，先来找符号，拿到符号名
                sym_name = strtab[symtab[sym].st_name]
                vi = None # version_info
                if not lookup_version_info(version_tracker, sym, sym_name, &vi): 
                    return False


                # 根据符号名来从依赖so中查找所需要的符号
                s = self.soinfo_do_lookup(elf, sym_name, lsi, needed)
                if (s == None):
                    #如果没找到，就用本身So的符号
                    s = symtab[sym]
                    if (s.st_info != STB_WEAK):
                        LOGE("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, elf.name)
                        return False
    
                    # switch (type) {
                    #     //下面是如果符号不为外部符号，就只能为以下几种类型
                    # #if defined(ANDROID_ARM_LINKER)
                    # case R_ARM_JUMP_SLOT:
                    # case R_ARM_GLOB_DAT:
                    # case R_ARM_ABS32:
                    # case R_ARM_RELATIVE:    /* Don't care. */
                    # #endif /* ANDROID_*_LINKER */
                    #     /* sym_addr was initialized to be zero above or relocation
                    #     code below does not care about value of sym_addr.
                    #     No need to do anything.  */
                    #     break;

                    # #if defined(ANDROID_ARM_LINKER)
                    # case R_ARM_COPY:
                    #     /* Fall through.  Can't really copy if weak symbol is
                    #     not found in run-time.  */
                    # #endif /* ANDROID_ARM_LINKER */
                    # default:
                    #     DL_ERR("unknown weak reloc type %d @ %p (%d)",
                    #                 type, rel, (int) (rel - start));
                    #     return -1;
                    # }
                else :
                    # 外部符号的地址
                    sym_addr = s.st_value + elf.load_bias_
                
                # count_relocation(kRelocSymbol);
            else:
                # 如果sym为0，就说明当前重定位用不到符号
                s = None

            #下面根据重定位类型来处理重定位
            if type == R_GENERIC_JUMP_SLOT:
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                self.ql.mem.writeU64(reloc, (sym_addr + addend))
            elif type == R_GENERIC_GLOB_DAT:
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                self.ql.mem.writeU64(reloc, (sym_addr + addend))
            elif type == R_GENERIC_RELATIVE:
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = (load_bias + addend);
                self.ql.mem.writeU64(reloc, (load_bias + addend))
            elif type == R_GENERIC_IRELATIVE:
                # ElfW(Addr) ifunc_addr = call_ifunc_resolver(load_bias + addend);
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = ifunc_addr;
                """
                ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
                  typedef ElfW(Addr) (*ifunc_resolver_t)(void);
                  ifunc_resolver_t ifunc_resolver = reinterpret_cast<ifunc_resolver_t>(resolver_addr);
                  ElfW(Addr) ifunc_addr = ifunc_resolver();
                  TRACE_TYPE(RELO, "Called ifunc_resolver@%p. The result is %p",
                      ifunc_resolver, reinterpret_cast<void*>(ifunc_addr));
                
                  return ifunc_addr;
                }
                """
                raise "Not Implemented"
            elif type == R_AARCH64_ABS64:
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
                self.ql.mem.writeU64(reloc, (sym_addr + addend))
            elif type == R_AARCH64_ABS32:
                # const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
                # const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
                # if ((min_value <= (sym_addr + addend)) &&
                #     ((sym_addr + addend) <= max_value)) {
                #     *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
                # } else {
                #     DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                #         sym_addr + addend, min_value, max_value);
                #     return false;
                # }
                self.ql.mem.writeU64(reloc, (sym_addr + addend))
            elif type == R_AARCH64_ABS16:
                # const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
                # const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
                # if ((min_value <= (sym_addr + addend)) &&
                #     ((sym_addr + addend) <= max_value)) {
                #     *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                # } else {
                #     DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                #         sym_addr + addend, min_value, max_value);
                #     return false;
                # }
                self.ql.mem.writeU64(reloc, (sym_addr + addend))
            elif type == R_AARCH64_PREL64:
                # *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
                self.ql.mem.writeU64(reloc, (sym_addr + addend - rel.r_offset))
            elif type == R_AARCH64_PREL32:
                # const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
                # const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
                # if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
                #     ((sym_addr + addend - rel->r_offset) <= max_value)) {
                #     *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
                # } else {
                #     DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                #         sym_addr + addend - rel->r_offset, min_value, max_value);
                #     return false;
                # }
                self.ql.mem.writeU64(reloc, (sym_addr + addend - rel.r_offset))
            elif type == R_AARCH64_PREL16:
                # const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
                # const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
                # if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
                #     ((sym_addr + addend - rel->r_offset) <= max_value)) {
                #     *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
                # } else {
                #     DL_ERR("0x%016llx out of range 0x%016llx to 0x%016llx",
                #         sym_addr + addend - rel->r_offset, min_value, max_value);
                #     return false;
                # }
                self.ql.mem.writeU64(reloc, (sym_addr + addend - rel.r_offset))
            elif type == R_AARCH64_TLS_TPREL64:
                pass
            elif type == R_AARCH64_TLS_DTPREL32:
                pass
            else:
                LOGE("unknown reloc idx:%d type:%d " % (idx, type));
                return False
        return True
    
    @staticmethod
    def soinfo_elf_lookup(si, hash, name):
        n = si.bucket[hash % si.nbucket]
        while n != 0: 
            s = si.symtab[n]
            if si.strtab[s.st_name] != name: continue

            if s.st_info in [STB_GLOBAL, STB_WEAK]:
                if (s.st_shndx == SHN_UNDEF):
                    n = si.chain[n]
                    continue
                return s;
            n = si.chain[n]
        return None

    @staticmethod
    def soinfo_do_lookup(si_from, symbol_name, lsi, needed):
        def done(si, result):
            if (result != None):
                LOGD("si %s sym %s s->st_value = 0x%08x, "
                        "found in %s, base = 0x%08x, load bias = 0x%08x" % 
                        si.name, name, result.st_value,
                        lsi.name, lsi.load_bias_, lsi.load_bias_)
            return result;
        
        # elf_hash = elfhash(name);
        s = None

        # 0. 先找自己
        if si_from.has_DT_SYMBOLIC:
            if not si_from.find_symbol_by_name(symbol_name, vi, s):
                return False

            if (s != None):
                lsi = si_from
                return done(s)

        # 1. Look for it in global_group
        # if (s == None):
        #     error = False;
        #     global_group.visit([&](soinfo* global_si) {
        #       DEBUG("%s: looking up %s in %s (from global group)",
        #           si_from->get_realpath(), name, global_si->get_realpath());
        #       if (!global_si->find_symbol_by_name(symbol_name, vi, &s)) {
        #         error = true;
        #         return false;
        #       }
        
        #       if (s != nullptr) {
        #         *si_found_in = global_si;
        #         return false;
        #       }
        
        #       return true;
        #     });
        
        #     if (error) {
        #       return false;

        # 2. 从need中找
        for so_name in needed:
            si = AndroidLinker.solist[so_name]
            if not si.find_symbol_by_name(symbol_name, vi, s):
                return False

            if (s != None):
                lsi = si
                return done(s)





def android_load(soPath):
    try:
        so = ctypes.CDLL(soPath, use_errno=True)
        return so
    except:
        pass

# initialize Qiling instance
# linker = Qiling(["/opt/bcc/tmp/stackplz"], r'/')
# linker.run()

linker = AndroidLinker()
linker.do_dlopen("/opt/bcc/tmp/libstackplz.so")

# linker = ctypes.CDLL("/opt/bcc/tmp/linker64")
# # linker.__dl_dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
# # linker.__dl_dlopen.restype = ctypes.c_void_p
# # linker.__dl_dlopen("/opt/libstackplz.so",  2)
# # 获取库的基地址
# base_address = ctypes.cast(linker._handle, ctypes.c_void_p).value
# # 计算符号的实际地址
# function_address = base_address + 0x0A55C
# my_function_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int)
# # 将地址转换为函数指针
# my_function = my_function_type(function_address)
# my_function("/opt/bcc/tmp/libstackplz.so".encode('utf-8'), 2)

# https://www.cnblogs.com/r0ysue/p/15433268.html

maps_file = f"/proc/{os.getpid()}/maps"
with open(maps_file, 'r') as f:
    maps = f.readlines()
    for line in maps:
        print(line.strip())
        
# ctypes.CDLL("/system/bin/linker64")  # Segmentation fault
# ctypes.CDLL("/opt/bcc/tmp/stackplz")   # OSError: /opt/bcc/tmp/stackplz: cannot dynamically load position-independent executable
# ctypes.CDLL("/apex/com.android.runtime/lib64/bionic/libdl.so")
# ctypes.CDLL("/apex/com.android.runtime/lib64/bionic/libdl_android.so")

ctypes.CDLL("/system/lib64/liblog.so")
ctypes.CDLL("/apex/com.android.runtime/lib64/bionic/libm.so")
ctypes.CDLL("/apex/com.android.runtime/lib64/bionic/libdl.so")
ctypes.CDLL("/apex/com.android.runtime/lib64/bionic/libc.so")
# ctypes.CDLL("/opt/bcc/tmp/libstackplz.so")  # /lib/aarch64-linux-gnu/libdl.so.2: version `LIBC' not found (required by /opt/bcc/tmp/libstackplz.so)

# libunwindstack = ctypes.CDLL("libbcc.so.0", use_errno=True)
# linker = ctypes.CDLL("/apex/com.android.runtime/bin/linker64", use_errno=True)
# linker = ctypes.CDLL("/system/bin/linker64", use_errno=True)
# linker.__loader_dlopen.argtypes = (ctypes.c_int, ctypes.c_int)  # 参数类型
# linker.__loader_dlopen.restype = ctypes.c_int                    # 返回类型
# result = linker.__loader_dlopen("/opt/libstackplz.so", 0)
# print(f"Result of __loader_dlopen: {result}")

# from cffi import FFI
# ffi = FFI()
# ffi.dlopen("/opt/libstackplz.so")
# 
#     # libunwindstack = ctypes.CDLL("/opt/libstackplz.so")


class unwind_reg_info(ctypes.Structure):
    _fields_ = [
        ("abi", ctypes.c_ulonglong),
        ("regs", ctypes.c_ulonglong * UNWIND_RGS_CNT)
    ]

class unwind_stack_info(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_ulonglong),
        ("data", ctypes.c_ubyte * UNWIND_SAMPLE_STACK_USER),
        ("dyn_size", ctypes.c_ulonglong),
    ]


def print_event(cpu, data, size):
    event_size = size
    if unwind:
        event_size = size - UNWIND_EVENT_SIZE
        regInfoAddr = data + event_size
        regInfo = unwind_reg_info.from_address(regInfoAddr)
        stackInfoAddr = regInfoAddr + ctypes.sizeof(unwind_reg_info)
        stackInfo = unwind_stack_info.from_address(stackInfoAddr)
        print("regInfo.abi:  ", regInfo.abi)
        print("stackInfo.size :", stackInfo.size)

    
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print(b"time_s:%-18.9f comm:%-16s pid:%-6d size:%d event_size:%d" % 
           (time_s, event.comm, event.pid, size, event_size))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, unwind_call_stack = unwind)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


#  // if (reader->is_unwind_call_stack) {
#   //   // 这里要和bpf代码里面传递的数据结构一致
#   //   int pid = *(int *)raw->data;
#   //   // 这里的 size 是 perf_submit 传递的那个大小
#   //   // 这里的 data 是整个传递的数据 也就是 PERF_SAMPLE_RAW 部分
#   //   // 到此处 ptr 也就是 PERF_SAMPLE_RAW 结尾
#   //   // 也就是说 write_size 是 PERF_SAMPLE_REGS_USER 和 PERF_SAMPLE_STACK_USER 的整个大小
#   //   int write_size = ((uint8_t *)data + size) - ptr;
#   //   print_frame_info(pid, ptr, write_size);
#   //   ptr += 16672;
#   // }