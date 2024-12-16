"""
created by jermain. 
this module is used to do stack-trace in arm64 arch android 
"""

import ctypes as ct

# lib = ct.CDLL("libbcc.so.0", use_errno=True)

# defined in libbpf.h
UNWIND_SAMPLE_STACK_USER  = 0x4000
UNWIND_EVENT_SIZE = 16672  #UNWIND_SAMPLE_STACK_USER + 

# #define UNWIND_SAMPLE_STACK_USER 0x4000  // MAX=65528   
# #define UNWIND_RGS_CNT	33  			 // arm64通用寄存器 + sp + pc

# struct unwind_reg_info{
# 	__u64 abi;
# 	__u64 regs[UNWIND_RGS_CNT];
# };

# struct unwind_stack_info{
# 	__u64 size;
# 	char data[UNWIND_SAMPLE_STACK_USER];
# 	__u64 dyn_size;
# };

# #define UNWIND_EVENT_SIZE    (sizeof(struct unwind_reg_info) + sizeof(struct unwind_stack_info)) //16672