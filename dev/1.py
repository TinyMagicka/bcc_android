from bcc import BPF
from bcc.utils import printb
import ctypes
import socket
import os, struct



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
# b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.attach_uprobe(name="/apex/com.android.runtime/lib64/bionic/libc.so", sym="mincore", fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
global unwind
unwind = 1

UNWIND_SAMPLE_STACK_USER = 0x4000 
UNWIND_EVENT_SIZE = 16672
UNWIND_RGS_CNT = 33
PAGE_SIZE = 0x1000

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





def getProcessName(pid):
    name = None 
    try:
        with open(f"/proc/{pid}/cmdline", "r") as f:
            name = f.readline()
            name = name.replace("\x00", "").strip()
    except :
        pass
    return name 

def print_event(cpu, data, size):
    event = b["events"].event(data)
    name = getProcessName(event.pid)
    if name == None:return 
    # if name != "com.ss.android.ugc.aweme": return
    print(name)

    event_size = size
    if unwind:
        event_size = size - UNWIND_EVENT_SIZE
        regInfoAddr = data + event_size
        regInfo = unwind_reg_info.from_address(regInfoAddr)
        stackInfoAddr = regInfoAddr + ctypes.sizeof(unwind_reg_info)
        stackInfo = unwind_stack_info.from_address(stackInfoAddr)
        print("regInfo.abi:  ", regInfo.abi)
        print("stackInfo.size :", stackInfo.size)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect("/dev/socket/mysock")
            print(f"发送数据:")
            sock.sendall(struct.pack('<i', event.pid))
            sock.sendall(struct.pack('<i', UNWIND_EVENT_SIZE))
            sock.sendall(ctypes.string_at(ctypes.cast(regInfoAddr, ctypes.POINTER(ctypes.c_char)), ctypes.sizeof(unwind_reg_info)))
            sock.sendall(ctypes.string_at(ctypes.cast(stackInfoAddr, ctypes.POINTER(ctypes.c_char)), ctypes.sizeof(unwind_stack_info)))
            print(f"接受数据:")
            n = sock.recv(4)
            n = struct.unpack("i", n)[0]
            s = sock.recv(n)
            s = s.decode('utf-8')
            print(s)
            sock.close()
        except Exception as e:
            print(f"发生错误: {e}")
        finally:
            # 关闭 socket 连接
            # sock.close()
            print("连接已关闭")
    
    global start
    
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