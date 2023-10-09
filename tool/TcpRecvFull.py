from __future__ import print_function
from bcc import BPF
from bcc.utils import printb,ArgString
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime
import re

# arguments
examples = """examples:
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -n main   # only print command lines containing "main"
    ./tcpconnect -pp 1000  # only trace PPID 1000
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-n", "--name",type=ArgString,
    help="only print commands matching this name (regex), any arg")
parser.add_argument("-pp", "--ppid",
    help="trace this PPID only")
args = parser.parse_args()


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
//#include <net/socket.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct bind_ipv4_data_t {
    u64 fd;
    u32 pid;
    u32 ppid;
    u32 addr;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(bind_ipv4_events);

struct bind_ipv6_data_t {
    u64 time;
    u64 fd;
    u32 pid;
    u32 ppid;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
    unsigned __int128 addr;
};
BPF_PERF_OUTPUT(bind_ipv6_events);



struct connect_ipv4_data_t {
    u64 fd;
    u32 pid;
    u32 ppid;
    u32 addr;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(connect_ipv4_events);

struct connect_ipv6_data_t {
    u64 time;
    u64 fd;
    u32 pid;
    u32 ppid;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
    unsigned __int128 addr;
};
BPF_PERF_OUTPUT(connect_ipv6_events);



struct accept_ipv4_data_t {
    char name[32];
    u32 pid;
    u32 ppid;
    u32 addr;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(accept_ipv4_events);

struct accept_ipv6_data_t {
    u64 time;
    char name[32];
    u32 pid;
    u32 ppid;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
    unsigned __int128 addr;
};
BPF_PERF_OUTPUT(accept_ipv6_events);



struct recv_ipv4_data_t {
    char name[32];
    u32 pid;
    u32 ppid;
    u32 addr;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(recv_ipv4_events);

struct recv_ipv6_data_t {
    u64 time;
    char name[32];
    u32 pid;
    u32 ppid;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
    unsigned __int128 addr;
};
BPF_PERF_OUTPUT(recv_ipv6_events);


 
TRACEPOINT_PROBE(syscalls, sys_enter_bind) 
{
    u16 port;   
    struct sockaddr *sa = args->umyaddr;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER_PID    

    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID

 
    if(sa->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sa;

        struct bind_ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        port = s->sin_port;
        data4.port = ntohs(port);
        data4.addr = s->sin_addr.s_addr;
        

        bind_ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else if(sa->sa_family == AF_INET6)
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sa;
        struct bind_ipv6_data_t data6 = {.pid = pid, .ppid = ppid};
    
        
        bpf_get_current_comm(&data6.task, sizeof(data6.task));  
        port = s6->sin6_port;
        data6.port = ntohs(port); 
        bpf_probe_read_user(&data6.addr, sizeof(data6.addr),s6->sin6_addr.in6_u.u6_addr32);
        
        
        
        bind_ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
} 

TRACEPOINT_PROBE(syscalls, sys_enter_connect) 
{
    u16 port;   
    struct sockaddr *sa = args->uservaddr;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER_PID    

    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID
 
    if(sa->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sa;
        struct connect_ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        port = s->sin_port;
        data4.port = ntohs(port);
        data4.addr = s->sin_addr.s_addr;
        
        connect_ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else if(sa->sa_family == AF_INET6)
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sa;
        struct connect_ipv6_data_t data6 = {.pid = pid, .ppid = ppid};
       
        bpf_get_current_comm(&data6.task, sizeof(data6.task));  
        port = s6->sin6_port;
        data6.port = ntohs(port); 
        bpf_probe_read_user(&data6.addr, sizeof(data6.addr),s6->sin6_addr.in6_u.u6_addr32);       
        
        connect_ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
} 

TRACEPOINT_PROBE(syscalls, sys_enter_accept) 
{
    u16 port;   
    struct sockaddr *sa = args->upeer_sockaddr;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER_PID    

    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID
 
    if(sa->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sa;
        struct accept_ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        port = s->sin_port;
        data4.port = ntohs(port);
        data4.addr = s->sin_addr.s_addr;
        
        accept_ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else if(sa->sa_family == AF_INET6)
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sa;
        struct accept_ipv6_data_t data6 = {.pid = pid, .ppid = ppid};
       
        bpf_get_current_comm(&data6.task, sizeof(data6.task));  
        port = s6->sin6_port;
        data6.port = ntohs(port); 
        bpf_probe_read_user(&data6.addr, sizeof(data6.addr),s6->sin6_addr.in6_u.u6_addr32);       
        
        accept_ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
} 

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)
{ 
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER_PID    


    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID

    u16 port = sk->__sk_common.skc_dport;
    
    u32 sa_family = sk->__sk_common.skc_family;
    if (sa_family == 2) {
        struct recv_ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        data4.addr = sk->__sk_common.skc_daddr;
        data4.port = ntohs(port);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        bpf_probe_read_kernel(&data4.name, sizeof(data4.name), sk->__sk_common.skc_prot->name);
        
        recv_ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if(sa_family == 10){
        struct recv_ipv6_data_t data6 = {.pid = pid, .ppid = ppid};

        
        bpf_probe_read_kernel(&data6.name, sizeof(data6.name), sk->__sk_common.skc_prot->name);
        bpf_probe_read_kernel(&data6.addr, sizeof(data6.addr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.port = ntohs(port);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        recv_ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
} 

"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID','if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')
if args.ppid:
    bpf_text = bpf_text.replace('FILTER_PPID','if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PPID', '')


# initialize BPF
b = BPF(text=bpf_text)


# process event
#bind
def print_bind_ipv4_event(cpu, data, size):
    event = b["bind_ipv4_events"].event(data)
    
    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("bind data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ( "PID", "PPID", "COMM", "DADDR", "DPORT"))
     
        dest_ip = inet_ntop(AF_INET, pack("I", event.addr)).encode()
        
        printb(b"%-7d %-7d %-15.12s  %-32.32s %-6d " % (event.pid, event.ppid,event.task, dest_ip, event.port))


def print_bind_ipv6_event(cpu, data, size):
    event = b["bind_ipv6_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("bind data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s  %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET6, event.addr).encode()
       
        printb(b"%-7d %-7d %-15.12s %-32.32s %-6d" % (event.pid, event.ppid,event.task, dest_ip, event.port))
    
#connect
def print_connect_ipv4_event(cpu, data, size):
    event = b["connect_ipv4_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("connect data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET, pack("I", event.addr)).encode()
       
        printb(b"%-7d %-7d %-15.12s %-32.32s %-6d " % (event.pid, event.ppid,event.task, dest_ip, event.port))


def print_connect_ipv6_event(cpu, data, size):
    event = b["connect_ipv6_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("connect data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET6, event.addr).encode()
     
        printb(b"%-7d %-7d %-15.12s %-6.6d %-32.32s %-6d" % (event.pid, event.ppid,event.task, event.fd, dest_ip, event.port))


#accept
def print_accept_ipv4_event(cpu, data, size):
    event = b["accept_ipv4_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("accept data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET, pack("I", event.addr)).encode()

        printb(b"%-7d %-7d %-15.12s %-32.32s %-6d " % (event.pid, event.ppid,event.task, dest_ip, event.port))


def print_accept_ipv6_event(cpu, data, size):
    event = b["accept_ipv6_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("accept data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET6, event.addr).encode()

        printb(b"%-7d %-7d %-15.12s %-6.6d %-32.32s %-6d" % (event.pid, event.ppid,event.task, event.fd, dest_ip, event.port))


#recv

def print_recv_ipv4_event(cpu, data, size):
    event = b["recv_ipv4_events"].event(data)

    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("recv data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))
 
        dest_ip = inet_ntop(AF_INET, pack("I", event.addr)).encode()

        printb(b"%-7d %-7d %-15.12s %-32.32s %-6d " % (event.pid, event.ppid,event.task, dest_ip, event.port))



def print_recv_ipv6_event(cpu, data, size):
    event = b["recv_ipv6_events"].event(data)
    
    skip = False
    if args.name and not re.search(bytes(args.name), event.task):
        skip = True
    if not skip:
        print("recv data[%s]"% strftime("%H:%M:%S"))
        print("%-7s %-7s %-15s %-32.32s %-6s" % ("PID", "PPID", "COMM", "DADDR", "DPORT"))

        dest_ip = inet_ntop(AF_INET6, event.addr).encode()

        printb(b"%-7d %-7d %-15.12s %-32.32s %-6d" % (event.pid, event.ppid,event.task, dest_ip, event.port))



print("Tracing accept ... Hit Ctrl-C to end")




# read events
b["bind_ipv4_events"].open_perf_buffer(print_bind_ipv4_event)
b["bind_ipv6_events"].open_perf_buffer(print_bind_ipv6_event)
b["connect_ipv4_events"].open_perf_buffer(print_connect_ipv4_event)
b["connect_ipv6_events"].open_perf_buffer(print_connect_ipv6_event)
b["recv_ipv4_events"].open_perf_buffer(print_recv_ipv4_event)
b["recv_ipv6_events"].open_perf_buffer(print_recv_ipv6_event)
b["accept_ipv4_events"].open_perf_buffer(print_accept_ipv4_event)
b["accept_ipv6_events"].open_perf_buffer(print_accept_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
        
      