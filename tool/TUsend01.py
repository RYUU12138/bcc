from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack


# arguments
examples = """examples:
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -pp 1000   # only trace PPID 1000
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-P", "--port",
    help="comma-separated list of destination ports to trace.")
group = parser.add_mutually_exclusive_group()
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
struct ipv4_data_t {
    char name[32];
    u32 pid;
    u32 ppid;
    u32 addr;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 time;
    char name[32];
    u32 pid;
    u32 ppid;
    u64 ip;
    u16 port;
    char task[TASK_COMM_LEN];
    unsigned __int128 addr;
};
BPF_PERF_OUTPUT(ipv6_events);

 
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) 
{
    u16 port;   
    u32 pid;
    struct sockaddr *sa = args->addr;
    
    pid = bpf_get_current_pid_tgid() >> 32;


    FILTER_PID    

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID
 
    if(sa->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sa;

        struct ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        port = s->sin_port;
        data4.port = ntohs(port);
        data4.addr = s->sin_addr.s_addr;
        strcpy(data4.name, "UDP");

        ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else if(sa->sa_family == AF_INET6)
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sa;
        struct ipv6_data_t data6 = {.pid = pid, .ppid = ppid};
    
        
        bpf_get_current_comm(&data6.task, sizeof(data6.task));  
        port = s6->sin6_port;
        data6.port = ntohs(port); 
        //data6.port = (s6->sin6_port >> 8) | ((s6->sin6_port <<8) & 0xff00 );
        bpf_probe_read_user(&data6.addr, sizeof(data6.addr),s6->sin6_addr.in6_u.u6_addr32);
        strcpy(data6.name, "UDPv6");
        
        
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
} 

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    u16 port;   
    u32 pid;
    
    
    pid = bpf_get_current_pid_tgid() >> 32;


    FILTER_PID    

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    FILTER_PPID

    port = sk->__sk_common.skc_dport;
    

    
    u32 sa_family = sk->__sk_common.skc_family;
    if (sa_family == 2) {
        struct ipv4_data_t data4 = {.pid = pid, .ppid = ppid};

        
        data4.addr = sk->__sk_common.skc_daddr;
        data4.port = ntohs(port);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        bpf_probe_read_kernel(&data4.name, sizeof(data4.name), sk->__sk_common.skc_prot->name);
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if(sa_family == 10){
        struct ipv6_data_t data6 = {.pid = pid, .ppid = ppid};

        
        bpf_probe_read_kernel(&data6.name, sizeof(data6.name), sk->__sk_common.skc_prot->name);
        bpf_probe_read_kernel(&data6.addr, sizeof(data6.addr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.port = ntohs(port);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
} 



"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID','if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')
if args.ppid:
    bpf_text = bpf_text.replace('FILTER_PPID','if (ppid != %s) { return 0; }' % args.ppid)
else:
    bpf_text = bpf_text.replace('FILTER_PPID', '')


# initialize BPF
b = BPF(text=bpf_text)


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    
    dest_ip = inet_ntop(AF_INET, pack("I", event.addr)).encode()

    printb(b"%-7d %-7d %-15.12s %-6.6s %-32.32s %-6d " % (event.pid, event.ppid,event.task, event.name, dest_ip, event.port))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    dest_ip = inet_ntop(AF_INET6, event.addr).encode()

    printb(b"%-7d %-7d %-15.12s %-6.6s %-32.32s %-6d" % (event.pid, event.ppid,event.task, event.name, dest_ip, event.port))
    
    

print("Tracing accept ... Hit Ctrl-C to end")

print("%-7s %-7s %-15s %-6.6s %-32.32s %-6s" % ("PID", "PPID", "COMM", "prot", "DADDR", "DPORT"))


# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()