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
    ./tcpconnect -u 1000   # only trace UID 1000
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
parser.add_argument("-u", "--uid",
    help="trace this UID only")
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
    u32 uid;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 time;
    char name[32];
    u32 pid;
    u32 uid;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
    unsigned __int128 daddr;
};
BPF_PERF_OUTPUT(ipv6_events);



/*
int trace_udprecv(struct pt_regs *ctx,struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
  
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    
    FILTER_PID

    
    u32 uid = bpf_get_current_uid_gid();

    FILTER_UID

    u16 dport = sk->__sk_common.skc_dport;
    

    
    u32 sa_family = sk->__sk_common.skc_family;
    if (sa_family == 2) {
        struct ipv4_data_t data4 = {.pid = pid};

        data4.uid = bpf_get_current_uid_gid();
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        bpf_probe_read_kernel(&data4.name, sizeof(data4.name), sk->__sk_common.skc_prot->name);
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if(sa_family == 10){
        struct ipv6_data_t data6 = {.pid = pid};

        
        data6.uid = bpf_get_current_uid_gid();
        bpf_probe_read_kernel(&data6.name, sizeof(data6.name), sk->__sk_common.skc_prot->name);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}
*/
    
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) 
{
    u16 port;   
    u32 pid;
    struct sockaddr *sa = args->addr;
    
    pid = bpf_get_current_pid_tgid() >> 32;


    FILTER_PID    

    u32 uid = bpf_get_current_uid_gid();
 
    if(sa->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sa;

        struct ipv4_data_t data4 = {.pid = pid, .uid = uid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        data4.dport = (s->sin_port >> 8) | ((s->sin_port <<8) & 0xff00 );
        data4.daddr = s->sin_addr.s_addr;

        ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else if(sa->sa_family == AF_INET6)
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sa;
        struct ipv6_data_t data6 = {.pid = pid, .uid = uid};
    
        
        bpf_get_current_comm(&data6.task, sizeof(data6.task));   
        data6.dport = (s6->sin6_port >> 8) | ((s6->sin6_port <<8) & 0xff00 );
        bpf_probe_read_user(&data6.daddr, sizeof(data6.daddr),s6->sin6_addr.in6_u.u6_addr32);
        
        
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
} 



"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID','if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')
if args.uid:
    bpf_text = bpf_text.replace('FILTER_UID','if (uid != %s) { return 0; }' % args.uid)
else:
    bpf_text = bpf_text.replace('FILTER_UID', '')


# initialize BPF
b = BPF(text=bpf_text)
# b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udprecv")
# b.attach_kprobe(event="__skb_recv_datagram", fn_name="trace_udprecv")
# b.attach_kprobe(event="__skb_recv_udp", fn_name="trace_udprecv")
# b.attach_kprobe(event="udp_v4_get_port", fn_name="trace_udprecv")
# b.attach_kprobe(event="syscalls:sys_enter_recvfrom", fn_name="trace_udprecv")

# b.attach_kprobe(event="__skb_try_recv_from_queue", fn_name="trace_udprecv")

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()

    printb(b"%-6d %-7d %-15.12s %-6.6s %-32.32s %-6d " % (event.uid, event.pid,event.task, event.name, dest_ip, event.dport))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    dest_ip = inet_ntop(AF_INET6, event.daddr).encode()

    printb(b"%-6d %-7d %-15.12s %-6.6s %-32.32s %-6d" % (event.uid, event.pid,event.task, event.name, dest_ip, event.dport))
    
    

print("Tracing accept ... Hit Ctrl-C to end")

print("%-6s %-7s %-15s %-6.6s %-32.32s %-6s" % ("UID", "PID", "COMM", "prot", "DADDR", "DPORT"))


# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()