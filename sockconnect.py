from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

# lock = Lock()
# arguments

parser = argparse.ArgumentParser(
    description = "sock connect",
    formatter_class = argparse.RawDescriptionHelpFormatter,
)

examples = """examples:
    ./tcp          # trace send/recv flow by host 
    ./tcp -p 100   # only trace PID 100
    
"""

parser.add_argument("-p", "--pid", 
    help = "Trace this pid only")


args = parser.parse_args()

bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>


BPF_HASH(sa, u32, struct sockaddr *);

struct ipv4_data_t {
    u32 pid;
    u32 addr;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    unsigned __int128 addr;
    u16 port;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) 
{  
    struct sockaddr *sap = args->uservaddr;
    
    u32 tid = bpf_get_current_pid_tgid();


    FILTER_PID    

    
    if(sap->sa_family == AF_INET || sap->sa_family == AF_INET6)
    {   
        sa.update(&tid, &sap);
    }
    

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) 
{  
    u32 pid,tid;
    struct sockaddr **sapp;
    
    tid = bpf_get_current_pid_tgid();
    pid = bpf_get_current_pid_tgid() >> 32 ;
    
    sapp = sa.lookup(&tid);
    if (sapp == 0) {
        return 0;   
    }
 
    struct sockaddr *sap = *sapp;
    

    if(sap->sa_family == AF_INET)
    {
        struct sockaddr_in * s = (struct sockaddr_in *)sap;

        struct ipv4_data_t data4 = {.pid = pid};

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        data4.port = (s->sin_port >> 8) | ((s->sin_port <<8) & 0xff00 );
        data4.addr = s->sin_addr.s_addr;

        ipv4_events.perf_submit(args, &data4, sizeof(data4));

    }else
    {   
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)sap;
        struct ipv6_data_t data6 = {.pid = pid};
    
        
        bpf_get_current_comm(&data6.task, sizeof(data6.task));   
        data6.port = (s6->sin6_port >> 8) | ((s6->sin6_port <<8) & 0xff00 );
        bpf_probe_read_kernel(&data6.addr, sizeof(data6.addr),s6->sin6_addr.in6_u.u6_addr32);
        
        
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    return 0;
}



"""

# code substitutions
if args.pid:
    bpf_program = bpf_program.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_program = bpf_program.replace('FILTER_PID','')



# init bpf
b = BPF(text=bpf_program)

#head
print("Tracing sock connect, ... Ctrl+C to quit." )



# output

# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)

    addr = inet_ntop(AF_INET, pack("I", event.addr)).encode()
    printb(b"%-10d %-12.12s %-16.16s %-10d " % (event.pid, event.task, addr, event.port))

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    addr = inet_ntop(AF_INET6, event.addr).encode()
    printb(b"%-10d %-12.12s %-16.16s %-10d " % (event.pid, event.task, addr, event.port))
    
    

print("%-10s %-12s %-16s %-10s " % ("PID", "COMM", "ADDRESS", "PORT"))


# read events

b["ipv6_events"].open_perf_buffer(print_ipv6_event)
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()