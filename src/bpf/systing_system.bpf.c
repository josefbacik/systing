#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#ifdef SYSTING_PYSTACKS
#include "strobelight/bpf_lib/common/common.h"
#include "strobelight/bpf_lib/python/pystacks/pystacks.bpf.h"
#endif

/* Task state definitions */
#define TASK_RUNNING		0x00000000
#define TASK_INTERRUPTIBLE	0x00000001
#define TASK_UNINTERRUPTIBLE	0x00000002

/* TASK_REPORT mask - valid task states for ftrace format (bits 0-6) */
#define TASK_REPORT		0x0000007f

/* Preemption flag in ftrace format */
#define TASK_REPORT_MAX		0x00000100

/* Address family constants (from linux/socket.h) */
#define AF_INET 2
#define AF_INET6 10

/*
 * Used specifically to make sure we don't accidentally record stats for a value
 * we didn't catch at sched_waking time.
 */
#define TASK_WAKING 4567

#define TASK_STATE_MASK 3

#define TASK_COMM_LEN 16

#define PF_WQ_WORKER 0x00000020
#define PF_KTHREAD 0x00200000

#define MAX_STACK_DEPTH 36
#define SKIP_STACK_DEPTH 3
#define NR_RINGBUFS 8

#define SYS_ENTER_COOKIE 0xFFFFFFFFFFFFFFFEULL
#define SYS_EXIT_COOKIE 0xFFFFFFFFFFFFFFFFULL

const volatile struct {
	u32 filter_pid;
	u32 filter_cgroup;
	u32 no_stack_traces;
	u32 no_cpu_stack_traces;
	u32 no_sleep_stack_traces;
	u32 no_interruptible_stack_traces;
	u32 num_perf_counters;
	u32 num_cpus;
	u32 my_tgid;
	u64 my_dev;
	u64 my_ino;
	u32 collect_pystacks;
	u32 collect_syscalls;
	u32 confidentiality_mode;
	u64 wakeup_data_size;  /* Ringbuf fill threshold for wakeup (0 = default) */
} tool_config = {};

enum event_type {
	SCHED_SWITCH,
	SCHED_WAKING,
	SCHED_WAKEUP_NEW,
	SCHED_WAKEUP,
	SCHED_SOFTIRQ_ENTER,
	SCHED_SOFTIRQ_EXIT,
	SCHED_IRQ_ENTER,
	SCHED_IRQ_EXIT,
	SCHED_PROCESS_EXIT,
};

enum stack_event_type {
	STACK_SLEEP,
	STACK_RUNNING,
};

struct task_info {
	u64 tgidpid;
	u8 comm[TASK_COMM_LEN];
};

/*
 * sched_switch is the largest event, for the smaller events we just use prev_*
 * for the values, and things are left uninitialized.
 */
struct task_event {
	enum event_type type;
	u32 cpu;
	u64 ts;
	u64 latency;
	u64 prev_state;
	u32 target_cpu;
	u32 next_prio;
	u32 prev_prio;
	struct task_info prev;
	struct task_info next;
};

enum arg_type {
	ARG_NONE,
	ARG_LONG,
	ARG_STRING,
	ARG_RETVAL,
};

struct arg_desc {
	enum arg_type arg_type;
	int arg_index;
};

#define MAX_ARGS 4
#define ARG_VALUE_SIZE 24

struct arg_value {
	enum arg_type type;
	u16 size;
	u8 value[ARG_VALUE_SIZE];
};

struct probe_event {
	u32 cpu;
	u64 ts;
	u64 cookie;
	struct task_info task;
	u8 num_args;
	struct arg_value args[MAX_ARGS];
};

struct stack_event {
	enum stack_event_type stack_event_type;
	u64 ts;
	u32 cpu;
	struct task_info task;
	u64 kernel_stack_length;
	u64 user_stack_length;
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
#ifdef SYSTING_PYSTACKS
	struct pystacks_message py_msg_buffer;
#endif
};

struct perf_counter_event {
	u64 ts;
	struct task_info task;
	struct bpf_perf_event_value value;
	u32 cpu;
	u32 counter_num;
};

enum network_protocol {
	NETWORK_TCP,
	NETWORK_UDP,
};

enum network_operation {
	NETWORK_SEND,
	NETWORK_RECV,
};

enum network_address_family {
	NETWORK_AF_INET,   // IPv4
	NETWORK_AF_INET6,  // IPv6
};

struct network_event {
	u64 start_ts;
	u64 end_ts;
	struct task_info task;
	enum network_protocol protocol;
	enum network_operation operation;
	enum network_address_family af;  // Address family (IPv4 or IPv6)
	u8 dest_addr[16];  // IPv4 (first 4 bytes) or IPv6 (all 16 bytes) in network byte order
	u16 dest_port;     // Port in host byte order
	u32 bytes;
	u32 sendmsg_seq;   // TCP sequence number at sendmsg time (TCP only)
	u32 cpu;
	u32 sndbuf_used;   // Bytes in send buffer after sendmsg (sk_wmem_queued)
	u32 sndbuf_limit;  // Max send buffer size (sk_sndbuf)
	u64 socket_id;     // Unique socket ID for correlation with packet events
};

enum packet_event_type {
	PACKET_ENQUEUE,         // TCP -> device queue
	PACKET_SEND,            // device queue -> NIC
	PACKET_RCV_ESTABLISHED, // NIC -> TCP layer (tcp_rcv_established)
	PACKET_QUEUE_RCV,       // TCP layer -> socket buffer (tcp_queue_rcv)
	PACKET_BUFFER_QUEUE,    // socket buffer -> application read (buffer queue latency)
	PACKET_UDP_SEND,        // UDP: udp_send_skb (UDP layer processing)
	PACKET_UDP_RCV,         // UDP: udp_queue_rcv_one_skb (UDP receive processing)
	PACKET_UDP_ENQUEUE,     // UDP: __udp_enqueue_schedule_skb (socket buffer enqueue)
};

struct packet_event {
	u64 ts;            // Instant event timestamp
	struct task_info task;
	enum network_protocol protocol;  // TCP or UDP
	enum network_address_family af;  // Address family (IPv4 or IPv6)
	u8 dest_addr[16];  // IPv4 (first 4 bytes) or IPv6 (all 16 bytes) in network byte order
	u16 dest_port;     // Port in host byte order
	u32 seq;           // TCP sequence number at transmit time
	u32 length;        // Packet length (calculated from end_seq - seq)
	u8 tcp_flags;      // TCP flags (SYN, ACK, FIN, etc.)
	enum packet_event_type event_type;  // Type of packet event (enqueue or send)
	u32 cpu;
	u32 sndbuf_used;   // Bytes in send buffer (sk_wmem_queued) - shows buffer drain on ACK
	u32 sndbuf_limit;  // Max send buffer size (sk_sndbuf)
	u64 socket_id;     // Unique socket ID for correlation with network events
	u8 is_retransmit;  // 1 if this packet is a TCP retransmit, 0 otherwise
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
struct stack_event _stack_event = {0};
struct perf_counter_event _perf_counter_event = {0};
struct network_event _network_event = {0};
struct packet_event _packet_event = {0};
struct task_info _task_info = {0};
struct probe_event _uprobe_event = {0};
struct arg_desc _arg_desc = {0};
enum event_type _type = SCHED_SWITCH;
enum arg_type _arg_type = ARG_NONE;
enum stack_event_type _stack_type = STACK_SLEEP;
enum network_protocol _network_proto = NETWORK_TCP;
enum network_operation _network_op = NETWORK_SEND;
enum network_address_family _network_af = NETWORK_AF_INET;
enum packet_event_type _packet_event_type = PACKET_ENQUEUE;
bool tracing_enabled = true;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 10240);
} perf_counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} wake_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 10240);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 10240);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} irq_events SEC(".maps");

struct arg_desc_array {
	u8 num_args;
	u8 pad[3];
	struct arg_desc args[MAX_ARGS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct arg_desc_array);
	__uint(max_entries, 10240);
} event_key_types SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 10240);
} event_stack_capture SEC(".maps");

struct arg_desc_array _arg_desc_array = {0};

struct network_send_info {
	enum network_protocol protocol;
	enum network_address_family af;
	u8 dest_addr[16];
	u16 dest_port;
	u64 start_ts;
	u32 sendmsg_seq;  // Sequence number at sendmsg time
	u64 sk_ptr;       // Socket pointer for reading buffer state on exit
	u64 socket_id;    // Unique socket ID for correlation
};

// Tracks pending receive operations with peer address
struct network_recv_info {
	enum network_protocol protocol;
	enum network_address_family af;
	u8 peer_addr[16];
	u16 peer_port;
	u64 start_ts;
	u64 sk_ptr;       // Socket pointer for buffer queue latency tracking
	u64 socket_id;    // Unique socket ID for correlation
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);  // tgidpid
	__type(value, struct network_send_info);
	__uint(max_entries, 10240);
} pending_network_sends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);  // tgidpid
	__type(value, struct network_recv_info);
	__uint(max_entries, 10240);
} pending_network_recvs SEC(".maps");

// Map sk pointer to tgidpid for associating packets with threads
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);  // struct sock * (cast to u64)
	__type(value, u64);  // tgidpid
	__uint(max_entries, 10240);
} sk_to_tgidpid SEC(".maps");


// Socket identity key - identifies a unique socket+destination pair
struct socket_identity_key {
	u64 sk_ptr;           // struct sock * cast to u64
	u8 dest_addr[16];     // Destination address (IPv4 in first 4 bytes)
	u16 dest_port;        // Destination port
	u16 _pad;             // Alignment padding
};

// Socket metadata stored in map, readable by userspace after tracing
struct socket_metadata {
	u64 socket_id;                    // Unique socket ID
	enum network_protocol protocol;   // TCP or UDP
	enum network_address_family af;   // IPv4 or IPv6
	u8 dest_addr[16];                 // Destination address
	u16 dest_port;                    // Destination port
	u16 _pad;                         // Alignment padding
	u64 tgidpid;                      // Process that created this connection
};

// Atomic counter for generating unique socket IDs (single-entry array)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} socket_id_counter SEC(".maps");

// Maps socket identity to metadata
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct socket_identity_key);
	__type(value, struct socket_metadata);
	__uint(max_entries, 10240);
} socket_metadata_map SEC(".maps");

#define MISSED_SCHED_EVENT 0
#define MISSED_STACK_EVENT 1
#define MISSED_PROBE_EVENT 2
#define MISSED_CACHE_EVENT 3
#define MISSED_NETWORK_EVENT 4
#define MISSED_PACKET_EVENT 5
#define MISSED_EVENT_MAX 6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MISSED_EVENT_MAX);
} missed_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} last_perf_counter_value SEC(".maps");

struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_events_node0 SEC(".maps"), ringbuf_events_node1 SEC(".maps"),
  ringbuf_events_node2 SEC(".maps"), ringbuf_events_node3 SEC(".maps"),
  ringbuf_events_node4 SEC(".maps"), ringbuf_events_node5 SEC(".maps"),
  ringbuf_events_node6 SEC(".maps"), ringbuf_events_node7 SEC(".maps");

struct stack_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_stack_events_node0 SEC(".maps"), ringbuf_stack_events_node1 SEC(".maps"),
  ringbuf_stack_events_node2 SEC(".maps"), ringbuf_stack_events_node3 SEC(".maps"),
  ringbuf_stack_events_node4 SEC(".maps"), ringbuf_stack_events_node5 SEC(".maps"),
  ringbuf_stack_events_node6 SEC(".maps"), ringbuf_stack_events_node7 SEC(".maps");

struct probe_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_probe_events_node0 SEC(".maps"), ringbuf_probe_events_node1 SEC(".maps"),
  ringbuf_probe_events_node2 SEC(".maps"), ringbuf_probe_events_node3 SEC(".maps"),
  ringbuf_probe_events_node4 SEC(".maps"), ringbuf_probe_events_node5 SEC(".maps"),
  ringbuf_probe_events_node6 SEC(".maps"), ringbuf_probe_events_node7 SEC(".maps");

struct perf_counter_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_perf_counter_events_node0 SEC(".maps"),
	ringbuf_perf_counter_events_node1 SEC(".maps"),
	ringbuf_perf_counter_events_node2 SEC(".maps"),
	ringbuf_perf_counter_events_node3 SEC(".maps"),
	ringbuf_perf_counter_events_node4 SEC(".maps"),
	ringbuf_perf_counter_events_node5 SEC(".maps"),
	ringbuf_perf_counter_events_node6 SEC(".maps"),
	ringbuf_perf_counter_events_node7 SEC(".maps");

struct network_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_network_events_node0 SEC(".maps"),
	ringbuf_network_events_node1 SEC(".maps"),
	ringbuf_network_events_node2 SEC(".maps"),
	ringbuf_network_events_node3 SEC(".maps"),
	ringbuf_network_events_node4 SEC(".maps"),
	ringbuf_network_events_node5 SEC(".maps"),
	ringbuf_network_events_node6 SEC(".maps"),
	ringbuf_network_events_node7 SEC(".maps");

struct packet_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_packet_events_node0 SEC(".maps"),
	ringbuf_packet_events_node1 SEC(".maps"),
	ringbuf_packet_events_node2 SEC(".maps"),
	ringbuf_packet_events_node3 SEC(".maps"),
	ringbuf_packet_events_node4 SEC(".maps"),
	ringbuf_packet_events_node5 SEC(".maps"),
	ringbuf_packet_events_node6 SEC(".maps"),
	ringbuf_packet_events_node7 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct ringbuf_map);
} ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_events_node0,
		&ringbuf_events_node1,
		&ringbuf_events_node2,
		&ringbuf_events_node3,
		&ringbuf_events_node4,
		&ringbuf_events_node5,
		&ringbuf_events_node6,
		&ringbuf_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct stack_ringbuf_map);
} stack_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_stack_events_node0,
		&ringbuf_stack_events_node1,
		&ringbuf_stack_events_node2,
		&ringbuf_stack_events_node3,
		&ringbuf_stack_events_node4,
		&ringbuf_stack_events_node5,
		&ringbuf_stack_events_node6,
		&ringbuf_stack_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct perf_counter_ringbuf_map);
} perf_counter_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_perf_counter_events_node0,
		&ringbuf_perf_counter_events_node1,
		&ringbuf_perf_counter_events_node2,
		&ringbuf_perf_counter_events_node3,
		&ringbuf_perf_counter_events_node4,
		&ringbuf_perf_counter_events_node5,
		&ringbuf_perf_counter_events_node6,
		&ringbuf_perf_counter_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct probe_ringbuf_map);
} probe_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_probe_events_node0,
		&ringbuf_probe_events_node1,
		&ringbuf_probe_events_node2,
		&ringbuf_probe_events_node3,
		&ringbuf_probe_events_node4,
		&ringbuf_probe_events_node5,
		&ringbuf_probe_events_node6,
		&ringbuf_probe_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct network_ringbuf_map);
} network_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_network_events_node0,
		&ringbuf_network_events_node1,
		&ringbuf_network_events_node2,
		&ringbuf_network_events_node3,
		&ringbuf_network_events_node4,
		&ringbuf_network_events_node5,
		&ringbuf_network_events_node6,
		&ringbuf_network_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct packet_ringbuf_map);
} packet_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_packet_events_node0,
		&ringbuf_packet_events_node1,
		&ringbuf_packet_events_node2,
		&ringbuf_packet_events_node3,
		&ringbuf_packet_events_node4,
		&ringbuf_packet_events_node5,
		&ringbuf_packet_events_node6,
		&ringbuf_packet_events_node7,
	},
};

// Generate new socket ID atomically
// Returns socket IDs starting from 1 (0 indicates failure)
static __always_inline u64 generate_socket_id(void)
{
	u32 key = 0;
	u64 *counter = bpf_map_lookup_elem(&socket_id_counter, &key);
	if (!counter)
		return 0;
	return __sync_fetch_and_add(counter, 1) + 1;  // Start from 1, not 0
}

// Get or create socket ID for socket+destination pair
// Returns 0 if socket metadata cannot be created
static __always_inline u64 get_or_create_socket_id(
	struct sock *sk,
	enum network_protocol protocol,
	enum network_address_family af,
	u8 *dest_addr,
	u16 dest_port,
	u64 tgidpid)
{
	struct socket_identity_key identity_key = {0};
	struct socket_metadata *existing;
	struct socket_metadata metadata = {0};

	identity_key.sk_ptr = (u64)sk;
	__builtin_memcpy(identity_key.dest_addr, dest_addr, 16);
	identity_key.dest_port = dest_port;

	// Check if we already have metadata for this socket+destination
	existing = bpf_map_lookup_elem(&socket_metadata_map, &identity_key);
	if (existing)
		return existing->socket_id;

	// Create new socket metadata
	metadata.socket_id = generate_socket_id();
	if (metadata.socket_id == 0)
		return 0;  // Counter lookup failed

	metadata.protocol = protocol;
	metadata.af = af;
	__builtin_memcpy(metadata.dest_addr, dest_addr, 16);
	metadata.dest_port = dest_port;
	metadata.tgidpid = tgidpid;

	bpf_map_update_elem(&socket_metadata_map, &identity_key, &metadata, BPF_NOEXIST);

	// Re-lookup in case of race condition (another CPU inserted first)
	existing = bpf_map_lookup_elem(&socket_metadata_map, &identity_key);
	return existing ? existing->socket_id : 0;
}

// Lookup socket ID for an existing socket+destination pair
// Returns 0 if not found
static __always_inline u64 lookup_socket_id(
	struct sock *sk,
	u8 *dest_addr,
	u16 dest_port)
{
	struct socket_identity_key identity_key = {0};
	struct socket_metadata *existing;

	identity_key.sk_ptr = (u64)sk;
	__builtin_memcpy(identity_key.dest_addr, dest_addr, 16);
	identity_key.dest_port = dest_port;

	existing = bpf_map_lookup_elem(&socket_metadata_map, &identity_key);
	return existing ? existing->socket_id : 0;
}

/*
 * Helper to determine wakeup flags based on ringbuf fill level.
 * Uses the kernel's recommended pattern from ringbuf_bench.c
 */
static __always_inline long get_ringbuf_flags(void *rb)
{
	long sz;

	if (!tool_config.wakeup_data_size)
		return 0;

	sz = bpf_ringbuf_query(rb, BPF_RB_AVAIL_DATA);
	return sz >= tool_config.wakeup_data_size ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static struct task_event *reserve_task_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct task_event), 0);
}

static struct stack_event *reserve_stack_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&stack_ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct stack_event), 0);
}

static struct perf_counter_event *reserve_perf_counter_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&perf_counter_ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct perf_counter_event), 0);
}

static struct probe_event *reserve_probe_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&probe_ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct probe_event), 0);
}

static struct network_event *reserve_network_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&network_ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct network_event), 0);
}

static struct packet_event *reserve_packet_event(long *flags)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&packet_ringbufs, &node);
	if (!rb)
		return NULL;
	*flags = get_ringbuf_flags(rb);
	return bpf_ringbuf_reserve(rb, sizeof(struct packet_event), 0);
}

static u32 task_cpu(struct task_struct *task)
{
	if (bpf_core_field_exists(task->thread_info)) {
		return task->thread_info.cpu;
	}
	struct thread_info *ti = task->stack;
	return ti->cpu;
}

static u64 task_cg_id(struct task_struct *task)
{
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;
	return cgrp->kn->id;
}

static u64 task_key(struct task_struct *task)
{
	return ((u64)task->tgid << 32) | task->pid;
}

struct systing_pid_filter {
	u32 kernel_tgid;
	u32 initialized;
};

struct systing_pid_filter filter = {0, 0};

static bool should_filter_systing(struct task_struct *task)
{
	return false;

	// If filter is initialized, check against kernel namespace TGID
	if (filter.initialized) {
		return task->tgid == filter.kernel_tgid;
	}

	// Filter not initialized - check if we have namespace info
	if (tool_config.my_dev == 0 && tool_config.my_ino == 0) {
		// No namespace info, use the userspace TGID directly
		filter.kernel_tgid = tool_config.my_tgid;
		filter.initialized = 1;
		return task->tgid == filter.kernel_tgid;
	}

	// We have namespace info, check if current process matches our namespace TGID
	struct bpf_pidns_info ns_info = {};
	if (bpf_get_ns_current_pid_tgid(tool_config.my_dev, tool_config.my_ino,
					 &ns_info, sizeof(ns_info)) == 0) {
		// Check if the namespace TGID matches our userspace TGID
		if (ns_info.tgid == tool_config.my_tgid) {
			// This is our process - get the kernel namespace TGID
			u64 pid_tgid = bpf_get_current_pid_tgid();
			filter.kernel_tgid = pid_tgid >> 32;
			filter.initialized = 1;
			return true; // This is systing process
		}
	}

	// Unable to determine if this is our process, don't filter
	return false;
}

static bool trace_task(struct task_struct *task)
{
	if (!tracing_enabled)
		return false;
	if (task->tgid == 0)
		return false;
	if (should_filter_systing(task))
		return false;
	if (tool_config.filter_pid) {
		u32 pid = task->tgid;
		if (bpf_map_lookup_elem(&pids, &pid) == NULL)
			return false;
	}
	if (tool_config.filter_cgroup) {
		u64 cgid = task_cg_id(task);
		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
			return false;
	}
	return true;
}

static int handle_missed_event(u32 index)
{
	u64 *value = bpf_map_lookup_elem(&missed_events, &index);
	if (value)
		*value += 1;
	return 0;
}

/*
 * Safe wrapper for reading kernel strings that handles confidentiality mode.
 * When confidentiality mode is enabled, bpf_probe_read_kernel_str is disabled,
 * so we use a placeholder string instead.
 */
static __always_inline long safe_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)
{
	if (tool_config.confidentiality_mode) {
		// In confidentiality mode, use a placeholder
		// We can't use bpf_probe_read_str as it's also restricted
		const char placeholder[] = "<restricted>";
		int len = sizeof(placeholder) - 1;
		if (len > size - 1)
			len = size - 1;
		__builtin_memcpy(dst, placeholder, len);
		((char *)dst)[len] = '\0';
		return len;
	}

	// Normal mode - use the standard kernel string reader
	return bpf_probe_read_kernel_str(dst, size, unsafe_ptr);
}

/*
 * Safe wrapper for reading user strings that handles confidentiality mode.
 * When confidentiality mode is enabled, bpf_probe_read_user_str is disabled,
 * so we use a placeholder string instead.
 */
static __always_inline long safe_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)
{
	if (tool_config.confidentiality_mode) {
		// In confidentiality mode, use a placeholder
		// We can't use bpf_probe_read_str as it's also restricted
		const char placeholder[] = "<restricted>";
		int len = sizeof(placeholder) - 1;
		if (len > size - 1)
			len = size - 1;
		__builtin_memcpy(dst, placeholder, len);
		((char *)dst)[len] = '\0';
		return len;
	}

	// Normal mode - use the standard user string reader
	return bpf_probe_read_user_str(dst, size, unsafe_ptr);
}

static void record_task_info(struct task_info *info, struct task_struct *task)
{
	info->tgidpid = task_key(task);

	// In confidentiality mode, use NULL comm (all zeros)
	if (tool_config.confidentiality_mode) {
		__builtin_memset(info->comm, 0, TASK_COMM_LEN);
		return;
	}

	if (task->flags & PF_WQ_WORKER) {
		struct kthread *k = bpf_core_cast(task->worker_private,
						  struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN,
					  worker->desc);
	} else {
		bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN,
					  task->comm);
	}
}

static void emit_stack_event(void *ctx,struct task_struct *task,
			     enum stack_event_type type)
{
	struct stack_event *event;
	long len = 0;

	if (tool_config.no_stack_traces)
		return;

	if (!trace_task(task))
		return;

	long flags;
	event = reserve_stack_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_STACK_EVENT);
		return;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);

#ifdef SYSTING_PYSTACKS
	event->py_msg_buffer.stack_len = 0;
	if (tool_config.collect_pystacks) {
		struct pt_regs *pt_regs = (struct pt_regs *)bpf_task_pt_regs(task);
		pystacks_read_stacks(pt_regs, NULL, &event->py_msg_buffer);
	}
#endif

	event->stack_event_type = type;

	if (!(task->flags & PF_KTHREAD)) {
		len = bpf_get_stack(ctx, &event->user_stack,
				    sizeof(event->user_stack),
				    BPF_F_USER_STACK);
		if (len > 0)
			event->user_stack_length = len / sizeof(u64);
		else
			event->user_stack_length = 0;
	} else {
		event->user_stack_length = 0;
	}

	len = bpf_get_stack(ctx, &event->kernel_stack,
			    sizeof(event->kernel_stack), SKIP_STACK_DEPTH);
	if (len > 0)
		event->kernel_stack_length = len / sizeof(u64);
	else
		event->kernel_stack_length = 0;
	bpf_ringbuf_submit(event, flags);
}

static int trace_irq_event(struct irqaction *action, int irq, int ret, bool enter)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(tsk))
		return 0;

	struct task_event *event;
	long flags;
	event = reserve_task_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->prev, tsk);
	event->target_cpu = irq;
	if (enter) {
		event->type = SCHED_IRQ_ENTER;
		if (tool_config.confidentiality_mode) {
			__builtin_memset(event->next.comm, 0, TASK_COMM_LEN);
		} else {
			bpf_probe_read_kernel_str(event->next.comm, TASK_COMM_LEN,
						  action->name);
		}
	} else {
		event->type = SCHED_IRQ_EXIT;
		event->next_prio = ret;
	}
	bpf_ringbuf_submit(event, flags);
	return 0;
}

static int trace_softirq_event(unsigned int vec_nr, bool enter)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(tsk))
		return 0;

	struct task_event *event;
	long flags;
	event = reserve_task_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->prev, tsk);
	event->target_cpu = vec_nr;
	event->type = enter ? SCHED_SOFTIRQ_ENTER : SCHED_SOFTIRQ_EXIT;
	bpf_ringbuf_submit(event, flags);
	return 0;
}

static int handle_wakeup(struct task_struct *waker, struct task_struct *wakee,
			 enum event_type type)
{
	struct task_event *event;
	long flags;
	u64 ts = bpf_ktime_get_boot_ns();
	u64 key = task_key(wakee);

	if (type == SCHED_WAKING || type == SCHED_WAKEUP_NEW)
		bpf_map_update_elem(&wake_ts, &key, &ts, BPF_ANY);

	event = reserve_task_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = ts;
	event->type = type;
	event->cpu = bpf_get_smp_processor_id();
	event->next_prio = wakee->prio;
	event->target_cpu = task_cpu(wakee);
	record_task_info(&event->prev, waker);
	record_task_info(&event->next, wakee);
	bpf_ringbuf_submit(event, flags);
	return 0;
}

static int handle_sched_wakeup(struct task_struct *task, int success)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(systing_sched_wakeup, struct task_struct *task, int success)
{
	return handle_sched_wakeup(task, success);
}

static int handle_sched_wakeup_new(struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP_NEW);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(systing_sched_wakeup_new, struct task_struct *task)
{
	return handle_sched_wakeup_new(task);
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev,
			       struct task_struct *next)
{
	struct task_event *event;
	long flags;
	u64 next_key = task_key(next);
	u64 ts = bpf_ktime_get_boot_ns();
	u64 latency = 0;
	u64 *start_ns;

	if (!trace_task(prev) && !trace_task(next))
		return 0;

	start_ns = bpf_map_lookup_elem(&wake_ts, &next_key);
	if (start_ns) {
		if (ts > *start_ns)
			latency = ts - *start_ns;
		bpf_map_delete_elem(&wake_ts, &next_key);
	}

	event = reserve_task_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);

	event->ts = ts;
	event->type = SCHED_SWITCH;
	event->latency = latency;
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->next, next);
	record_task_info(&event->prev, prev);
	/* Convert raw task state to ftrace format (mask to TASK_REPORT bits + preemption) */
	event->prev_state = preempt ? TASK_REPORT_MAX : (prev->__state & TASK_REPORT);
	event->next_prio = next->prio;
	event->prev_prio = prev->prio;
	bpf_ringbuf_submit(event, flags);

	/*
	 * Record the blocked stack trace for sleep states.
	 * TASK_INTERRUPTIBLE and TASK_UNINTERRUPTIBLE are mutually exclusive.
	 * sleep-stacks controls all sleep stacks; interruptible-stacks adds
	 * additional control for interruptible sleep specifically.
	 */
	if (!tool_config.no_sleep_stack_traces) {
		if (prev->__state & TASK_UNINTERRUPTIBLE)
			emit_stack_event(ctx, prev, STACK_SLEEP);
		else if (!tool_config.no_interruptible_stack_traces &&
			 prev->__state & TASK_INTERRUPTIBLE)
			emit_stack_event(ctx, prev, STACK_SLEEP);
	}
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(systing_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

static int handle_sched_waking(struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKING);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(systing_sched_waking, struct task_struct *task)
{
	return handle_sched_waking(task);
}

static int handle_sched_process_exit(struct task_struct *task)
{
	struct task_event *event;
	long flags;
	u64 ts = bpf_ktime_get_boot_ns();

	if (!trace_task(task))
		return 0;

	event = reserve_task_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = ts;
	event->type = SCHED_PROCESS_EXIT;
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->prev, task);
	event->prev_prio = task->prio;
	bpf_ringbuf_submit(event, flags);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(systing_sched_process_exit, struct task_struct *task)
{
	return handle_sched_process_exit(task);
}

static int handle_sched_process_fork(struct task_struct *parent,
				     struct task_struct *child)
{
	// Check if parent is being traced
	if (!trace_task(parent))
		return 0;

	// Add child to the pids map so we trace it too
	u32 child_pid = child->tgid;
	u8 val = 1;
	bpf_map_update_elem(&pids, &child_pid, &val, BPF_ANY);

	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(systing_sched_process_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	return handle_sched_process_fork(parent, child);
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(systing_irq_handler_entry, int irq, struct irqaction *action)
{
	return trace_irq_event(action, irq, 0, true);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(systing_irq_handler_exit, int irq, struct irqaction *action, int ret)
{
	return trace_irq_event(action, irq, ret, false);
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(systing_softirq_entry, unsigned int vec_nr)
{
	return trace_softirq_event(vec_nr, true);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(systing_softirq_exit, unsigned int vec_nr)
{
	return trace_softirq_event(vec_nr, false);
}

SEC("usdt")
int systing_usdt(struct pt_regs *ctx)
{
	if (tool_config.confidentiality_mode)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_usdt_cookie(ctx);
	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PROBE_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->num_args = 0;

	struct arg_desc_array *desc_array = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc_array && desc_array->num_args > 0) {
		event->num_args = desc_array->num_args < MAX_ARGS ? desc_array->num_args : MAX_ARGS;

		for (int i = 0; i < MAX_ARGS && i < desc_array->num_args; i++) {
			struct arg_desc *desc = &desc_array->args[i];
			long val = 0;

			event->args[i].type = ARG_NONE;
			event->args[i].size = 0;

			// ARG_RETVAL not supported for USDT - skip it
			if (desc->arg_type == ARG_RETVAL) {
				continue;
			}

			bpf_usdt_arg(ctx, desc->arg_index, &val);

			if (val) {
				if (desc->arg_type == ARG_STRING) {
					int len = safe_probe_read_user_str(&event->args[i].value,
									   sizeof(event->args[i].value), (long *)val);
					event->args[i].type = ARG_STRING;
					event->args[i].size = len > 0 ? len : 0;
				} else if (desc->arg_type == ARG_LONG) {
					__builtin_memcpy(&event->args[i].value, &val, sizeof(long));
					event->args[i].type = ARG_LONG;
					event->args[i].size = sizeof(long);
				}
			}
		}
	}
	bpf_ringbuf_submit(event, flags);

	u8 *should_capture_stack = bpf_map_lookup_elem(&event_stack_capture, &cookie);
	if (should_capture_stack && *should_capture_stack)
		emit_stack_event(ctx, task, STACK_RUNNING);

	return 0;
}

static void read_counters(void *ctx, struct task_struct *task)
{
	u32 key, cpu = bpf_get_smp_processor_id();

	if (!trace_task(task))
		return;

	u64 ts = bpf_ktime_get_boot_ns();
	key = cpu;

	for (int i = 0; i < tool_config.num_perf_counters; i++, key += tool_config.num_cpus) {
		int err;
		long flags;

		struct perf_counter_event *event = reserve_perf_counter_event(&flags);
		if (!event) {
			handle_missed_event(MISSED_CACHE_EVENT);
			continue;
		}

		err = bpf_perf_event_read_value(&perf_counters, key, (void *)&event->value,
						sizeof(event->value));
		if (err) {
			bpf_ringbuf_discard(event, 0);
			continue;
		}
		if (event->value.counter == 0) {
			bpf_ringbuf_discard(event, 0);
			continue;
		}
		u32 index = i;
		u64 *last_value = bpf_map_lookup_elem(&last_perf_counter_value, &index);
		if (last_value) {
			u64 old_value = event->value.counter;
			event->value.counter -= *last_value;
			*last_value = old_value;
		}
		event->ts = ts;
		event->cpu = cpu;
		event->counter_num = i;
		record_task_info(&event->task, task);
		bpf_ringbuf_submit(event, flags);
	}
}

SEC("perf_event")
int systing_perf_event_clock(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!tool_config.no_cpu_stack_traces)
		emit_stack_event(ctx, task, STACK_RUNNING);
	read_counters(ctx, task);
	return 0;
}

static void handle_probe_event(struct pt_regs *ctx, bool kernel)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return;

	u64 cookie = bpf_get_attach_cookie(ctx);
	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->num_args = 0;

	struct arg_desc_array *desc_array = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc_array && desc_array->num_args > 0) {
		event->num_args = desc_array->num_args < MAX_ARGS ? desc_array->num_args : MAX_ARGS;

		for (int i = 0; i < MAX_ARGS && i < desc_array->num_args; i++) {
			struct arg_desc *desc = &desc_array->args[i];
			u64 arg = 0;

			event->args[i].type = ARG_NONE;
			event->args[i].size = 0;

			if (desc->arg_type == ARG_RETVAL) {
				arg = PT_REGS_RC_CORE(ctx);
				__builtin_memcpy(&event->args[i].value, &arg, sizeof(u64));
				event->args[i].type = ARG_RETVAL;
				event->args[i].size = sizeof(u64);
			} else {
				if (desc->arg_index == 0) {
					arg = PT_REGS_PARM1_CORE(ctx);
				} else if (desc->arg_index == 1) {
					arg = PT_REGS_PARM2_CORE(ctx);
				} else if (desc->arg_index == 2) {
					arg = PT_REGS_PARM3_CORE(ctx);
				} else if (desc->arg_index == 3) {
					arg = PT_REGS_PARM4_CORE(ctx);
				} else if (desc->arg_index == 4) {
					arg = PT_REGS_PARM5_CORE(ctx);
				} else if (desc->arg_index == 5) {
					arg = PT_REGS_PARM6_CORE(ctx);
				}

				if (desc->arg_type == ARG_STRING) {
					int len;
					if (kernel)
						len = safe_probe_read_kernel_str(&event->args[i].value,
										 sizeof(event->args[i].value),
										 (void *)arg);
					else
						len = safe_probe_read_user_str(&event->args[i].value,
									       sizeof(event->args[i].value),
									       (void *)arg);
					event->args[i].type = ARG_STRING;
					event->args[i].size = len > 0 ? len : 0;
				} else if (desc->arg_type == ARG_LONG) {
					__builtin_memcpy(&event->args[i].value, &arg, sizeof(u64));
					event->args[i].type = ARG_LONG;
					event->args[i].size = sizeof(u64);
				}
			}
		}
	}
	bpf_ringbuf_submit(event, flags);

	u8 *should_capture_stack = bpf_map_lookup_elem(&event_stack_capture, &cookie);
	if (should_capture_stack && *should_capture_stack)
		emit_stack_event(ctx, task, STACK_RUNNING);
}

SEC("uprobe")
int systing_uprobe(struct pt_regs *ctx)
{
	// Exit early in confidentiality mode since probe helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

	handle_probe_event(ctx, false);
	return 0;
}

SEC("kprobe")
int systing_kprobe(struct pt_regs *ctx)
{
	// Exit early in confidentiality mode since probe helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

	handle_probe_event(ctx, true);
	return 0;
}

SEC("raw_tracepoint")
int systing_raw_tracepoint(struct bpf_raw_tracepoint_args *args)
{
	if (tool_config.confidentiality_mode)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_get_attach_cookie(args);
	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->num_args = 0;

	struct arg_desc_array *desc_array = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc_array && desc_array->num_args > 0) {
		event->num_args = desc_array->num_args < MAX_ARGS ? desc_array->num_args : MAX_ARGS;

		for (int i = 0; i < MAX_ARGS && i < desc_array->num_args; i++) {
			struct arg_desc *desc = &desc_array->args[i];
			u64 arg = 0;

			event->args[i].type = ARG_NONE;
			event->args[i].size = 0;

			// ARG_RETVAL not supported for raw_tracepoint - skip it
			if (desc->arg_type == ARG_RETVAL) {
				continue;
			}

			if (desc->arg_index == 0) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[0]);
			} else if (desc->arg_index == 1) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[1]);
			} else if (desc->arg_index == 2) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[2]);
			} else if (desc->arg_index == 3) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[3]);
			} else if (desc->arg_index == 4) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[4]);
			} else if (desc->arg_index == 5) {
				bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[5]);
			}

			if (desc->arg_type == ARG_STRING) {
				int len = safe_probe_read_kernel_str(&event->args[i].value,
								     sizeof(event->args[i].value),
								     (void *)arg);
				event->args[i].type = ARG_STRING;
				event->args[i].size = len > 0 ? len : 0;
			} else if (desc->arg_type == ARG_LONG) {
				__builtin_memcpy(&event->args[i].value, &arg, sizeof(u64));
				event->args[i].type = ARG_LONG;
				event->args[i].size = sizeof(u64);
			}
		}
	}
	bpf_ringbuf_submit(event, flags);

	u8 *should_capture_stack = bpf_map_lookup_elem(&event_stack_capture, &cookie);
	if (should_capture_stack && *should_capture_stack)
		emit_stack_event(args, task, STACK_RUNNING);

	return 0;
}

SEC("tracepoint")
int systing_tracepoint(struct bpf_raw_tracepoint_args *args)
{
	if (tool_config.confidentiality_mode)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_get_attach_cookie(args);
	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->num_args = 0;

	bpf_ringbuf_submit(event, flags);

	u8 *should_capture_stack = bpf_map_lookup_elem(&event_stack_capture, &cookie);
	if (should_capture_stack && *should_capture_stack)
		emit_stack_event(args, task, STACK_RUNNING);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!tool_config.collect_syscalls)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!trace_task(task))
		return 0;

	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = SYS_ENTER_COOKIE;
	event->num_args = 1;
	event->args[0].type = ARG_LONG;
	event->args[0].size = sizeof(u64);
	__builtin_memcpy(&event->args[0].value, &ctx->id, sizeof(u64));

	bpf_ringbuf_submit(event, flags);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!tool_config.collect_syscalls)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!trace_task(task))
		return 0;

	long flags;
	struct probe_event *event = reserve_probe_event(&flags);
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = SYS_EXIT_COOKIE;
	event->num_args = 2;
	event->args[0].type = ARG_LONG;
	event->args[0].size = sizeof(u64);
	__builtin_memcpy(&event->args[0].value, &ctx->id, sizeof(u64));
	event->args[1].type = ARG_LONG;
	event->args[1].size = sizeof(u64);
	__builtin_memcpy(&event->args[1].value, &ctx->ret, sizeof(u64));

	bpf_ringbuf_submit(event, flags);
	return 0;
}

static __always_inline int read_socket_dest_info(struct sock *sk,
						  enum network_address_family *af,
						  u8 *dest_addr,
						  u16 *dest_port)
{
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (family == AF_INET) {
		*af = NETWORK_AF_INET;
		u32 addr;
		bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
		__builtin_memcpy(dest_addr, &addr, 4);
		u16 port;
		bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_dport);
		*dest_port = __builtin_bswap16(port);
		return 0;
	} else if (family == AF_INET6) {
		*af = NETWORK_AF_INET6;
		bpf_probe_read_kernel(dest_addr, 16, &sk->__sk_common.skc_v6_daddr);
		u16 port;
		bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_dport);
		*dest_port = __builtin_bswap16(port);
		return 0;
	}
	return -1;
}

static int handle_sendmsg_entry(struct sock *sk, struct msghdr *msg, enum network_protocol protocol)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_send_info info = {0};

	info.protocol = protocol;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;

	if (protocol == NETWORK_TCP && sk) {
		struct tcp_sock *tp = (struct tcp_sock *)sk;
		u32 write_seq = 0;
		bpf_probe_read_kernel(&write_seq, sizeof(write_seq), &tp->write_seq);
		info.sendmsg_seq = write_seq;
	}

	// For UDP (and optionally TCP with msg_name), try to read from msghdr first
	// This handles unconnected UDP sockets where destination is passed per-send
	if (msg) {
		void *msg_name;
		size_t msg_namelen;

		// Read msg_name and msg_namelen from the msghdr structure using probe_read
		bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
		bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

		if (msg_name) {
			u16 family;
			bpf_probe_read_kernel(&family, sizeof(family), msg_name);

			// Check if this is IPv4
			if (family == AF_INET && msg_namelen >= sizeof(struct sockaddr_in)) {
				struct sockaddr_in addr;
				bpf_probe_read_kernel(&addr, sizeof(addr), msg_name);

				info.af = NETWORK_AF_INET;
				__builtin_memcpy(info.dest_addr, &addr.sin_addr.s_addr, 4);
				info.dest_port = __builtin_bswap16(addr.sin_port);
			}
			// Check if this is IPv6
			else if (family == AF_INET6 && msg_namelen >= sizeof(struct sockaddr_in6)) {
				struct sockaddr_in6 addr6;
				bpf_probe_read_kernel(&addr6, sizeof(addr6), msg_name);

				info.af = NETWORK_AF_INET6;
				__builtin_memcpy(info.dest_addr, &addr6.sin6_addr, 16);
				info.dest_port = __builtin_bswap16(addr6.sin6_port);
			}
		}
	}

	if (sk && info.dest_port == 0) {
		read_socket_dest_info(sk, &info.af, info.dest_addr, &info.dest_port);
	}

	// Store socket pointer for reading buffer state on exit
	info.sk_ptr = (u64)sk;

	// Get or create socket ID for this socket+destination pair
	if (sk && info.dest_port != 0) {
		info.socket_id = get_or_create_socket_id(sk, protocol, info.af,
							  info.dest_addr, info.dest_port, tgidpid);
	}

	bpf_map_update_elem(&pending_network_sends, &tgidpid, &info, BPF_ANY);

	return 0;
}

static int handle_sendmsg_exit(void *ctx, int ret)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	// Only record successful sends
	if (ret <= 0)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_send_info *info = bpf_map_lookup_elem(&pending_network_sends, &tgidpid);

	if (!info) {
		// No matching entry, skip
		return 0;
	}

	long flags;
	struct network_event *event = reserve_network_event(&flags);
	if (!event) {
		bpf_map_delete_elem(&pending_network_sends, &tgidpid);
		return handle_missed_event(MISSED_NETWORK_EVENT);
	}

	event->start_ts = info->start_ts;
	event->end_ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->protocol = info->protocol;
	event->operation = NETWORK_SEND;
	event->af = info->af;
	__builtin_memcpy(event->dest_addr, info->dest_addr, 16);
	event->dest_port = info->dest_port;
	event->bytes = (u32)ret;  // Return value is number of bytes sent
	event->sendmsg_seq = info->sendmsg_seq;  // TCP sequence at sendmsg time

	// Read send buffer state from socket (TCP only)
	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;
	if (info->protocol == NETWORK_TCP && info->sk_ptr) {
		struct sock *sk = (struct sock *)info->sk_ptr;
		int wmem_queued = 0;
		int sndbuf = 0;
		bpf_probe_read_kernel(&wmem_queued, sizeof(wmem_queued), &sk->sk_wmem_queued);
		bpf_probe_read_kernel(&sndbuf, sizeof(sndbuf), &sk->sk_sndbuf);
		event->sndbuf_used = (u32)wmem_queued;
		event->sndbuf_limit = (u32)sndbuf;
	}

	// Copy socket_id for correlation
	event->socket_id = info->socket_id;

	bpf_ringbuf_submit(event, flags);
	bpf_map_delete_elem(&pending_network_sends, &tgidpid);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	if (sk) {
		u64 sk_ptr = (u64)sk;
		u64 tgidpid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&sk_to_tgidpid, &sk_ptr, &tgidpid, BPF_ANY);
	}

	return handle_sendmsg_entry(sk, msg, NETWORK_TCP);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(tcp_sendmsg_exit, int ret)
{
	return handle_sendmsg_exit(ctx, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	if (sk) {
		u64 sk_ptr = (u64)sk;
		u64 tgidpid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&sk_to_tgidpid, &sk_ptr, &tgidpid, BPF_ANY);
	}

	return handle_sendmsg_entry(sk, msg, NETWORK_UDP);
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(udp_sendmsg_exit, int ret)
{
	return handle_sendmsg_exit(ctx, ret);
}

// For TCP: read peer address from socket structure
static int handle_tcp_recvmsg_entry(struct sock *sk, struct msghdr *msg)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info info = {0};

	info.protocol = NETWORK_TCP;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;  // Default to IPv4
	info.sk_ptr = (u64)sk;  // Store socket pointer for buffer queue latency

	if (sk) {
		read_socket_dest_info(sk, &info.af, info.peer_addr, &info.peer_port);
		// Get or create socket ID for this socket+destination pair
		if (info.peer_port != 0) {
			info.socket_id = get_or_create_socket_id(sk, NETWORK_TCP, info.af,
								  info.peer_addr, info.peer_port, tgidpid);
		}
	}

	bpf_map_update_elem(&pending_network_recvs, &tgidpid, &info, BPF_ANY);

	return 0;
}

static int handle_recvmsg_exit(void *ctx, int ret)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	// Only record successful receives
	if (ret <= 0)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info *info = bpf_map_lookup_elem(&pending_network_recvs, &tgidpid);

	if (!info) {
		// No matching entry, skip
		return 0;
	}

	// For UDP: skip if peer address wasn't successfully extracted (peer_port will be 0)
	// This can happen if __skb_recv_udp returned NULL
	if (info->protocol == NETWORK_UDP && info->peer_port == 0) {
		bpf_map_delete_elem(&pending_network_recvs, &tgidpid);
		return 0;
	}

	long flags;
	struct network_event *event = reserve_network_event(&flags);
	if (!event) {
		bpf_map_delete_elem(&pending_network_recvs, &tgidpid);
		return handle_missed_event(MISSED_NETWORK_EVENT);
	}

	event->start_ts = info->start_ts;
	event->end_ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->protocol = info->protocol;
	event->operation = NETWORK_RECV;
	event->af = info->af;
	event->bytes = (u32)ret;  // Return value is number of bytes received

	// Use the peer address that was extracted in the entry handler
	__builtin_memcpy(event->dest_addr, info->peer_addr, 16);
	event->dest_port = info->peer_port;

	// Copy socket_id for correlation
	event->socket_id = info->socket_id;

	bpf_ringbuf_submit(event, flags);
	bpf_map_delete_elem(&pending_network_recvs, &tgidpid);

	// Note: Buffer queue end events are now emitted at packet dequeue time
	// in tcp_recv_skb probe, not here at recvmsg exit

	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	return handle_tcp_recvmsg_entry(sk, msg);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(tcp_recvmsg_exit, int ret)
{
	return handle_recvmsg_exit(ctx, ret);
}

// Store timing info for UDP receives on entry
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	// Track socket -> tgidpid for UDP receive packets (same as UDP send)
	if (sk) {
		u64 sk_ptr = (u64)sk;
		u64 tgidpid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&sk_to_tgidpid, &sk_ptr, &tgidpid, BPF_ANY);
	}

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info info = {0};

	info.protocol = NETWORK_UDP;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;  // Default to IPv4
	// Peer address/port will be extracted from sk_buff headers by __skb_recv_udp kretprobe

	bpf_map_update_elem(&pending_network_recvs, &tgidpid, &info, BPF_ANY);

	return 0;
}

// Capture the sk_buff when __skb_recv_udp returns it
SEC("kretprobe/__skb_recv_udp")
int BPF_KRETPROBE(skb_recv_udp_exit, struct sk_buff *skb)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	if (!skb)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info *info = bpf_map_lookup_elem(&pending_network_recvs, &tgidpid);

	if (!info || info->protocol != NETWORK_UDP)
		return 0;

	// Extract headers from the sk_buff
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (head) {
		// First, determine IP version by reading the first byte
		u8 ip_version = 0;
		bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network_header);
		ip_version = (ip_version >> 4) & 0x0F;

		if (ip_version == 4) {
			// IPv4
			struct iphdr ip = {0};
			struct udphdr udp = {0};

			info->af = NETWORK_AF_INET;

			// Read IP header to get source address (peer who sent to us)
			if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
				__builtin_memcpy(info->peer_addr, &ip.saddr, 4);
			}

			// Read UDP header to get source port (peer port)
			if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
				info->peer_port = __builtin_bswap16(udp.source);
			}
		} else if (ip_version == 6) {
			// IPv6
			struct ipv6hdr ip6 = {0};
			struct udphdr udp = {0};

			info->af = NETWORK_AF_INET6;

			// Read IPv6 header to get source address
			if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + network_header) == 0) {
				__builtin_memcpy(info->peer_addr, &ip6.saddr, 16);
			}

			// Read UDP header to get source port
			if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
				info->peer_port = __builtin_bswap16(udp.source);
			}
		}

		// Now that we have peer address/port, get or create socket ID
		// Get the sock from the sk_buff
		if (info->peer_port != 0) {
			struct sock *sk = NULL;
			bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
			if (sk) {
				info->socket_id = get_or_create_socket_id(sk, NETWORK_UDP, info->af,
									  info->peer_addr, info->peer_port, tgidpid);
			}
		}
	}

	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(udp_recvmsg_exit, int ret)
{
	return handle_recvmsg_exit(ctx, ret);
}

// ========== UDP Packet-Level Tracing ==========

// Trace udp_send_skb to capture UDP transmit packet details
// Emits instant PACKET_UDP_SEND event
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb_entry, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
{
	if (!skb || !fl4)
		return 0;

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
	if (!sk)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);

	u64 tgidpid;
	if (tgidpid_ptr) {
		tgidpid = *tgidpid_ptr;
	} else {
		// Socket not yet tracked - use current task (may be kernel thread)
		tgidpid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&sk_to_tgidpid, &sk_ptr, &tgidpid, BPF_ANY);
	}

	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_UDP;
	event->event_type = PACKET_UDP_SEND;
	event->cpu = bpf_get_smp_processor_id();
	event->af = NETWORK_AF_INET;
	event->seq = 0;
	event->tcp_flags = 0;
	event->is_retransmit = 0;

	// Calculate UDP payload length like kernel does (udp.c:1126-1127)
	u32 skb_len = 0;
	u16 network_header = 0;
	u16 transport_header = 0;
	bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	// Calculate IP header length
	u32 ip_header_len = transport_header - network_header;

	// Payload length = total - IP header - UDP header
	u32 payload_len = skb_len > (ip_header_len + sizeof(struct udphdr))
		? skb_len - ip_header_len - sizeof(struct udphdr)
		: 0;
	event->length = payload_len;

	// Read flow info to get destination address
	u32 daddr = 0;
	u16 dport = 0;
	bpf_probe_read_kernel(&daddr, sizeof(daddr), &fl4->daddr);
	bpf_probe_read_kernel(&dport, sizeof(dport), &fl4->uli.ports.dport);

	__builtin_memcpy(event->dest_addr, &daddr, 4);
	event->dest_port = __builtin_bswap16(dport);

	// Look up socket ID for this socket+destination pair
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace udp_queue_rcv_one_skb to capture UDP receive
// Emits instant PACKET_UDP_RCV event
SEC("kprobe/udp_queue_rcv_one_skb")
int BPF_KPROBE(udp_queue_rcv_one_skb_entry, struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !skb)
		return 0;

	// Get tgidpid from socket
	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	// Extract headers from skb
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (!head)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	__builtin_memset(event->task.comm, 0, TASK_COMM_LEN);
	event->protocol = NETWORK_UDP;
	event->event_type = PACKET_UDP_RCV;
	event->cpu = bpf_get_smp_processor_id();
	event->af = NETWORK_AF_INET;
	event->seq = 0;
	event->tcp_flags = 0;
	event->is_retransmit = 0;

	// Read IP and UDP headers to get peer address and payload length
	struct iphdr ip = {0};
	struct udphdr udp = {0};

	if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
		__builtin_memcpy(event->dest_addr, &ip.saddr, 4);
	}

	if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
		event->dest_port = __builtin_bswap16(udp.source);
		u16 udp_total_len = __builtin_bswap16(udp.len);
		event->length = udp_total_len > sizeof(struct udphdr)
			? udp_total_len - sizeof(struct udphdr)
			: 0;
	}

	// Look up socket ID
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace __udp_enqueue_schedule_skb to capture buffer queue entry point
// Emits instant PACKET_UDP_ENQUEUE event
SEC("kprobe/__udp_enqueue_schedule_skb")
int BPF_KPROBE(udp_enqueue_schedule_skb_entry, struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !skb)
		return 0;

	// Get tgidpid from socket (we're in softirq context)
	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	// Extract headers from skb
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (!head)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	__builtin_memset(event->task.comm, 0, TASK_COMM_LEN);
	event->protocol = NETWORK_UDP;
	event->event_type = PACKET_UDP_ENQUEUE;
	event->cpu = bpf_get_smp_processor_id();
	event->af = NETWORK_AF_INET;
	event->seq = 0;
	event->tcp_flags = 0;
	event->is_retransmit = 0;

	// Read IP and UDP headers to get peer address and payload length
	struct iphdr ip = {0};
	struct udphdr udp = {0};

	if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
		__builtin_memcpy(event->dest_addr, &ip.saddr, 4);
	}

	if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
		event->dest_port = __builtin_bswap16(udp.source);
		u16 udp_total_len = __builtin_bswap16(udp.len);
		event->length = udp_total_len > sizeof(struct udphdr)
			? udp_total_len - sizeof(struct udphdr)
			: 0;
	}

	// Look up socket ID
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace __tcp_transmit_skb to capture packet details at transmission
// Emits instant PACKET_ENQUEUE event with tcp_skb_cb metadata
SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(tcp_transmit_skb_entry, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	if (!sk || !skb)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);

	u64 tgidpid;
	if (tgidpid_ptr) {
		tgidpid = *tgidpid_ptr;
	} else {
		// Socket not yet tracked - use current task (may be kernel thread)
		tgidpid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&sk_to_tgidpid, &sk_ptr, &tgidpid, BPF_ANY);
	}

	// Filter based on tgidpid from socket (may differ from current task due to TSQ/softirq)
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_TCP;
	event->event_type = PACKET_ENQUEUE;
	event->cpu = bpf_get_smp_processor_id();

	// Extract destination address and port from the socket
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (family == AF_INET) {
		event->af = NETWORK_AF_INET;
		u32 addr;
		bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
		__builtin_memcpy(event->dest_addr, &addr, 4);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	} else if (family == AF_INET6) {
		event->af = NETWORK_AF_INET6;
		bpf_probe_read_kernel(event->dest_addr, 16, &sk->__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	}

	struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)&skb->cb[0];
	u32 start_seq = 0;
	u32 end_seq = 0;
	u8 tcp_flags = 0;
	u8 sacked = 0;

	bpf_probe_read_kernel(&start_seq, sizeof(start_seq), &tcb->seq);
	bpf_probe_read_kernel(&end_seq, sizeof(end_seq), &tcb->end_seq);
	bpf_probe_read_kernel(&tcp_flags, sizeof(tcp_flags), &tcb->tcp_flags);
	bpf_probe_read_kernel(&sacked, sizeof(sacked), &tcb->sacked);

	event->seq = start_seq;
	event->length = end_seq - start_seq;
	event->tcp_flags = tcp_flags;

	// Check TCPCB_RETRANS flag (0x10) to detect retransmits
	#define TCPCB_RETRANS 0x10
	event->is_retransmit = (sacked & TCPCB_RETRANS) ? 1 : 0;

	// Look up socket ID for this socket+destination pair
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	// Read send buffer state from socket
	int wmem_queued = 0;
	int sndbuf = 0;
	bpf_probe_read_kernel(&wmem_queued, sizeof(wmem_queued), &sk->sk_wmem_queued);
	bpf_probe_read_kernel(&sndbuf, sizeof(sndbuf), &sk->sk_sndbuf);
	event->sndbuf_used = (u32)wmem_queued;
	event->sndbuf_limit = (u32)sndbuf;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Helper to extract TCP sequence from skb
static __always_inline int read_tcp_seq_from_skb(struct sk_buff *skb, u32 *seq)
{
	unsigned char *head = NULL;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (!head || transport_header == (u16)~0U)
		return -1;

	struct tcphdr tcp = {0};
	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) != 0)
		return -1;

	*seq = __builtin_bswap32(tcp.seq);
	return 0;
}

// Helper to emit instant packet event for TCP with full socket metadata
static __always_inline int emit_tcp_packet_event(struct sock *sk, struct sk_buff *skb,
						  u64 tgidpid, enum packet_event_type event_type)
{
	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_TCP;
	event->event_type = event_type;
	event->cpu = bpf_get_smp_processor_id();

	// Extract destination address and port from the socket
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (family == AF_INET) {
		event->af = NETWORK_AF_INET;
		u32 addr;
		bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
		__builtin_memcpy(event->dest_addr, &addr, 4);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	} else if (family == AF_INET6) {
		event->af = NETWORK_AF_INET6;
		bpf_probe_read_kernel(event->dest_addr, 16, &sk->__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	}

	// Read seq from TCP header in skb
	u32 seq = 0;
	read_tcp_seq_from_skb(skb, &seq);
	event->seq = seq;
	event->length = 0;  // Length not available at this probe point
	event->tcp_flags = 0;  // tcp_skb_cb not available at this probe point
	event->is_retransmit = 0;  // TCPCB_RETRANS not available at this probe point

	// Look up socket ID for this socket+destination pair
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	// Read send buffer state from socket
	int wmem_queued = 0;
	int sndbuf = 0;
	bpf_probe_read_kernel(&wmem_queued, sizeof(wmem_queued), &sk->sk_wmem_queued);
	bpf_probe_read_kernel(&sndbuf, sizeof(sndbuf), &sk->sk_sndbuf);
	event->sndbuf_used = (u32)wmem_queued;
	event->sndbuf_limit = (u32)sndbuf;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Helper to emit instant packet event for UDP with socket metadata
static __always_inline int emit_udp_packet_event(struct sock *sk, struct sk_buff *skb,
						  u64 tgidpid, u32 length,
						  enum packet_event_type event_type)
{
	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_UDP;
	event->event_type = event_type;
	event->cpu = bpf_get_smp_processor_id();
	event->seq = 0;
	event->length = length;
	event->tcp_flags = 0;
	event->is_retransmit = 0;

	// Extract destination address and port from the socket
	u16 family;
	bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

	if (family == AF_INET) {
		event->af = NETWORK_AF_INET;
		u32 addr;
		bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
		__builtin_memcpy(event->dest_addr, &addr, 4);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	} else if (family == AF_INET6) {
		event->af = NETWORK_AF_INET6;
		bpf_probe_read_kernel(event->dest_addr, 16, &sk->__sk_common.skc_v6_daddr);
		bpf_probe_read_kernel(&event->dest_port, sizeof(event->dest_port),
				      &sk->__sk_common.skc_dport);
		event->dest_port = __builtin_bswap16(event->dest_port);
	}

	// Look up socket ID for this socket+destination pair
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace net_dev_start_xmit to capture actual packet transmission (device queue -> NIC)
// TCP PACKET_ENQUEUE is emitted at __tcp_transmit_skb, so this only emits PACKET_SEND
SEC("tp_btf/net_dev_start_xmit")
int BPF_PROG(net_dev_start_xmit, struct sk_buff *skb, struct net_device *dev)
{
	if (!skb)
		return 0;

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
	if (!sk)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	// Check protocol type from socket
	u16 protocol = 0;
	bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol);

	// Emit PACKET_SEND instant event
	if (protocol == IPPROTO_TCP) {
		return emit_tcp_packet_event(sk, skb, tgidpid, PACKET_SEND);
	} else if (protocol == IPPROTO_UDP) {
		// Get packet length from skb
		u32 len = 0;
		bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
		return emit_udp_packet_event(sk, skb, tgidpid, len, PACKET_SEND);
	}

	return 0;
}

// Helper to read source address from IP headers in received packet
static __always_inline int read_src_addr_from_skb(struct sk_buff *skb,
						   enum network_address_family *af,
						   u8 *src_addr, u16 *src_port)
{
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (!head || network_header == (u16)~0U || transport_header == (u16)~0U)
		return -1;

	u8 ip_version = 0;
	bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network_header);
	ip_version = (ip_version >> 4) & 0x0F;

	if (ip_version == 4) {
		*af = NETWORK_AF_INET;
		struct iphdr ip = {0};
		struct tcphdr tcp = {0};

		if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) != 0)
			return -1;
		if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) != 0)
			return -1;

		__builtin_memcpy(src_addr, &ip.saddr, 4);
		*src_port = __builtin_bswap16(tcp.source);
		return 0;
	} else if (ip_version == 6) {
		*af = NETWORK_AF_INET6;
		struct ipv6hdr ip6 = {0};
		struct tcphdr tcp = {0};

		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + network_header) != 0)
			return -1;
		if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) != 0)
			return -1;

		__builtin_memcpy(src_addr, &ip6.saddr, 16);
		*src_port = __builtin_bswap16(tcp.source);
		return 0;
	}

	return -1;
}

// Trace tcp_rcv_established to capture when packet enters TCP layer
// Emits instant PACKET_RCV_ESTABLISHED event
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established_entry, struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !skb)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_TCP;
	event->event_type = PACKET_RCV_ESTABLISHED;
	event->cpu = bpf_get_smp_processor_id();
	event->is_retransmit = 0;

	// For receive: dest_addr/port are actually the peer who sent to us
	if (read_src_addr_from_skb(skb, &event->af, event->dest_addr, &event->dest_port) != 0) {
		bpf_ringbuf_discard(event, flags);
		return 0;
	}

	struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)&skb->cb[0];
	u32 start_seq = 0;
	u32 end_seq = 0;
	u8 tcp_flags = 0;

	bpf_probe_read_kernel(&start_seq, sizeof(start_seq), &tcb->seq);
	bpf_probe_read_kernel(&end_seq, sizeof(end_seq), &tcb->end_seq);
	bpf_probe_read_kernel(&tcp_flags, sizeof(tcp_flags), &tcb->tcp_flags);

	event->seq = start_seq;
	event->length = end_seq - start_seq;
	event->tcp_flags = tcp_flags;

	// Look up socket ID for this socket+destination pair
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace tcp_queue_rcv to capture when data enters socket buffer (fast path)
// Emits instant PACKET_QUEUE_RCV event
SEC("kprobe/tcp_queue_rcv")
int BPF_KPROBE(tcp_queue_rcv_entry, struct sock *sk, struct sk_buff *skb, bool *fragstolen)
{
	if (!sk || !skb)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_TCP;
	event->event_type = PACKET_QUEUE_RCV;
	event->cpu = bpf_get_smp_processor_id();
	event->is_retransmit = 0;

	// Read source (peer) address from skb
	if (read_src_addr_from_skb(skb, &event->af, event->dest_addr, &event->dest_port) != 0) {
		bpf_ringbuf_discard(event, flags);
		return 0;
	}

	// Read seq from TCP header
	u32 seq = 0;
	read_tcp_seq_from_skb(skb, &seq);
	event->seq = seq;

	// Read length from tcp_skb_cb
	struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)&skb->cb[0];
	u32 start_seq = 0;
	u32 end_seq = 0;
	bpf_probe_read_kernel(&start_seq, sizeof(start_seq), &tcb->seq);
	bpf_probe_read_kernel(&end_seq, sizeof(end_seq), &tcb->end_seq);
	event->length = end_seq - start_seq;
	event->tcp_flags = 0;

	// Look up socket ID
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Trace tcp_data_queue to capture slow path packets (packets arriving when buffer has data)
// This complements tcp_queue_rcv which only handles fast path
// Emits instant PACKET_QUEUE_RCV event
SEC("kprobe/tcp_data_queue")
int BPF_KPROBE(tcp_data_queue_entry, struct sock *sk, struct sk_buff *skb)
{
	if (!sk || !skb)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *event = reserve_packet_event(&flags);
	if (!event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	event->ts = bpf_ktime_get_boot_ns();
	event->task.tgidpid = tgidpid;
	event->protocol = NETWORK_TCP;
	event->event_type = PACKET_QUEUE_RCV;
	event->cpu = bpf_get_smp_processor_id();
	event->is_retransmit = 0;

	// Read source (peer) address from skb
	if (read_src_addr_from_skb(skb, &event->af, event->dest_addr, &event->dest_port) != 0) {
		bpf_ringbuf_discard(event, flags);
		return 0;
	}

	// Read seq from TCP header
	u32 seq = 0;
	read_tcp_seq_from_skb(skb, &seq);
	event->seq = seq;

	// Read length from tcp_skb_cb
	struct tcp_skb_cb *tcb = (struct tcp_skb_cb *)&skb->cb[0];
	u32 start_seq = 0;
	u32 end_seq = 0;
	bpf_probe_read_kernel(&start_seq, sizeof(start_seq), &tcb->seq);
	bpf_probe_read_kernel(&end_seq, sizeof(end_seq), &tcb->end_seq);
	event->length = end_seq - start_seq;
	event->tcp_flags = 0;

	// Look up socket ID
	event->socket_id = lookup_socket_id(sk, event->dest_addr, event->dest_port);

	event->sndbuf_used = 0;
	event->sndbuf_limit = 0;

	bpf_ringbuf_submit(event, flags);
	return 0;
}

// Track when data is copied from skb to userspace (actual packet consumption)
// Emits instant PACKET_BUFFER_QUEUE event
SEC("tp_btf/skb_copy_datagram_iovec")
int BPF_PROG(skb_copy_datagram_iovec, const struct sk_buff *skb, int len)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	if (!skb)
		return 0;

	struct sock *sk = NULL;
	bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
	if (!sk)
		return 0;

	u64 sk_ptr = (u64)sk;
	u64 *tgidpid_ptr = bpf_map_lookup_elem(&sk_to_tgidpid, &sk_ptr);
	if (!tgidpid_ptr)
		return 0;

	u64 tgidpid = *tgidpid_ptr;
	u32 tgid = tgidpid >> 32;
	if (tgid == 0 || tgid == tool_config.my_tgid)
		return 0;

	long flags;
	struct packet_event *pkt_event = reserve_packet_event(&flags);
	if (!pkt_event)
		return handle_missed_event(MISSED_PACKET_EVENT);

	pkt_event->ts = bpf_ktime_get_boot_ns();
	pkt_event->task.tgidpid = tgidpid;
	__builtin_memset(pkt_event->task.comm, 0, TASK_COMM_LEN);
	record_task_info(&pkt_event->task, task);
	pkt_event->protocol = NETWORK_TCP;
	pkt_event->event_type = PACKET_BUFFER_QUEUE;
	pkt_event->cpu = bpf_get_smp_processor_id();
	pkt_event->is_retransmit = 0;

	// Read peer address from socket
	if (read_socket_dest_info(sk, &pkt_event->af, pkt_event->dest_addr, &pkt_event->dest_port) != 0) {
		bpf_ringbuf_discard(pkt_event, flags);
		return 0;
	}

	// Read seq from TCP header
	u32 seq = 0;
	read_tcp_seq_from_skb(skb, &seq);
	pkt_event->seq = seq;
	pkt_event->length = len;
	pkt_event->tcp_flags = 0;

	// Look up socket ID
	pkt_event->socket_id = lookup_socket_id(sk, pkt_event->dest_addr, pkt_event->dest_port);

	pkt_event->sndbuf_used = 0;
	pkt_event->sndbuf_limit = 0;

	bpf_ringbuf_submit(pkt_event, flags);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
