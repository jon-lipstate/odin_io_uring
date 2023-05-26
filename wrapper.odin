package io_uring
//
import "core:fmt"
import "core:os"
import "core:sys/unix"
import "core:intrinsics"
import "core:sync"
import "core:math"
import "core:math/bits"
// import "core:c/libc"
//
main :: proc() {
	fmt.println("Start")
	ring := init_ring(1, 0)
	fmt.println("Middle1")
	sqe, err := nop(&ring, 0x2A)
	assert(err == .None, "nop-err")
	n_pending := sq_ready(&ring)
	n_submitted, serr := submit(&ring, 1)
	n_ready := cq_ready(&ring)
	fmt.printf("pending:%v, submitted:%v, error:%v, n_ready:%v\n", n_pending, n_submitted, serr, n_ready)
	cqe := make([]io_uring_cqe, 1)
	n_copied, cerr := copy_cqes(&ring, cqe, 1)
	fmt.printf("n_copied:%v, cerr:%v\n", n_copied, cerr)
	fmt.println(cqe[0])
	fmt.println("Middle2")
	destroy_ring(&ring)
	fmt.println("End")
}
// in private file:
PROT_READ :: 0x1
PROT_WRITE :: 0x2
MAP_SHARED :: 0x1 // VERIFY : incorrect in core??
MAP_POPULATE :: 0x008000
EBUSY :: 16 // not in os
//
Handle :: os.Handle
Socket :: distinct Handle
sockaddr :: uint
epoll_event :: struct {
	events: u32, /* Epoll events */
	data:   epoll_data, /* User data variable */
}
epoll_data :: struct #raw_union {
	ptr: rawptr,
	fd:  Handle,
	u32: u32,
	u64: u64,
}
Statx :: struct {}

//
IO_Uring_Error :: enum {
	None,
	EntriesZero,
	EntriesNotPowerOfTwo,
	ParamsOutsideAccessibleAddressSpace,
	ArgumentsInvalid,
	ProcessFdQuotaExceeded,
	SystemFdQuotaExceeded,
	SystemResources,
	PermissionDenied,
	SystemOutdated,
	SubmissionQueueFull,
	FileDescriptorInvalid,
	FileDescriptorInBadState,
	CompletionQueueOvercommitted,
	SubmissionQueueEntryInvalid,
	BufferInvalid,
	RingShuttingDown,
	OpcodeNotSupported,
	SignalInterrupt,
	BuffersNotRegistered,
	FilesAlreadyRegistered,
	FilesEmpty,
	UserFdQuotaExceeded,
	RingShuttingDownOrAlreadyRegisteringFiles,
	FilesNotRegistered,
}

IO_Uring :: struct {
	fd:       Handle,
	sq:       Submission_Queue,
	cq:       Completion_Queue,
	flags:    u32,
	features: u32,
}
//
Submission_Queue :: struct {
	head:      ^u32,
	tail:      ^u32,
	mask:      u32,
	flags:     ^u32,
	dropped:   ^u32,
	array:     []u32,
	sqes:      []io_uring_sqe,
	mmap:      []u8, // align(mem.page_size)
	mmap_sqes: []u8, // align(mem.page_size) 

	// We use `sqe_head` and `sqe_tail` in the same way as liburing:
	// We increment `sqe_tail` (but not `tail`) for each call to `get_sqe()`.
	// We then set `tail` to `sqe_tail` once, only when these events are actually submitted.
	// This allows us to amortize the cost of the @atomicStore to `tail` across multiple SQEs.
	sqe_head:  u32,
	sqe_tail:  u32,
}
//
Completion_Queue :: struct {
	head:     ^u32,
	tail:     ^u32,
	mask:     u32,
	overflow: ^u32,
	cqes:     []io_uring_cqe,
}
// 
init_ring :: proc(entries: u32, flags: u32) -> IO_Uring {
	params := io_uring_params{}
	params.flags |= flags
	ring := init_params(entries, &params)
	return ring
}
init_params :: proc(entries: u32, p: ^io_uring_params) -> IO_Uring {
	assert(entries > 0)
	assert(math.is_power_of_two(int(entries)))
	//
	assert(p.sq_entries == 0)
	assert(p.cq_entries == 0 || p.flags & IORING_SETUP_CQSIZE != 0)
	assert(p.features == 0)
	assert(p.wq_fd == 0 || p.flags & IORING_SETUP_ATTACH_WQ != 0)
	assert(p.resv[0] == 0)
	assert(p.resv[1] == 0)
	assert(p.resv[2] == 0)
	//
	fd, err := io_uring_setup(entries, p)
	assert(err == os.ERROR_NONE)
	assert(fd >= 0)
	//
	assert(p.features & IORING_FEAT_SINGLE_MMAP != 0)
	//
	assert(p.sq_entries != 0)
	assert(p.cq_entries != 0)
	assert(p.cq_entries >= p.sq_entries)
	//
	sq, serr := init_submission_queue(fd, p)
	assert(serr == .None, "Submmision_Queue Alloc Error")
	cq := init_completion_queue(fd, p, &sq)
	// assert(cerr == .None)

	//
	assert(sq.head^ == 0)
	assert(sq.tail^ == 0)
	assert(sq.mask == p.sq_entries - 1)
	//
	assert(sq.dropped^ == 0)
	assert(len(sq.array) == int(p.sq_entries))
	assert(len(sq.sqes) == int(p.sq_entries))
	assert(sq.sqe_head == 0)
	assert(sq.sqe_tail == 0)
	//
	assert(cq.head^ == 0)
	assert(cq.tail^ == 0)
	assert(cq.mask == p.cq_entries - 1)
	assert(cq.overflow^ == 0)
	assert(len(cq.cqes) == int(p.cq_entries))

	ring := IO_Uring {
		fd       = fd,
		sq       = sq,
		cq       = cq,
		flags    = p.flags,
		features = p.features,
	}
	return ring
}
destroy_ring :: proc(ring: ^IO_Uring) {
	assert(ring.fd >= 0)
	destroy_submission_queue(&ring.sq)
	destroy_completion_queue(&ring.cq)
	os.close(ring.fd)
	ring.fd = -1
}
//
get_sqe :: proc(ring: ^IO_Uring) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sq := &ring.sq
	head: u32 = sync.atomic_load_explicit(sq.head, .Acquire)
	next := sq.sqe_tail + 1 // Todo: wrap is default?
	if int(next - head) > len(sq.sqes) {err = .SubmissionQueueFull;return}
	sqe = &sq.sqes[sq.sqe_tail & sq.mask]
	sq.sqe_tail = next
	return
}
submit :: proc(ring: ^IO_Uring, wait_nr: u32 = 0) -> (n_submitted: u32, err: IO_Uring_Error) {
	n_submitted = flush_sq(ring)
	flags: u32 = 0
	if sq_ring_needs_enter(ring, &flags) || wait_nr > 0 {
		if wait_nr > 0 || ring.flags & IORING_SETUP_IOPOLL != 0 {
			flags |= IORING_ENTER_GETEVENTS
		}
		n_submitted, err = enter(ring, n_submitted, wait_nr, flags)
	}
	return
}
enter :: proc(ring: ^IO_Uring, n_to_submit: u32, min_complete: u32, flags: u32) -> (n_submitted: u32, err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	ns, errn := io_uring_enter(ring.fd, n_to_submit, min_complete, flags, nil)
	n_submitted = u32(ns)
	e_val: os.Errno = os.Errno(os.get_last_error())
	switch e_val {
	case os.ERROR_NONE:
		err = .None
	case os.EAGAIN:
		// The kernel was unable to allocate memory or ran out of resources for the request. (try again)
		err = .SystemResources
	case os.EBADF:
		// The SQE `fd` is invalid, or `IOSQE_FIXED_FILE` was set but no files were registered
		err = .FileDescriptorInvalid
	case os.EBADFD:
		// The `fd` is valid, but the ring is not in the right state. See io_uring_register(2) for how to enable the ring.
		err = .FileDescriptorInBadState
	case EBUSY:
		// Attempted to overcommit the number of requests it can have pending. Should wait for some completions and try again.
		err = .CompletionQueueOvercommitted
	case os.EINVAL:
		// The SQE is invalid, or valid but the ring was setup with `IORING_SETUP_IOPOLL`
		err = .SubmissionQueueEntryInvalid
	case os.EFAULT:
		// The buffer is outside the process' accessible address space, or `IORING_OP_READ_FIXED`
		// or `IORING_OP_WRITE_FIXED` was specified but no buffers were registered, or the range
		// described by `addr` and `len` is not within the buffer registered at `buf_index`
		err = .BufferInvalid
	case os.ENXIO:
		err = .RingShuttingDown
	case os.EOPNOTSUPP:
		// The kernel believes the `fd` doesn't refer to an `io_uring`, or the opcode isn't supported by this kernel (more likely)
		err = .OpcodeNotSupported
	case os.EINTR:
		// The op was interrupted by a delivery of a signal before it could complete.This can happen while waiting for events with `IORING_ENTER_GETEVENTS`
		err = .SignalInterrupt
	case:
		panic("unhandled error")
	}
	return
}
flush_sq :: proc(ring: ^IO_Uring) -> (n_pending: u32) {
	sq := &ring.sq
	to_submit := sq.sqe_tail - sq.sqe_head
	if to_submit != 0 {
		tail := sq.tail^
		i: u32 = 0
		for ; i < to_submit; i += 1 {
			sq.array[tail & sq.mask] = sq.sqe_head & sq.mask
			tail += 1
			sq.sqe_head += 1
		}
		sync.atomic_store_explicit(sq.tail, tail, .Release)
	}
	n_pending = sq_ready(ring)
	return
}
//
sq_ready :: proc(ring: ^IO_Uring) -> (n_pending: u32) {
	// Always use the shared ring state (i.e. head and not sqe_head) to avoid going out of sync,
	// see https://github.com/axboe/liburing/issues/92.
	n_pending = ring.sq.sqe_tail - sync.atomic_load_explicit(ring.sq.head, .Acquire)
	return
}
cq_ready :: proc(ring: ^IO_Uring) -> (n_ready: u32) {
	n_ready = sync.atomic_load_explicit(ring.cq.tail, .Acquire) - ring.cq.head^
	return
}
// todo: return the flag instead?
sq_ring_needs_enter :: proc(ring: ^IO_Uring, flags: ^u32) -> bool {
	assert(flags^ == 0)
	if ring.flags & IORING_SETUP_SQPOLL == 0 {return true}
	if sync.atomic_load_explicit(ring.sq.flags, .Relaxed) & IORING_SQ_NEED_WAKEUP != 0 {
		flags^ |= IORING_ENTER_SQ_WAKEUP
		return true
	}
	return false
}
//
copy_cqes :: proc(ring: ^IO_Uring, cqes: []io_uring_cqe, wait_nr: u32) -> (n_copied: u32, err: IO_Uring_Error) {
	n_copied = copy_cqes_ready(ring, cqes)
	if n_copied > 0 {return}
	if wait_nr > 0 || cq_ring_needs_flush(ring) {
		_, err = enter(ring, 0, wait_nr, IORING_ENTER_GETEVENTS)
		n_copied = copy_cqes_ready(ring, cqes)
	}
	return
}
copy_cqes_ready :: proc(ring: ^IO_Uring, cqes: []io_uring_cqe) -> (n_copied: u32) {
	n_ready := cq_ready(ring)
	n_copied = min(u32(len(cqes)), n_ready)
	head := ring.cq.head^
	tail := head + n_copied
	i := 0
	for head != tail {
		cqes[i] = ring.cq.cqes[head & ring.cq.mask]
		head += 1
		i += 1
	}
	cq_advance(ring, n_copied)
	return
}
// copy_cqe :: proc(ring: ^IO_Uring) -> (cqe: io_uring_cqe, err: IO_Uring_Error) {}

cq_ring_needs_flush :: proc(ring: ^IO_Uring) -> bool {
	return sync.atomic_load_explicit(ring.sq.flags, .Relaxed) & IORING_SQ_CQ_OVERFLOW != 0
}
cqe_seen :: proc(ring: ^IO_Uring) {
	cq_advance(ring, 1)
}
cq_advance :: proc(ring: ^IO_Uring, count: u32) {
	if count == 0 {return}
	sync.atomic_store_explicit(ring.cq.head, ring.cq.head^ + count, .Release)
}
// `fsync(2)`
fsync :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .FSYNC
	sqe.rw_flags = i32(flags)
	sqe.fd = fd
	sqe.user_data = user_data

	return
}
nop :: proc(ring: ^IO_Uring, user_data: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .NOP
	sqe.user_data = user_data
	return
}
// [`read(2)`](https://linux.die.net/man/2/read)
// TODO: `IOSQE_BUFFER_SELECT` version not implemented
read :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, buf: []u8, offset: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .READ
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&buf[0])
	sqe.len = u32(len(buf))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
// [`readv(2)`](https://linux.die.net/man/2/readv), `preadv2()` can be set on `rw_flags` of sqe
readv :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, iovecs: []iovec, offset: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .READV
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&iovecs[0])
	sqe.len = u32(len(iovecs))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
Registered_Buffer :: struct {
	buf:   ^iovec,
	index: u16,
}
read_fixed :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	fd: Handle,
	buf: Registered_Buffer,
	offset: u64,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.READ_FIXED
	sqe.buf_index = buf.index
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&buf.buf[0])
	sqe.len = u32(len(buf.buf))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
// [`write(2)`](https://linux.die.net/man/2/write)
write :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, buf: []u8, offset: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .WRITE
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&buf[0])
	sqe.len = u32(len(buf))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
// [`pwritev`](https://linux.die.net/man/2/pwritev)
writev :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, iovecs: []iovec, offset: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .WRITE
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&iovecs[0]) // TODO: Verify
	sqe.len = u32(len(iovecs))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
write_fixed :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	fd: Handle,
	buf: Registered_Buffer,
	offset: u64,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = .WRITE_FIXED
	sqe.buf_index = buf.index
	sqe.fd = fd
	sqe.addr = cast(u64)uintptr(&buf.buf[0])
	sqe.len = u32(len(buf.buf))
	sqe.off = offset
	sqe.user_data = user_data
	return
}
// [`accept4(2)`](https://linux.die.net/man/2/accept4)
// `addr`,`addr_len` optional
accept :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	sockfd: Socket,
	addr: ^sockaddr,
	addr_len: ^u32,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.ACCEPT
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(addr)
	sqe.off = cast(u64)uintptr(addr_len)
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
// [`connect(2)`](https://linux.die.net/man/2/connect)
connect :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	sockfd: Socket,
	addr: ^sockaddr,
	addr_len: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.CONNECT
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(addr)
	sqe.off = cast(u64)uintptr(addr_len)
	sqe.user_data = user_data
	return
}

// [`epoll_ctl(2)`](https://linux.die.net/man/2/epoll_ctl)
epoll_ctl :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	epoll_fd: Handle,
	fd: Handle,
	op: u32,
	ev: ^epoll_event,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.EPOLL_CTL
	sqe.fd = epoll_fd
	sqe.addr = cast(u64)uintptr(ev)
	sqe.len = op
	sqe.off = cast(u64)uintptr(fd)
	sqe.user_data = user_data
	return
}

// [`recv(2)`](https://linux.die.net/man/2/recv)
recv :: proc {
	recv_buf,
	recv_registered,
}
// [`recv(2)`](https://linux.die.net/man/2/recv)
recv_buf :: proc(ring: ^IO_Uring, user_data: u64, sockfd: Socket, buf: []byte, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.RECV
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(&buf[0])
	sqe.len = cast(u32)uintptr(len(buf))
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
// [`recv(2)`](https://linux.die.net/man/2/recv)
recv_registered :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	sockfd: Socket,
	group_id: u16,
	group_len: u32,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.RECV
	sqe.fd = transmute(Handle)sockfd
	sqe.len = group_len
	sqe.rw_flags = i32(flags)
	sqe.flags |= u8(IOSQE_BUFFER_SELECT)
	sqe.buf_index = group_id
	sqe.user_data = user_data
	return
}
// [`send(2)`](https://linux.die.net/man/2/send)
send :: proc(ring: ^IO_Uring, user_data: u64, sockfd: Socket, buf: []byte, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.SEND
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(&buf[0])
	sqe.len = u32(len(buf))
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
msghdr :: struct {}
// [`recvmsg(2)`](https://linux.die.net/man/2/recvmsg)
recvmsg :: proc(ring: ^IO_Uring, user_data: u64, sockfd: Socket, msg: ^msghdr, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.RECVMSG
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(msg)
	sqe.len = 1
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
// [`sendmsg(2)`](https://linux.die.net/man/2/sendmsg)
sendmsg :: proc(ring: ^IO_Uring, user_data: u64, sockfd: Socket, msg: ^msghdr, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.SENDMSG
	sqe.fd = transmute(Handle)sockfd
	sqe.addr = cast(u64)uintptr(msg)
	sqe.len = 1
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
// [`openat(2)`](https://linux.die.net/man/2/openat)
openat :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	fd: Handle,
	path: cstring,
	mode: u32,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.OPENAT
	sqe.fd = fd
	sqe.addr = cast(u64)transmute(uintptr)path
	sqe.len = cast(u32)mode
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
// [`close(2)`](https://linux.die.net/man/2/close)
close :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.CLOSE
	sqe.fd = fd
	sqe.user_data = user_data
	return
}
kernel_timespec :: struct {}
timeout :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	ts: ^kernel_timespec,
	count: u32,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.TIMEOUT
	sqe.fd = -1
	sqe.addr = transmute(u64)uintptr(ts)
	sqe.len = 1
	sqe.off = u64(count)
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
timeout_remove :: proc(ring: ^IO_Uring, user_data: u64, timeout_user_data: u64, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.TIMEOUT_REMOVE
	sqe.fd = -1
	sqe.addr = timeout_user_data
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}

link_timeout :: proc(ring: ^IO_Uring, user_data: u64, ts: ^kernel_timespec, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.LINK_TIMEOUT
	sqe.fd = -1
	sqe.addr = transmute(u64)uintptr(ts)
	sqe.len = 1
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
poll_add :: proc(ring: ^IO_Uring, user_data: u64, fd: Handle, poll_mask: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.POLL_ADD
	sqe.fd = fd
	// Reason to force LE: <https://www.spinics.net/lists/io-uring/msg02848.html>
	sqe.rw_flags = i32(bits.to_le_u32(poll_mask))
	sqe.user_data = user_data
	return
}

poll_remove :: proc(ring: ^IO_Uring, user_data: u64, target_user_data: u64) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.POLL_REMOVE
	sqe.fd = -1
	sqe.addr = target_user_data
	sqe.user_data = user_data
	return
}

poll_update :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	old_user_data: u64,
	new_user_data: u64,
	poll_mask: u32,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.POLL_REMOVE
	sqe.fd = -1
	sqe.addr = old_user_data
	sqe.len = flags
	sqe.off = new_user_data
	// Reason to force LE: <https://www.spinics.net/lists/io-uring/msg02848.html>
	sqe.rw_flags = i32(bits.to_le_u32(poll_mask))
	sqe.user_data = user_data
	return
}
//[`fallocate(2)`](https://linux.die.net/man/2/fallocate)
fallocate :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	fd: Handle,
	mode: i32,
	offset: u64,
	length: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.FALLOCATE
	sqe.fd = fd
	sqe.len = transmute(u32)mode
	sqe.addr = u64(length)
	sqe.off = offset
	sqe.user_data = user_data
	return
}
//[`statx(2)`](https://manpages.debian.org/testing/manpages-dev/statx.2.en.html)
statx :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	fd: Handle,
	path: cstring,
	flags: u32,
	mask: u32,
	buf: ^Statx,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.STATX
	sqe.fd = fd
	sqe.addr = cast(u64)transmute(uintptr)path
	sqe.len = mask
	sqe.off = cast(u64)uintptr(buf)
	sqe.user_data = user_data
	return
}
//[`cancel(2)`](https://linux.die.net/man/2/shutdown)
// TODO: Verify correct link
cancel :: proc(ring: ^IO_Uring, user_data: u64, cancel_user_data: u64, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.ASYNC_CANCEL
	sqe.fd = -1
	sqe.addr = cancel_user_data
	sqe.user_data = user_data
	return
}
//[`shutdown(2)`](https://linux.die.net/man/2/shutdown)
shutdown :: proc(ring: ^IO_Uring, user_data: u64, sockfd: Socket, how: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.SHUTDOWN
	sqe.fd = transmute(Handle)sockfd
	sqe.len = how
	sqe.user_data = user_data
	return
}
//[`renameat(2)`](https://linux.die.net/man/2/renameat)
renameat :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	old_dir_fd: Handle,
	old_path: cstring,
	new_dir_fd: Handle,
	new_path: cstring,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	pold := transmute([^]u8)(old_path)
	pnew := transmute([^]u8)(new_path)
	sqe^ = {}
	sqe.opcode = IORING_OP.RENAMEAT
	sqe.fd = old_dir_fd
	sqe.addr = transmute(u64)transmute(uintptr)pold
	sqe.off = transmute(u64)transmute(uintptr)pnew
	sqe.len = cast(u32)new_dir_fd
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
//[`unlinkat(2)`](https://linux.die.net/man/2/unlinkat)
unlinkat :: proc(ring: ^IO_Uring, user_data: u64, dir_fd: Handle, path: cstring, flags: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.UNLINKAT
	sqe.fd = dir_fd
	sqe.addr = transmute(u64)transmute(uintptr)path
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}
//[`mkdirat(2)`](https://linux.die.net/man/2/mkdirat)
/*mode: mode_t*/
mkdirat :: proc(ring: ^IO_Uring, user_data: u64, dir_fd: Handle, path: cstring, mode: u32) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.MKDIRAT
	sqe.fd = dir_fd
	sqe.addr = transmute(u64)transmute(uintptr)path
	sqe.len = mode
	sqe.user_data = user_data
	return
}

symlinkat :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	target: cstring,
	new_dir_fd: Handle,
	link_path: cstring,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.SYMLINKAT
	sqe.fd = new_dir_fd
	sqe.addr = transmute(u64)transmute(uintptr)target
	sqe.len = 0
	sqe.off = transmute(u64)transmute(uintptr)link_path
	sqe.user_data = user_data
	return
}

linkat :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	old_dir_fd: Handle,
	old_path: cstring,
	new_dir_fd: Handle,
	new_path: cstring,
	flags: u32,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	pold := transmute([^]u8)(old_path)
	pnew := transmute([^]u8)(new_path)
	sqe^ = {}
	sqe.opcode = IORING_OP.LINKAT
	sqe.fd = old_dir_fd
	sqe.addr = transmute(u64)transmute(uintptr)pold
	sqe.len = cast(u32)new_dir_fd
	sqe.off = transmute(u64)transmute(uintptr)pnew
	sqe.rw_flags = i32(flags)
	sqe.user_data = user_data
	return
}

provide_buffers :: proc(
	ring: ^IO_Uring,
	user_data: u64,
	buffers: [^]u8,
	buffer_len: uint,
	buffers_count: uint,
	group_id: u16,
	buffer_id: uint,
) -> (
	sqe: ^io_uring_sqe,
	err: IO_Uring_Error,
) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.PROVIDE_BUFFERS
	sqe.fd = transmute(Handle)cast(i32)buffers_count
	sqe.addr = transmute(u64)transmute(uintptr)&buffers[0]
	sqe.len = u32(buffer_len)
	sqe.off = cast(u64)buffer_id
	sqe.buf_index = group_id
	sqe.user_data = user_data
	return
}

remove_buffers :: proc(ring: ^IO_Uring, user_data: u64, buffers_count: u32, group_id: u16) -> (sqe: ^io_uring_sqe, err: IO_Uring_Error) {
	sqe, err = get_sqe(ring)
	if err != .None {return}
	sqe^ = {}
	sqe.opcode = IORING_OP.REMOVE_BUFFERS
	sqe.fd = transmute(Handle)cast(i32)buffers_count
	sqe.buf_index = group_id
	sqe.user_data = user_data
	return
}
register_files :: proc(ring: ^IO_Uring, fds: []Handle) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .REGISTER_FILES, uintptr(&fds[0]), u32(len(fds)))
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
register_files_update :: proc(ring: ^IO_Uring, offset: u32, fds: []Handle) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	files_update :: struct {
		offset: u32,
		resv:   u32,
		fds:    u64, // #align(8),
	}
	update := files_update{offset, 0, transmute(u64)transmute(uintptr)&fds[0]}
	result := io_uring_register(ring.fd, .REGISTER_FILES_UPDATE, uintptr(&update), u32(len(fds))) // TODO: does kernel snag right away or this is use after free???
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
register_eventfd :: proc(ring: ^IO_Uring, fd: Handle) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .REGISTER_EVENTFD, uintptr(fd), 1) // todo: fd or ^fd??
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
register_eventfd_async :: proc(ring: ^IO_Uring, fd: Handle) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .REGISTER_EVENTFD_ASYNC, uintptr(fd), 1) // todo: fd or ^fd??
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
unregister_eventfd :: proc(ring: ^IO_Uring) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .UNREGISTER_EVENTFD, 0, 0)
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
register_buffers :: proc(ring: ^IO_Uring, buffers: []iovec) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .REGISTER_BUFFERS, uintptr(&buffers[0]), u32(len(buffers)))
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
unregister_buffers :: proc(ring: ^IO_Uring) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .UNREGISTER_BUFFERS, 0, 0)
	err = handle_registration_result(-1 * transmute(int)result)
	return
}
unregister_files :: proc(ring: ^IO_Uring) -> (err: IO_Uring_Error) {
	assert(ring.fd >= 0)
	result := io_uring_register(ring.fd, .UNREGISTER_FILES, 0, 0)
	eno := os.Errno(os.get_last_error())
	switch eno {
	case os.ERROR_NONE:
		err = .None
	case os.ENXIO:
		err = .FilesNotRegistered
	case:
		panic("unhandled")
	}
	return
}
// Converts io_uring syscall result into an Error Type
handle_registration_result :: proc(result: int) -> (err: IO_Uring_Error) {
	switch os.Errno(result) {
	case os.ERROR_NONE:
		err = .None
	case os.EBADF:
		// One or more fds in the array are invalid, or the kernel does not support sparse sets:
		err = .FileDescriptorInvalid
	case EBUSY:
		err = .FilesAlreadyRegistered
	case os.EINVAL:
		err = .FilesEmpty
	case os.EMFILE:
		// Adding `nr_args` file references would exceed the maximum allowed number of files the
		// user is allowed to have according to the per-user RLIMIT_NOFILE resource limit and
		// the CAP_SYS_RESOURCE capability is not set, or `nr_args` exceeds the maximum allowed
		// for a fixed file set (older kernels have a limit of 1024 files vs 64K files):
		err = .UserFdQuotaExceeded
	case os.ENOMEM:
		// Insufficient kernel resources, or the caller had a non-zero RLIMIT_MEMLOCK soft
		// resource limit but tried to lock more memory than the limit permitted (not enforced
		// when the process is privileged with CAP_IPC_LOCK):
		err = .SystemResources
	case os.ENXIO:
		// Attempt to register files on a ring already registering files or being torn down:
		err = .RingShuttingDownOrAlreadyRegisteringFiles
	case:
		panic("unhandled")
	}
	return
}
//
//
//
init_submission_queue :: proc(fd: Handle, p: ^io_uring_params) -> (sq: Submission_Queue, err: IO_Uring_Error) {
	assert(fd >= 0)
	assert(p.features & IORING_FEAT_SINGLE_MMAP != 0)
	sq_size := p.sq_off.array + p.sq_entries * size_of(u32)
	cq_size := p.cq_off.cqes + p.cq_entries * size_of(io_uring_cqe)
	size := max(sq_size, cq_size)
	//  rawptr mmap(void *addr, size_t length, int " prot ", int " flags ", int fd, off_t offset)
	mmap_result := intrinsics.syscall(
		unix.SYS_mmap,
		0,
		uintptr(size),
		uintptr(PROT_READ | PROT_WRITE),
		uintptr(MAP_SHARED | MAP_POPULATE),
		uintptr(fd),
		uintptr(IORING_OFF_SQ_RING),
	)
	assert(mmap_result >= 0, "mmap allocation failure")
	mmap := transmute([^]u8)mmap_result

	// TODO: test for failuer to alloc
	size_of_sqes := p.sq_entries * size_of(io_uring_sqe)
	mmap_sqes_result := intrinsics.syscall(
		unix.SYS_mmap,
		0,
		uintptr(size_of_sqes),
		uintptr(PROT_READ | PROT_WRITE),
		uintptr(MAP_SHARED | MAP_POPULATE),
		uintptr(fd),
		uintptr(IORING_OFF_SQES),
	)
	assert(mmap_sqes_result >= 0, "mmap allocation failure")
	mmap_sqes := transmute([^]u8)mmap_sqes_result

	// TODO: test for failuer to alloc
	array := transmute([^]u32)&mmap[p.sq_off.array]
	sqes := transmute([^]io_uring_sqe)mmap_sqes
	// We expect the kernel copies p.sq_entries to the u32 pointed to by p.sq_off.ring_entries,
	// see https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L7843-L7844
	// assert(p.sq_entries == (cast(^u32)&mmap[p.sq_off.ring_entries])^)
	sq = Submission_Queue {
		head      = transmute(^u32)&mmap[p.sq_off.head],
		tail      = transmute(^u32)&mmap[p.sq_off.tail],
		mask      = (transmute(^u32)&mmap[p.sq_off.ring_mask])^,
		flags     = transmute(^u32)&mmap[p.sq_off.flags],
		dropped   = transmute(^u32)&mmap[p.sq_off.dropped],
		array     = array[:p.sq_entries],
		sqes      = sqes[:p.sq_entries],
		mmap      = mmap[:size],
		mmap_sqes = mmap_sqes[:size_of_sqes],
	}

	return
}
destroy_submission_queue :: proc(sq: ^Submission_Queue) {
	intrinsics.syscall(unix.SYS_munmap, uintptr(&sq.mmap_sqes[0]), uintptr(len(sq.mmap_sqes)))
	intrinsics.syscall(unix.SYS_munmap, uintptr(&sq.mmap[0]), uintptr(len(sq.mmap)))
}
//
init_completion_queue :: proc(fd: Handle, p: ^io_uring_params, sq: ^Submission_Queue) -> Completion_Queue {
	assert(fd >= 0)
	assert(p.features & IORING_FEAT_SINGLE_MMAP != 0)
	mmap := sq.mmap
	cqes := transmute([^]io_uring_cqe)&mmap[p.cq_off.cqes]
	// assert(p.cq_entries == cast(u32)uintptr(&mmap[p.cq_off.cqes]))
	cq := Completion_Queue {
		head     = transmute(^u32)&mmap[p.cq_off.head],
		tail     = transmute(^u32)&mmap[p.cq_off.tail],
		mask     = (transmute(^u32)&mmap[p.cq_off.ring_mask])^,
		overflow = transmute(^u32)&mmap[p.cq_off.overflow],
		cqes     = cqes[:p.cq_entries],
	}
	return cq
}
destroy_completion_queue :: proc(cq: ^Completion_Queue) { /*nop*/}
