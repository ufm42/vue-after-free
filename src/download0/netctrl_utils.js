"use strict";

//#region Constants
var RTP_SET = 1;
var MAIN_CORE = 4;
var CPU_WHICH_TID = 1;
var CPU_LEVEL_WHICH = 3;
var RTP_PRIO_REALTIME = 2;

var COMMAND_IDLE = -1;
var COMMAND_SHUTDOWN = -2;
var COMMAND_UIO_READ = 0;
var COMMAND_UIO_WRITE = 1;
var COMMAND_IOV_RECVMSG = 0;

var pthread_cond_broadcast = new NativeFunction(jsc_base.add(0x860), "bigint");
var pthread_cond_wait = new NativeFunction(jsc_base.add(0x8B0), "bigint");
var pthread_mutex_lock = new NativeFunction(jsc_base.add(0x920), "bigint");
var pthread_mutex_unlock = new NativeFunction(jsc_base.add(0x940), "bigint");

var rtprio_thread = new NativeFunction(0x1D2, "bigint");
var cpuset_setaffinity = new NativeFunction(0x1E8, "bigint");
//#endregion
//#region Classes
var Worker = Worker || class {
    constructor(ctx_addr, total) {
        this.can_free = false;
        this.ctx = worker_ctx.from(ctx_addr);

        if (total) {
            this.can_free = true;
            this.ctx.total = total;
            this.ctx.cmd = COMMAND_IDLE;

            this.ctx.mutex = alloc(8);
            this.ctx.cond = alloc(8);

            if (pthread_mutex_init.invoke(this.ctx.mutex, 0).neq(0)) {
              throw new Error("Unable to create mutex");
            }

            if (pthread_cond_init.invoke(this.ctx.cond, 0).neq(0)) {
              throw new Error("Unable to create cond");
            }
        } 
    }

    free() {
        if (this.can_free) {
            if (pthread_mutex_destroy.invoke(this.ctx.mutex).neq(0)) {
              throw new Error("Unable to destroy mutex");
            }

            if (pthread_cond_destroy.invoke(this.ctx.cond).neq(0)) {
              throw new Error("Unable to destroy cond");
            }
        }
    }

    signal_work(cmd) {
        if (pthread_mutex_lock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to lock mutex ${this.ctx.mutex} !!`);
        }

        this.ctx.started = 0;
        this.ctx.finished = 0;
        this.ctx.cmd = cmd;

        if (pthread_cond_broadcast.invoke(this.ctx.cond).neq(0)) {
            throw new Error(`Unable to broadcast cond ${this.ctx.cond} !!`);
        }

        if (this.ctx.cmd !== COMMAND_SHUTDOWN) {
            while (this.ctx.started < this.ctx.total) {
                if (pthread_cond_wait.invoke(this.ctx.cond, this.ctx.mutex).neq(0)) {
                    throw new Error(`Unable to wait for cond ${this.ctx.cond} !!`);
                }
            }
        }

        if (pthread_mutex_unlock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to unlock mutex ${this.ctx.mutex} !!`);
        }
    }

    wait_for_work() {
        if (pthread_mutex_lock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to lock mutex ${this.ctx.mutex} !!`);
        }

        while (this.ctx.cmd === COMMAND_IDLE || this.ctx.finished !== 0) {
            if (pthread_cond_wait.invoke(this.ctx.cond, this.ctx.mutex).neq(0)) {
                throw new Error(`Unable to wait for cond ${this.ctx.cond} !!`);
            }
        }

        if (this.ctx.cmd !== COMMAND_SHUTDOWN) {
            this.ctx.started++;

            if (this.ctx.started === this.ctx.total) {
                if (pthread_cond_broadcast.invoke(this.ctx.cond).neq(0)) {
                    throw new Error(`Unable to broadcast cond ${this.ctx.cond} !!`);
                }
            }
        }

        var cmd = this.ctx.cmd;

        if (pthread_mutex_unlock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to unlock mutex ${this.ctx.mutex} !!`);
        }

        return cmd;
    }

    signal_finished() {
        if (pthread_mutex_lock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to lock mutex ${this.ctx.mutex} !!`);
        }

        this.ctx.finished++;

        if (this.ctx.finished === this.ctx.total) {
            if (pthread_cond_broadcast.invoke(this.ctx.cond).neq(0)) {
                throw new Error(`Unable to broadcast cond ${this.ctx.cond} !!`);
            }
        }

        if (pthread_mutex_unlock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to unlock mutex ${this.ctx.mutex} !!`);
        }
    }

    wait_for_finished() {
        if (pthread_mutex_lock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to lock mutex ${this.ctx.mutex} !!`);
        }

        while (this.ctx.finished < this.ctx.total) {
            if (pthread_cond_wait.invoke(this.ctx.cond, this.ctx.mutex).neq(0)) {
                throw new Error(`Unable to wait for cond ${this.ctx.cond} !!`);
            }
        }

        this.ctx.cmd = COMMAND_IDLE;

        if (pthread_mutex_unlock.invoke(this.ctx.mutex).neq(0)) {
            throw new Error(`Unable to unlock mutex ${this.ctx.mutex} !!`);
        }
    }
};
//#endregion
//#region Functions
function _cpuset_setaffinity(core) {
    var mask_addr = alloc(cpuset.sizeof);
    var mask = cpuset.from(mask_addr);

    mask.bits.put(0, 1 << core);

    if (cpuset_setaffinity.invoke(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, cpuset.sizeof, mask.addr).neq(0)) {
        throw new SyscallError(`Unable to setaffinity to core ${core}`);
    }
};

function _rtprio_thread(value) {
    var prio_addr = alloc(rtprio.sizeof);
    var prio = rtprio.from(prio_addr);
    
    prio.type = RTP_PRIO_REALTIME;
    prio.prio = value;

    if (rtprio_thread.invoke(RTP_SET, 0, prio.addr).neq(0)) {
        throw new SyscallError(`Unable to set priority to ${value}`);
    }
};
//#endregion
//#region Structs
var cpuset = new Struct("cpuset", [
    { type: "Uint64", name: "bits", count: 2 }
]);

var rtprio = new Struct("rtprio", [
    { type: "Uint16", name: "type" },
    { type: "Uint16", name: "prio" },
]);

var worker_ctx = new Struct("worker_ctx", [
    { type: "Int32", name: "total" },
    { type: "Int32", name: "started" },
    { type: "Int32", name: "finished" },
    { type: "Int32", name: "cmd" },
    { type: "Uint64", name: "mutex" }, // modified only in main thread
    { type: "Uint64", name: "cond" }  // modified only in main thread
]);
//#endregion

_cpuset_setaffinity(MAIN_CORE);
_rtprio_thread(0x100);