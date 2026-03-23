// intended for use after kexploit

var SIZE = 0x2A00000;

var O_WRONLY = 1
var O_CREAT  = 0x40
var O_TRUNC  = 0x200

var fd = open.invoke("/data/kernel.elf", O_WRONLY | O_CREAT | O_TRUNC, 777);
if (fd.eq(-1)) {
  throw new SyscallError(`Unable to open ${path} !!`)
}

var buffer = alloc(0x4000);

var offset = 0;
while (offset < SIZE) {
    var step = Math.min(SIZE - offset, 0x4000);

    kv.kread(buffer, kernel_base.add(offset), step);

    var n = write.invoke(fd, buffer, step);
    if (n.neq(step)) {
      throw new SyscallError(`Expected ${step} got ${n} !!`);
    }

    offset += step;

    sleep(1e6);
}

if (close.invoke(fd).neq(0)) {
  throw new SyscallError(`Unable to close fd ${fd} !!`);
}

debug("done !!");