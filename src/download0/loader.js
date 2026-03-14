"use strict";

//#region Contants
var PAGE_SIZE = 0x4000;

var PF_X = 1;
var PF_W = 2;
var PF_R = 4;

var PROT_READ = 1;
var PROT_WRITE = 2;
var PROT_EXEC = 4;

var ET_DYN = 3;
var ET_EXEC = 2;

var MAP_SHARED = 1;
var MAP_PRIVATE = 2;
var MAP_FIXED = 0x10;
var MAP_ANONYMOUS = 0x1000;

var PT_LOAD = 1;
var SHT_RELA = 4;
var MADV_DONTNEED = 5;
var R_X86_64_RELATIVE = 8;

var munmap = new NativeFunction(0x49, "bigint");
var mprotect = new NativeFunction(0x4A, "bigint");
var madvise = new NativeFunction(0x4B, "bigint");
var mmap = new NativeFunction(0x1DD, "bigint");
var jitshm_create = new NativeFunction(0x215, "bigint");
var mname = new NativeFunction(0x24C, "bigint");
var kexec = new NativeFunction(0x295, "bigint");
//#endregion Constants
//#region Classes
class Elf {
  constructor(name, addr, size) {
    this.name = name;
    this.addr = addr;
    this.size = size;

    var ehdr = Elf64_Ehdr.from(this.addr);

    if (this.size < Elf64_Ehdr.sizeof 
      || this.size.lt(ehdr.e_phoff.add(Elf64_Phdr.sizeof)) 
      || this.size.lt(ehdr.e_shoff.add(Elf64_Shdr.sizeof))) {
      throw new Error("Invalid ELF structure !!");
    }

    if (ehdr.e_ident.at(0) !== 0x7F 
    || ehdr.e_ident.at(1) !== 0x45
    || ehdr.e_ident.at(2) !== 0x4C
    || ehdr.e_ident.at(3) !== 0x46) {
      throw new Error("Invalid ELF signature !!");
    }

    var phdr = Elf64_Phdr.from(this.addr.add(ehdr.e_phoff));
    for (var i = 0; i < ehdr.e_phnum; i++) {
      if (this.size.lt(phdr.from_at(i).p_offset.add(phdr.at(i).p_filesz))) {
        throw new Error("Truncated ELF !!");
      }
    }
  }

  load() {
    var ehdr = Elf64_Ehdr.from(this.addr);
    var phdr = Elf64_Phdr.from(this.addr.add(ehdr.e_phoff));
    var shdr = Elf64_Shdr.from(this.addr.add(ehdr.e_shoff));

    var min_vaddr = 0;
    var max_vaddr = 0;

    for (var i = 0; i < ehdr.e_phnum; i++) {
      if (phdr.from_at(i).p_vaddr.lt(min_vaddr)) {
        min_vaddr = phdr.from_at(i).p_vaddr;
      }

      if (phdr.from_at(i).p_vaddr.add(phdr.from_at(i).p_memsz).gt(max_vaddr)) {
        max_vaddr = phdr.from_at(i).p_vaddr.add(phdr.from_at(i).p_memsz);
      }
    }

    this.base_size = new BigInt(max_vaddr.align_up(PAGE_SIZE) - min_vaddr.align_down(PAGE_SIZE));

    var flags = MAP_PRIVATE | MAP_ANONYMOUS;
    var prot = PROT_READ | PROT_WRITE;
    if (ehdr.e_type === ET_DYN) {
      this.base_addr = 0;
    } else if(ehdr.e_type === ET_EXEC) {
      this.base_addr = min_vaddr;
      flags |= MAP_FIXED;
    } else {
      throw new Error("ELF type not supported");
    }

    this.base_addr = mmap.invoke(this.base_addr, this.base_size, prot, flags, -1, 0);
    if (this.base_addr.eq(-1)) {
      throw new SyscallError(`Unable to map memory with size ${this.base_size} !!`);
    }

    if (mname.invoke(this.base_addr, this.base_size, this.name).neq(0)) {
      throw new SyscallError(`Unable to name mapped memory ${this.base_addr} with size ${this.base_size} to ${this.name} !!`);
    }

    log(`${this.name} mapped into ${this.base_addr} of size ${this.base_size} !!`);

    for (var i = 0; i < ehdr.e_phnum; i++) {
      if (phdr.from_at(i).p_type === PT_LOAD) {
        if (phdr.from_at(i).p_memsz.eq(0) || phdr.from_at(i).p_filesz.eq(0)) {
          continue;
        }

        var src = this.addr.add(phdr.from_at(i).p_offset);
        var dst = this.base_addr.add(phdr.from_at(i).p_vaddr);
        var sz = phdr.from_at(i).p_filesz.valueOf();

        copy(dst, src, sz);
      }
    }

    for (var i = 0; i < ehdr.e_shnum; i++) {
      if (shdr.from_at(i).s_type !== SHT_RELA) {
        continue;
      }

      var rela = Elf64_Rela.from(this.addr.add(shdr.from_at(i).s_offset));
      for (var j = 0; shdr.from_at(i).s_size.div(Elf64_Rela.sizeof).gt(j); j++) {
        if (rela.from_at(j).r_info.lo === R_X86_64_RELATIVE) {
          var reloc = this.base_addr.add(rela.from_at(j).r_addend);
          view(this.base_addr).setBigInt(rela.from_at(j).r_offset, reloc, true);
        }
      }
    }

    for (var i = 0; i < ehdr.e_phnum; i++) {
      if (phdr.from_at(i).p_type !== PT_LOAD || phdr.at(i).p_memsz.eq(0)) {
        continue;
      }

      var addr = this.base_addr.add(phdr.from_at(i).p_vaddr);
      var size = phdr.at(i).p_memsz.align_up(PAGE_SIZE);
      var pprot = (phdr.from_at(i).p_flags & PF_R ? PROT_READ : 0) 
                | (phdr.from_at(i).p_flags & PF_W ? PROT_WRITE : 0) 
                | (phdr.from_at(i).p_flags & PF_X ? PROT_EXEC : 0);

      if (mprotect.invoke(addr, size, pprot).neq(0)) {
        munmap.invoke(this.base_addr, this.base_size);
        throw new SyscallError(`Unable to set memory at ${this.base_addr} with size ${this.base_size} to prot ${prot} !!`);
      }
    }

    debug(`ELF entry point: ${this.base_addr.add(ehdr.e_entry)}`);

    return new NativeFunction(this.base_addr.add(ehdr.e_entry), "bigint");
  }

  unload() {
    if (madvise.invoke(this.base_addr, this.base_size, MADV_DONTNEED).neq(0)) {
      throw new SyscallError(`Mapped memory ${this.base_addr} with size ${this.base_size} still in use !!`);
    }

    munmap.invoke(this.base_addr, this.base_size);
  }
};
//#endregion
//#region Functions
function load_bin(data, exit) {
  var sz = data.length.align_up(PAGE_SIZE);
  var prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  var flags = MAP_PRIVATE | MAP_ANONYMOUS;

  var entry_addr = mmap.invoke(0, sz, prot, flags, -1, 0);
  debug(`entry_addr: ${entry_addr}`);
  if (entry_addr.eq(-1)) {
    throw new SyscallError(`Unable to map memory with size ${sz} !!`);
  }

  copy(entry_addr, data.get_backing(), data.length);

  var pthread_addr_addr = alloc(8);

  if (pthread_create.invoke(pthread_addr_addr, 0, entry_addr, 0).neq(0)) {
    throw new Error(`Unable to create bin thread !!`);
  }

  var pthread_addr = view(pthread_addr_addr).getBigInt(0, true);
  var pthread_id = view(pthread_addr).getBigInt(0, true);

  log(`Created bin thread with id ${pthread_id} !!`);

  if (exit) {
    var kill = new NativeFunction(0x25, "bigint");

    var pid = getpid.invoke();

    kill.invoke(pid, 9);
  }
}
//#endregion
//#region Structs
var Elf64_Ehdr = new Struct("Elf64_Ehdr", [
  { type: "Uint8", name: "e_ident", count: 16 },
  { type: "Uint16", name: "e_type" },
  { type: "Uint16", name: "e_machine" },
  { type: "Uint32", name: "e_version" },
  { type: "Uint64", name: "e_entry" },
  { type: "Uint64", name: "e_phoff" },
  { type: "Uint64", name: "e_shoff" },
  { type: "Uint32", name: "e_flags" },
  { type: "Uint16", name: "e_ehsize" },
  { type: "Uint16", name: "e_phentsize" },
  { type: "Uint16", name: "e_phnum" },
  { type: "Uint16", name: "e_shentsize" },
  { type: "Uint16", name: "e_shnum" },
  { type: "Uint16", name: "e_shstrndx" },
]);
var Elf64_Phdr = new Struct("Elf64_Phdr", [
  { type: "Uint32", name: "p_type" },
  { type: "Uint32", name: "p_flags" },
  { type: "Uint64", name: "p_offset" },
  { type: "Uint64", name: "p_vaddr" },
  { type: "Uint64", name: "p_paddr" },
  { type: "Uint64", name: "p_filesz" },
  { type: "Uint64", name: "p_memsz" },
  { type: "Uint64", name: "p_align" },
]);

var Elf64_Shdr = new Struct("Elf64_Shdr", [
  { type: "Uint32", name: "s_name" },
  { type: "Uint32", name: "s_type" },
  { type: "Uint64", name: "s_flags" },
  { type: "Uint64", name: "s_addr" },
  { type: "Uint64", name: "s_offset" },
  { type: "Uint64", name: "s_size" },
  { type: "Uint32", name: "s_link" },
  { type: "Uint32", name: "s_info" },
  { type: "Uint64", name: "s_addralign" },
  { type: "Uint64", name: "s_entsize" },
]);

var Elf64_Rela = new Struct("Elf64_Rela", [
  { type: "Uint64", name: "r_offset" },
  { type: "Uint64", name: "r_info" },
  { type: "Int64", name: "r_addend" },
]);
//#endregion