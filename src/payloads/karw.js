// intended for use after kexploit

function hexdump(u8) {
  var result = '\n';

  for (var i = 0; i < u8.length; i += 0x10) {
    var slice = u8.subarray(i, i + 0x10);

    var offset = i.toString(16).toUpperCase().pad_start(8, '0');
    var hex = Array.from(slice)
      .map(b => b.toString(16).toUpperCase().pad_start(2, '0'))
      .join(' ')
      .pad_end(0x10 * 3 - 1);

    // ASCII part
    var ascii = Array.from(slice)
      .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');

    result += `${offset}  ${hex} ${ascii}\n`;
  }

  return result;
}

function kdump(addr, sz) {
    var buffer = alloc(sz);

    kv.kread(buffer, addr, sz);

    debug(hexdump(buffer.arr));

    dispose(buffer);
}

var target = new BigInt("0xFFFFD9112D157000"); // kernel address
kdump(target, 0x120);