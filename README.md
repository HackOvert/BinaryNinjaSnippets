# Binary Ninja Snippets

_Binary Ninja Snippets_ is a collection of Python examples showing how to work with [Binary Ninja][0]'s [Python API][1]. Many of the examples here focus on using the Binary Ninja Intermediate Language (BNIL) suite which includes LLIL, MLIL, HLIL along with [SSA](https://en.wikipedia.org/wiki/Static_single_assignment_form) versions of each.

# Latest Release & API Docs

- Interested in Binary Ninja? [Check it out here][0].
- Looking for the latest Python API docs? [View them here][1].
- Looking for user docs? [View them here][5].

# Community

- Follow Vector 35 on [Twitter][2].
- Read the Binary Ninja [Blog][3].
- Join the public [Slack][4].
- Check out Vector 35 on [YouTube][6].

# Contributing

Feel free to submit pull requests with any modifications you see fit. Most of these snippets are meant to be verbose, but if you know of a better way to do something, please consider sharing it. Thanks!

# Table of Contents

<details>
<summary>Working with Binary Targets</summary>

- [`Loading a binary`](#loading-a-binary)
- [`Getting basic information from a BinaryView`](#getting-basic-information-from-a-binaryview)

</details>

<details>

<summary>Working with Functions</summary>

- [`Listing all functions`](#listing-all-functions)
- [`Getting calll site details`](#getting-call-site-details)
- [`Finding callers for a function`](#finding-callers-for-a-function)
- [`Finding callees for a function`](#finding-callees-for-a-function)
- [`Get functions by name`](#get-functions-by-name)

</details>

## Working with Binary Targets

In this section we'll cover common methods for loading binary targets and getting information about the target.

### Loading a binary

Binary Ninja uses a [BinaryView](https://api.binary.ninja/binaryninja.binaryview-module.html) is one of the most important objects in Binary Ninja. If you need to work on any component of a target, you'll be doing it through a BinaryView (BV for short). Let's see a basic way to getting a BV.

```python
# Method 1
with binaryninja.open_view("/bin/true") as bv:
    print(type(bv))

# Method 2: Using this method, you must close the binary view yourself when done with it
bv = binaryninja.BinaryViewType.get_view_of_file_with_options("/bin/true")
print(type(bv))
bv.file.close()
```

<details>
<summary>Output example</summary>

```
<class 'binaryninja.binaryview.BinaryView'>
<class 'binaryninja.binaryview.BinaryView'>
```

</details>

<br>[⬆ Back to top](#table-of-contents)

### Getting basic information from a BinaryView

Let's grab some simple information from a BV and display it to the user. I often use `print(dir(bv))` to remind myself what attributes and methods are available on a BinaryView. You can get much more detailed information from the [BinaryView docs](https://api.binary.ninja/binaryninja.binaryview.BinaryView.html).

```python
with binaryninja.open_view("/bin/true") as bv:
    print("Binary name:     {}".format(bv.file.filename))
    print("Number of funcs: {}".format(len(bv.functions)))
    print("Endianness:      {}".format(bv.endianness.name))
    print("Entry function:  {}".format(bv.entry_function))
    print("Entry point:     0x{:08X}".format(bv.entry_point))
    print("Executable:      {}".format(bv.executable))
    print("Address size:    {}".format(bv.address_size))
    print("Arch:            {}".format(bv.arch))
```

<details>
<summary>Output example</summary>

```
Binary name:     true
Number of funcs: 106
Endianness:      LittleEndian
Entry function:  int64_t _start(int64_t arg1, int64_t arg2, void (* arg3)()) __noreturn
Entry point:     0x004017B0
Executable:      True
Address size:    8
Arch:            <arch: x86_64>
```

</details>

<br>[⬆ Back to top](#table-of-contents)

## Working with functions

In this section we'll work with functions including listing them, finding cross references to them, finding call targets, etc.

### Listing all functions

Once you have a BinaryView, getting function information is extremely easy, just reference the `.function` attribute to get a list of all functions in the target binary.

```python
with binaryninja.open_view("/bin/true") as bv:
    funcs = bv.functions
    print("Function count: {}".format(len(funcs)))
    for func in funcs:
        print("0x{:X}: {}".format(func.start, func.name))
```

<details>
<summary>Output example</summary>

```
Function count: 106
0x4013D0: _init
0x401400: __uflow
0x401406: sub_401406
0x401410: getenv
0x401420: free
0x401430: abort
0x401440: __errno_location
0x401450: strncmp
...snip...
```

</details>

<br>[⬆ Back to top](#table-of-contents)

### Getting call site details

When analyzing a function you may want to know if it calls other functions, some details such as:

- At what address does the call happen?
- What function is called (callee)?
- Is the callee an external (imported) function?

You can quickly and easily get this information and more. Let's take a look at how to do it.

```python
with binaryninja.open_view("/bin/true") as bv:
    funcs = bv.functions
    for func in funcs:
        call_sites = func.call_sites
        callees = func.callees
        print("\nFunction {} calls {} function(s).".format(func.name, len(callees)))
        for i, callee in enumerate(callees):
            symbol_type = callee.symbol.type.name
            print("  Callee {}: Call site @ {}, calls function {} which is a {}.".format(i+1, call_sites[i], callees[i].name, symbol_type))
```

<details>
<summary>Output example</summary>

```
...snip...
Function sub_404860 calls 8 function(s).
  Callee 1: Call site @ <ref: x86_64@0x404867>, calls function fileno which is a ImportedFunctionSymbol.
  Callee 2: Call site @ <ref: x86_64@0x404873>, calls function __freading which is a ImportedFunctionSymbol.
  Callee 3: Call site @ <ref: x86_64@0x40487f>, calls function sub_4048e0 which is a FunctionSymbol.
  Callee 4: Call site @ <ref: x86_64@0x404888>, calls function __errno_location which is a ImportedFunctionSymbol.
  Callee 5: Call site @ <ref: x86_64@0x404896>, calls function fclose which is a ImportedFunctionSymbol.
  Callee 6: Call site @ <ref: x86_64@0x4048ab>, calls function fileno which is a ImportedFunctionSymbol.
  Callee 7: Call site @ <ref: x86_64@0x4048b9>, calls function lseek which is a ImportedFunctionSymbol.
  Callee 8: Call site @ <ref: x86_64@0x4048cb>, calls function fclose which is a ImportedFunctionSymbol.

Function sub_4048e0 calls 4 function(s).
  Callee 1: Call site @ <ref: x86_64@0x4048e9>, calls function __freading which is a ImportedFunctionSymbol.
  Callee 2: Call site @ <ref: x86_64@0x4048fe>, calls function fflush which is a ImportedFunctionSymbol.
  Callee 3: Call site @ <ref: x86_64@0x404912>, calls function sub_404920 which is a FunctionSymbol.
  Callee 4: Call site @ <ref: x86_64@0x40491b>, calls function fflush which is a ImportedFunctionSymbol.
...snip...
```

</details>

<br>[⬆ Back to top](#table-of-contents)

### Finding callers for a function

When analyzing a function you may want to know where that function is called from. Binary Ninja makes this easy for resolvable calls. In cases where calls are dynamic, more work may be needed to recover this information.

```python
with binaryninja.open_view("/bin/true") as bv:
    funcs = bv.functions
    for func in funcs:
        callers = func.callers
        print("\nFunction {} is called from {} known locations.".format(func.name, len(callers)))
        for i, caller in enumerate(callers):
            print("  Caller {}: {} is called from function {}.".format(i+1, func.name, caller.name))
```

<details>
<summary>Output example</summary>

```
...snip...
Function sub_404210 is called from 2 known locations.
  Caller 1: sub_404210 is called from function sub_404240.
  Caller 2: sub_404210 is called from function sub_403250.

Function sub_404240 is called from 0 known locations.

Function sub_404260 is called from 4 known locations.
  Caller 1: sub_404260 is called from function sub_404070.
  Caller 2: sub_404260 is called from function sub_4030a0.
  Caller 3: sub_404260 is called from function sub_404010.
  Caller 4: sub_404260 is called from function sub_4041e0.
  ...snip...
```

</details>

<br>[⬆ Back to top](#table-of-contents)

### Finding callees for a function

When analyzing a function you may want to know what calls are being made from that function. These called functions are known as `callees` and Binary Ninja exposes an easy way to get them. Getting a list of callees is only the first step, as you'll probably want to know at what address they are _called from_. This list of call locations is referred to as `call sites`.

Once we have the callees, it's easy to covert those callee call site locations to LLIL and MLIL, unfortunately it's not so easy with HLIL, as we'll show.

Take this example where we'll collect "native" callees, then covert to LLIL, MLIL, and HLIL.

```python
with binaryninja.open_view("/bin/true") as bv:
    funcs = bv.functions
    for func in funcs:
        callees = func.callees
        natv_call_sites = func.call_sites # native call sites
        llil_call_sites = [func.get_llil_at(x.address) for x in func.call_sites]
        mlil_call_sites = [func.get_llil_at(x.address).mlil for x in func.call_sites]
        hlil_call_sites = [func.get_llil_at(x.address).hlil for x in func.call_sites]
        if len(callees) > 0:
            print("\nFunction {} calls {} function(s).".format(func.name, len(callees)))
            for i, callee in enumerate(callees):
                print("  Callee {}: {}".format(i+1, callees[i].name))
                (natv_index, natv_addr) = ("N/A", hex(natv_call_sites[i].address)) if natv_call_sites[i] else ("None", "None")
                (llil_index, llil_addr) = (llil_call_sites[i].instr_index, hex(llil_call_sites[i].address)) if llil_call_sites[i] else ("None", "None")
                (mlil_index, mlil_addr) = (mlil_call_sites[i].instr_index, hex(mlil_call_sites[i].address)) if mlil_call_sites[i] else ("None", "None")
                (hlil_index, hlil_addr) = (hlil_call_sites[i].instr_index, hex(hlil_call_sites[i].address)) if hlil_call_sites[i] else ("None", "None")
                print("    - [Natv] Call site @ {}:{}.".format(natv_index, natv_addr))
                print("    - [LLIL] Call site @ {}:{}.".format(llil_index, llil_addr))
                print("    - [MLIL] Call site @ {}:{}.".format(mlil_index, mlil_addr))
                print("    - [HLIL] Call site @ {}:{}.".format(hlil_index, hlil_addr))
```

<details>
<summary>Output example</summary>

```
...snip...
Function sub_48e0 calls 4 function(s).
  Callee 1: __freading
    - [Natv] Call site @ N/A:0x48e9.
    - [LLIL] Call site @ 7:0x48e9.
    - [MLIL] Call site @ 5:0x48e9.
    - [HLIL] Call site @ 18446744073709551615:0x48e9.   <-- Failed to convert to HLIL location
  Callee 2: fflush
    - [Natv] Call site @ N/A:0x48fe.
    - [LLIL] Call site @ 6:0x48fe.
    - [MLIL] Call site @ 4:0x48fe.
    - [HLIL] Call site @ 3:0x48fe.
  Callee 3: sub_4920
    - [Natv] Call site @ N/A:0x4912.
    - [LLIL] Call site @ 13:0x4912.
    - [MLIL] Call site @ 9:0x4912.
    - [HLIL] Call site @ 1:0x4912.
  Callee 4: fflush
    - [Natv] Call site @ N/A:0x491b.
    - [LLIL] Call site @ 16:0x491b.
    - [MLIL] Call site @ 11:0x491b.
    - [HLIL] Call site @ 2:0x491b.
...snip...
```

Let's break this down. First, at the "native level" we collect the call sites and callees. When we print this information, there is no such thing as an instruction index as the native level so it appears as "N/A". When we convert this native call site to LLIL and MLIL it works every time, telling us at what instruction and instruction index the call is made. However, HLIL is another story as it will sometimes fail to convert a call site to a HLIL location, resulting in a "HLIL_COP" instruction with an index of `18446744073709551615` (or `0xffffffffffffffff`).

In other words, there is no concise way to get call sites in HLIL. It works much of the time, but fails seemingly randomly.

</details>

<br>[⬆ Back to top](#table-of-contents)

### Get functions by name

Getting a function object by name sounds like a simple process, but once you consider function overloading (i.e. multiple functions can share the same name), mangled names, and platform-specific qualified names, things start to get complex.

In its most simple form, you can loop over `bv.functions` checking the `name` member for the value you want:

```python
# You probably don't want to do this!
for function in bv.functions:
  if function.name == "continuePlaying":
    return function
```

This falls apart when you start analyzing complex C++ targets. For example, there may be numerous functions named "continuePlaying", and the above code will only return one. What happens if you want to find a function by it's mangled name or qualified name? Because of this, we'll go for a more encompasing solution.

```python
def get_functions_by_name(bv, fname):
    functions = []
    for function in bv.functions:
        if function.name == fname:
            functions.append(function)
        else:
            type_gnu3, name_gnu3 = binaryninja.demangle_gnu3(bv.arch, function.name)
            if type_gnu3 != None and type(name_gnu3) == list and len(name_gnu3) == 2:
                gnu3_fn = name_gnu3[1]
                gnu3_qn = binaryninja.get_qualified_name(name_gnu3)
                if gnu3_fn == fname or gnu3_qn == fname:
                    functions.append(function)
                    continue
            type_ms, name_ms = binaryninja.demangle_ms(bv.arch, function.name)
            if type_ms != None and type(name_ms) == list and len(name_ms) == 2:
                ms_fn = name_ms[1]
                ms_qn = binaryninja.get_qualified_name(name_ms)
                if ms_fn == fname or ms_qn == fname:
                    functions.append(function)
    return functions
```

<details>
<summary>Output example</summary>

```
# Use case 1
# Using this function on a libvlc.dll target to find
# functions named "continuePlaying".
# get_functions_by_name(bv, "continuePlaying")

int32_t _ZN8FileSink15continuePlayingEv(void* arg1)
int32_t _ZN12BasicUDPSink15continuePlayingEv(void* arg1)
int32_t _ZN8HTTPSink15continuePlayingEv(void* arg1)
int32_t _ZN16H264VideoRTPSink15continuePlayingEv(int32_t* arg1)
int32_t _ZN18MultiFramedRTPSink15continuePlayingEv(int32_t* arg1)
int32_t _ZN9DummySink15continuePlayingEv(void* arg1)
int32_t _ZN17QuickTimeFileSink15continuePlayingEv(void* arg1)
int32_t _ZN11AVIFileSink15continuePlayingEv(void* arg1)

# Use case 2
# Using this function on a libvlc.dll target to find
# functions named "_ZN9DummySink15continuePlayingEv" (mangled)

int32_t _ZN9DummySink15continuePlayingEv(void* arg1)

# Use case 3
# Using this function on a libvlc.dll target to find
# functions named "AVIFileSink::continuePlaying" (qualified name)

int32_t _ZN11AVIFileSink15continuePlayingEv(void* arg1)

```

</details>

<br>[⬆ Back to top](#table-of-contents)

[0]: https://binary.ninja/
[1]: https://api.binary.ninja/
[2]: https://twitter.com/vector35
[3]: https://binary.ninja/blog/
[4]: https://slack.binary.ninja/
[5]: https://docs.binary.ninja/
[6]: https://www.youtube.com/channel/UCtIKC7NSj7l9zcHomQS1fBA
