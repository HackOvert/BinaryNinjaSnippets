# Binary Ninja Snippets
*Binary Ninja Snippets* is a collection of Python examples showing how to work with [Binary Ninja][0]'s Python API. Many of the examples here focus on using the Binary Ninja Intermediate Language (BNIL) suite which includes LLIL, MLIL, HLIL along with [SSA](https://en.wikipedia.org/wiki/Static_single_assignment_form) versions of each.

# Latest Release & API Docs
* Interested in Binary Ninja? [Check it out here][0].
* Looking for the latest Python API Docs? [View them here][1].

# Contributing

Feel free to submit pull requests with any modifications you see fit. Most of these snippets are meant to be verbose, but if you know of a better way to do something, please consider sharing it. Thanks!

# Table of Contents
<details>
<summary>Loading and Working with Binary Targets</summary>

* [`Loading a binary`](#loading-a-binary)
* [`Getting basic information from a BinaryView`](#getting-basic-information-from-a-binaryview)

</details>


## Loading and Working with Binary Targets
In this section we'll cover common methods for loading binary targets and getting information about the target.

### Loading a binary
Binary Ninja uses a [BinaryView](https://api.binary.ninja/binaryninja.binaryview-module.html) is one of the most important objects in Binary Ninja. If you need to work on any component of a target, you'll be doing it through a BinaryView (BV for short).  Let's see a basic way to getting a BV.

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
entry function:  int64_t _start(int64_t arg1, int64_t arg2, void (* arg3)()) __noreturn
entry point:     0x004017B0
executable:      True
Address size:    8
Arch:            <arch: x86_64>
```
</details>

<br>[⬆ Back to top](#table-of-contents)


[0]: https://binary.ninja/
[1]: https://api.binary.ninja/
