# What is _Enoki_ ?
The _Enoki_ script is a wrapper class for [IDAPython](https://www.hex-rays.com/products/ida/support/idapython_docs/). It regroups various useful functions for reverse engineering of non-standard 
and/or uncommon binaries. Many of the scripts currently available online are geared towards malware analysis of Windows [Portable Executable (PE)
files](https://en.wikipedia.org/wiki/Portable_Executable) and as such, most of their functionalities are geared toward Intel-based systems and perform many tasks to detect or
deobfuscate malicious, well-known file standards. _Enoki_ seeks to provide a set of basic functions for analysis of binaries, memory maps
or other non-malware oriented files for reverse engineering purposes.

## Summary

The _Enoki_ script is a wrapper around many IDAPython functions and is designed for analysts conducting reverse engineering on
non-standard and uncommon files such as firmware of embedded devices or simply plain unknown files for ICS systems. _Enoki_ provides
additional shortcut functions for extracting, searching and analyzing machines code, useful when IDA as issue parsing
or detecting the actual processor.

## Usage

To use _Enoki_ with [IDA](https://www.hex-rays.com/products/ida/), simply load the _enoki-*.py_ file into IDA. An instance of the _Enoki_ object will automatically be created in the ```e``` variable or you can create your own
instance using the following command in the interpreter:

```
e = Enoki()
```

Simply call any of the function required using the instance, for example:

```
Python>hex(e.current_file_offset())
0x74fc
```

## Examples

This section provides some example of the functionalities provded by the _Enoki_ script. More details can be found by consulting the wiki of the project.

### Find a byte string

One of the function provided by _Enoki_ is the ```find_byte_string```, which allow the analyst to search for specific sequence of bytes or words in the machine
code. The function will return all locations where the specific byte string has been found in the range searched. 

```
Python>e.find_byte_string(ScreenEA(), ScreenEA() + 0x1000, "7980 ????")
[150, 155, 173, 198, 208]
```

If you need the output in hexadecimal addresses, simply wrap the result using the ```hex()``` function:

```
Python>[hex(i) for i in e.find_byte_string(ScreenEA(), ScreenEA() + 0x1000, "7980 ????")]
['0x96', '0x9b', '0xad', '0xc6', '0xd0']
```

### Compare two code ranges for similarity

Another functionality available is to compare the similarity of two code segments via the ```compare_code``` function. This function
will take two arrays of opcodes or assembly instructions and calculate the similarity of the sequence. In the example below, 
the similarity is only 11%, meaning the 2 code segments are quite different.

```
Python>c1 = e.get_words_between(0x2C00, 0x2CFF)
Python>c2 = e.get_words_between(0x8000, 0x80FF)
Python>e.compare_code(c1, c2)
0.11328125
```

Other functions are available within _Enoki_ and more details can be found in the comments of the script or in the future wiki of the project.


## References

If you find this script useful for your projects or research, please add a reference or link to this project to help make it better.

- __URL:__
  - [Enoki](https://github.com/InfectedPacket/Idacraft), https://github.com/InfectedPacket/Idacraft
- __Reference (Chicago):__
  - Racicot, Jonathan. 2016. Enoki (version 1.0.2). Windows/Mac/Linux. Ottawa, Canada.
- __Reference (IEEE):__
  - J. Racicot, Enoki. Ottawa, Canada, 2016.
  
