# Junpacker
Dynamic unpacker based on [Speakeasy](https://github.com/fireeye/speakeasy).
## How it works
Executes target binary in emulator. Whenever memory jump to original entry point (```OEP```) is encountered, dumps executable image and tries to rebuild it. For most of the simple packers, the first memory jump would mean that image is already unpacked. In more complex scenarios, you can specify the number of jumps needed for unpacking with the `--jump` option. There are some examples in the ```test_samples``` to play with.
## Features
- helps with simple packers (such as ```UPX```)
- helps with custom or modified packers
- rebuilds working unpacked executable
- tries to restore import table
- tested a little bit with ```UPX```, ```ASPack``` and ```FSG```
- platform independent
- safe to use on your host OS
## Usage
```sh
usage: junpacker.py [-h] [-v] [-o OUTPUT] [-j JUMP] [-t TIMEOUT] pe_file

positional arguments:
  pe_file               path to input PE file

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         be verbose
  -o OUTPUT, --output OUTPUT
                        path to output PE file
  -j JUMP, --jump JUMP  number of memory jumps to ignore (default 0)
  -t TIMEOUT, --timeout TIMEOUT
                        timeout in seconds (default 10)
```
## Examples
```sh
python junpacker.py test_samples\upx_whoami.exe_
python junpacker.py test_samples\pec_whoami.exe_ -j 5
```