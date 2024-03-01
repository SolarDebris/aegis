# aegis

Automatic Exploitation Generator Instrumentation Service

> python script that automatically exploits binaries

```
                  /¯¯\
                  \__/
                   ||
                   ||
                  |  |
                  |  |
                  |  |
                  |  |
                  |  |
                  |  |
              .--.----.--.
            .-----\__/-----.
    ___---¯¯////¯¯|\/|¯¯\\\\¯¯---___
 /¯¯ __O_--////   |  |   \\\\--_O__ ¯¯\
| O?¯      ¯¯¯    |  |    ¯¯¯      ¯?O |
|  '    _.-.      |  |      .-._    '  |
|O|    ?..?      ./  \.      ?..?    |O|
| |     '?. .-.  | /\ |  .-. .?'     | |
| ---__  ¯?__?  /|\¯¯/|\  ?__?¯  __--- |
|O     \         ||\/ |         /     O|
|       \  /¯?_  ||   |  _?¯\  /       |
|       / /    - ||   | -    \ \       |
|O   __/  | __   ||   |   __ |  \__   O|
| ---     |/  -_/||   |\_-  \|     --- |
|O|            \ ||   | /            |O|
\ '              ||   |        ^~DLF ' /
 \O\    _-¯?.    ||   |    .?¯-_    /O/
  \ \  /  /¯¯¯?  ||   |  ?¯¯¯\  \  / /
   \O\/   |      ||   |      |   \/O/
    \     |      ||   |      |     /
     '.O  |_     ||   |     _|  O.'
        '._O'.__/||   |\__.'O_.'
           '._ O ||   | O _.'
              '._||   |_.'
                 ||   |
                 ||   |
                 | \/ |
                 |  | |
                  \ |/
                   \/
```

### Project Structure

This is an updated version of RageAgainstTheMachine that is meant to vastly improve on in terms of project structure, exploits, and user interface. For some of the tools and libraries it uses Headless Binaryninja, ROPgadget, pwntools, and angr. For this I have split up the categories into three different files or categories. The first category is in static analysis which mainly uses headless binaryninja. The goal of this is to identify what type of problem this is and to then grab all the information that is needed for the exploit. The second category is dynamic analysis using a debugger. The purpose for this is also to grab information but also to grab information that static analysis can't grab.

### Script

The ./aegis script is what will setup the control flow for analyzing and exploiting the binary. It will also deal with multithreading and submitting stuff to ctfd. 
To automatically submit flags with ctfd you need to have an environment variable `CTFD_TOK` and set it to your ctfd token. You will also need to run the script `get_chals_list.sh` which
will grab a list of all of the challenges and put it into `bininfo/challenges.csv`. To run it multithreaded add `-thread` when you run the command. To exploit multiple files, run `./aegis -batch (bininfo/challenges.csv)` or `./aegis -batch bins/`


### Static Analysis

The static analyis file, `rage/machine.py` will check for is things like printf vulnerabilities and snippets of code that have vulnerabilities using the binaryninja python api. It will also check symbol tables, the got, plt, and data.
It will also find rop gadgets using ROPgadget as well and sort for the most efficient gadget. 

### Dynamic Analysis

The dynamic analysis will mostly grab values and addresses that are specific at run time and will colaborate with the static analysis.
The main purpose will be to try to either wrap GDB to make it headless or to use the binaryninja debugger when it comes out.

### Symbolic Analysis

The main goal of the symbolic analysis module will be trying to deal with the edge cases that aren't expected in the dynamic and static analysis section. This is mainly useful for path finding, say if we need to know how to get to a specific function.
This is in the `rage/rage.py` file and uses angr to symbollically find the padding for the buffer overflow.

### Exploit Management

The exploit generator will take all the information from the static, dynamic, and symbolic analysis and create parts of the exploit, send the exploit and verify it.'
The file is `rage/against.py` and where exploits can be added. 

##### Running the program

```
./aegis -bin binary_name (-ip service -port port -ctfd ctfd_site -id ctfd_chal_id -lib libc)
```

##### Problem Set and Methodology

###### Stack Buffer Overflow

```

Variable Overflow

Instruction Pointer Overwrite (Ret2Win)

Return Oreinted Programming

    * Return to System
    * Return to Execve
    * Return to Syscall
      * execve("/bin/sh")
      * open sendfile
    * Return to Libc
      * Given libc address
      * Libc puts leak
      * Libc format leak
    * Write Primitives
    * SIGROP
    * Ret2DLResolve

```

###### Format Vulnerabilities

```
Format Stack Leak
Format Variable Write
Format GOT overwrite
Format Leak Canary

```

###### Array Abuse

```
Index Array Out of Bounds
```

### Installation

`pip3 install -r requirements.txt`

Make sure to also install Binary Ninja Commercial
