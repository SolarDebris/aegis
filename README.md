# aegis
Automatic Exploitation Generator
                  
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
This will include running the binary with running all three modules in the binary and choosing which exploit to use. It will also include the logging and ctfd submit script. 

### Static Analysis
The static analyis file will check for is things like printf vulnerabilities and snippets of code that have vulnerabilities. It will also check symbol tables, the got, plt, and data. 

### Dynamic Analysis
The dynamic analysis will mostly grab values and addresses that are specific at run time and will colaborate with the 

### Symbolic Analysis
The main goal of the symbolic analysis module will be trying to deal with the edge cases that aren't expected in the dynamic and static analysis section. This is mainly useful for path finding, say if we need to know how to get to a specific function. 

### Exploit Generator
The exploit generator will take all the information from the static, dynamic, and symbolic analysis and create the exploit. 

### Exploit Runner 
The exploit runner will run the binary locally (if there is one) and then check if there is a flag in the output. If there is then send it to the remote server and get the flag.


##### Running the program

```
./aegis -b binary_name (-l libc -r remote)
```
