# Ghidra
​
Ghidra is a reverse engineering tool that allows you to disassemble binaries in order to get a better understanding of how they work. It is completely [open source](https://github.com/nationalsecurityagency/ghidra) allowing anyone to use it.
​
The best feature of Ghidra for students learning about reverse engineering is the decompiler. Just as a compiler transforms C code into machine language, the decompiler transforms machine language into readable C code. This makes analysis of the binary much simpler, especially for those not very familiar with reading assembly language. Here are some of the important windows that will help you reverse engineer the binaries in this course
​
### Listing
This is your standard disassembled view. It shows the assembly as you would see it when using `objdump` or `gdb`. You can add comments to the assembly in order to keep track of reverse engineering.
​
![](assets/listing.png)
​
### Decompiler
This view shows the decompiled C code. It is much easier to reverse engineer C code since we are more used to it and have learned about different vulnerabilites involving it.
​
![](assets/decompiler.png)
​
The decomiled code will not be completely readable when you first load it. I will discuss modifying the compiled code later on in order to improve readability. The reference manual for Ghidra lists the following capabilities of the decompiler:
​
**Recovers Expressions** - The decompiler does full dataflow analysis which allows it to perform **slicing** on functions. Slicing is the process of reducing a function to its core components such that for any given input, it produces the same output. The most tangible benefit to the user is that complicated expressions, which have been split into distinct operations/instructions and then mixed together with other instructions by the compiling/optimizing process, are reconstituted into a single expression again by the decompiler.
​
**Recovers High-Level Scoped Variables** -  The decompiler understands how compilers use processor stacks and registers to implement variables with different scopes within a function. Data-flow allows it to follow what was originally a single variable as it moves from the stack, into a register, into a different register, etc. Thus it can effectively recover the original programs *concept* of a variable, minimizing the need to introduce artificial variables in the output.
​
**Recovers Function Parameters** - The decompiler understands the parameter passing conventions of the compiler and can reconstruct the form of the original function call.
​
**Uses Data type, Name, and Signature Annotations** -  The decompiler automatically pulls in all the different data types and variable names that the user has applied to functions, and the C output is altered to reflect this. High-level variables are appropriately named, structure fields and array indices are calculated and displayed with correct syntax, constant char pointers are replaced with appropriate quoted strings, etc.
​
**Performs Local Type Propagation** - In the absence of information, the decompiler does its best to fill in information from what it does know. Variables whose data type has not been explicitly labeled by the user can often by recovered by seeing how the variable is used or by allowing the known data types to propagate.
​
**Can be used to Automatically Recover Structure Fields** - The decompiler can be leveraged to recover references to a structure
​
### Function Call Graph
This representation of a program will be familiar to anyone who has used IDA before. Every function call is graphed as a tree, showing you every other function a function calls. This can give you insight about what a specific function's purpose is without needing to look at the assembly or decompiled code.
​
![](assets/functioncallgraph.png)
​
### Symbol Table
The symbol table will show you a list of symbols that are defined in the binary, such as functions or global variables. Many of the binaries in this class are compiled with debugging symbols enabled allowing you to see function names.
​
![](assets/symboltable.png)
​
The symbol tree itself doesn't necessarily help with exploitation, but it can help give you a better overview of the binary, and certain function names may provide hints as to where you might find a vulnerability
​
## Using Ghidra to solve binary challenges
As powerful as Ghidra is, it won't just *give* you the answer. You'll still need to work for it, although it can make it quite a bit easier. Using the features descibed above, you can recreate the C code as it was written originally, which can then be scoured for bugs. As mentioned above, the original decompiled C code isn't the easiest to read right off the bat. Let's see how we can clean it up a little bit in order to understand it better.
​
Let's take a look at the `validate_name` function from the [Protostar Challenge `final0`](https://github.com/xXKingRalphXx/Protostar-Binaries/blob/master/final0). I found this method by beginning with the main method, then stepping through the function call graph to `background_process` and then `validate_name`. 
The original decompiled code looks like
```c
void validate_name(int param_1) {
  int local_10;
  
  local_10 = 0;
  while( true ) {
    if (*(char *)(local_10 + param_1) == '\0') {
      return;
    }
    if ((((*(char *)(local_10 + param_1) < 'a') || ('z' < *(char *)(local_10 + param_1))) &&
        ((*(char *)(local_10 + param_1) < 'A' || ('Z' < *(char *)(local_10 + param_1))))) &&
       ((*(char *)(local_10 + param_1) < '0' || ('9' < *(char *)(local_10 + param_1))))) break;
    local_10 = local_10 + 1;
  }
  fwrite("background_process: incorrect name\n",1,0x23,stderr);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
The first thing that stands out is all the casts to  `char *` inside the while loop. Let's see what value is being passed in to validate_name. To find out where validate name is called, we can look at the function call graph (**Window -> Function Call Graph**). The function call graph shows that `validate_name` is called by two methods, `background_process` and `restart_process`. Let's look at the `background_process` method to see where `validate_name` is called. Double click on the `background_process` circle to open it in the listing and decompiler view. 
​
Line 16 of `background_process` calls `validate_name` with argument `param_1`, which is of type `int`. Let's go further up the stack to see where `background_process` is called. `background_process` is only called from `main`, which calls `background_process` with the arguments `"((int)final0",0,0)`. Hm, it's casting the string as an integer. Let's adjust the signature of `background_process` to accept a cstring, rather than an int. To do so, navigate back to `background_process` (either through the symbol tree, function call graph, or simply double clicking on the method in the decompiler view), right click on the method signature, and select **Edit Function Signature**. Modify `param_1` to be of type `char*`. Now if we look at the `main` method, it isn't casting "final0" to an `int`. However, now `background_process` casts `param_1` to an `int` before sending to `validate_name`. Modify the method signature of `validate_name` as well. 
​
You should notice when you do this that all of the dereferences to the casts to `char*` (`*(char *)(local_10 + param_1)`) get replaced with simple array lookups, which makes sense. `param_1` was an address, `local_10` was an offset from that address. Then to get the char at that address, you cast it as a pointer to a char, and then dereference it. 
​
Now it's clear what the function does. It checks each character in the string to see if it is an alphanumeric character. If not, the program exits.
​
To clean up the code a little more, we can rename the variables `param_1` and `local_10` to `name` and `i`. To rename a variable, simple click on it and press `L`. The final code looks like 
​
```c
void validate_name(char *name) {
  int i;
  
  i = 0;
  while( true ) {
    if (name[i] == '\0') {
      return;
    }
    if ((((name[i] < 'a') || ('z' < name[i])) && ((name[i] < 'A' || ('Z' < name[i])))) &&
       ((name[i] < '0' || ('9' < name[i])))) break;
    i = i + 1;
  }
  fwrite("background_process: incorrect name\n",1,0x23,stderr);
  exit(1);
}
```
Now this looks like code that a human might actually write. 
​
## Useful resources and tutorials
​
### Ghidra Help
You can access Ghidra's builtin help by going to **Help -> Contents**. 
​
### Ghidra Ninja
[Ghidra Ninja](https://www.youtube.com/channel/UC3S8vxwRfqLBdIhgRlDRVzw) is a youtube channel that has 3 videos showing how to use ghidra to reverse software. His video about reversing a firmware scheme gives more examples of how to declutter the decompiled code, and if you know about 
