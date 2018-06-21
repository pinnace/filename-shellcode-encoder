# filename-shellcode-encoder

This encoder was written for a module for the OSCE.

It uses the technique presented by muts in this exploit; https://www.exploit-db.com/exploits/5342/

This encoder assumes that the following instructions are available:
AND EAX - \x25
SUB EAX - \x2D
PUSH EAX - \x50
POP ESP - \x5C
INC ECX - \x41

With these instructions, an arbitrary blob of shellcode is encoded using an arbitrary allowed characters set
