# Binary File Splitter
Takes a binary file and splits it in `chunks` of a designated size in order to help with AV evasion.

```text
Binary file splitter 1.0.0

Usage: split.py <binary-file> <chunk-size>
```

## Running the Splitter
```bash
docker run -it --rm --name my-running-script -v "$PWD":/usr/src/myapp -v "/tmp/binSplit":"/tmp/binSplit" -w /usr/src/myapp python:2 python binsplit.py cat 100
```

The output will look as follows:

```text
Usage: split.py cat 100
Splitting 'cat' (394 chunks of 100 bytes)
Files will be stored in: /tmp/binSplit
/tmp/binSplit/cat_0 - Offset: 0
/tmp/binSplit/cat_1 - Offset: 100
/tmp/binSplit/cat_2 - Offset: 200
/tmp/binSplit/cat_3 - Offset: 300
/tmp/binSplit/cat_4 - Offset: 400
/tmp/binSplit/cat_5 - Offset: 500
/tmp/binSplit/cat_6 - Offset: 600
/tmp/binSplit/cat_7 - Offset: 700

... snipped ...

/tmp/binSplit/cat_390 - Offset: 39000
/tmp/binSplit/cat_391 - Offset: 39100
/tmp/binSplit/cat_392 - Offset: 39200
/tmp/binSplit/cat_393 - Offset: 39300
```

Perfoming `file` on `/tmp/binSplit` shows chunks of the executable:

```text
... snipped ...

/tmp/binSplit/cat_159: Non-ISO extended-ASCII text, with no line terminators
/tmp/binSplit/cat_16:  data
/tmp/binSplit/cat_160: data
/tmp/binSplit/cat_161: SVr2 curses screen image, big-endian
/tmp/binSplit/cat_162: amd 29k coff noprebar executable
/tmp/binSplit/cat_163: data
/tmp/binSplit/cat_164: data
/tmp/binSplit/cat_165: data
/tmp/binSplit/cat_166: data
/tmp/binSplit/cat_167: data
/tmp/binSplit/cat_168: data
/tmp/binSplit/cat_169: data
/tmp/binSplit/cat_17:  Targa image data - RGB 2 x 65536 x 1 +9 +2 "\010"
/tmp/binSplit/cat_170: data

... snipped ...
```

## Checking for AV Signatures
To look for any signatures in the chunks run *Clam AV*:
```text
 clamscan /tmp/binSplit/*
Loading:     7s, ETA:   0s [========================>]    2.03M/2.03M sigs
Compiling:   2s, ETA:   0s [========================>]       41/41 tasks

/tmp/binSplit/cat_0: OK
/tmp/binSplit/cat_1: OK
/tmp/binSplit/cat_10: OK
/tmp/binSplit/cat_100: OK
/tmp/binSplit/cat_101: OK
/tmp/binSplit/cat_102: OK

... snipped ...

/tmp/binSplit/cat_99: OK

----------- SCAN SUMMARY -----------
Known viruses: 2032854
Engine version: 1.0.2
Scanned directories: 0
Scanned files: 394
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 9.844 sec (0 m 9 s)
Start Date: 2023:12:04 23:36:36
End Date:   2023:12:04 23:36:46
```
