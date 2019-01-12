# AESimplementation

The project is written in the aes.c file; run `make` from terminal to compile to the executable `aes`. 
Run `make clean` to remove the executable for more secure recompilation.

Run the project with this:
```
./aes [plaintextfile] [keyfile]
```
Replace `[plaintextfile] [keyfile]` with their respective file names. The order above must be followed for correct execution. 
The following file dependencies must be included:   

* `'aes_sbox.txt'`
* `'aes_inv_sbox.txt'`

These files should be included in the same directory with the correct names.

An output from the most recent run:

```
--> PlainText Filename: test1plaintext.txt
--> Key Filename:       test1key.txt

--> PlainText: 
32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34 
--> Key: 
2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c 

--> Key Schedule: 
2b7e1516, 28aed2a6, abf71588, 09cf4f3c, 
a0fafe17, 88542cb1, 23a33939, 2a6c7605, 
f2c295f2, 7a96b943, 5935807a, 7359f67f, 
3d80477d, 4716fe3e, 1e237e44, 6d7a883b, 
ef44a541, a8525b7f, b671253b, db0bad00, 
d4d1c6f8, 7c839d87, caf2b8bc, 11f915bc, 
6d88a37a, 110b3efd, dbf98641, ca0093fd, 
4e54f70e, 5f5fc9f3, 84a64fb2, 4ea6dc4f, 
ead27321, b58dbad2, 312bf560, 7f8d292f, 
ac7766f3, 19fadc21, 28d12941, 575c006e, 
d014f9a8, c9ee2589, e13f0cc8, b6630ca6

--> ENCRYPTION PROCESS 
------------------------
Round 1
---------
19 3d e3 be  a0 f4 e2 2b  9a c6 8d 2a  e9 f8 48 08 

Round 2
---------
a4 9c 7f f2  68 9f 35 2b  6b 5b ea 43  02 6a 50 49 

Round 3
---------
aa 8f 5f 03  61 dd e3 ef  82 d2 4a d2  68 32 46 9a 

Round 4
---------
48 6c 4e ee  67 1d 9d 0d  4d e3 b1 38  d6 5f 58 e7 

Round 5
---------
e0 92 7f e8  c8 63 63 c0  d9 b1 35 50  85 b8 be 01 

Round 6
---------
f1 00 6f 55  c1 92 4c ef  7c c8 8b 32  5d b5 d5 0c 

Round 7
---------
26 0e 2e 17  3d 41 b7 7d  e8 64 72 a9  fd d2 8b 25 

Round 8
---------
5a 41 42 b1  19 49 dc 1f  a3 e0 19 65  7a 8c 04 0c 

Round 9
---------
ea 83 5c f0  04 45 33 2d  65 5d 98 ad  85 96 b0 c5 

Round 10
---------
eb 40 f2 1e  59 2e 38 84  8b a1 13 e7  1b c3 42 d2 

--> Cipher Text
-----------------
39 25 84 1d  02 dc 09 fb  dc 11 85 97  19 6a 0b 32 

--> DECRYPTION PROCESS 
------------------------
Round 10
---------
eb 40 f2 1e  59 2e 38 84  8b a1 13 e7  1b c3 42 d2 

Round 9
---------
ea 83 5c f0  04 45 33 2d  65 5d 98 ad  85 96 b0 c5 

Round 8
---------
5a 41 42 b1  19 49 dc 1f  a3 e0 19 65  7a 8c 04 0c 

Round 7
---------
26 0e 2e 17  3d 41 b7 7d  e8 64 72 a9  fd d2 8b 25 

Round 6
---------
f1 00 6f 55  c1 92 4c ef  7c c8 8b 32  5d b5 d5 0c 

Round 5
---------
e0 92 7f e8  c8 63 63 c0  d9 b1 35 50  85 b8 be 01 

Round 4
---------
48 6c 4e ee  67 1d 9d 0d  4d e3 b1 38  d6 5f 58 e7 

Round 3
---------
aa 8f 5f 03  61 dd e3 ef  82 d2 4a d2  68 32 46 9a 

Round 2
---------
a4 9c 7f f2  68 9f 35 2b  6b 5b ea 43  02 6a 50 49 

Round 1
---------
19 3d e3 be  a0 f4 e2 2b  9a c6 8d 2a  e9 f8 48 08 

--> Plain Text
-----------------
32 43 f6 a8  88 5a 30 8d  31 31 98 a2  e0 37 07 34 

End of Processing
```