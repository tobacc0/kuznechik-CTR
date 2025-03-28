# Kuznechik CTR

Symmetrical block cipher algorithm, also known as GOST R 34.12-2015. Comes with the CTR mode of operational.

#### Usage　

Write down the plaintext in "in.txt" file and use makefile to compile and get the result.

```javascript
make
```

To change the key, open the "kuz_test.h" file and change the key. Notice that keeping the key size at 256 bits is mandatory.

```c
static const unsigned char test_key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
};
```
