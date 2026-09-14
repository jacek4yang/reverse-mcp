// simple test binary for reverse-mcp integration testing
#include <stdio.h>
#include <string.h>

int helper(int a, int b) {
    return a + b;
}

int decrypt_packet(unsigned char *buf, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
    return len;
}

int dispatch(int cmd) {
    switch (cmd) {
    case 1: return 10;
    case 2: return 20;
    case 3: return 30;
    default: return -1;
    }
}

int main(int argc, char **argv) {
    char msg[] = "usage: simple <file>";
    int x = helper(1, 2);
    int y = dispatch(3);
    unsigned char data[8];
    memcpy(data, "12345678", 8);
    decrypt_packet(data, 8, 0xAA);
    printf("%s %d %d\n", msg, x, y);
    return 0;
}
