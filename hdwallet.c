#include <stdio.h>
#include <string.h>

#include "bip32.h"

uint8_t *fromhex(const char *str)
{
    static uint8_t buf[128];
    uint8_t c;
    size_t i;
    for (i = 0; i < strlen(str) / 2; i++) {
        c = 0;
        if (str[i*2] >= '0' && str[i*2] <= '9') c += (str[i*2] - '0') << 4;
        if (str[i*2] >= 'a' && str[i*2] <= 'f') c += (10 + str[i*2] - 'a') << 4;
        if (str[i*2+1] >= '0' && str[i*2+1] <= '9') c += (str[i*2+1] - '0');
        if (str[i*2+1] >= 'a' && str[i*2+1] <= 'f') c += (10 + str[i*2+1] - 'a');
        buf[i] = c;
    }
    return buf;
}

int main() {
    HDNode node;
    char identifier[BIP32_IDENTIFIER_LENGTH];
    char serialized_public[BIP32_SERIALIZED_LENGTH];
    /*hdnode_new(&node);*/
    hdnode_from_seed( fromhex("000102030405060708090a0b0c0d0e0f"), 16, &node);

    hdnode_identifier(&node, identifier);
    hdnode_serialize_public(&node, serialized_public);
    printf("address: %s, identifier: %s\n", node.address, identifier);
    return 1;
}
