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

void hex_identifier (HDNode *node, char *hex_identifier) {
    char *ptr = hex_identifier;
    for( int i = 0; i < 20; i++ ) {
        sprintf(ptr, "%02x", node->identifier[i] );
        ptr += 2;
    }
}

void print_node (HDNode *node) {
    printf("Depth: %d ", node->depth);
    printf("Fingerprint: ");
        printf("%02x", node->parent_fingerprint & 0x000000FF);
        printf("%02x", node->parent_fingerprint >> 8 & 0x000000FF);
        printf("%02x", node->parent_fingerprint >> 16 & 0x000000FF);
        printf("%02x", node->parent_fingerprint >> 24 & 0x000000FF);
    printf(" Identifier: ");
    for(int i = 0; i < BIP32_IDENTIFIER_LENGTH; i++) {
        printf("%02x",node->identifier[i]);
    }
    printf("\n");
}

int main() {
    HDNode node;
    char identifier_1[BIP32_IDENTIFIER_LENGTH*2];

    /*hdnode_new(&node);*/
    hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16, &node);
    print_node( &node );
    hdnode_descent( &node, 0 );
    print_node( &node );
    hdnode_descent( &node, 0 );
    print_node( &node );
    hdnode_descent( &node, 0 );
    print_node( &node );

    /*hex_identifier(&node, identifier_1);*/
    /*printf("address: %s, identifier: %s\n", node.address, identifier_1);*/
    return 1;
}

