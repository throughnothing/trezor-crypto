#ifndef __BIP32_H__
#define __BIP32_H__

#include <stdint.h>

#define BIP32_SERIALIZED_LENGTH 112
#define BIP32_IDENTIFIER_LENGTH 20
#define BIP32_FINGERPRINT_LENGTH 4

#define BIP32_VERSION_MAINNET_PUBLIC 0x0488B21E
#define BIP32_VERSION_MAINNET_PRIVATE 0x0488ADE4

#define BIP32_VERSION_TESTNET_PUBLIC 0x043587CF
#define BIP32_VERSION_TESTNET_PRIVATE 0x04358394

typedef struct {
	uint32_t version;
	uint32_t depth;
	// Making this a byte-array to avoid endianness issues
	uint8_t parent_fingerprint[BIP32_FINGERPRINT_LENGTH];
	uint32_t child_num;
	uint8_t private_key[32]; // private_key + chain_code have to
	uint8_t chain_code[32];  // form a continuous 64 byte block
	uint8_t public_key[33];
	char address[35];
	uint8_t identifier[BIP32_IDENTIFIER_LENGTH];
	// Making this a byte-array to avoid endianness issues
	uint8_t fingerprint[BIP32_FINGERPRINT_LENGTH];
} HDNode;

typedef struct {
	uint32_t version;
	uint8_t depth;
	uint32_t parent_fingerprint;
	uint32_t child_num;
	uint8_t chain_code[32];
	uint8_t key[33];
} HDSerializableNode;

extern uint8_t hdnode_coin_version;

void hdnode_from_pub(uint32_t version, uint32_t depth, uint32_t fingerprint, uint32_t child_num, uint8_t *chain_code, uint8_t *public_key, HDNode *out);

void hdnode_new(HDNode *out);
void hdnode_from_seed(uint8_t *seed, int seed_len, HDNode *out);

#define hdnode_descent_prime(X, I) hdnode_descent((X), ((I) | 0x80000000))
void hdnode_descent(HDNode *inout, uint32_t i);

void hdnode_fill_public_key(HDNode *xprv);
void hdnode_fill_address(HDNode *xprv);
void hdnode_fill_identifier(HDNode *node);

void hdnode_serialize_public(HDNode *node, char out[BIP32_SERIALIZED_LENGTH]);
void hdnode_serialize_private(HDNode *node, char out[BIP32_SERIALIZED_LENGTH]);

#endif
