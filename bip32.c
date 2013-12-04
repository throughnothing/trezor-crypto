#include <string.h>

#include "bignum.h"
#include "bip32.h"
#include "ecdsa.h"
#include "hmac.h"
#include "rand.h"
#include "ripemd160.h"
#include "sha2.h"

uint8_t hdnode_coin_version = 0x00;

void hdnode_from_pub(uint32_t version, uint32_t depth, uint32_t fingerprint, uint32_t child_num, uint8_t *chain_code, uint8_t *public_key, HDNode *out)
{
	out->version = version;
	out->depth = depth;
    // This should be the parent fingerprint
	memcpy(&out->parent_fingerprint, &fingerprint, 4);
	out->child_num = child_num;
	memcpy(out->chain_code, chain_code, 32);
	memcpy(out->public_key, public_key, 33);
	memset(out->private_key, 0, 32);
	hdnode_fill_address(out);
}

void hdnode_new(HDNode *out)
{
    int i;
    uint32_t data[15];

    init_rand();
    for (i = 0; i < 16; i++) {
        data[i] = random32();
    }
    hdnode_from_seed((uint8_t *)data, 16, out);
}

void hdnode_from_seed(uint8_t *seed, int seed_len, HDNode *out)
{
	out->version = BIP32_VERSION_MAINNET_PRIVATE;
	out->depth = 0;
	*out->parent_fingerprint = 0x00000000;
	out->child_num = 0;
	// this can be done because private_key[32] and chain_code[32]
	// form a continuous 64 byte block in the memory
	hmac_sha512((uint8_t *)"Bitcoin seed", 12, seed, seed_len, out->private_key);
	hdnode_fill_public_key(out);
	hdnode_fill_address(out);
	hdnode_fill_identifier(out);
}

void hdnode_descent(HDNode *inout, uint32_t i)
{
	uint8_t data[1 + 32 + 4];
	bignum256 a, b;

	// First 32-bits of the identifier is the fingerprint
	memcpy(&inout->parent_fingerprint, &inout->fingerprint, 4 );
	/*inout->parent_fingerprint = inout->fingerprint;*/

	if (i & 0x80000000) { // private derivation
		data[0] = 0;
		memcpy(data + 1, inout->private_key, 32);
	} else { // public derivation
		memcpy(data, inout->public_key, 33);
	}
	write_be(data + 33, i);

	bn_read_be(inout->private_key, &a);

	// this can be done because private_key[32] and chain_code[32]
	// form a continuous 64 byte block in the memory
	hmac_sha512(inout->chain_code, 32, data, sizeof(data), inout->private_key);

	bn_read_be(inout->private_key, &b);
	bn_addmod(&a, &b, &order256k1);

	inout->depth++;
	inout->child_num = i;
	bn_write_be(&a, inout->private_key);

	hdnode_fill_public_key(inout);
	hdnode_fill_address(inout);
    hdnode_fill_identifier(inout);
}

void hdnode_fill_public_key(HDNode *xprv)
{
	ecdsa_get_public_key33(xprv->private_key, xprv->public_key);
}

void hdnode_fill_identifier(HDNode *node)
{
	uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
	SHA256_Raw((uint8_t *) node->public_key, 33, sha256_hash);
	ripemd160(sha256_hash, SHA256_DIGEST_LENGTH, node->identifier);
	memcpy(&node->fingerprint, &node->identifier, 4);
}

void hdnode_fill_address(HDNode *xprv)
{
	ecdsa_get_address(xprv->public_key, hdnode_coin_version, xprv->address);
}

void hdnode_serialize_public(HDNode *node, uint8_t out[BIP32_SERIALIZED_LENGTH])
{
	HDSerializableNode snode;

	snode.version = BIP32_VERSION_MAINNET_PUBLIC;
	snode.depth = (uint8_t) node->depth;
	snode.child_num = node->child_num;
	memcpy(&snode.parent_fingerprint, &node->parent_fingerprint, 4);
	memcpy(snode.chain_code, node->chain_code, 32);
	memcpy(snode.key, node->public_key, 33);

	uint8_t ripemd160_hash[20], sha256_hash[SHA256_DIGEST_LENGTH];
	SHA256_Raw((uint8_t *) &snode, 78, sha256_hash);
	ripemd160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);
}

void hdnode_serialize_private(HDNode *node, uint8_t out[BIP32_SERIALIZED_LENGTH])
{

}
