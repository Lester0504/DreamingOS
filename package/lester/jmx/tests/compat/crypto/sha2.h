#ifndef JMX_TEST_CRYPTO_SHA2_H
#define JMX_TEST_CRYPTO_SHA2_H

#include <openssl/sha.h>

#include <linux/types.h>

static inline void sha256(const void *data, unsigned int length, u8 out[32])
{
	SHA256((const unsigned char *)data, length, out);
}

#endif
