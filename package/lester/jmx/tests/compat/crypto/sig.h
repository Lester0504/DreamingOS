#ifndef JMX_TEST_CRYPTO_SIG_H
#define JMX_TEST_CRYPTO_SIG_H

#include <linux/errno.h>
#include <linux/types.h>

/*
 * Ed25519 verification stand-in.
 *
 * The kernel's real transform is unavailable in a host fixture, so the outcome
 * is injected: jmx_test_sig_available decides whether allocation succeeds
 * (PROVIDER_UNAVAIL when it does not) and jmx_test_sig_verify_result decides
 * whether a signature verifies (TAMPERED when it does not).  Those are exactly
 * the two branches the gate contract cares about, and driving them explicitly
 * is what lets a fixture assert that a tampered credential cannot reach
 * bootstrap fail-open.
 */
struct crypto_sig {
	int in_use;
};

extern int jmx_test_sig_available;
extern int jmx_test_sig_verify_result;
extern struct crypto_sig jmx_test_sig_tfm;
extern u8 jmx_test_sig_digest[128];
extern unsigned int jmx_test_sig_digest_len;

#define IS_ERR(pointer) ((unsigned long)(void *)(pointer) >= (unsigned long)-4095)
#define PTR_ERR(pointer) ((long)(pointer))
#define ERR_PTR(error) ((void *)(long)(error))

static inline struct crypto_sig *crypto_alloc_sig(const char *name, u32 type,
						  u32 mask)
{
	(void)name;
	(void)type;
	(void)mask;
	if (!jmx_test_sig_available)
		return ERR_PTR(-ENOENT);
	return &jmx_test_sig_tfm;
}

static inline void crypto_free_sig(struct crypto_sig *tfm)
{
	(void)tfm;
}

static inline int crypto_sig_set_pubkey(struct crypto_sig *tfm, const u8 *key,
					unsigned int keylen)
{
	(void)tfm;
	(void)key;
	(void)keylen;
	return 0;
}

static inline int crypto_sig_verify(struct crypto_sig *tfm, const void *src,
				    unsigned int slen, const void *digest,
				    unsigned int dlen)
{
	const u8 *bytes = digest;
	unsigned int capture;
	unsigned int i;

	(void)tfm;
	(void)src;
	(void)slen;
	capture = dlen < sizeof(jmx_test_sig_digest) ?
		  dlen : sizeof(jmx_test_sig_digest);
	jmx_test_sig_digest_len = capture;
	for (i = 0; i < capture; i++)
		jmx_test_sig_digest[i] = bytes[i];
	return jmx_test_sig_verify_result;
}

#endif
