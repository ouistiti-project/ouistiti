#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#include "ouistiti/hash.h"

static unsigned long hotp_generator(const hash_t *hash, const char* key, size_t keylen, unsigned long modulus, uint64_t counter)
{
	uint64_t t = counter;
	char T[17] = {0};
//	int Tlen = snprintf(T, 17, "%.016X", (unsigned int)t);
	for (int i = sizeof(t) - 1; i >= 0; i--)
	{
		if ( t == 0) break;
		T[i] = t & 0x0ff;
		t = t >> 8;
	}
	T[0] &= 0x7f;
	int Tlen = sizeof(t);
	void *hmac = hash->initkey(key, keylen);
	hash->update(hmac, T, Tlen);

	char longpassd[HASH_MAX_SIZE];
	int length = hash->finish(hmac, longpassd);
	int offset = longpassd[ length - 1] & 0x0F;
	uint32_t binary = ((longpassd[ offset] & 0x7F) << 24) |
		((longpassd[ offset + 1] & 0xFF) << 16) |
		((longpassd[ offset + 2] & 0xFF) << 8) |
		(longpassd[ offset + 3] & 0xFF);
	uint32_t otp = binary % modulus;
	return otp;
}

static unsigned long totp_generator(const hash_t *hash, const char* key, size_t keylen, unsigned long modulus, int period)
{
	long t0 = 0;
	long x = period;
//#ifndef DEBUG
	long t = (time(NULL) - t0 ) / x;
//#else
//	time_t t = 56666053;
//#endif
	return hotp_generator(hash, key, keylen, modulus, t);
}

void otp_url(const unsigned char* key, unsigned int keylen, const char *user, const char *issuer)
{
	void *base32state = base32->encoder.init();
	char *keyb32 = malloc((int)keylen * 2);
	size_t keyb32len = base32->encoder.update(base32state, keyb32, key, keylen);
	keyb32len += base32->encoder.finish(base32state, keyb32 + keyb32len);
	free(base32state);
	while (keyb32[keyb32len - 1] == '=') keyb32len --;
	printf("otpauth://totp/%s:%s?secret=%.*s&issuer=%s\n", issuer, user, (int)keyb32len, keyb32, issuer);
	free(keyb32);
}
#if 1
int main(int argc, const char *argv[])
{
	const char *key = argv[1];
	otp_url(key, strlen(key), "mch@example.com", "test");
	unsigned int otp = totp_generator(hash_macsha1, key, strlen(key), 100000000, 30);
	printf("%u\n", otp);
	return 0;
}
#else
#ifdef RFC4226
int main(void)
{
	// test from RFC4226 Appendix D
	const char key[] = "12345678901234567890";
	const uint32_t expected[] = {755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489};

	for (uint64_t i = 0; i < 10; i++)
	{
		uint32_t otp = hotp_generator(hash_macsha1, key, sizeof(key) - 1, 1000000, i);
		printf("%u ", otp);
		if (otp != expected[i])
			fprintf(stderr, "HOTP computing error %u/%u\n", otp, expected[i]);
	}
	printf("\n");
	return 0;
}
#else
int main(void)
{
	// test from RFC6238 Appendix B
	const char key[] = "12345678901234567890";
	const long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
	const long T0 = 0;
	const int step = 30;
	const uint32_t expected[] = {94287082, 7081804, 14050471, 89005924, 69279037, 65353130};

	for (int i = 0; i < (sizeof(testTime) / sizeof(long)); i++)
	{
		uint32_t otp = hotp_generator(hash_macsha1, key, sizeof(key) - 1, 100000000, (testTime[i] - T0)/ step);
		printf("%u ", otp);
		if (otp != expected[i])
			fprintf(stderr, "HOTP computing error %u/%u\n", otp, expected[i]);
	}
	printf("\n");
	return 0;
}
#endif
#endif
