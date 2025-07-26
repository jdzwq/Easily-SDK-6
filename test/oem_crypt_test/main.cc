
#include <oem.h>

#ifdef _OS_WINDOWS
#include <conio.h>
#endif

int main(int argc, char* argv[])
{
	//aes_self_test(1);

	//arc4_self_test(1);

	//base64_self_test(1);

	//chacha20_self_test(1);

	//chachapoly_self_test(1);

	//ctr_drbg_self_test(1);

	//hmac_drbg_self_test(1);

	//des_self_test(1);

	//dhm_self_test(1);

	//ecdh_x25519_test(1);

	//ecdh_test(1);

	//ecp_self_test(1);

	//ecp_test_parse(1);

	//entropy_self_test(1);

	//gcm_self_test(1);

	//test_hkdf(1);

	//md2_self_test(1);

	//md4_self_test(1);

	//md5_self_test(1);

	//mpi_self_test(1);

	//poly1305_self_test(1);

	//ripemd160_self_test(1);

	//rsa_self_test(1);

	//rsa_test_parse(1);

	//sha1_self_test(1);

	//sha256_self_test(1);

	//sha512_self_test(1);

	//sm3_self_test(1);

	//timing_self_test(1);

	x509_self_test(1);

#ifdef _OS_WINDOWS
	getch();
#endif

	return 0;
}

