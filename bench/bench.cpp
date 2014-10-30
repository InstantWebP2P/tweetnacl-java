
#include <iostream>
#include <stdio.h>
#include <sys/time.h>

#include "tweetnacl.h"

using namespace std;

void randombytes(unsigned char * nonce, unsigned long long d) {
	for (unsigned long long i = 0; i < d; i ++)
		nonce[i] = d;
}

int main(int argc, char *argv[]) {

	// Stress on secretBox

	// shared key
	int i;

	unsigned char shk[crypto_secretbox_KEYBYTES];
	for (i = 0; i < sizeof(shk); i ++)
		shk[i] = 0x66;

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	for (i = 0; i < sizeof(nonce); i ++)
		nonce[i] = 0x68;

	// messages
	string m0 = "Helloword, TweetNacl...";

	// cipher A -> B
	cout << "streess on secret box@"+m0;

	timeval curTime;

	for (int t = 0; t < 19; t ++, m0 += m0) {
		const char * mb0 = m0.c_str();

		printf("\n\n\tstreess/%fkB: %d times\n", m0.length()/1000.0, t);

		gettimeofday(&curTime, NULL);
		printf("secret box ...@%6.3f\n", curTime.tv_sec*1000.0 + (curTime.tv_usec / 1000.0));

		unsigned char cab[crypto_secretbox_ZEROBYTES+m0.length()];
		crypto_secretbox((unsigned char *)cab, (unsigned char *)mb0, m0.length(), (unsigned char *)nonce, (unsigned char *)shk);

		gettimeofday(&curTime, NULL);
		printf("... secret box@%6.3f\n", curTime.tv_sec*1000.0 + (curTime.tv_usec / 1000.0));


		gettimeofday(&curTime, NULL);
		printf("\nsecret box open ...@%6.3f\n", curTime.tv_sec*1000.0 + (curTime.tv_usec / 1000.0));

		unsigned char mba[crypto_secretbox_ZEROBYTES+m0.length()];
		crypto_secretbox_open((unsigned char *)mba, (unsigned char *)(cab+16), 16+m0.length(), (unsigned char *)nonce, (unsigned char *)shk);

		gettimeofday(&curTime, NULL);
		printf("... secret box open@%6.3f\n", curTime.tv_sec*1000.0 + (curTime.tv_usec / 1000.0));
	}

	return 0;
}
