#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_ECB 0b0000
#define AES_CBC 0b1000
#define AES_128 0b0100
#define AES_192 0b0010
#define AES_256 0b0001

typedef enum AESMode
{
	AES_ECB_128 = 0b0100,
	AES_ECB_192 = 0b0010,
	AES_ECB_256 = 0b0001,
	AES_CBC_128 = 0b1100,
	AES_CBC_192 = 0b1010,
	AES_CBC_256 = 0b1001
} AESMode;

typedef uint8_t Byte;

typedef struct AESBuffer
{
	Byte* buf;
	size_t size;
} AESBuffer;

//Encrypt buffer. IV can be NULL if ECB. Will not pad buffer or key
void AESEncrypt(AESMode mode, Byte* buf, size_t size, const char* cipherKey, const char* iv);

//Decrypt buffer. IV can be NULL if ECB. Will not pad buffer or key
void AESDecrypt(AESMode mode, Byte* buf, size_t size, const char* cipherKey, const char* iv);

//Generates a heap allocated padded buffer with a string termination character at the end
AESBuffer AESGenBuffer(const char* str);

//Free's the AESBuffer, must be called
void AESFreeBuffer(AESBuffer* buffer);

//Fills string with random bytes to use as a key or initialization vector
void AESGenRandom(char* str, int size);

#endif //AES_H
