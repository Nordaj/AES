//Jordan Chapman

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include "AES.h"

//State is the current 4x4 block (or matrix) pointer
typedef Byte* State;

static void Encipher(State state, Byte* expandedKey, uint8_t Nr);
static void Decipher(State state, Byte* expandedKey, uint8_t Nr);
static void ExpandKey(const char* cipherKey, char Nk, char* expKey);
static void SubBytes(Byte* val, int len);
static void InvSubBytes(Byte* val, int len);
static void ShiftRows(State state);
static void InvShiftRows(State state);
static void MixColumns(State state);
static void InvMixColumns(State state);
static void AddRoundKey(State state, State roundKey);
static void RotBytes(Byte* val, int len);
static uint8_t GFMultBy2(uint8_t a);
static uint8_t GFMultBy09(uint8_t a);
static uint8_t GFMultBy11(uint8_t a);
static uint8_t GFMultBy13(uint8_t a);
static uint8_t GFMultBy14(uint8_t a);

static const uint8_t Nb = 4;
//Nk is interpreted based on size of key given unless specified
//Nr is Nk + 6 since Nb is always 4

static const Byte sBox[256] = {
	//0   1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,	//0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,	//1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,	//2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,	//3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,	//4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,	//5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,	//6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,	//7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,	//8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,	//9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,	//A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,	//B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,	//C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,	//D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,	//E
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16	//F
};

static const Byte invSBox[256] = {
	//0   1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,	//0
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,	//1
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,	//2
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,	//3
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,	//4
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,	//5
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,	//6
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,	//7
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,	//8
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,	//9
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,	//A
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,	//B
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,	//C
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,	//D
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,	//E
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d	//F
};

static const uint8_t rcon[11] = { 0x00, 0x01,	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

//Encrypt buffer
void AESEncrypt(AESMode mode, Byte* buf, size_t size, const char* cipherKey, const char* iv)
{
	//Get Nk (number of key columns)
	int Nk = (mode & AES_128) ? 4 :
		(mode & AES_192) ? 6 : 8;

	//Expand key
	///Allocates max Nr + 1, not always used but better than heap
	Byte expandedKey[16 * 15] = {0};
	ExpandKey(cipherKey, Nk, expandedKey);

	//Encrypt first block using IV if cbc
	if (mode & AES_CBC)
		AddRoundKey(buf, iv);
	Encipher(buf, expandedKey, Nk + 6);

	//Encrypt the rest
	for (State state = buf + 16; state + 16 <= buf + size; state += 16)
	{
		//XOR if CBC mode (AddRoundKey is just an XOR of blocks)
		if (mode & AES_CBC)
			AddRoundKey(state, state - 16);
	
		//Cipher block
		Encipher(state, expandedKey, Nk + 6);
	}
}

//Decrypt buffer
void AESDecrypt(AESMode mode, Byte* buf, size_t size, const char* cipherKey, const char* iv)
{
	//Get Nk (number of key columns)
	int Nk = (mode & AES_128) ? 4 :
		(mode & AES_192) ? 6 : 8;

	//Expand key
	///Allocates max Nr + 1, not always used but better than heap
	Byte expandedKey[16 * 15] = {0};
	ExpandKey(cipherKey, Nk, expandedKey);

	//Decrypt the rest
	for (State state = buf + size - 16 - (size % 16); state - 16 >= buf; state -= 16)
	{
		//Decipher block
		Decipher(state, expandedKey, Nk + 6);

		//XOR if CBC mode (AddRoundKey is just an XOR of blocks)
		if (mode & AES_CBC)
			AddRoundKey(state, state - 16);
	}

	//Decipher first block using IV if cbc
	Decipher(buf, expandedKey, Nk + 6);
	if (mode & AES_CBC)
		AddRoundKey(buf, iv);
}

//Generates a buffer object from a string
AESBuffer AESGenBuffer(const char* str)
{
	AESBuffer b = {0};

	//Get string size and add padding
	size_t len = strlen(str);
	b.size = len + 16 - (len % 16) + 1;

	//Allocate and fill memory
	b.buf = calloc(1, b.size);
	memcpy(b.buf, str, len);

	return b;
}

//Free's the buffer object
void AESFreeBuffer(AESBuffer* buffer)
{
	free(buffer->buf);
}

//Generate random bytes
void AESGenRandom(char* str, int size)
{
	for (int i = 0; i < size; i++)
		str[i] = rand();
}

//Encipher's a single block
void Encipher(State state, Byte* expandedKey, uint8_t Nr)
{
	//Initial round keys
	AddRoundKey(state, expandedKey);

	//Go through main rounds
	for (int i = 1; i < Nr; i++)
	{
		SubBytes(state, 16);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, &expandedKey[i * 16]);
	}

	//Go through special round
	SubBytes(state, 16);
	ShiftRows(state);
	AddRoundKey(state, &expandedKey[Nr * 16]);
}

//Decipher's a single block
void Decipher(State state, Byte* expandedKey, uint8_t Nr)
{
	//Go through special round
	AddRoundKey(state, &expandedKey[Nr * 16]);
	InvSubBytes(state, 16);
	InvShiftRows(state);

	//Go through main round
	for (int i = Nr - 1; i > 0; i--)
	{
		AddRoundKey(state, &expandedKey[i * 16]);
		InvMixColumns(state);
		InvSubBytes(state, 16);
		InvShiftRows(state);
	}

	//Initial round key
	AddRoundKey(state, expandedKey);
}

//Expands key to be unique for each round
void ExpandKey(const char* cipherKey, char Nk, char* expKey)
{
	//Re useable temp
	uint32_t temp = 0;

	//Copy key over to first columns of expanded
	memcpy(expKey, cipherKey, Nk * 4);

	//Iterate through columns (Nr = Nk + 6 as long as Nb is 4) 
	for (int i = Nk; i < Nb * (Nk + 7); i++)
	{
		//Get the last column
		memcpy(&temp, &expKey[((i - 1) * 4)], 4);

		//If edge column
		if (i % Nk == 0)
		{
			//Rotate, substitute, xor first byte with round constant
			RotBytes(&temp, 4);
			SubBytes(&temp, 4);
			temp ^= rcon[i / Nk];
		}
		else if (Nk == 8 && i % Nk == 4) //If 256 bit key and in middle column
		{
			//Just sub bytes
			SubBytes(&temp, 4);
		}

		//Xor current column with last matrix's corresponding column
		((uint32_t*)expKey)[i] = ((uint32_t*)expKey)[i - Nk] ^ temp;
	}
}

//Substitutes each byte with sBox[byte]
static void SubBytes(Byte* val, int len)
{
	for (int i = 0; i < len; i++)
		val[i] = sBox[val[i]];
}

//Reverses SubBytes
static void InvSubBytes(Byte* val, int len)
{
	for (int i = 0; i < len; i++)
		val[i] = invSBox[val[i]];
}

//Shift rows of a 4x4 column major byte matrix by r bytes to left
static void ShiftRows(State state) //BROKEN
{
	Byte temp;

	//Shift row 1
	temp = state[4 * 0 + 1];
	state[4 * 0 + 1] = state[4 * 1 + 1];
	state[4 * 1 + 1] = state[4 * 2 + 1];
	state[4 * 2 + 1] = state[4 * 3 + 1];
	state[4 * 3 + 1] = temp;

	//Shift row 2
	temp = state[4 * 0 + 2];
	state[4 * 0 + 2] = state[4 * 2 + 2];
	state[4 * 2 + 2] = temp;

	temp = state[4 * 1 + 2];
	state[4 * 1 + 2] = state[4 * 3 + 2];
	state[4 * 3 + 2] = temp;

	//Shift row 3
	temp = state[4 * 3 + 3];
	state[4 * 3 + 3] = state[4 * 2 + 3];
	state[4 * 2 + 3] = state[4 * 1 + 3];
	state[4 * 1 + 3] = state[4 * 0 + 3];
	state[4 * 0 + 3] = temp;
}

//Shift rows of a 4x4 column major byte matrix by r bytes to right
static void InvShiftRows(State state)
{
	Byte temp;

	//Shift row 1
	temp = state[4 * 3 + 1];
	state[4 * 3 + 1] = state[4 * 2 + 1];
	state[4 * 2 + 1] = state[4 * 1 + 1];
	state[4 * 1 + 1] = state[4 * 0 + 1];
	state[4 * 0 + 1] = temp;

	//Shift row 2
	temp = state[4 * 2 + 2];
	state[4 * 2 + 2] = state[4 * 0 + 2];
	state[4 * 0 + 2] = temp;

	temp = state[4 * 3 + 2];
	state[4 * 3 + 2] = state[4 * 1 + 2];
	state[4 * 1 + 2] = temp;

	//Shift row 3
	temp = state[4 * 0 + 3];
	state[4 * 0 + 3] = state[4 * 1 + 3];
	state[4 * 1 + 3] = state[4 * 2 + 3];
	state[4 * 2 + 3] = state[4 * 3 + 3];
	state[4 * 3 + 3] = temp;
}

//Multiply each column in block as a vector the by fixed AES matrix created from polynomial (0x03x^3 + 0x01x^2 + 0x01x + 0x02) in GF(2^8)
static void MixColumns(State state)
{
	uint8_t Tmp, Tm, a0;
	uint8_t* a;

	//Iterate columns
	for (int j = 0; j < 4; j++)
	{
		//Get current column
		a = &state[j * 4];

		//Multiply column as a vector by the fixed AES matrix in GF(2^8)
		//Found this from here, and modified the style a tad: 
		//https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
		Tmp = a[0] ^ a[1] ^ a[2] ^ a[3];
		a0 = a[0];

		Tm = a[0] ^ a[1];
		Tm = GFMultBy2(Tm);
		a[0] ^= Tm ^ Tmp;

		Tm = a[1] ^ a[2];
		Tm = GFMultBy2(Tm);
		a[1] ^= Tm ^ Tmp;

		Tm = a[2] ^ a[3];
		Tm = GFMultBy2(Tm);
		a[2] ^= Tm ^ Tmp;

		Tm = a[3] ^ a0;
		Tm = GFMultBy2(Tm);
		a[3] ^= Tm ^ Tmp;
	}
}

//Multiply each column in block as a vector the by inverse fixed AES matrix created from polynomial (0x0Bx^3 + 0x0Dx^2 + 0x09x + 0x0E) in GF(2^8)
static void InvMixColumns(State state)
{
	uint8_t a[4];

	//Iterate columns
	for (int j = 0; j < 4; j++)
	{
		//Copy current column
		memcpy(a, &state[j * 4], 4);

		//Multiply column as a vector by the fixed AES inverse matrix in GF(2^8)
		state[j * 4 + 0] = GFMultBy14(a[0]) ^ GFMultBy11(a[1]) ^ GFMultBy13(a[2]) ^ GFMultBy09(a[3]);
		state[j * 4 + 1] = GFMultBy09(a[0]) ^ GFMultBy14(a[1]) ^ GFMultBy11(a[2]) ^ GFMultBy13(a[3]);
		state[j * 4 + 2] = GFMultBy13(a[0]) ^ GFMultBy09(a[1]) ^ GFMultBy14(a[2]) ^ GFMultBy11(a[3]);
		state[j * 4 + 3] = GFMultBy11(a[0]) ^ GFMultBy13(a[1]) ^ GFMultBy09(a[2]) ^ GFMultBy14(a[3]);
	}
}

//Xor 128 bit value with 128 bit exp key
static void AddRoundKey(State state, State roundKey)
{
	//Xor in as few commands as possible
	((int64_t*)state)[0] ^= ((int64_t*)roundKey)[0];
	((int64_t*)state)[1] ^= ((int64_t*)roundKey)[1];
}

//Rotates bytes 1 byte to the left, the first will be wrapped
static void RotBytes(Byte* val, int len)
{
	Byte c = val[0];
	memcpy(val, val + 1, len - 1);
	val[len - 1] = c;
}

//Multiplies polynomial by 0x02 in the field GF(2^8)
static uint8_t GFMultBy2(uint8_t a)
{
	//This is done by performing a left shift one bit,
	//if the msbit was 1, it will XOR 0x1B
	return (a << 1) ^ (((a >> 7) & 0x01) * 0x1B);
}

//The following operations found from:
//https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns

//Multiplies polynomial by 0x09 in the field GF(2^8)
static uint8_t GFMultBy09(uint8_t a)
{
	return GFMultBy2(GFMultBy2(GFMultBy2(a))) ^ a;
}

//Multiplies polynomial by 0x0B in the field GF(2^8)
static uint8_t GFMultBy11(uint8_t a)
{
	return GFMultBy2(GFMultBy2(GFMultBy2(a)) ^ a) ^ a;
}

//Multiplies polynomial by 0x0D in the field GF(2^8)
static uint8_t GFMultBy13(uint8_t a)
{
	return GFMultBy2(GFMultBy2(GFMultBy2(a) ^ a)) ^ a;
}

//Multiplies polynomial by 0x0E in the field GF(2^8)
static uint8_t GFMultBy14(uint8_t a)
{
	return GFMultBy2(GFMultBy2(GFMultBy2(a) ^ a) ^ a);
}
