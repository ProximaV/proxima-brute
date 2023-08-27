
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include "iaesni.h"

#include "types.h"
#include <windows.h>

#define MAXTHREADS 192


// Define the structs
typedef struct {
    int index;
    size_t length;
    unsigned char* values;
} IndexData;

typedef struct MyData {
    int val1;
} MYDATA, * PMYDATA;


// Define the globals we will used
static int count = 0;
static int solved = 0;
CRITICAL_SECTION crit;

IndexData* g_indexDataArray;
int isreverse = 0;
int num_dwords = 0;
int num_threads = 0;
int done = 0;
unsigned char* answer;

unsigned char* g_header = NULL;
unsigned char* g_body = NULL;
int g_header_size = 0;
int g_body_size = 0;
uint64_t g_totalCombinations;

uint64_t threaditerations[MAXTHREADS] = { 0 };

/**
 * @brief Dumps the contents of a byte buffer in hexadecimal format.
 *
 * This function prints the contents of a byte buffer to the standard output.
 * The output format is a hexadecimal dump that optionally includes an offset
 * and a label string. Each line of the dump shows 16 bytes of data.
 *
 * @param str An optional label string to print before the hex dump. Pass NULL if no label is desired.
 * @param offs An offset value that is added to the index in the display.
 * @param buf Pointer to the byte buffer to dump.
 * @param size The size of the byte buffer to dump.
 *
 * @return void
 */
void hex_dump(char *str,  int offs, unsigned char *buf, int size)
{
  int i;

  if(str)
    printf("%s:", str);

  for(i=0; i<size; i++){
    if((i%16)==0){
      printf("\n%04X:", i+offs);
    }
    printf(" %02X", buf[i]);
  }
  printf("\n\n");
}

	
/**
 * @brief Opens a binary file and returns its size.
 *
 * This function opens a binary file and calculates its size. The size is returned
 * via an output parameter.
 *
 * @param name The name of the file to open.
 * @param size Pointer to an integer where the file size will be stored.
 *
 * @return A pointer to the opened FILE object, or NULL if the file could not be opened.
 */
FILE *open_file(char *name, int *size)
{
	FILE *fp;

    if (fopen_s(&fp, name, "rb")) { return NULL; }
	if(fp==NULL){
		//printf("Open file %s failed!\n", name);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return fp;
}						
/**
 * @brief Loads a binary file into a buffer.
 *
 * This function opens a binary file and loads its content into a dynamically
 * allocated buffer. The size of the file is returned via an output parameter.
 *
 * @param name The name of the file to load.
 * @param size Pointer to an integer where the file size will be stored.
 *
 * @return A pointer to the buffer containing the file's content, or NULL if the file could not be loaded.
 */
unsigned char *load_file(char *name, int *size)
{
	FILE *fp;
	unsigned char *buf;

	fp = open_file(name, size);
	if(fp==NULL)
		return NULL;
	buf = (unsigned char *) malloc(*size);
    if (buf) {
        fread(buf, *size, 1, fp);
    }
    else {
        printf("Malloc error!\n");
        fclose(fp);
        return NULL;
    }
	fclose(fp);

	return buf;
}

/**
 * @brief Writes a buffer into a binary file.
 *
 * This function takes a buffer and its size, and writes it to a binary file.
 *
 * @param file The name of the file to write to.
 * @param buf Pointer to the buffer containing the data to write.
 * @param size The size of the buffer in bytes.
 *
 * @return The number of bytes written, or -1 if the file could not be written.
 */
int write_file(char *file, void *buf, int size)
{
	FILE *fp;
	int written;
	int res;
	
	res = fopen_s(&fp,file, "wb");
	if(res)
		return -1;
	written = (int)fwrite(buf, 1, size, fp);
	fclose(fp);

	return written;
}

/**
 * @brief Converts a hexadecimal character to its decimal value.
 *
 * This function takes a single character representing a hexadecimal digit
 * (0-9, A-F, a-f) and returns its decimal value.
 *
 * @param c The hexadecimal character to convert.
 *
 * @return The decimal value of the hexadecimal character, or -1 if the character is invalid.
 */
int hexCharToDecimal(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1; // Invalid hexadecimal character
}


/**
 * @brief Converts a hexadecimal string to a byte array.
 * 
 * This function takes a string containing hexadecimal digits and converts
 * it to an array of unsigned bytes. The resulting byte array and its length
 * are stored in the output parameters.
 *
 * @param hexString The input string containing hexadecimal digits.
 * @param byteArray Pointer to an unsigned char pointer where the resulting byte array will be stored.
 * @param length Pointer to a size_t variable where the length of the byte array will be stored.
 * 
 * @return 0 on success, -1 on failure (e.g., invalid input or memory allocation failure).
 */
int hexStringToByteArray(const char* hexString, unsigned char** byteArray, size_t* byteArraySize) {
    size_t len = strlen(hexString);
    if (len % 2 != 0) {
        printf("Bad Len\n");
        return -1;
    }

    size_t size = len / 2;
    unsigned char* bytes = (unsigned char*)malloc(size);
    if (bytes == NULL) {
        printf("Bad malloc\n");
        return -1;
    }

    for (size_t i = 0, j = 0; i < len; i += 2, j++) {
        char pair[3] = { hexString[i], hexString[i + 1], '\0' };
        bytes[j] = (unsigned char)strtol(pair, NULL, 16);
    }

    *byteArray = bytes;
    *byteArraySize = size;

    return 0;
}


/**
 * @brief Reads an index data file and populates the indexDataArray with values.
 *
 * This function reads a text file where each line contains index-value pairs
 * separated by a colon. The function fills the indexDataArray with the corresponding
 * values for each index. The value 'ALL' can be used to indicate that all byte
 * values from 0x00 to 0xFF should be used.
 *
 * @param filename The name of the text file to read.
 * @param indexDataArray Pointer to an array of IndexData structures to be populated.
 *
 * @return 0 on success, -1 on failure.
 */
int readIndexDataFile(const char* filename, IndexData* indexDataArray) {
    FILE* file;
    errno_t err = fopen_s(&file, filename, "r");
    if (err != 0 || !file) {
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* token;
        char* next_token;

        token = strtok_s(line, ":", &next_token);
        if (token == NULL) continue;

        int index;
        sscanf_s(token, "%x", &index);

        token = strtok_s(NULL, "\n", &next_token);
        if (token != NULL) {
            size_t length = strlen(token) / 2;
            unsigned char* byteArray;

            if (hexStringToByteArray(token, &byteArray, &length) != 0) {
                fclose(file);
                return -1;
            }

            indexDataArray[index].index = index;
            indexDataArray[index].length = length;
            indexDataArray[index].values = byteArray;
        }
        else {
            // Full range 0x00 to 0xFF
            indexDataArray[index].index = index;
            indexDataArray[index].length = 0x100;
            indexDataArray[index].values = malloc(0x100);
            if (indexDataArray[index].values == NULL) {
                fclose(file);
                return -1;
            }
            for (int i = 0; i < 0x100; ++i) {
                indexDataArray[index].values[i] = (unsigned char)i;
            }
        }
    }

    fclose(file);
    return 0;
}


/*
int
                 AES_set_decrypt_key(const unsigned char *userKey,
                                     const int bits, AES_KEY *key)
									 
void
                 AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                                 size_t length, const AES_KEY *key,
                                 unsigned char *ivec, const int enc)									 
									 */

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4


// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const unsigned char sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// The round constant word array, Rcon[i], contains the values given by 
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const unsigned char Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
void KeyExpansion(unsigned char start, unsigned short AesSize,  unsigned char* key)
{
  unsigned char RoundKey10[240];
  unsigned int i, j, k;
  unsigned char tempa[4]; // Used for the column/row operations
  unsigned char Nk = AesSize / 32;
  // Nr: The number of rounds in AES Cipher: 10, 12 or 14
  unsigned char Nr = Nk+6;
  start *=4;
  // The first round key is the key itself.
  for(i = start; i < (Nk+start); ++i)
  {
    RoundKey10[(i * 4) + 0] = key[((i-start) * 4) + 0];
    RoundKey10[(i * 4) + 1] = key[((i-start) * 4) + 1];
    RoundKey10[(i * 4) + 2] = key[((i-start) * 4) + 2];
    RoundKey10[(i * 4) + 3] = key[((i-start) * 4) + 3];
  }
  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey10[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    RoundKey10[i * 4 + 0] = RoundKey10[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey10[i * 4 + 1] = RoundKey10[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey10[i * 4 + 2] = RoundKey10[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey10[i * 4 + 3] = RoundKey10[(i - Nk) * 4 + 3] ^ tempa[3];
  }
  for(i=(Nk+start-1); i>(Nk-1); i--)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey10[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }
    }
    RoundKey10[(i - Nk) * 4 + 0] = RoundKey10[i * 4 + 0] ^ tempa[0];
    RoundKey10[(i - Nk) * 4 + 1] = RoundKey10[i * 4 + 1] ^ tempa[1];
    RoundKey10[(i - Nk) * 4 + 2] = RoundKey10[i * 4 + 2] ^ tempa[2];
    RoundKey10[(i - Nk) * 4 + 3] = RoundKey10[i * 4 + 3] ^ tempa[3];
  }


	

	for(int i = 0; i < 16; i++){		
		key[i]=RoundKey10[i];
		//printf("%02X",key[i]);
	}
	//printf("\n");
	
	
}





/**
 * @brief Counts the number of zero bytes in a given byte array.
 *
 * This function iterates through a byte array and counts the occurrences
 * of bytes with a value of 0.
 *
 * @param buf Pointer to the byte array to analyze.
 * @param len The length of the byte array.
 *
 * @return The number of zero bytes found in the array.
 */
int countzeros(unsigned char * buf, int len) {
	int i,r=0;
	for(i=0;i<len;i++) {
		if (buf[i] == 0) r++;
	}
	return r;
}

/**
 * @brief Calculates the total number of combinations possible based on lengths at each index.
 *
 * This function iterates through an array of indices, each containing a length,
 * and calculates the total number of unique combinations possible by multiplying
 * these lengths together.
 *
 * @param lengths An array containing the lengths for each index.
 * @param numIndices The number of indices in the array.
 *
 * @return The total number of combinations as a 64-bit integer.
 */
uint64_t calculateTotalCombinations(IndexData* indexDataArray, size_t size) {
    uint64_t totalCombinations = 1;
    for (size_t i = 0; i < size; ++i) {
        if (indexDataArray[i].values) {
            totalCombinations *= indexDataArray[i].length;
        }
    }
    return totalCombinations;
}




/**
 * @brief Calculates the estimated time remaining for a loop to complete.
 *
 * This function estimates the remaining time for a loop based on the total number
 * of iterations, completed iterations, and elapsed time. The formula used for estimation is:
 * \f[
 * \text{time\_remaining} = \left( \frac{x}{y} - 1 \right) \times z
 * \f]
 *
 * @param totalIterations Total number of iterations the loop will perform.
 * @param completedIterations Number of iterations completed so far.
 * @param elapsedTime Time elapsed in seconds for the completed iterations.
 *
 * @return Estimated time remaining in seconds to complete the loop, or -1.0 if the parameters are invalid.
 */
u64 calculateTimeRemaining(u64 totalIterations, u64 completedIterations, u64 elapsedTime) {
    if (completedIterations <= 0 || elapsedTime <= 0) {
        // Prevent division by zero or negative time.
        return -1.0;
    }

    double timePerIteration = (double)elapsedTime / (double)completedIterations;
    u64 remainingIterations = totalIterations - completedIterations;
    u64 timeRemaining = (u64)(timePerIteration * (double)remainingIterations);

    return timeRemaining;
}


/*


*/
/**
 * @brief Performs brute-force decryption using the AES algorithm on the given data.
 *
 * This function is intended to run as a separate thread. It uses a brute-force approach to
 * try to decrypt a header and a body of a file using the AES algorithm. This is performed in
 * the context of a single thread. The function keeps track of the number of iterations
 * performed and flags when a correct key has been found.
 * 
 * This is where all the specifics of the brute force logic are implemented.
 * Currently this supports brute forcing bytes based on the config file.
 * 
 * It is using the header for first layer of decryption and body for the second.
 * The 00s check in the header is infomational only and not blocking.
 *
 * The 00s check in the body can be adjusted for levels of sensitivity.
 * Currently using 20 for a 0x200 byte body
 * 
 * @param lpParam Pointer to a structure containing thread-specific data, such as the starting
 *                point for this thread's brute-force attempt.
 *
 * @return A DWORD representing the status of the thread execution. Returns 0 on successful
 *         completion and -1 on error.
 *
 * @note This function is part of a multithreaded application and makes use of global variables
 *       protected by critical sections.
 *
 * @warning This function allocates memory dynamically and it's the caller's responsibility to
 *          free that memory.
 *
 * Usage Example:
 * @code
 *   PMYDATA pData = (PMYDATA) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MYDATA));
 *   pData->val1 = 0;  // Initialize with the starting index for this thread
 *   CreateThread(NULL, 0, bruteforceThread, pData, 0, NULL);
 * @endcode
 */
DWORD WINAPI bruteforceThread(LPVOID lpParam ) {
    int target;
    PMYDATA pDataArray =(PMYDATA)lpParam;
    u32 *key32;
    u8 *in;
    u8 *out;
    u8 *out2;
    u8 key[0x10];
    u8 iv[0x10];
    u8 zeros[0x10];
    u64 bruteforce;

    in = (u8*)malloc(g_header_size);
    if (!in) {
        printf("Error in thread %d malloc!\n", pDataArray->val1);
        return -1;
    }

    out = (u8*)malloc(g_header_size);
    if (!out) {
        printf("Error in thread %d malloc!\n", pDataArray->val1);
        return -1;
    }

    out2 = (u8*)malloc(g_body_size);
    if (!out2) {
        printf("Error in thread %d malloc!\n", pDataArray->val1);
        return -1;
    }

    key32 = (u32*) key;
    void (*decrypt)(_AES_IN UCHAR *, _AES_OUT UCHAR *, _AES_IN UCHAR *, _AES_IN size_t , _AES_IN UCHAR *);


    // Init Stuff
    memset(key,0,0x10);
    memset(iv,0,0x10);
    memset(in,0, g_header_size);
    memset(out,0, g_header_size);
    memset(out2,0, g_body_size);
    memset(zeros,0,0x10);
    target=pDataArray->val1;
    if(num_dwords == 4) {
        decrypt = intel_AES_dec128_CBC;
    } else if (num_dwords == 8 ) {
        decrypt = intel_AES_dec256_CBC;
    } else {
        printf("Invalid key size\n");
        return -1;
    }

    //Set Initial Values
    bruteforce=target;

    memcpy(in,g_header, g_header_size);

    while(bruteforce<(g_totalCombinations)) {
        //Build key
        memset(iv,0,0x10);
        uint64_t n = bruteforce;
        int maxDepth = 0x10;
        // Get using the bruteforce number as the index into each possible value
        // generate this rounds key from the variations on the keyconfig.txt file
        for (int depth = maxDepth - 1; depth >= 0; --depth) {
            size_t indexValue = n % g_indexDataArray[depth].length;
            key[depth] = g_indexDataArray[depth].values[indexValue];
            n /= g_indexDataArray[depth].length;
        }

        KeyExpansion(10, 128,key);
        //hex_dump("key", 0, (u8*)key, 0x10);
        intel_AES_dec128_CBC((u8*)in,(u8*)out,(u8*)key,(g_header_size /16),iv);

        // Informational, in case the header has a known structure when decrypted
        // Modify as appropriate for your target
        if(memcmp(&out[0x34], zeros,8) == 0) {
            printf("%x Found 00s!\n", target);
            hex_dump("key", 0, (u8*)key, 0x10);
            hex_dump("header", 0, (u8*)out, g_header_size);
                    
        }
        memset(iv,0,0x10);
        intel_AES_dec128_CBC((u8*)g_body, (u8*)out2, (u8*) out, (g_body_size /16),iv);

        // This is the simple entropy check of the decrypted body. In this case the target
        // can be successfully identified if more than 20 zeros are found in the decrypted body
        // Modify as appropriate for your target
        if(countzeros(out2, g_body_size) >= 20) {
            //int i;
            EnterCriticalSection(&crit);
            printf("WOOHOO! Thread %d found correct key!\n", target);
            hex_dump("key", 0, (u8*)key, 0x10);
            hex_dump("header", 0, (u8*)out, g_header_size);
            hex_dump("body", 0, (u8*)out2, g_body_size);
            solved=1;
            LeaveCriticalSection(&crit);
            break;
        }
        bruteforce+=num_threads;
        // Keep track of thread iterations for performance calculations.
        threaditerations[target] += 1;
        if(solved) break;
    }

  done+=1;  
  free(in);
  free(out);
  free(out2);
  return 0;  
}




/**
 * @brief Entry point for the program, performs multiple operations including file loading, key value options configuration, and running threads for brute force.
 *
 * This function does the following:
 * 1. Validates the command-line arguments.
 * 2. Loads header and body files.
 * 3. Reads key configuration from a text file and populates an array.
 * 4. Prints the total number of key combinations.
 * 5. Creates and starts threads for brute force key finding.
 * 6. Periodically estimates and prints the remaining time.
 * 7. Frees allocated memory and prints elapsed time.
 *
 * Usage Example:
 * @code
 *   ./proxima-brute headerfile.txt bodyfile.txt keyconfig.txt 4
 * @endcode
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of pointers to the command-line arguments.
 *
 * @return Returns 0 on successful execution, and -1 otherwise.
 */

int main(int argc, char *argv[]) {
	
    int i;
    PMYDATA pDataArray[MAXTHREADS];
    int start, endt;
    InitializeCriticalSection(&crit);
    num_dwords=4;

    IndexData indexDataArray[16];

    done=0;
    if(argc != 5) {
    printf("usage: %s headerfile bodyfile keyconfig num_threads\n", argv[0]);
    return -1;
    }
    g_header = load_file(argv[1], &g_header_size);
    g_body = load_file(argv[2], &g_body_size);
    if (g_header_size <= 0) {
        printf("Invalid headerfile\n");
        return -1;
    }
    if (g_body_size <= 0) {
        printf("Invalid bodyfile\n");
        return -1;
    }
    num_threads= atol(argv[4]);
    if((num_threads>MAXTHREADS) || (num_threads < 1)) {
    printf("currently supports 1-%d threads\n", MAXTHREADS);
    return -1;
    }
    

    if (readIndexDataFile(argv[3], indexDataArray) == 0) {
        // Now indexDataArray is populated, you can use it
        printf("\nKey value options configuration:\n\n");
        for (int i = 0; i < 16; ++i) {
            if (indexDataArray[i].values) {
                printf("Index: %02x, Length: %+3zu, Values: ", indexDataArray[i].index, indexDataArray[i].length);
                if (indexDataArray[i].length == 0x100) {
                    printf("0x00 - 0xFF ");
                }
                else {
                    for (size_t j = 0; j < indexDataArray[i].length; ++j) {
                        printf("%02x ", indexDataArray[i].values[j]);
                    }
                }
                printf("\n");
                
            }
        }
    }
    else {
        printf("An error occurred while reading the file.\n");
        return -1;
    }
    g_totalCombinations = calculateTotalCombinations(indexDataArray, 16);
    printf("\nTotal combinations: %llu\n", g_totalCombinations);
    g_indexDataArray = &indexDataArray;

    printf("\nStarting brute force with %d threads\n", num_threads);

    start=(int)time(0);
    for(i=0;i<num_threads;i++) {
        pDataArray[i] = (PMYDATA) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                sizeof(MYDATA));

        if( pDataArray[i] == NULL )
        {
            // If the array allocation fails, the system is out of memory
            // so there is no point in trying to print an error message.
            // Just terminate execution.
            ExitProcess(2);
        }  
        pDataArray[i]->val1=i;
        CreateThread(NULL, 0, bruteforceThread, pDataArray[i],0,NULL);
    }

    // Now wait for all the threads to complete or for the key to be found.
    int estimateDone = 0;
    while(!solved && (done!=num_threads)) {
        Sleep(1);
        int curtime = (int)time(0);
        if ((curtime - start) >= 15 && !estimateDone) {
            u64 sofar = 0;
            for (int i = 0; i < num_threads; i++) sofar += threaditerations[i];

            u64 totalIterations = g_totalCombinations;
            u64 completedIterations = sofar;
            u64 elapsedTime = (curtime - start);

            u64 timeRemaining = calculateTimeRemaining(totalIterations, completedIterations, elapsedTime);
            estimateDone = 1;
            if (timeRemaining >= 0) {
                // Convert the time from seconds to days, hours, minutes, and seconds
                int days = (int)(timeRemaining / (24 * 3600));
                timeRemaining = (int)timeRemaining % (24 * 3600);
                int hours = (int)(timeRemaining / 3600);
                timeRemaining %= 3600;
                int minutes = (int)(timeRemaining / 60);
                int seconds = (int)(timeRemaining % 60);

                printf("MAX time remaining: %d days, %d hours, %d minutes, %d seconds based on completing %llu iterations so far out of %llu\n",
                    days, hours, minutes, seconds, completedIterations, totalIterations);
            }
            else {
                printf("Invalid parameters.\n");
            }
        }
    }

    endt=(int)time(0);
    printf("Elapsed time %d seconds\n", endt-start);
    for(int i=0;i<0x10;i++) free(indexDataArray[i].values);

    return 0;
}
