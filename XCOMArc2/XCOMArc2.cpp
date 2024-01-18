#pragma warning(disable : 4996)
#define _CRT_SECURE_NO_WARNINGS

#include <conio.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <Windows.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <applink.c>

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

bool key(std::string& str);
int encode(char* input, char* output,int sizeEnc, const char* keyfile);
int decode(char* input, char* output, int sizeDec, const char* keyfile);
bool fileEx(std::string& str);
void Base64Decode(unsigned char* b64message, unsigned char* buffer);
void Base64Encode(unsigned char* b64message, unsigned char* buffer);

std::string pubkey = "kfl";
std::string b64file = "b64key";
int main(int argc, char** argv)
{
    CRYPTO_secure_malloc_init(4096, 32);
    OpenSSL_add_all_algorithms();
    setlocale(LC_ALL, "ru");
    
    char *arr,*out;
    size_t fileSize;
    FILE* newFile=0;
    std::string tmp;

    if (argc > 1) {
        // --g  - создание ключей
        if (strcmp(const_cast<char*>(argv[1]), "--g") == 0) {
            if (argc == 3) tmp = argv[2];
            else tmp = pubkey;
            if (fileEx(tmp)) {
                //если файлы уже есть - выйти
                std::cout << std::endl << "Файл ключей уже создан" << std::endl;
                return 0;
            }

            key(tmp);
            return 0;
        }
        else
            //--e кодирование файла/папки
            if (strcmp(const_cast<char*>(argv[1]), "--e") == 0) {
                if (fileEx(pubkey)) {
                    FILE* file = fopen(argv[2], "rb");
                    fseek(file, 0, SEEK_END);
                    fileSize = ftell(file);
                    arr = (char*)malloc(fileSize);
                    out = (char*)malloc(fileSize*2);
                    fseek(file, 0, SEEK_SET);
                    fread(arr, 1, fileSize, file);
                    int result = encode(arr,out,fileSize, pubkey.c_str());
                    newFile = fopen(argv[3], "wb+");
                    fwrite(out, 1, result, newFile);
                    free(arr);
                    free(out);
                    fclose(file);
                    fclose(newFile);
                }
                else {
                    std::cout << "Создайте ключи шифрования при помощи параметра --g" << std::endl;
                }

            }
            else
                //--d декодирование
                if (strcmp(const_cast<char*>(argv[1]), "--d") == 0) {

                    FILE* file = fopen(argv[2], "rb");
                    fseek(file, 0, SEEK_END);
                    fileSize = ftell(file);
                    arr = (char*)malloc(fileSize);
                    out = (char*)malloc(fileSize*2);
                    if (arr && out) {
                        fseek(file, 0, SEEK_SET);
                        fread(arr, 1, fileSize, file);
                        int result = decode(arr, out, fileSize, pubkey.c_str());
                        newFile = fopen(argv[3], "wb+");
                        fwrite(out, 1, result, newFile);
                        free(arr);
                        free(out);
                    }
                    if(file)fclose(file);
                    if(newFile)fclose(newFile);
                }
                else if (strcmp(const_cast<char*>(argv[1]), "--b64enc") == 0) {
                        FILE* file = fopen(pubkey.c_str(), "rb");
                        unsigned char* key = new unsigned char[49];
	                    unsigned char* b64key = new unsigned char[65];
                        fread(key, 1, 48, file);
                        key[48] = '\0';
                        Base64Encode(key,b64key);
                        b64key[64] = '\0';
                        fclose(file);
                        file = fopen(b64file.c_str(), "wb+");
                        fwrite(b64key, 1, 64, file);
                        fclose(file);
                }
                else if (strcmp(const_cast<char*>(argv[1]), "--b64dec") == 0) {
                        FILE* file = fopen(b64file.c_str(), "rb");
                        unsigned char* key = new unsigned char[49];
	                    unsigned char* b64key = new unsigned char[65];
                        fread(b64key, 1, 64, file);
                        b64key[64] = '\0';
                        
                        Base64Decode(b64key,key);
                        key[48] = '\0';
                        fclose(file);
                        file = fopen("b64decode", "wb+");
                        fwrite(key, 1, 48, file);
                        fclose(file);
                }

    }
    else {
        std::cout << "--g: <keyfile>: создание ключей шифрования\n--e <source> <destination> :шифрование файла source в destination\n--d <source> <destination> :расшифровка из source в destination\n\n" << std::endl;
        //std::cout << "\nоткрытым ключем" << std::endl;
    }
    return 0;
}

bool fileEx(std::string& str) {
    if (FILE* file = fopen(str.c_str(), "r")) {
        fclose(file);
        return true;
    }
    else {
        return false;
    }
}


int encode(char* input, char* output, int sizeEnc, const char* keyfile) {
    FILE* file;
    unsigned char* key = new unsigned char[32];
	unsigned char* iv = new unsigned char[16];
    
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    int len=0;

    file = fopen(keyfile, "rb");
    fread(key, 1, 32, file);
    fread(iv, 1, 16, file);
    fclose(file);

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -2;
    if(1 != EVP_EncryptUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)input,  sizeEnc))
        return -3;
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)output + len, &len))
        return -4;
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(key);
    free(iv);
    return ciphertext_len;

}



int decode(char* input, char* output, int sizeDec, const char* keyfile) {
    unsigned char* key = new unsigned char[32];
	unsigned char* iv = new unsigned char[16];
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    FILE* file;
    
    file = fopen(keyfile, "rb");
    fread(key, 1, 32, file);
    fread(iv, 1, 16, file);
    fclose(file);


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -2;
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);
    if(1 != EVP_DecryptUpdate(ctx, (unsigned char*)output, &len,(unsigned char*)input, sizeDec))
        return -3;
    plaintext_len = len;
    if(1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)(output + len), &len))
        return -4;
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    delete []key;
    delete []iv;
    return plaintext_len;
}


bool key(std::string& str) {//создаёт ключ
    unsigned char* key = new unsigned char[32];
	unsigned char* iv = new unsigned char[16];
    FILE* file;
    int iv_len = 16;
    int key_len = 32;
    RAND_priv_bytes(iv, iv_len);
    RAND_priv_bytes(key, key_len);
    file = fopen(str.c_str(), "wb+");
    size_t res = fwrite(key, 1, 32, file);
    res = fwrite(iv, 1, 16, file);
    fclose(file);
    delete[] key;
    delete[] iv;
    return (1);

}

size_t calcDecodeLength(char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(unsigned char* b64message, unsigned char* buffer) {
    const int length=64;
    EVP_DecodeBlock(buffer, b64message, length);
}

void Base64Encode(unsigned char* b64message, unsigned char* buffer) {
    const int length=64;
    EVP_EncodeBlock(buffer, b64message, length);
}