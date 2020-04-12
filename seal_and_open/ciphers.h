// 10.04.2020 Martin Balko (balkoma1)
#include <openssl/evp.h>
typedef enum {CBC, ECB} OperationMode;
typedef enum {AES_128, AES_256} CipherType;

typedef struct {
    CipherType type;
    OperationMode opmode;
    int key_length, iv_length;
} CipherInfo;

/* =============================================================== */

const EVP_CIPHER * get_aes_128(OperationMode opmode) {
    switch(opmode) {
        case CBC:   return EVP_aes_128_cbc();
        case ECB:   return EVP_aes_128_ecb();
        default:    return EVP_enc_null();
    }
}

const EVP_CIPHER * get_aes_256(OperationMode opmode) {
    switch(opmode) {
        case CBC:   return EVP_aes_256_cbc();
        case ECB:   return EVP_aes_256_ecb();
        default:    return EVP_enc_null();
    }
}

const EVP_CIPHER * get_cipher(CipherInfo info) {
    switch(info.type) {
        case AES_128:   return get_aes_128(info.opmode);
        case AES_256:   return get_aes_256(info.opmode);
        default:        return EVP_enc_null();
    }
}
