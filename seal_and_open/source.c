#include <stdio.h>
#include <string.h>
#include <openssl/evp.h> // EVP_*()
#include <openssl/pem.h> // PEM_read_PUBKEY(), PEM_read_PrivateKey()
#include "ciphers.h" // CipherInfo, get_cipher()

#define BLOCK_SIZE 128
#define MAX_LENGTH 1024

void encrypt(FILE * file_in, char * pemfile, char * filename_out) {
    // Load RSA public key from PEM file
    FILE * tmp = fopen(pemfile, "rb");
    if (!tmp)
        return;
    EVP_PKEY * pubkey = PEM_read_PUBKEY(tmp, NULL, NULL, NULL);
    fclose(tmp);

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();                            // Context
    CipherInfo cipher_info = {AES_128, CBC, 0, EVP_MAX_IV_LENGTH};          // Cipher info struct
    const EVP_CIPHER * cipher = get_cipher(cipher_info);                    // Cipher getting from cipher info struct
    unsigned char iv[cipher_info.iv_length];                                // Memory for initialization vector
    unsigned char * ek = (unsigned char *) malloc(sizeof(unsigned char) * EVP_PKEY_size(pubkey));   // Memory for encrypted cipher key
    unsigned char buffer[MAX_LENGTH];                                       // Buffer for memory loaded from file_in
    unsigned char crypted_buffer[MAX_LENGTH];                               // Buffer for encrypted memory
    int buffer_length, crypted_buffer_length;

    FILE * file_out = fopen(filename_out, "wb");
    if (!file_out)
        return;

    // SealInit generates random encrypted key and initialization vector
    if (!EVP_SealInit(ctx, cipher, &ek, &(cipher_info.key_length), iv, &pubkey, 1))
        return;

    // Save needed data into crypted file's header
    fwrite(&cipher_info, sizeof(CipherInfo), 1, file_out);
    fwrite(ek, sizeof(unsigned char), cipher_info.key_length, file_out);
    fwrite(iv, sizeof(unsigned char), cipher_info.iv_length, file_out);

    // Encrypt data
    while ((buffer_length = fread(buffer, sizeof(unsigned char), BLOCK_SIZE, file_in))) {
        EVP_SealUpdate(ctx, crypted_buffer, &crypted_buffer_length, buffer, buffer_length);
        fwrite(crypted_buffer, sizeof(unsigned char), crypted_buffer_length, file_out);
    }
    if (!EVP_SealFinal(ctx, crypted_buffer, &crypted_buffer_length))
        return;
    fwrite(crypted_buffer, sizeof(unsigned char), crypted_buffer_length, file_out);

    // Clean up
    fclose(file_out);
    free(ek);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
}

/* =============================================================== */

void decrypt(FILE * file_in, char * pemfile, char * filename_out) {
    // Load private RSA key
    FILE * tmp = fopen(pemfile, "rb");
    if (!tmp)
        return;
    EVP_PKEY * pkey = PEM_read_PrivateKey(tmp, NULL, NULL, NULL);
    fclose(tmp);

    CipherInfo cipher_info;                      // Cipher info struct
    unsigned char * iv;                          // Memory for initialization vector
    unsigned char buffer[MAX_LENGTH];            // Buffer for encrypted memory loaded from file_in
    unsigned char decrypted_buffer[MAX_LENGTH];  // Decrypted memory from file_in
    int buffer_length, decrypted_buffer_length;
    unsigned char * ek;                          // Pointer for encrypted cipher key
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new(); // Context
    const EVP_CIPHER * cipher;                   // Pointer for cipher

    // Read cipher info from file_in and get cipher
    fread(&cipher_info, sizeof(CipherInfo), 1, file_in);
    cipher = get_cipher(cipher_info);

    // Allocate memory for encrypted key and load it
    ek = (unsigned char *) malloc(sizeof(unsigned char) * cipher_info.key_length);
    fread(ek, sizeof(unsigned char), cipher_info.key_length, file_in);

    // Allocate memory for initialization vector and load it
    iv = (unsigned char *) malloc(sizeof(unsigned char) * cipher_info.iv_length);
    fread(iv, sizeof(unsigned char), cipher_info.iv_length, file_in);

    FILE * file_out = fopen(filename_out, "wb");
    if (!file_out)
        return;

    // Decrypt data
    if (!EVP_OpenInit(ctx, cipher, ek, cipher_info.key_length, iv, pkey))
        return;
    while ((buffer_length = fread(buffer, sizeof(unsigned char), BLOCK_SIZE, file_in))) {
        EVP_OpenUpdate(ctx, decrypted_buffer, &decrypted_buffer_length, buffer, buffer_length);
        fwrite(decrypted_buffer, sizeof(unsigned char), decrypted_buffer_length, file_out);
    }
    if (!EVP_OpenFinal(ctx, decrypted_buffer, &decrypted_buffer_length))
        return;
    fwrite(decrypted_buffer, sizeof(unsigned char), decrypted_buffer_length, file_out);

    // Clean up
    fclose(file_out);
    free(ek);
    free(iv);
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

/* =============================================================== */

int main(int argc, char * argv[]) {
    if (argc < 4) {
        printf("Usage:\n-> Encryption: %s -e file_in pubkey.pem [file_out]\n-> Decryption: %s -d file_in privkey.pem [file_out]\n", argv[0], argv[0]);
        return 1;
    }

    FILE * file_in;
    file_in = fopen(argv[2], "rb");
    if (!file_in)
        return 1;

    OpenSSL_add_all_ciphers();

    if (!strcmp(argv[1], "-e")) {
        if (argc == 5)
            encrypt(file_in, argv[3], argv[4]);
        else
            encrypt(file_in, argv[3], "crypted_file");
    }
    else if (!strcmp(argv[1], "-d")) {
        if (argc == 5)
            decrypt(file_in, argv[3], argv[4]);
        else
            decrypt(file_in, argv[3], "decrypted_file");
    }

    fclose(file_in);
    return 0;
}
