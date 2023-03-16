#pragma once

#include "../../common/ds.hpp"


#ifndef USE_OpenSSLCryptoLib

/* Simple lib */
#ifdef __cplusplus
extern "C"
{
#endif 

#include "../../../thirdparty/cryptopp/aes.h"
#include "../../../thirdparty/cryptopp/gcm.h"

#ifdef __cplusplus
}
#endif 


class CryptoLib {
private:
    gcm_context ctx;            // includes the AES context structure
    size_t key_len, iv_len, add_len, tag_len;
    uint8_t* key, * iv, * add, * tag;
public:
    CryptoLib();

    operation_result encryption(const unsigned char* key,
        const unsigned char* iv,
        size_t iv_len,
        const unsigned char* add,
        size_t add_len,
        const unsigned char* input,
        size_t length,
        unsigned char* output,
        unsigned char* tag,
        size_t tag_len) {

        void* context = gcm_init();
        if (!context) {
            return OPERATION_FAIL;
        }

        operation_result flag = gcm_setkey(context, key, 128);
        if (OPERATION_FAIL == flag) { return OPERATION_FAIL; }

        gcm_crypt_and_tag(context,
            iv, iv_len,
            add, add_len,
            input, length,
            output,
            tag, tag_len);

        gcm_free(context);

        return OPERATION_SUC;

    }

    operation_result decryption(const unsigned char* key,
        const unsigned char* iv,
        size_t iv_len,
        const unsigned char* add,
        size_t add_len,
        const unsigned char* tag,
        size_t tag_len,
        const unsigned char* input,
        size_t length,
        unsigned char* output) {

        void* context = gcm_init();
        if (!context) {
            return OPERATION_FAIL;
        }

        operation_result flag = gcm_setkey(context, key, 128);
        if (OPERATION_FAIL == flag) { return OPERATION_FAIL; }

        gcm_auth_decrypt(context,
            iv, iv_len,
            add, add_len,
            tag, tag_len,
            input, length,
            output);

        gcm_free(context);

        return OPERATION_SUC;

    }

    void encrypt(uint8_t* src, size_t src_len, uint8_t* dst);
    void decrypt(uint8_t* src, size_t src_len, uint8_t* dst);
};
static CryptoLib g_crypto_lib;

#else

/* Openssl lib */
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <iostream>

class CryptoLib {
private:
    size_t key_len, iv_len, aad_len, tag_len;
    uint8_t* key, * iv, * aad;

    bool is_error = false;
public:
    CryptoLib();

    void encrypt(uint8_t* src, size_t src_len, uint8_t* dst);

    void decrypt(uint8_t* src, size_t src_len, uint8_t* dst);

    void handle_errors();
};
static CryptoLib g_crypto_lib;

#endif  // USE_OpenSSLCryptoLib