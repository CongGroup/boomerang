#include "cryptolib.h"

#ifndef USE_OpenSSLCryptoLib

CryptoLib::CryptoLib() {
    key = new uint8_t[AES_BLOCK_SIZE]{};
    memcpy(key, DUMMY_KEY, AES_BLOCK_SIZE);
    key_len = AES_BLOCK_SIZE;

    iv = new uint8_t[GCM_DEFAULT_IV_LEN]{};
    iv_len = GCM_DEFAULT_IV_LEN;

    add = NULL;
    add_len = 0;
}


void CryptoLib::encrypt(uint8_t* pt, size_t pt_len, uint8_t* ct) {
    encryption(key,
        iv, iv_len,
        add, add_len,
        pt, pt_len,
        ct,
        ct + pt_len, MAC_SIZE);
}


void CryptoLib::decrypt(uint8_t* ct, size_t ct_len, uint8_t* pt) {
    decryption(key,
        iv, iv_len,
        add, add_len,
        ct + ct_len - MAC_SIZE, MAC_SIZE,
        ct, ct_len - MAC_SIZE,
        pt);
}


#else

CryptoLib::CryptoLib() {
    key = new uint8_t[16]{};
    memcpy(key, DUMMY_KEY, 16);
    key_len = 16;

    iv = new uint8_t[12]{};
    iv_len = 12;

    aad = nullptr;
    aad_len = 0;
}

void CryptoLib::encrypt(uint8_t* pt, size_t pt_len, uint8_t* ct) {
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX* ctx;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handle_errors();

    // /*
    //  * Set IV length if default 12 bytes (96 bits) is not appropriate
    //  */
    // if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    //     handle_errors();

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handle_errors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))  // len=0
        handle_errors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len))  // len=3
        handle_errors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ct + len, &len))  //len=0
        handle_errors();
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, ct + pt_len))
        handle_errors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}


void CryptoLib::decrypt(uint8_t* ct, size_t ct_len, uint8_t* pt) {
    int len;
    int plaintext_len;

    EVP_CIPHER_CTX* ctx;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handle_errors();


    // /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    // if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    //     handle_errors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handle_errors();


    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handle_errors();


    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len - MAC_SIZE))
        handle_errors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MAC_SIZE, ct + ct_len - MAC_SIZE))
        handle_errors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    EVP_DecryptFinal_ex(ctx, pt + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void CryptoLib::handle_errors() {
    if (!is_error) {
        std::cout << "[Client] Crypto lib error" << std::endl;
        is_error = true;
    }
}

#endif  // USE_OpenSSLCryptoLib