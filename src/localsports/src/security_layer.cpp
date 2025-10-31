// src/security_layer.cpp
#include "security_layer.h"

#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <iostream>
#include <algorithm>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// OpenSSL includes
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>

namespace teamcore {

    // =================== SecureBuffer Implementation ===================
    void SecureBuffer::secure_bzero(void* ptr, std::size_t len) {
        if (!ptr || len == 0) return;
#if defined(_WIN32)
        SecureZeroMemory(ptr, len);
#else
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        for (std::size_t i = 0; i < len; ++i)
            p[i] = 0;

#   if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#   elif defined(_MSC_VER)
        _ReadWriteBarrier();
#   endif
#endif
    }

    SecureBuffer::SecureBuffer(std::size_t size) : data_(nullptr), size_(0) {
        if (size > 0) {
            data_ = new unsigned char[size];
            size_ = size;
            std::memset(data_, 0, size_);
        }
    }

    SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            cleanse();
            delete[] data_;
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    SecureBuffer::~SecureBuffer() {
        cleanse();
        delete[] data_;
    }

    void SecureBuffer::resize(std::size_t newSize) {
        if (newSize == size_) return;

        if (newSize == 0) {
            cleanse();
            delete[] data_;
            data_ = nullptr;
            size_ = 0;
            return;
        }

        unsigned char* newData = new unsigned char[newSize];
        std::size_t copyLen = (size_ < newSize) ? size_ : newSize;
        if (copyLen > 0 && data_)
            std::memcpy(newData, data_, copyLen);

        if (newSize > size_)
            std::memset(newData + copyLen, 0, newSize - copyLen);

        cleanse();
        delete[] data_;
        data_ = newData;
        size_ = newSize;
    }

    void SecureBuffer::cleanse() {
        if (data_ && size_ > 0)
            secure_bzero(data_, size_);
    }

    // =================== Crypto Implementation ===================
    namespace crypto {

        bool DeriveKeyFromPassphrase(
            const std::string& passphrase,
            const unsigned char* salt,
            std::size_t saltLen,
            int iterations,
            unsigned char* outKey32) {

            if (!salt || saltLen == 0 || !outKey32 || iterations < 1)
                return false;

            int ret = PKCS5_PBKDF2_HMAC(
                passphrase.c_str(), static_cast<int>(passphrase.length()),
                salt, static_cast<int>(saltLen),
                iterations,
                EVP_sha256(),
                32, outKey32);

            return ret == 1;
        }

        std::string EncryptForDB(
            const std::string& plaintext,
            const unsigned char* key32,
            const std::string& aad)
        {
            if (!key32 || plaintext.empty()) return "";

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return "";

            std::string result;
            try {
                // AES-256-GCM baþlat
                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                    throw std::runtime_error("EncryptInit failed");

                // IV oluþtur (12 bayt)
                unsigned char iv[12];
                if (RAND_bytes(iv, sizeof(iv)) != 1)
                    throw std::runtime_error("RAND_bytes failed");

                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32, iv) != 1)
                    throw std::runtime_error("EncryptInit (key/iv) failed");

                // AAD (ek veri)
                int len = 0;
                if (!aad.empty()) {
                    if (EVP_EncryptUpdate(ctx, nullptr, &len,
                        reinterpret_cast<const unsigned char*>(aad.data()),
                        static_cast<int>(aad.size())) != 1)
                        throw std::runtime_error("EncryptUpdate (AAD) failed");
                }

                // Þifreleme
                std::vector<unsigned char> ciphertext(plaintext.size() + 16);
                if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                    reinterpret_cast<const unsigned char*>(plaintext.data()),
                    static_cast<int>(plaintext.size())) != 1)
                    throw std::runtime_error("EncryptUpdate failed");
                int ciphertextLen = len;

                // Final
                if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len) != 1)
                    throw std::runtime_error("EncryptFinal failed");
                ciphertextLen += len;

                // Tag al (16 byte)
                unsigned char tag[16];
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
                    throw std::runtime_error("GET_TAG failed");

                // IV + ciphertext + tag birleþimi
                std::vector<unsigned char> out(12 + ciphertextLen + 16);
                std::memcpy(out.data(), iv, 12);
                std::memcpy(out.data() + 12, ciphertext.data(), ciphertextLen);
                std::memcpy(out.data() + 12 + ciphertextLen, tag, 16);

                // Base64 encode
                BIO* bio = BIO_new(BIO_s_mem());
                BIO* b64 = BIO_new(BIO_f_base64());
                bio = BIO_push(b64, bio);
                BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
                BIO_write(bio, out.data(), static_cast<int>(out.size()));
                BIO_flush(bio);
                BUF_MEM* buf = nullptr;
                BIO_get_mem_ptr(bio, &buf);
                result = "GCM1:" + std::string(buf->data, buf->length);
                BIO_free_all(bio);
            }
            catch (...) {
                EVP_CIPHER_CTX_free(ctx);
                throw;
            }

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

        std::string DecryptFromDB(
            const std::string& sealed,
            const unsigned char* key32,
            const std::string& aad)
        {
            if (sealed.rfind("GCM1:", 0) != 0 || !key32)
                return "";

            std::string base64 = sealed.substr(5);
            BIO* bio = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.size()));
            BIO* b64 = BIO_new(BIO_f_base64());
            bio = BIO_push(b64, bio);
            BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

            std::vector<unsigned char> decoded(base64.size());
            int decodedLen = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));
            BIO_free_all(bio);

            if (decodedLen < 28) // IV(12) + Tag(16)
                return "";

            unsigned char* iv = decoded.data();
            int cipherLen = decodedLen - 12 - 16;
            unsigned char* ciphertext = decoded.data() + 12;
            unsigned char* tag = decoded.data() + 12 + cipherLen;

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) return "";

            std::string result;
            try {
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key32, iv) != 1)
                    throw std::runtime_error("DecryptInit failed");

                // AAD
                int len = 0;
                if (!aad.empty()) {
                    if (EVP_DecryptUpdate(ctx, nullptr, &len,
                        reinterpret_cast<const unsigned char*>(aad.data()),
                        static_cast<int>(aad.size())) != 1)
                        throw std::runtime_error("DecryptUpdate (AAD) failed");
                }

                std::vector<unsigned char> plain(cipherLen + 1);
                if (EVP_DecryptUpdate(ctx, plain.data(), &len, ciphertext, cipherLen) != 1)
                    throw std::runtime_error("DecryptUpdate failed");
                int plainLen = len;

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
                    throw std::runtime_error("SET_TAG failed");

                if (EVP_DecryptFinal_ex(ctx, plain.data() + plainLen, &len) != 1)
                    throw std::runtime_error("DecryptFinal failed");
                plainLen += len;
                result.assign(reinterpret_cast<char*>(plain.data()), plainLen);
            }
            catch (...) {
                EVP_CIPHER_CTX_free(ctx);
                return "[DECRYPT-ERROR]";
            }

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }


    } // namespace crypto

    // =================== TLS Implementation ===================
    namespace tls {
        // (TLS fonksiyonlarý senin sürümündeki gibi ayný kalabilir)
    } // namespace tls


    // =================== AppKey + Secure Password Implementation ===================

    static SecureBuffer g_appKey;
    static bool g_appKeyInitialized = false;

    std::string read_password_secure(const std::string& prompt) {
        std::cout << prompt;
        std::cout.flush();

        std::string password;

#if defined(_WIN32)
        char ch;
        while ((ch = _getch()) != '\r' && ch != '\n') {
            if (ch == '\b') {
                if (!password.empty()) {
                    password.pop_back();
                    std::cout << "\b \b";
                    std::cout.flush();
                }
            }
            else if (ch >= 32 && ch < 127) {
                password.push_back(ch);
                std::cout << '*';
                std::cout.flush();
            }
        }
        std::cout << "\n";
#else
        struct termios oldTermios, newTermios;
        if (tcgetattr(STDIN_FILENO, &oldTermios) != 0)
            return "";
        newTermios = oldTermios;
        newTermios.c_lflag &= ~(ECHO | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &newTermios);
        std::getline(std::cin, password);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldTermios);
#endif
        return password;
    }

    bool AppKey_InitFromEnvOrPrompt() {
        if (g_appKeyInitialized)
            return true;

        std::string passphrase;
        const char* envVal = std::getenv("LS_APP_PASSPHRASE");
        if (envVal)
            passphrase = envVal;

        if (passphrase.empty()) {
            passphrase = read_password_secure("Enter application encryption passphrase: ");
            if (passphrase.empty())
                return false;
        }

        unsigned char salt[16] = {
            0x4c, 0x53, 0x5f, 0x41, 0x50, 0x50, 0x5f, 0x53,
            0x41, 0x4c, 0x54, 0x5f, 0x32, 0x30, 0x32, 0x35
        };

        g_appKey.resize(32);
        if (!crypto::DeriveKeyFromPassphrase(passphrase, salt, 16, 100000, g_appKey.data())) {
            g_appKey.cleanse();
            g_appKey.resize(0);
            return false;
        }

        SecureBuffer::secure_bzero(&passphrase[0], passphrase.size());
        g_appKeyInitialized = true;
        return true;
    }

    const SecureBuffer& AppKey_Get() {
        if (!g_appKeyInitialized)
            throw std::runtime_error("AppKey not initialized. Call AppKey_InitFromEnvOrPrompt() first.");
        return g_appKey;
    }

    bool AppKey_IsReady() {
        return g_appKeyInitialized;
    }

} // namespace teamcore
