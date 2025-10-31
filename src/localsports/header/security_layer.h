#pragma once
#include <cstddef>
#include <string>

namespace teamcore {

    // =================== SecureBuffer ===================
    class SecureBuffer {
    public:
        // Dýþarýdan da kullanýlabilsin diye public yaptýk
        static void secure_bzero(void* ptr, std::size_t len);

        explicit SecureBuffer(std::size_t size = 0);
        SecureBuffer(const SecureBuffer&) = delete;
        SecureBuffer& operator=(const SecureBuffer&) = delete;
        SecureBuffer(SecureBuffer&& other) noexcept;
        SecureBuffer& operator=(SecureBuffer&& other) noexcept;
        ~SecureBuffer();

        void resize(std::size_t newSize);
        void cleanse();

        unsigned char* data() { return data_; }
        const unsigned char* data() const { return data_; }
        std::size_t size() const { return size_; }

    private:
        unsigned char* data_{ nullptr };
        std::size_t size_{ 0 };
    };

    // =================== Crypto ===================
    namespace crypto {
        bool DeriveKeyFromPassphrase(const std::string& passphrase,
            const unsigned char* salt,
            std::size_t saltLen,
            int iterations,
            unsigned char* outKey32);

        std::string EncryptForDB(const std::string& plaintext,
            const unsigned char* key32,
            const std::string& aad);

        std::string DecryptFromDB(const std::string& sealed,
            const unsigned char* key32,
            const std::string& aad);
    } // namespace crypto

    // =================== TLS ===================
    namespace tls {
        void* MakeTls13ClientCtxWithMTLS(const char* caPem,
            const char* certPem,
            const char* keyPem);

        std::string ComputeSpkiSha256B64FromFile(const std::string& certPemPath);

        bool CheckPinnedSpkiFromFile(const std::string& certPemPath,
            const std::string& expectedHash,
            bool throwOnMismatch);
    } // namespace tls

    // =================== AppKey (bildirimleri ekledik) ===================
    bool AppKey_InitFromEnvOrPrompt();
    const SecureBuffer& AppKey_Get();
    bool AppKey_IsReady();

    // =================== Güvenli parola giriþi (bildirim) ===================
    std::string read_password_secure(const std::string& prompt);

} // namespace teamcore
