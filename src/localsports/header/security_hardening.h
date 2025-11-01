#pragma once

#include <string>
#include <cstdint>
#include <functional>

namespace teamcore {
namespace hardening {

    // =================== Anti-Debug ===================
    /**
     * @brief Debugger tespiti (Windows ve Linux)
     * @return true ise debugger algılandı
     */
    bool IsDebuggerPresent();

    /**
     * @brief Anti-debug kontrolünü başlat (arka planda izleme thread)
     * @details Her 5 saniyede bir debugger kontrolü yapar, tespit ederse uygulamayı sonlandırır
     */
    void StartAntiDebugMonitor();

    /**
     * @brief Anti-debug monitoring thread'ini durdur
     */
    void StopAntiDebugMonitor();

    // =================== Anti-Tamper ===================
    /**
     * @brief Executable'ın SHA256 hash değerini hesapla
     * @return Hex string (64 karakter)
     */
    std::string GetExecutableHash();

    /**
     * @brief Kodun değiştirilip değiştirilmediğini kontrol et
     * @param expectedHash Bilinen doğru hash (build time'da ayarlanır)
     * @return false ise tamper edilmiş
     */
    bool VerifyIntegrity(const std::string& expectedHash);

    // =================== Emulator/VM Detection ===================
    /**
     * @brief Sanal makina veya emulator tespiti
     * @return true ise VM/emulator algılandı
     */
    bool IsRunningInVM();

    // =================== Root/Jailbreak Detection ===================
    /**
     * @brief Windows: Admin yetkileri kontrolü, Linux: Root user kontrolü
     * @return true ise root/admin yetkisi var
     */
    bool IsRootedOrJailbroken();

    // =================== Environment Checks ===================
    /**
     * @brief Güvenlik ortamı kontrollerini başlat
     * @details Debugger, VM tespitlerini bir arada yapar
     * @return true ise tüm kontroller geçti, false ise tehdit var
     */
    bool PerformSecurityChecks();

    // =================== Code Obfuscation - Opaque Predicates ===================
    /**
     * @brief Opaque predicate (her zaman true dönen karmaşık koşul)
     * @details Kontrol akışını karmaşıklaştırmak için kullanılır
     * @return Her zaman true
     */
    bool OpaquePredicateAlwaysTrue();

    /**
     * @brief Opaque predicate (her zaman false dönen karmaşık koşul)
     * @return Her zaman false
     */
    bool OpaquePredicateAlwaysFalse();

    /**
     * @brief Karmaşık matematiksel opaque predicate
     * @param x Input değeri
     * @return Her zaman true (x*x >= 0)
     */
    bool OpaqueMathPredicate(int x);

    // =================== String Obfuscation ===================
    /**
     * @brief Compile-time string obfuscation (XOR ile)
     * @param str Şifrelenecek string
     * @return Obfuscate edilmiş string (runtime'da decode edilir)
     */
    std::string ObfuscateString(const char* str);

    /**
     * @brief Obfuscate edilmiş string'i decode et
     * @param obfuscated Obfuscate edilmiş string
     * @return Orijinal string
     */
    std::string DeobfuscateString(const std::string& obfuscated);

    /**
     * @brief Magic number obfuscation
     * @param value Saklanacak değer
     * @return Obfuscate edilmiş değer
     */
    uint64_t ObfuscateValue(uint64_t value);

    /**
     * @brief Obfuscate edilmiş değeri decode et
     * @param obfuscated Obfuscate edilmiş değer
     * @return Orijinal değer
     */
    uint64_t DeobfuscateValue(uint64_t obfuscated);

    // =================== Control Flow Obfuscation ===================
    /**
     * @brief Kontrol akışını karmaşıklaştıran opaque loop
     * @param iterations İterasyon sayısı
     * @details Dummy hesaplamalar ile kod analizi zorlaştırır
     */
    void OpaqueLoop(int iterations);

    /**
     * @brief İndirect function call (fonksiyon pointer gizleme)
     * @param func Çağrılacak fonksiyon
     */
    void CallObfuscated(void (*func)());

    /**
     * @brief Boolean değişkenler için obfuscation
     * @param condition Koşul
     * @return Aynı koşul ama karmaşık hesaplama ile
     */
    bool ObfuscateBooleanCondition(bool condition);

    // =================== Fake Function & Arithmetic Obfuscation ===================
    /**
     * @brief Sahte fonksiyon (reverse engineer'ı yanıltmak için)
     * @details Gerçekte hiçbir işe yaramaz ama önemli gibi görünür
     */
    void FakeSecurityCheck();

    /**
     * @brief Aritmetik işlemleri karmaşıklaştırma
     * @param a İlk değer
     * @param b İkinci değer
     * @return a + b (ama karmaşık hesaplama ile)
     */
    int ObfuscateAdd(int a, int b);

    /**
     * @brief Aritmetik işlemleri karmaşıklaştırma (çarpma)
     * @param a İlk değer
     * @param b İkinci değer
     * @return a * b (ama karmaşık hesaplama ile)
     */
    int ObfuscateMultiply(int a, int b);

    // =================== Random Exit Points ===================
    /**
     * @brief Rastgele çıkış noktaları (kontrol akışını gizleme)
     * @param checksPassed Güvenlik kontrolleri geçti mi?
     */
    void RandomExitPoint(bool checksPassed);

    // =================== Fail-Safe Actions ===================
    /**
     * @brief Güvenlik ihlali durumunda uygulamayı sonlandır
     * @param reason Sonlandırma nedeni
     */
    [[noreturn]] void TerminateOnThreat(const char* reason);

    /**
     * @brief Belleği temizle ve uygulamayı kapat
     */
    [[noreturn]] void SecureTerminate();

    // =================== Debug Log Obfuscation ===================
    /**
     * @brief Release modunda debug loglarını kaldır
     * @param message Log mesajı
     */
    void SecureLog(const std::string& message);

    /**
     * @brief Build configuration kontrolü
     * @return true ise debug build, false ise release build
     */
    bool IsDebugBuild();

} // namespace hardening
} // namespace teamcore
