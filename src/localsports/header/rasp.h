#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <vector>

namespace teamcore {
namespace rasp {

    // =================== Runtime Security Status ===================
    struct SecurityEvent {
        std::string timestamp;
        std::string eventType;
        std::string description;
        int severity; // 1=info, 2=warning, 3=critical
    };

    // =================== IsDebuggerPresent & ptrace ===================
    /**
     * @brief Runtime debugger tespiti (IsDebuggerPresent API ve ptrace kontrolü)
     * @details Windows: IsDebuggerPresent() + NtQueryInformationProcess
     *          Linux: ptrace(PTRACE_TRACEME) kontrolü
     * @return true ise debugger algılandı
     */
    bool DetectDebugger();

    /**
     * @brief Periyodik debugger izleme başlat (arka plan thread)
     * @param callback Debugger tespit edildiğinde çağrılacak fonksiyon
     * @param intervalMs Kontrol aralığı (milisaniye)
     */
    void StartDebuggerMonitoring(std::function<void()> callback, int intervalMs = 5000);

    /**
     * @brief Debugger izlemeyi durdur
     */
    void StopDebuggerMonitoring();

    // =================== .text Section Checksum Verification ===================
    /**
     * @brief Executable'ın .text bölümünün SHA-256 checksum'ını hesapla
     * @details Runtime'da kod bölgesinin hash'ini alır
     * @return SHA-256 hash (64 karakter hex string)
     */
    std::string CalculateTextSectionChecksum();

    /**
     * @brief .text bölümünün checksum doğrulaması
     * @param expectedChecksum Build-time'da kaydedilen doğru checksum
     * @return true ise doğrulama başarılı, false ise kod değiştirilmiş
     */
    bool VerifyTextSectionIntegrity(const std::string& expectedChecksum);

    /**
     * @brief Önyükleme sırasında checksum kontrolü yap
     * @details Uygulama başlarken .text bölümünü doğrular
     * @param expectedChecksum Bilinen doğru checksum
     * @return false ise uygulama sonlandırılmalı
     */
    bool BootTimeIntegrityCheck(const std::string& expectedChecksum);

    // =================== IAT/PLT Hook Detection ===================
    /**
     * @brief Import Address Table (Windows) hook tespiti
     * @details IAT'daki fonksiyon pointer'larını kontrol eder
     * @return Değiştirilen fonksiyon sayısı (0 ise temiz)
     */
    int DetectIATHooks();

    /**
     * @brief Procedure Linkage Table (Linux) hook tespiti
     * @details PLT/GOT tablosundaki pointer'ları kontrol eder
     * @return Değiştirilen entry sayısı (0 ise temiz)
     */
    int DetectPLTHooks();

    /**
     * @brief Beklenmeyen fonksiyon pointer kontrolü (thunk analizi)
     * @details Kritik fonksiyonların (malloc, strcpy, vb) hook edilip edilmediğini kontrol eder
     * @param functionName Kontrol edilecek fonksiyon adı
     * @return true ise hook tespit edildi
     */
    bool IsThunkModified(const std::string& functionName);

    /**
     * @brief Tüm kritik fonksiyonların hook kontrolü
     * @details Önceden tanımlı kritik fonksiyon listesini tarar
     * @return Hook tespit edilen fonksiyon sayısı
     */
    int ScanCriticalFunctions();

    // =================== Security Event Logging ===================
    /**
     * @brief Güvenlik olayını kaydet
     * @param event Olay bilgisi
     * @return true ise kayıt başarılı
     */
    bool LogSecurityEvent(const SecurityEvent& event);

    /**
     * @brief Kritik güvenlik olayını kaydet ve fail-closed davranış göster
     * @param eventType Olay tipi (örn: "DEBUGGER_DETECTED")
     * @param description Olay açıklaması
     * @param terminateApp true ise uygulamayı sonlandır
     */
    void HandleCriticalEvent(const std::string& eventType, 
                            const std::string& description,
                            bool terminateApp = true);

    /**
     * @brief Tüm güvenlik olaylarını getir
     * @return Olay listesi
     */
    std::vector<SecurityEvent> GetSecurityEventLog();

    /**
     * @brief Güvenlik log dosyasını temizle
     */
    void ClearSecurityLog();

    // =================== Process Isolation & Fail-Closed ===================
    /**
     * @brief Süreç izolasyonu kontrolü
     * @details Uygulamanın güvenli bir ortamda çalışıp çalışmadığını kontrol eder
     * @return true ise izole ortam güvenli
     */
    bool VerifyProcessIsolation();

    /**
     * @brief Fail-closed davranış: Güvenlik tehdidi durumunda uygulamayı sonlandır
     * @param reason Sonlandırma nedeni
     */
    void FailClosedShutdown(const std::string& reason);

    /**
     * @brief Güvenli durum kaydı (crash dump olmadan çıkış)
     * @details Hassas verileri temizledikten sonra uygulamayı sonlandırır
     */
    void SecureTerminate();

    // =================== Comprehensive RASP Initialization ===================
    /**
     * @brief RASP sistemini başlat
     * @details Tüm runtime korumalarını aktive eder:
     *          - Debugger monitoring
     *          - Checksum verification
     *          - Hook detection
     *          - Event logging
     * @param expectedChecksum .text bölümünün bilinen checksum'ı
     * @param autoTerminateOnThreat true ise tehdit algılandığında otomatik sonlanma
     * @return true ise başarılı, false ise başlatma hatası
     */
    bool InitializeRASP(const std::string& expectedChecksum, bool autoTerminateOnThreat = true);

    /**
     * @brief RASP sistemini durdur
     */
    void ShutdownRASP();

    /**
     * @brief RASP durumu sorgulama
     * @return true ise RASP aktif
     */
    bool IsRASPActive();

    /**
     * @brief Periyodik güvenlik kontrolü yap
     * @details Debugger, hook, integrity kontrollerini yapar
     * @return true ise tüm kontroller başarılı
     */
    bool PerformSecurityScan();

    // =================== Configuration ===================
    struct RASPConfig {
        bool enableDebuggerDetection = true;
        bool enableChecksumVerification = true;
        bool enableHookDetection = true;
        bool autoTerminateOnThreat = true;
        int monitoringIntervalMs = 5000;
        std::string logFilePath = "rasp_security.log";
    };

    /**
     * @brief RASP yapılandırması ayarla
     * @param config Yapılandırma parametreleri
     */
    void ConfigureRASP(const RASPConfig& config);

    /**
     * @brief Aktif yapılandırmayı getir
     * @return Mevcut RASP yapılandırması
     */
    RASPConfig GetRASPConfig();

} // namespace rasp
} // namespace teamcore
