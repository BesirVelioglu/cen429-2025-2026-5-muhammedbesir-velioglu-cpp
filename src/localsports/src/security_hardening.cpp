// src/security_hardening.cpp
#include "security_hardening.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>

// Platform-specific includes
#if defined(_WIN32)
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #include <windows.h>
    #include <tlhelp32.h>
    #include <intrin.h>
    #include <shlobj.h>
#else
    #include <sys/ptrace.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <fcntl.h>
#endif

// OpenSSL for hashing
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace teamcore {
namespace hardening {

    // =================== Global State ===================
    static std::atomic<bool> g_antiDebugRunning{false};
    static std::thread g_antiDebugThread;

    // Obfuscation anahtarları (compile-time randomize edilebilir)
    static constexpr uint8_t XOR_KEY = 0xAA;
    static constexpr uint64_t VALUE_MASK = 0x5A5A5A5A5A5A5A5AULL;

    // =================== Anti-Debug ===================
    bool IsDebuggerPresent() {
#if defined(_WIN32)
        // Windows API kullanarak debugger tespiti
        if (::IsDebuggerPresent()) {
            return true;
        }

        // PEB kontrolü (daha gelişmiş tespit)
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent)) {
            if (isDebuggerPresent) {
                return true;
            }
        }

        // NtGlobalFlag kontrolü
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            typedef LONG(NTAPI* pfnNtQueryInformationProcess)(
                HANDLE ProcessHandle,
                DWORD ProcessInformationClass,
                PVOID ProcessInformation,
                DWORD ProcessInformationLength,
                PDWORD ReturnLength
            );

            pfnNtQueryInformationProcess NtQueryInformationProcess =
                (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

            if (NtQueryInformationProcess) {
                DWORD ProcessDebugPort = 0;
                DWORD returnLength = 0;
                LONG status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    7, // ProcessDebugPort
                    &ProcessDebugPort,
                    sizeof(ProcessDebugPort),
                    &returnLength
                );

                if (status == 0 && ProcessDebugPort != 0) {
                    return true;
                }
            }
        }

        return false;
#else
        // Linux: ptrace trick
        static bool checked = false;
        static bool result = false;

        if (!checked) {
            if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
                result = true; // Debugger attached
            } else {
                ptrace(PTRACE_DETACH, 0, 1, 0);
                result = false;
            }
            checked = true;
        }

        // /proc/self/status kontrolü
        std::ifstream statusFile("/proc/self/status");
        std::string line;
        while (std::getline(statusFile, line)) {
            if (line.find("TracerPid:") == 0) {
                std::string pidStr = line.substr(10);
                int tracerPid = std::stoi(pidStr);
                if (tracerPid != 0) {
                    return true;
                }
            }
        }

        return result;
#endif
    }

    void StartAntiDebugMonitor() {
        if (g_antiDebugRunning.exchange(true)) {
            return; // Zaten çalışıyor
        }

        g_antiDebugThread = std::thread([]() {
            while (g_antiDebugRunning.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));

                if (IsDebuggerPresent()) {
                    TerminateOnThreat("Debugger detected by monitoring thread");
                }
            }
        });
    }

    void StopAntiDebugMonitor() {
        g_antiDebugRunning.store(false);
        if (g_antiDebugThread.joinable()) {
            g_antiDebugThread.join();
        }
    }

    // =================== Anti-Tamper ===================
    std::string GetExecutableHash() {
#if defined(_WIN32)
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
            return "";
        }
#else
        char path[1024];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len == -1) {
            return "";
        }
        path[len] = '\0';
#endif

        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return "";
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            return "";
        }

        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(file.gcount()));
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned int hashLen = 0;
        EVP_DigestFinal_ex(ctx, hash, &hashLen);
        EVP_MD_CTX_free(ctx);

        std::ostringstream oss;
        for (unsigned int i = 0; i < hashLen; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return oss.str();
    }

    bool VerifyIntegrity(const std::string& expectedHash) {
        if (expectedHash.empty()) {
            return true; // Hash belirtilmemiş, atlama
        }

        std::string currentHash = GetExecutableHash();
        return currentHash == expectedHash;
    }

    // =================== VM Detection ===================
    bool IsRunningInVM() {
#if defined(_WIN32)
        // CPUID kontrolü (VMware, VirtualBox, Hyper-V)
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);

        // Hypervisor bit (ECX register, bit 31)
        bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

        if (hypervisorPresent) {
            return true;
        }

        // Registry kontrolleri (VMware)
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }

        // VirtualBox registry
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }

        // BIOS bilgisi
        HKEY biosKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\Description\\System\\BIOS", 0, KEY_READ, &biosKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            if (RegQueryValueExA(biosKey, "SystemManufacturer", NULL, NULL,
                (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string manufacturer(buffer);
                std::transform(manufacturer.begin(), manufacturer.end(),
                    manufacturer.begin(), ::tolower);

                if (manufacturer.find("vmware") != std::string::npos ||
                    manufacturer.find("virtualbox") != std::string::npos ||
                    manufacturer.find("qemu") != std::string::npos ||
                    manufacturer.find("microsoft corporation") != std::string::npos) {
                    RegCloseKey(biosKey);
                    return true;
                }
            }
            RegCloseKey(biosKey);
        }

        return false;
#else
        // Linux: DMI bilgilerini kontrol et
        std::ifstream dmi("/sys/class/dmi/id/product_name");
        std::string product;
        if (dmi && std::getline(dmi, product)) {
            std::transform(product.begin(), product.end(), product.begin(), ::tolower);
            if (product.find("virtualbox") != std::string::npos ||
                product.find("vmware") != std::string::npos ||
                product.find("qemu") != std::string::npos ||
                product.find("kvm") != std::string::npos) {
                return true;
            }
        }

        // /proc/cpuinfo kontrolü
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            std::transform(line.begin(), line.end(), line.begin(), ::tolower);
            if (line.find("hypervisor") != std::string::npos ||
                line.find("vmware") != std::string::npos ||
                line.find("virtualbox") != std::string::npos) {
                return true;
            }
        }

        return false;
#endif
    }

    // =================== Root Detection ===================
    bool IsRootedOrJailbroken() {
#if defined(_WIN32)
        // Windows: Admin kontrolü
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&NtAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin != 0;
#else
        // Linux: Root user kontrolü
        return geteuid() == 0;
#endif
    }

    // =================== Combined Security Check ===================
    bool PerformSecurityChecks() {
        // SESSIZ MOD: Saldırgana bilgi verme
        // Sadece kontrolleri yap, log yazma
        
        // 1. Anti-debug kontrolü - Tespit ederse sessizce kapan
        if (IsDebuggerPresent()) {
            std::exit(EXIT_FAILURE); // Hiçbir bilgi verme
        }

        // 2. VM detection - Tespit et ama bilgi verme
        volatile bool isVM = IsRunningInVM();
        (void)isVM; // Compiler warning önleme

        // 3. Root/Admin - Tespit et ama bilgi verme  
        volatile bool isRoot = IsRootedOrJailbroken();
        (void)isRoot;

        return true;
    }

    // =================== Opaque Predicates ===================
    bool OpaquePredicateAlwaysTrue() {
        // Karmaşık matematik işlemi ama her zaman true döner
        volatile int x = static_cast<int>(time(nullptr) % 100);
        volatile int y = x * x;

        // x^2 >= 0 her zaman doğru
        return (y >= 0) || (x == x);
    }

    bool OpaquePredicateAlwaysFalse() {
        // Karmaşık işlem ama her zaman false döner
        volatile int x = static_cast<int>(time(nullptr) % 100);
        volatile int y = x * x;

        // x^2 < 0 her zaman yanlış
        return (y < 0) && (x != x);
    }

    bool OpaqueMathPredicate(int x) {
        // x^2 >= 0 her zaman doğru
        volatile int result = x * x;
        return result >= 0;
    }

    // =================== String Obfuscation ===================
    std::string ObfuscateString(const char* str) {
        std::string result;
        for (size_t i = 0; str[i] != '\0'; ++i) {
            result += static_cast<char>(str[i] ^ XOR_KEY);
        }
        return result;
    }

    std::string DeobfuscateString(const std::string& obfuscated) {
        std::string result;
        for (char c : obfuscated) {
            result += static_cast<char>(c ^ XOR_KEY);
        }
        return result;
    }

    uint64_t ObfuscateValue(uint64_t value) {
        return value ^ VALUE_MASK;
    }

    uint64_t DeobfuscateValue(uint64_t obfuscated) {
        return obfuscated ^ VALUE_MASK;
    }

    // =================== Control Flow Obfuscation ===================
    void OpaqueLoop(int iterations) {
        // Dummy hesaplamalar ile kontrol akışını karmaşıklaştır
        volatile int dummy = 0;

        for (int i = 0; i < iterations; ++i) {
            if (OpaquePredicateAlwaysTrue()) {
                dummy += (i * 3 + 7) % 13;
            }

            if (OpaquePredicateAlwaysFalse()) {
                dummy -= (i * 2 + 5) % 11; // Hiç çalışmaz
            }

            // Rastgele matematik işlemi
            dummy = (dummy * 13 + 17) % 97;
        }

        // Compiler optimization'ı engellemek için
        if (dummy == 0x12345678) {
            std::cout << ""; // Hiç olmayacak
        }
    }

    void CallObfuscated(void (*func)()) {
        // Fonksiyon pointer'ını gizle (indirect call)
        volatile void* ptr = reinterpret_cast<void*>(func);

        // Opaque predicate ile koşullu çağrı
        if (OpaquePredicateAlwaysTrue()) {
            reinterpret_cast<void(*)()>(ptr)();
        }
    }

    bool ObfuscateBooleanCondition(bool condition) {
        // Boolean değeri karmaşık hesaplama ile gizle
        volatile int x = condition ? 1 : 0;
        volatile int y = (x * 137 + 42) % 256;
        volatile int z = (y - 42) / 137;

        return z != 0;
    }

    // =================== Fake Function & Arithmetic Obfuscation ===================
    void FakeSecurityCheck() {
        // Sahte güvenlik fonksiyonu (reverse engineer'ı yanıltmak için)
        volatile unsigned char fakeBuffer[256];

        for (int i = 0; i < 256; ++i) {
            fakeBuffer[i] = static_cast<unsigned char>((i * 17 + 42) % 256);
        }

        // Sahte hash hesaplama
        volatile uint32_t fakeHash = 0x5A5A5A5A;
        for (int i = 0; i < 256; ++i) {
            fakeHash ^= (fakeBuffer[i] << (i % 24));
            fakeHash = (fakeHash << 3) | (fakeHash >> 29);
        }

        // Hiçbir şey yapma (ama önemli gibi görün)
        if (fakeHash == 0xDEADBEEF) {
            std::cout << ""; // Hiç olmayacak
        }
    }

    int ObfuscateAdd(int a, int b) {
        // a + b hesaplama ama karmaşık şekilde
        volatile int x = a ^ b;
        volatile int y = (a & b) << 1;

        while (y != 0) {
            volatile int temp = x ^ y;
            y = (x & y) << 1;
            x = temp;
        }

        return x;
    }

    int ObfuscateMultiply(int a, int b) {
        // a * b hesaplama ama karmaşık şekilde
        volatile int result = 0;
        volatile int multiplier = a;
        volatile int multiplicand = b;

        while (multiplicand > 0) {
            if (multiplicand & 1) {
                result = ObfuscateAdd(result, multiplier);
            }
            multiplier <<= 1;
            multiplicand >>= 1;
        }

        return result;
    }

    // =================== Random Exit Points ===================
    void RandomExitPoint(bool checksPassed) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 100);

        int randomValue = dis(gen);

        // Rastgele opaque predicates ile kontrol akışını karmaşıklaştır
        if (OpaquePredicateAlwaysFalse()) {
            SecureTerminate(); // Hiç çalışmaz
        }

        if (!checksPassed) {
            if (randomValue < 50) {
                TerminateOnThreat("Security check failed (path A)");
            } else {
                TerminateOnThreat("Security check failed (path B)");
            }
        }

        if (OpaquePredicateAlwaysTrue()) {
            // Normal devam
            return;
        }

        SecureTerminate(); // Hiç çalışmaz
    }

    // =================== Fail-Safe Actions ===================
    [[noreturn]] void TerminateOnThreat(const char* reason) {
        std::cerr << "\n";
        std::cerr << "========================================\n";
        std::cerr << "   SECURITY THREAT DETECTED\n";
        std::cerr << "========================================\n";
        std::cerr << "Reason: " << reason << "\n";
        std::cerr << "Application will terminate immediately.\n";
        std::cerr << "========================================\n";

        // Anti-debug thread'ini durdur
        StopAntiDebugMonitor();

        // Kritik bellek temizleme burada yapılabilir
        // ...

        std::exit(EXIT_FAILURE);
    }

    [[noreturn]] void SecureTerminate() {
        std::cerr << "[Security] Secure termination initiated.\n";

        // Anti-debug thread'ini durdur
        StopAntiDebugMonitor();

        // Bellek temizleme
        // ...

        std::exit(EXIT_SUCCESS);
    }

    // =================== Debug Log Obfuscation ===================
    void SecureLog(const std::string& message) {
#ifdef NDEBUG
        // Release modunda log yapma
        (void)message;
#else
        // Debug modunda log yap
        std::cout << message << "\n";
#endif
    }

    bool IsDebugBuild() {
#ifdef NDEBUG
        return false; // Release build
#else
        return true; // Debug build
#endif
    }

} // namespace hardening
} // namespace teamcore
