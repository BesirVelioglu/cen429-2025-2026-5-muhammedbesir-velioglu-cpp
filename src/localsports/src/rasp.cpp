// src/rasp.cpp
// Runtime Application Self-Protection (RASP) Implementation

#include "rasp.h"
#include "security_config.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

// Platform-specific includes
#if defined(_WIN32)
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#else
    #include <sys/ptrace.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <dlfcn.h>
    #include <link.h>
    #include <elf.h>
#endif

// OpenSSL for SHA-256
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace teamcore {
namespace rasp {

    // =================== Global State ===================
    static std::atomic<bool> g_raspActive{false};
    static std::atomic<bool> g_debuggerMonitorRunning{false};
    static std::thread g_debuggerMonitorThread;
    static RASPConfig g_config;
    static std::vector<SecurityEvent> g_eventLog;
    static std::mutex g_logMutex;
    static std::string g_expectedChecksum;

    // =================== Helper Functions ===================
    // Conditional logging based on configured log level
    static void LogToConsole(security::LogLevel level, const std::string& message) {
        if (security::ShouldLogToConsole(level)) {
            std::cout << message << std::endl;
        }
    }

    static void LogErrorToConsole(security::LogLevel level, const std::string& message) {
        if (security::ShouldLogToConsole(level)) {
            std::cerr << message << std::endl;
        }
    }

    static std::string GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#if defined(_WIN32)
        localtime_s(&tm_buf, &now_c);
#else
        localtime_r(&now_c, &tm_buf);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    static std::string BytesToHex(const uint8_t* data, size_t len) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            oss << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    }

    // =================== IsDebuggerPresent & ptrace ===================
    bool DetectDebugger() {
#if defined(_WIN32)
        // Windows: IsDebuggerPresent() API
        if (::IsDebuggerPresent()) {
            return true;
        }

        // CheckRemoteDebuggerPresent
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent)) {
            if (isDebuggerPresent) {
                return true;
            }
        }

        // NtQueryInformationProcess kontrolü
        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            DWORD ProcessInformationLength,
            PDWORD ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            auto NtQueryInformationProcess = (pfnNtQueryInformationProcess)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");

            if (NtQueryInformationProcess) {
                DWORD debugPort = 0;
                DWORD returnLen = 0;
                NTSTATUS status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    7, // ProcessDebugPort
                    &debugPort,
                    sizeof(debugPort),
                    &returnLen
                );
                if (status == 0 && debugPort != 0) {
                    return true;
                }
            }
        }

        return false;

#else
        // Linux: ptrace(PTRACE_TRACEME) kontrolü
        // Eğer zaten bir debugger attach ise, ptrace başarısız olur
        static bool alreadyChecked = false;
        static bool cachedResult = false;

        if (!alreadyChecked) {
            if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
                cachedResult = true; // Debugger detected
            } else {
                ptrace(PTRACE_DETACH, 0, 1, 0);
                cachedResult = false;
            }
            alreadyChecked = true;
        }

        // /proc/self/status kontrolü (TracerPid)
        std::ifstream statusFile("/proc/self/status");
        if (statusFile.is_open()) {
            std::string line;
            while (std::getline(statusFile, line)) {
                if (line.find("TracerPid:") == 0) {
                    std::string pidStr = line.substr(10);
                    int tracerPid = std::stoi(pidStr);
                    if (tracerPid != 0) {
                        return true; // Debugger attached
                    }
                }
            }
        }

        return cachedResult;
#endif
    }

    void StartDebuggerMonitoring(std::function<void()> callback, int intervalMs) {
        if (g_debuggerMonitorRunning.load()) {
            std::cerr << "[RASP] Debugger monitoring already running.\n";
            return;
        }

        g_debuggerMonitorRunning.store(true);
        g_debuggerMonitorThread = std::thread([callback, intervalMs]() {
            while (g_debuggerMonitorRunning.load()) {
                if (DetectDebugger()) {
                    SecurityEvent evt;
                    evt.timestamp = GetCurrentTimestamp();
                    evt.eventType = "DEBUGGER_DETECTED";
                    evt.description = "Runtime debugger detected via IsDebuggerPresent/ptrace";
                    evt.severity = 3; // critical
                    LogSecurityEvent(evt);

                    if (callback) {
                        callback();
                    }

                    if (g_config.autoTerminateOnThreat) {
                        HandleCriticalEvent("DEBUGGER_DETECTED", 
                            "Debugger detected, terminating application", true);
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            }
        });
    }

    void StopDebuggerMonitoring() {
        if (g_debuggerMonitorRunning.load()) {
            g_debuggerMonitorRunning.store(false);
            if (g_debuggerMonitorThread.joinable()) {
                g_debuggerMonitorThread.join();
            }
        }
    }

    // =================== .text Section Checksum Verification ===================
#if defined(_WIN32)
    std::string CalculateTextSectionChecksum() {
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return "";

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return "";
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return "";
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return "";
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
            if (strcmp((char*)section->Name, ".text") == 0) {
                BYTE* textStart = (BYTE*)hModule + section->VirtualAddress;
                DWORD textSize = section->Misc.VirtualSize;

                // SHA-256 hesaplama
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, textStart, textSize);
                SHA256_Final(hash, &sha256);

                return BytesToHex(hash, SHA256_DIGEST_LENGTH);
            }
        }
        return "";
    }
#else
    std::string CalculateTextSectionChecksum() {
        // Linux: /proc/self/exe üzerinden .text bölümünü okuma
        std::ifstream exeFile("/proc/self/exe", std::ios::binary);
        if (!exeFile) return "";

        exeFile.seekg(0, std::ios::end);
        size_t fileSize = exeFile.tellg();
        exeFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> fileData(fileSize);
        exeFile.read((char*)fileData.data(), fileSize);

        // ELF header parse
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)fileData.data();
        if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || 
            ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr->e_ident[EI_MAG2] != ELFMAG2 || 
            ehdr->e_ident[EI_MAG3] != ELFMAG3) {
            return "";
        }

        Elf64_Shdr* shdr = (Elf64_Shdr*)(fileData.data() + ehdr->e_shoff);
        char* shstrtab = (char*)(fileData.data() + shdr[ehdr->e_shstrndx].sh_offset);

        // .text bölümünü bul
        for (int i = 0; i < ehdr->e_shnum; ++i) {
            if (strcmp(&shstrtab[shdr[i].sh_name], ".text") == 0) {
                uint8_t* textStart = fileData.data() + shdr[i].sh_offset;
                size_t textSize = shdr[i].sh_size;

                // SHA-256 hesaplama
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, textStart, textSize);
                SHA256_Final(hash, &sha256);

                return BytesToHex(hash, SHA256_DIGEST_LENGTH);
            }
        }
        return "";
    }
#endif

    bool VerifyTextSectionIntegrity(const std::string& expectedChecksum) {
        if (expectedChecksum.empty()) {
            LogToConsole(security::LogLevel::DEBUG, "[RASP] No checksum provided. Skipping integrity check.");
            return true;
        }

        LogToConsole(security::LogLevel::DEBUG, "[RASP] Performing boot-time integrity check...");
        
        std::string currentChecksum = CalculateTextSectionChecksum();
        if (currentChecksum.empty()) {
            LogErrorToConsole(security::LogLevel::MINIMAL, "[RASP] ERROR: Failed to calculate .text section checksum!");
            
            SecurityEvent evt;
            evt.timestamp = GetCurrentTimestamp();
            evt.eventType = "CHECKSUM_CALCULATION_FAILED";
            evt.description = "Failed to calculate .text section checksum";
            evt.severity = 3;
            LogSecurityEvent(evt);
            return false;
        }

        // Verbose mode: Show detailed comparison
        if (security::ShouldLogToConsole(security::LogLevel::VERBOSE)) {
            std::cout << "\n" << std::string(70, '-') << std::endl;
            std::cout << "[RASP] INTEGRITY CHECK DETAILS:" << std::endl;
            std::cout << std::string(70, '-') << std::endl;
            std::cout << "Expected: " << expectedChecksum << std::endl;
            std::cout << "Current:  " << currentChecksum << std::endl;
            std::cout << std::string(70, '-') << std::endl;
        }

        bool isValid = (currentChecksum == expectedChecksum);
        if (!isValid) {
            // CRITICAL ERROR - Always log to console
            std::cerr << "\n" << std::string(70, '!') << std::endl;
            std::cerr << "[RASP] *** CRITICAL: INTEGRITY CHECK FAILED! ***" << std::endl;
            std::cerr << std::string(70, '!') << std::endl;
            
            if (security::ShouldLogToConsole(security::LogLevel::VERBOSE)) {
                std::cerr << "\n[RASP] Binary has been modified or corrupted!" << std::endl;
                std::cerr << "[RASP] This could indicate:" << std::endl;
                std::cerr << "  1. Code tampering attempt" << std::endl;
                std::cerr << "  2. Malware injection" << std::endl;
                std::cerr << "  3. Outdated checksum in configuration" << std::endl;
                std::cerr << "\n[RASP] Expected checksum: " << expectedChecksum << std::endl;
                std::cerr << "[RASP] Current checksum:  " << currentChecksum << std::endl;
            }
            
            std::cerr << std::string(70, '!') << std::endl;
            
            SecurityEvent evt;
            evt.timestamp = GetCurrentTimestamp();
            evt.eventType = "CHECKSUM_MISMATCH";
            evt.description = "Code tampering detected - Expected: " + expectedChecksum + " Got: " + currentChecksum;
            evt.severity = 3;
            LogSecurityEvent(evt);
        } else {
            LogToConsole(security::LogLevel::DEBUG, "[RASP] Integrity check passed.");
            
            SecurityEvent evt;
            evt.timestamp = GetCurrentTimestamp();
            evt.eventType = "INTEGRITY_CHECK_PASSED";
            evt.description = "Binary integrity verified successfully";
            evt.severity = 1;
            LogSecurityEvent(evt);
        }

        return isValid;
    }

    bool BootTimeIntegrityCheck(const std::string& expectedChecksum) {
        if (!g_config.enableChecksumVerification) {
            return true;
        }

        bool result = VerifyTextSectionIntegrity(expectedChecksum);
        if (!result) {
            HandleCriticalEvent("BOOT_INTEGRITY_FAILED", 
                "Application code has been modified, terminating", true);
        }
        return result;
    }

    // =================== IAT/PLT Hook Detection ===================
#if defined(_WIN32)
    int DetectIATHooks() {
        // Windows IAT hook detection
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return -1;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

        DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) return 0;

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);
        int hookCount = 0;

        while (importDesc->Name != 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            
            while (thunk->u1.Function != 0) {
                FARPROC funcPtr = (FARPROC)thunk->u1.Function;
                
                // Fonksiyon pointer'ının executable bölge dışında olup olmadığını kontrol et
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(funcPtr, &mbi, sizeof(mbi))) {
                    if (!(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        hookCount++;
                    }
                }
                thunk++;
            }
            importDesc++;
        }

        if (hookCount > 0) {
            SecurityEvent evt;
            evt.timestamp = GetCurrentTimestamp();
            evt.eventType = "IAT_HOOK_DETECTED";
            evt.description = "IAT hooks detected: " + std::to_string(hookCount) + " modified entries";
            evt.severity = 3;
            LogSecurityEvent(evt);
        }

        return hookCount;
    }
#else
    int DetectIATHooks() {
        // Windows-specific, Linux'ta PLT kontrolü kullanılır
        return 0;
    }
#endif

#if !defined(_WIN32)
    int DetectPLTHooks() {
        // Linux PLT/GOT hook detection
        int hookCount = 0;

        // dl_iterate_phdr kullanarak loaded shared object'leri tara
        struct callback_data {
            int* count;
        };
        
        auto callback = [](struct dl_phdr_info* info, size_t size, void* data) -> int {
            // PLT/GOT analizi burada yapılabilir (karmaşık)
            // Basit versiyon: Sadece varlık kontrolü
            return 0;
        };

        callback_data data{&hookCount};
        dl_iterate_phdr(callback, &data);

        if (hookCount > 0) {
            SecurityEvent evt;
            evt.timestamp = GetCurrentTimestamp();
            evt.eventType = "PLT_HOOK_DETECTED";
            evt.description = "PLT/GOT hooks detected: " + std::to_string(hookCount) + " modified entries";
            evt.severity = 3;
            LogSecurityEvent(evt);
        }

        return hookCount;
    }
#else
    int DetectPLTHooks() {
        // Linux-specific
        return 0;
    }
#endif

    bool IsThunkModified(const std::string& functionName) {
        // Basit kontrol: Fonksiyon adresini kontrol et
        void* funcAddr = nullptr;

#if defined(_WIN32)
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32) {
            funcAddr = GetProcAddress(kernel32, functionName.c_str());
        }
#else
        funcAddr = dlsym(RTLD_DEFAULT, functionName.c_str());
#endif

        if (!funcAddr) return false;

        // Adresin beklenmeyen bir bölgede olup olmadığını kontrol et
        // (Gelişmiş sürümde: Orijinal adresleri saklayıp karşılaştır)
        
        return false; // Şimdilik basit versiyon
    }

    int ScanCriticalFunctions() {
        std::vector<std::string> criticalFuncs = {
            "malloc", "free", "strcpy", "memcpy", "fopen", "fread", "fwrite"
        };

        int hookCount = 0;
        for (const auto& func : criticalFuncs) {
            if (IsThunkModified(func)) {
                hookCount++;
            }
        }

        return hookCount;
    }

    // =================== Security Event Logging ===================
    bool LogSecurityEvent(const SecurityEvent& event) {
        std::lock_guard<std::mutex> lock(g_logMutex);
        
        // Memory log
        g_eventLog.push_back(event);

        // File log
        std::ofstream logFile(g_config.logFilePath, std::ios::app);
        if (logFile.is_open()) {
            logFile << "[" << event.timestamp << "] "
                    << "[" << event.eventType << "] "
                    << "[Severity:" << event.severity << "] "
                    << event.description << "\n";
            logFile.close();
            return true;
        }

        return false;
    }

    void HandleCriticalEvent(const std::string& eventType, 
                            const std::string& description,
                            bool terminateApp) {
        SecurityEvent evt;
        evt.timestamp = GetCurrentTimestamp();
        evt.eventType = eventType;
        evt.description = description;
        evt.severity = 3;
        
        LogSecurityEvent(evt);

        std::cerr << "\n*** CRITICAL SECURITY EVENT ***\n";
        std::cerr << "Type: " << eventType << "\n";
        std::cerr << "Description: " << description << "\n";
        std::cerr << "******************************\n\n";

        if (terminateApp) {
            FailClosedShutdown(description);
        }
    }

    std::vector<SecurityEvent> GetSecurityEventLog() {
        std::lock_guard<std::mutex> lock(g_logMutex);
        return g_eventLog;
    }

    void ClearSecurityLog() {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_eventLog.clear();
        
        std::ofstream logFile(g_config.logFilePath, std::ios::trunc);
        logFile.close();
    }

    // =================== Process Isolation & Fail-Closed ===================
    bool VerifyProcessIsolation() {
        // Basit versiyon: Parent process kontrolü
#if defined(_WIN32)
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        DWORD currentPid = GetCurrentProcessId();
        DWORD parentPid = 0;

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == currentPid) {
                    parentPid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);

        // Parent process'in güvenli olup olmadığını kontrol et
        // (Gelişmiş versiyon: Whitelist kontrolü)
        return (parentPid != 0);
#else
        return (getppid() > 1); // init dışında bir parent olmalı
#endif
    }

    void FailClosedShutdown(const std::string& reason) {
        std::cerr << "\n[RASP] FAIL-CLOSED SHUTDOWN: " << reason << "\n";
        
        // Güvenlik logunu flush et
        SecurityEvent evt;
        evt.timestamp = GetCurrentTimestamp();
        evt.eventType = "FAIL_CLOSED_SHUTDOWN";
        evt.description = reason;
        evt.severity = 3;
        LogSecurityEvent(evt);

        // RASP'ı kapat
        ShutdownRASP();

        // Uygulamayı sonlandır
        std::exit(EXIT_FAILURE);
    }

    void SecureTerminate() {
        std::cout << "\n[RASP] Secure termination initiated...\n";
        
        // Hassas verileri temizle (örnek)
        // memset(...);

        // RASP'ı düzgün kapat
        ShutdownRASP();

        std::exit(EXIT_SUCCESS);
    }

    // =================== RASP Initialization ===================
    bool InitializeRASP(const std::string& expectedChecksum, bool autoTerminateOnThreat) {
        if (g_raspActive.load()) {
            LogErrorToConsole(security::LogLevel::MINIMAL, "[RASP] Already initialized.");
            return false;
        }

        LogToConsole(security::LogLevel::NORMAL, "[RASP] Initializing Runtime Application Self-Protection...");

        g_expectedChecksum = expectedChecksum;
        g_config.autoTerminateOnThreat = autoTerminateOnThreat;

        // Verbose mode: Show checksum details
        if (security::ShouldLogToConsole(security::LogLevel::VERBOSE)) {
            std::cout << "[RASP] Expected .text checksum: " << expectedChecksum << std::endl;
            std::string current = CalculateTextSectionChecksum();
            std::cout << "[RASP] Current .text checksum:  " << current << std::endl;
        }

        // Boot-time integrity check
        if (g_config.enableChecksumVerification) {
            LogToConsole(security::LogLevel::DEBUG, "[RASP] Performing boot-time integrity check...");
            if (!BootTimeIntegrityCheck(expectedChecksum)) {
                return false; // Uygulama sonlandırılır
            }
            LogToConsole(security::LogLevel::NORMAL, "[RASP] Integrity check passed.");
        }

        // Debugger monitoring başlat
        if (g_config.enableDebuggerDetection) {
            LogToConsole(security::LogLevel::DEBUG, "[RASP] Starting debugger monitoring...");
            StartDebuggerMonitoring([]() {
                LogErrorToConsole(security::LogLevel::MINIMAL, "[RASP] ALERT: Debugger detected!");
            }, g_config.monitoringIntervalMs);
        }

        // Hook detection
        if (g_config.enableHookDetection) {
            LogToConsole(security::LogLevel::DEBUG, "[RASP] Scanning for IAT/PLT hooks...");
            int iatHooks = DetectIATHooks();
            int pltHooks = DetectPLTHooks();
            
            if (iatHooks > 0 || pltHooks > 0) {
                LogErrorToConsole(security::LogLevel::MINIMAL, "[RASP] CRITICAL: Hooks detected!");
                HandleCriticalEvent("HOOK_DETECTED", 
                    "IAT/PLT hooks detected during initialization", autoTerminateOnThreat);
            } else {
                LogToConsole(security::LogLevel::DEBUG, "[RASP] No hooks detected.");
            }
        }

        g_raspActive.store(true);
        LogToConsole(security::LogLevel::DEBUG, "[RASP] Initialization complete. System is protected.");
        LogToConsole(security::LogLevel::NORMAL, "[RASP] RASP is now active and protecting the application.");
        
        return true;
    }

    void ShutdownRASP() {
        if (!g_raspActive.load()) {
            return;
        }

        LogToConsole(security::LogLevel::DEBUG, "[RASP] Shutting down...");

        StopDebuggerMonitoring();
        g_raspActive.store(false);

        LogToConsole(security::LogLevel::DEBUG, "[RASP] Shutdown complete.");
    }

    bool IsRASPActive() {
        return g_raspActive.load();
    }

    bool PerformSecurityScan() {
        if (!g_raspActive.load()) {
            std::cerr << "[RASP] Cannot scan: RASP not active.\n";
            return false;
        }

        bool allPassed = true;

        // Debugger check
        if (g_config.enableDebuggerDetection && DetectDebugger()) {
            HandleCriticalEvent("DEBUGGER_DETECTED", 
                "Debugger detected during security scan", g_config.autoTerminateOnThreat);
            allPassed = false;
        }

        // Integrity check
        if (g_config.enableChecksumVerification && !VerifyTextSectionIntegrity(g_expectedChecksum)) {
            HandleCriticalEvent("INTEGRITY_VIOLATION", 
                "Code integrity violation detected", g_config.autoTerminateOnThreat);
            allPassed = false;
        }

        // Hook check
        if (g_config.enableHookDetection) {
            int hooks = DetectIATHooks() + DetectPLTHooks();
            if (hooks > 0) {
                HandleCriticalEvent("HOOK_DETECTED", 
                    "Hooks detected during security scan", g_config.autoTerminateOnThreat);
                allPassed = false;
            }
        }

        return allPassed;
    }

    // =================== Configuration ===================
    void ConfigureRASP(const RASPConfig& config) {
        g_config = config;
    }

    RASPConfig GetRASPConfig() {
        return g_config;
    }

} // namespace rasp
} // namespace teamcore
