// src/localsportsapp.cpp
#include "localsportsapp.h"
#include "localsports.h"
#include "rasp.h"  // RASP Runtime Protection
#include "security_config.h"  // Security configuration

#include <iostream>
#include <string>

static int readInt(const std::string& prompt) {
    while (true) {
        std::cout << prompt;
        std::string s;
        if (!std::getline(std::cin, s)) return 0;
        try {
            size_t idx = 0;
            int v = std::stoi(s, &idx);
            if (idx == s.size()) return v;
        }
        catch (...) {}
        std::cout << "Lutfen gecerli bir tamsayi girin.\n";
    }
}

static void banner() {
    std::cout
        << "\n###############################################################\n"
        << "#                     LOCAL SPORTS MANAGER                    #\n"
        << "###############################################################\n";
    if (LS_IsAuthenticated()) {
        std::cout << "# Oturum: " << (LS_CurrentUsername() ? LS_CurrentUsername() : "(yok)") << "\n";
    }
    std::cout << "---------------------------------------------------------------\n";
}

static void rosterMenu() {
    while (true) {
        banner();
        std::cout << "[ROSTER]\n"
            << " 1) Oyuncu ekle\n"
            << " 2) Oyuncu duzenle\n"
            << " 3) Oyuncu sil\n"
            << " 4) Roster listele\n"
            << " 0) Geri\n";
        int sel = readInt("Secim: ");
        if (sel == 0) return;
        switch (sel) {
        case 1: LS_AddPlayerInteractive(); break;
        case 2: LS_EditPlayerInteractive(); break;
        case 3: LS_RemovePlayerInteractive(); break;
        case 4: LS_ListPlayersInteractive(); break;
        default: std::cout << "Gecersiz secim.\n"; break;
        }
        std::cout << "\nDevam etmek icin Enter...\n"; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

static void gamesMenu() {
    while (true) {
        banner();
        std::cout << "[GAMES]\n"
            << " 1) Mac ekle\n"
            << " 2) Maclari listele\n"
            << " 3) Sonucu isaretle/duzenle\n"
            << " 0) Geri\n";
        int sel = readInt("Secim: ");
        if (sel == 0) return;
        switch (sel) {
        case 1: LS_AddGameInteractive(); break;
        case 2: LS_ListGamesInteractive(); break;
        case 3: LS_RecordResultInteractive(); break;
        default: std::cout << "Gecersiz secim.\n"; break;
        }
        std::cout << "\nDevam etmek icin Enter...\n"; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

static void statsMenu() {
    while (true) {
        banner();
        std::cout << "[STATS]\n"
            << " 1) Mac icin oyuncu istatistigi ekle\n"
            << " 2) Oyuncu toplamlarini goruntule\n"
            << " 0) Geri\n";
        int sel = readInt("Secim: ");
        if (sel == 0) return;
        switch (sel) {
        case 1: LS_RecordStatsInteractive(); break;
        case 2: LS_ViewPlayerTotalsInteractive(); break;
        default: std::cout << "Gecersiz secim.\n"; break;
        }
        std::cout << "\nDevam etmek icin Enter...\n"; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

static void commsMenu() {
    while (true) {
        banner();
        std::cout << "[COMMUNICATION]\n"
            << " 1) Duyuru/Mesaj olustur\n"
            << " 2) Mesajlari listele\n"
            << " 0) Geri\n";
        int sel = readInt("Secim: ");
        if (sel == 0) return;
        switch (sel) {
        case 1: LS_AddMessageInteractive(); break;
        case 2: LS_ListMessagesInteractive(); break;
        default: std::cout << "Gecersiz secim.\n"; break;
        }
        std::cout << "\nDevam etmek icin Enter...\n"; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

static void authGate() {
    while (!LS_IsAuthenticated()) {
        banner();
        std::cout << "[AUTH]\n"
            << " 1) Giris yap\n"
            << " 2) Kayit ol\n"
            << " 0) Cikis\n";
        int sel = readInt("Secim: ");
        if (sel == 0) std::exit(0);
        if (sel == 1) (void)LS_AuthLoginInteractive();
        else if (sel == 2) LS_AuthRegisterInteractive();
        else std::cout << "Gecersiz secim.\n";
        std::cout << "\nDevam etmek icin Enter...\n"; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
}

void LS_AppStart() {
    LS_Init();
    authGate();

    while (true) {
        banner();
        std::cout << "[MAIN MENU]\n"
            << " 1) Team Roster\n"
            << " 2) Game Scheduler\n"
            << " 3) Statistic Tracker\n"
            << " 4) Communication Tool\n"
            << " 5) Oturumu kapat\n"
            << " 0) Programdan cik\n";
        int sel = readInt("Secim: ");
        switch (sel) {
        case 0: std::cout << "Cikis yapiliyor...\n"; return;
        case 1: rosterMenu(); break;
        case 2: gamesMenu(); break;
        case 3: statsMenu(); break;
        case 4: commsMenu(); break;
        case 5: LS_AuthLogout(); authGate(); break;
        default: std::cout << "Gecersiz secim.\n"; break;
        }
    }
}

int main() {
    using namespace teamcore::security;
    using namespace teamcore::rasp;
    
    // =================== RASP Initialization ===================
    // Log level kontrolü: VERBOSE ise detaylı, MINIMAL ise sessiz
    if (ShouldLogToConsole(LogLevel::NORMAL)) {
        std::cout << "\n[SECURITY] Initializing RASP (Runtime Application Self-Protection)...\n";
    }
    
    // Verbose mode: Show checksum details
    if (ShouldLogToConsole(LogLevel::VERBOSE)) {
        std::string expectedChecksum = GetExpectedChecksum();
        std::cout << "[SECURITY] Expected .text checksum: " << expectedChecksum << "\n";
        
        std::string currentChecksum = CalculateTextSectionChecksum();
        std::cout << "[SECURITY] Current .text checksum:  " << currentChecksum << "\n";
    }
    
    // RASP yapılandırması (security_config.h'den alınıyor)
    RASPConfig config;
    config.enableDebuggerDetection = ENABLE_DEBUGGER_DETECTION;
    config.enableChecksumVerification = ENABLE_INTEGRITY_CHECK;
    config.enableHookDetection = ENABLE_HOOK_DETECTION;
    config.autoTerminateOnThreat = AUTO_TERMINATE_ON_THREAT;
    config.monitoringIntervalMs = MONITORING_INTERVAL_MS;
    config.logFilePath = SECURITY_LOG_FILE;
    
    ConfigureRASP(config);
    
    // RASP'ı başlat (stored checksum ile doğrulama yapılacak)
    if (!InitializeRASP(GetExpectedChecksum(), config.autoTerminateOnThreat)) {
        std::cerr << "\n[SECURITY] RASP initialization failed! Exiting...\n";
        return 1;
    }
    
    if (ShouldLogToConsole(LogLevel::NORMAL)) {
        std::cout << "[SECURITY] RASP is now active and protecting the application.\n\n";
    }
    
    // =================== Application Start ===================
    LS_AppStart();
    
    // =================== RASP Shutdown ===================
    if (ShouldLogToConsole(LogLevel::DEBUG)) {
        std::cout << "\n[SECURITY] Shutting down RASP...\n";
    }
    ShutdownRASP();
    
    return 0;
}
