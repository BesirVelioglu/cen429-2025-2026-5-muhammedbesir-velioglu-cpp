// src/localsportsapp.cpp
#include "localsportsapp.h"
#include "localsports.h"
#include "rasp.h"
#include "security_config.h"

#include <iostream>
#include <string>
#include <iomanip>
#include <limits>
#include <thread>
#include <chrono>

// Windows color codes
#ifdef _WIN32
#include <windows.h>
static void setColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
#define COLOR_RESET 7
#define COLOR_BLUE 9
#define COLOR_GREEN 10
#define COLOR_CYAN 11
#define COLOR_RED 12
#define COLOR_YELLOW 14
#define COLOR_WHITE 15
#else
// ANSI color codes for Linux/Mac
static void setColor(const char* color) {
    std::cout << color;
}
#define COLOR_RESET "\033[0m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RED "\033[1;31m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_WHITE "\033[1;37m"
#endif

static void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

static void waitForEnter() {
    setColor(COLOR_CYAN);
    std::cout << "\nDevam etmek icin Enter...";
    setColor(COLOR_RESET);
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
}

static int readInt(const std::string& prompt) {
    while (true) {
        setColor(COLOR_CYAN);
        std::cout << prompt;
        setColor(COLOR_RESET);
        std::string s;
        if (!std::getline(std::cin, s)) return 0;
        try {
            size_t idx = 0;
            int v = std::stoi(s, &idx);
            if (idx == s.size()) return v;
        }
        catch (...) {}
        setColor(COLOR_RED);
        std::cout << "Hata: Lutfen gecerli bir sayi girin.\n";
        setColor(COLOR_RESET);
    }
}

static void banner() {
    clearScreen();
    setColor(COLOR_CYAN);
    std::cout << "\n";
    std::cout << "================================================================================\n";
    std::cout << "                    LOCAL SPORTS MANAGEMENT SYSTEM                              \n";
    std::cout << "================================================================================\n";
    setColor(COLOR_RESET);
    
    if (LS_IsAuthenticated()) {
        setColor(COLOR_GREEN);
        std::cout << "  Kullanici: ";
        setColor(COLOR_YELLOW);
        std::cout << (LS_CurrentUsername() ? LS_CurrentUsername() : "(yok)");
        setColor(COLOR_RESET);
        std::cout << "\n";
    }
    
    setColor(COLOR_CYAN);
    std::cout << "--------------------------------------------------------------------------------\n";
    setColor(COLOR_RESET);
}

static void rosterMenu() {
    while (true) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[TAKIM KADROSU]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Oyuncu ekle\n"
                  << "  2) Oyuncu duzenle\n"
                  << "  3) Oyuncu sil\n"
                  << "  4) Roster listele\n"
                  << "  0) Geri\n\n";
        
        int sel = readInt("Seciminiz: ");
        if (sel == 0) return;
        std::cout << "\n";
        switch (sel) {
        case 1: LS_AddPlayerInteractive(); break;
        case 2: LS_EditPlayerInteractive(); break;
        case 3: LS_RemovePlayerInteractive(); break;
        case 4: LS_ListPlayersInteractive(); break;
        default: 
            setColor(COLOR_RED);
            std::cout << "Gecersiz secim.\n";
            setColor(COLOR_RESET);
            break;
        }
        waitForEnter();
    }
}

static void gamesMenu() {
    while (true) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[MAC PLANLAYICI]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Mac ekle\n"
                  << "  2) Maclari listele\n"
                  << "  3) Sonucu isaretle/duzenle\n"
                  << "  0) Geri\n\n";
        
        int sel = readInt("Seciminiz: ");
        if (sel == 0) return;
        std::cout << "\n";
        switch (sel) {
        case 1: LS_AddGameInteractive(); break;
        case 2: LS_ListGamesInteractive(); break;
        case 3: LS_RecordResultInteractive(); break;
        default: 
            setColor(COLOR_RED);
            std::cout << "Gecersiz secim.\n";
            setColor(COLOR_RESET);
            break;
        }
        waitForEnter();
    }
}

static void statsMenu() {
    while (true) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[ISTATISTIK TAKIPCI]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Mac icin oyuncu istatistigi ekle\n"
                  << "  2) Oyuncu toplamlarini goruntule\n"
                  << "  0) Geri\n\n";
        
        int sel = readInt("Seciminiz: ");
        if (sel == 0) return;
        std::cout << "\n";
        switch (sel) {
        case 1: LS_RecordStatsInteractive(); break;
        case 2: LS_ViewPlayerTotalsInteractive(); break;
        default: 
            setColor(COLOR_RED);
            std::cout << "Gecersiz secim.\n";
            setColor(COLOR_RESET);
            break;
        }
        waitForEnter();
    }
}

static void commsMenu() {
    while (true) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[ILETISIM ARACI]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Duyuru/Mesaj olustur\n"
                  << "  2) Mesajlari listele\n"
                  << "  0) Geri\n\n";
        
        int sel = readInt("Seciminiz: ");
        if (sel == 0) return;
        std::cout << "\n";
        switch (sel) {
        case 1: LS_AddMessageInteractive(); break;
        case 2: LS_ListMessagesInteractive(); break;
        default: 
            setColor(COLOR_RED);
            std::cout << "Gecersiz secim.\n";
            setColor(COLOR_RESET);
            break;
        }
        waitForEnter();
    }
}

static void authGate() {
    while (!LS_IsAuthenticated()) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[KIMLIK DOGRULAMA]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Giris yap\n"
                  << "  2) Kayit ol\n"
                  << "  0) Cikis\n\n";
        
        int sel = readInt("Seciminiz: ");
        if (sel == 0) std::exit(0);
        std::cout << "\n";
        if (sel == 1) {
            (void)LS_AuthLoginInteractive();
        }
        else if (sel == 2) {
            LS_AuthRegisterInteractive();
        }
        else {
            setColor(COLOR_RED);
            std::cout << "Gecersiz secim.\n";
            setColor(COLOR_RESET);
        }
        waitForEnter();
    }
}

void LS_AppStart() {
    LS_Init();
    
    // Sistem başlatma
    clearScreen();
    setColor(COLOR_CYAN);
    std::cout << "\n\n        SISTEM BASLATILIYOR...\n";
    setColor(COLOR_RESET);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    authGate();

    while (true) {
        banner();
        setColor(COLOR_YELLOW);
        std::cout << "\n[ANA MENU]\n";
        setColor(COLOR_RESET);
        std::cout << "  1) Team Roster        - Takim kadrosu yonetimi\n"
                  << "  2) Game Scheduler     - Mac planlayici ve takipci\n"
                  << "  3) Statistic Tracker  - Istatistik ve performans analizi\n"
                  << "  4) Communication Tool - Duyuru ve mesajlasma\n"
                  << "  5) Oturumu kapat      - Guvenli cikis yap\n"
                  << "  0) Programdan cik     - Uygulamayi sonlandir\n\n";
        
        int sel = readInt("Seciminiz: ");
        switch (sel) {
        case 0: 
            setColor(COLOR_GREEN);
            std::cout << "\nCikis yapiliyor...\n";
            setColor(COLOR_RESET);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            return;
        case 1: 
            rosterMenu(); 
            break;
        case 2: 
            gamesMenu(); 
            break;
        case 3: 
            statsMenu(); 
            break;
        case 4: 
            commsMenu(); 
            break;
        case 5: 
            setColor(COLOR_YELLOW);
            std::cout << "\nOturum kapatiliyor...\n";
            setColor(COLOR_RESET);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            LS_AuthLogout(); 
            authGate(); 
            break;
        default: 
            setColor(COLOR_RED);
            std::cout << "\nGecersiz secim. Lutfen 0-5 arasi bir deger girin.\n";
            setColor(COLOR_RESET);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            break;
        }
    }
}



int main() {
    using namespace teamcore::security;
    using namespace teamcore::rasp;
    
    // =================== RASP Initialization ===================
    if (ShouldLogToConsole(LogLevel::NORMAL)) {
        setColor(COLOR_CYAN);
        std::cout << "\n================================================================================\n";
        std::cout << "                     GUVENLIK KATMANI BASLATILIYOR                             \n";
        std::cout << "================================================================================\n";
        setColor(COLOR_RESET);
    }
    
    // Verbose mode: Show checksum details
    if (ShouldLogToConsole(LogLevel::VERBOSE)) {
        std::string expectedChecksum = GetExpectedChecksum();
        setColor(COLOR_YELLOW);
        std::cout << "Beklenen .text checksum: " << expectedChecksum << "\n";
        
        std::string currentChecksum = CalculateTextSectionChecksum();
        std::cout << "Mevcut .text checksum:   " << currentChecksum << "\n";
        setColor(COLOR_RESET);
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
        setColor(COLOR_RED);
        std::cerr << "\nRASP baslatma basarisiz! Uygulama sonlandiriliyor...\n";
        setColor(COLOR_RESET);
        return 1;
    }
    
    if (ShouldLogToConsole(LogLevel::NORMAL)) {
        setColor(COLOR_GREEN);
        std::cout << "RASP aktif - Uygulama korunuyor.\n";
        setColor(COLOR_CYAN);
        std::cout << "--------------------------------------------------------------------------------\n\n";
        setColor(COLOR_RESET);
    }
    
    // =================== Application Start ===================
    LS_AppStart();
    
    // =================== RASP Shutdown ===================
    if (ShouldLogToConsole(LogLevel::DEBUG)) {
        setColor(COLOR_YELLOW);
        std::cout << "\nRASP kapatiliyor...\n";
        setColor(COLOR_RESET);
    }
    ShutdownRASP();
    
    setColor(COLOR_GREEN);
    std::cout << "\nProgram basariyla sonlandirildi.\n";
    setColor(COLOR_RESET);
    
    return 0;
}
