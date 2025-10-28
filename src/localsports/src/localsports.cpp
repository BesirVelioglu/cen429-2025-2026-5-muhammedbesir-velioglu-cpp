// src/localsports.cpp
#include "localsports.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <ctime>
#include <climits>

#if defined(_MSC_VER)
#pragma warning(disable : 4996)
#endif

// ---- File names (binary) ----
const char* FILE_PLAYERS = "players.bin";
const char* FILE_GAMES = "games.bin";
const char* FILE_STATS = "stats.bin";
const char* FILE_MESSAGES = "messages.bin";
const char* FILE_USERS = "users.bin";

// ---- Auth session (in-memory) ----
static bool g_isAuthed = false;
static char g_currentUser[32] = { 0 };

// ---- Small utilities ----
static std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string s;
    std::getline(std::cin, s);
    return s;
}

static int readInt(const std::string& prompt, int minV = INT32_MIN, int maxV = INT32_MAX) {
    while (true) {
        std::cout << prompt;
        std::string s;
        if (!std::getline(std::cin, s)) return 0;
        try {
            size_t idx = 0;
            int v = std::stoi(s, &idx);
            if (idx == s.size() && v >= minV && v <= maxV) return v;
        }
        catch (...) {}
        std::cout << "Lutfen gecerli bir tamsayi girin";
        if (minV != INT32_MIN || maxV != INT32_MAX) std::cout << " [" << minV << " - " << maxV << "]";
        std::cout << ".\n";
    }
}

static void copyTo(char* dst, size_t n, const std::string& src) {
    std::snprintf(dst, n, "%s", src.c_str());
}

static std::string nowDateTime() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min);
    return std::string(buf);
}

// ---- Generic binary I/O ----
template<typename T>
static std::vector<T> readAll(const char* path) {
    std::vector<T> out;
    std::ifstream f(path, std::ios::binary);
    if (!f) return out;
    T rec{};
    while (f.read(reinterpret_cast<char*>(&rec), sizeof(T))) {
        out.push_back(rec);
    }
    return out;
}

template<typename T>
static bool writeAll(const char* path, const std::vector<T>& v) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    for (const auto& rec : v) {
        f.write(reinterpret_cast<const char*>(&rec), sizeof(T));
        if (!f) return false;
    }
    return true;
}

template<typename T>
static uint32_t nextId(const std::vector<T>& v) {
    uint32_t m = 0;
    for (const auto& r : v) if (r.id > m) m = r.id;
    return m + 1;
}

// ---- FNV-1a 64 (for simple passHash placeholder) ----
static uint64_t fnv1a64(const std::string& s) {
    const uint64_t FNV_OFFSET = 1469598103934665603ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t h = FNV_OFFSET;
    for (unsigned char c : s) {
        h ^= c;
        h *= FNV_PRIME;
    }
    return h;
}

// ---- Public init ----
void LS_Init() {
    // Ensure files exist (touch if missing)
    auto ensure = [](const char* p) {
        std::ifstream in(p, std::ios::binary);
        if (!in.good()) {
            std::ofstream out(p, std::ios::binary | std::ios::trunc);
            (void)out;
        }
        };
    ensure(FILE_PLAYERS);
    ensure(FILE_GAMES);
    ensure(FILE_STATS);
    ensure(FILE_MESSAGES);
    ensure(FILE_USERS);

    // if users file is empty, create a default admin: admin/admin
    auto users = readAll<User>(FILE_USERS);
    if (users.empty()) {
        User u{};
        u.id = 1;
        std::snprintf(u.username, sizeof(u.username), "%s", "admin");
        u.passHash = fnv1a64("admin");
        std::snprintf(u.role, sizeof(u.role), "%s", "admin");
        u.active = 1;
        users.push_back(u);
        writeAll(FILE_USERS, users);
    }
}

// =================== AUTH ===================
bool LS_AuthLoginInteractive() {
    std::string uname = readLine("Kullanici adi: ");
    std::string pwd = readLine("Sifre: ");
    uint64_t h = fnv1a64(pwd);

    auto users = readAll<User>(FILE_USERS);
    for (const auto& u : users) {
        if (u.active && uname == u.username && u.passHash == h) {
            g_isAuthed = true;
            std::snprintf(g_currentUser, sizeof(g_currentUser), "%s", u.username);
            std::cout << "Giris basarili. Hos geldin, " << g_currentUser << "!\n";
            return true;
        }
    }
    std::cout << "Hatali kullanici adi ya da sifre.\n";
    return false;
}

void LS_AuthRegisterInteractive() {
    auto users = readAll<User>(FILE_USERS);

    std::string uname;
    while (true) {
        uname = readLine("Yeni kullanici adi (3-31): ");
        if (uname.size() < 3 || uname.size() > 31) { std::cout << "Uzunluk hatasi.\n"; continue; }
        bool exists = false;
        for (auto& u : users) if (u.active && uname == u.username) { exists = true; break; }
        if (exists) { std::cout << "Bu kullanici adi zaten var.\n"; continue; }
        break;
    }

    std::string pwd1 = readLine("Sifre: ");
    std::string pwd2 = readLine("Sifre (tekrar): ");
    if (pwd1 != pwd2) { std::cout << "Sifreler eslesmiyor.\n"; return; }

    User u{};
    u.id = nextId(users);
    copyTo(u.username, sizeof(u.username), uname);
    u.passHash = fnv1a64(pwd1);
    std::snprintf(u.role, sizeof(u.role), "%s", "member");
    u.active = 1;

    users.push_back(u);
    if (writeAll(FILE_USERS, users)) std::cout << "Kayit olusturuldu. ID=" << u.id << "\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

void LS_AuthLogout() {
    g_isAuthed = false;
    g_currentUser[0] = '\0';
    std::cout << "Oturum kapatildi.\n";
}

bool LS_IsAuthenticated() { return g_isAuthed; }
const char* LS_CurrentUsername() { return g_currentUser[0] ? g_currentUser : nullptr; }

// =================== ROSTER ===================
void LS_ListPlayersInteractive() {
    auto players = readAll<Player>(FILE_PLAYERS);
    std::cout << "\nID  " << std::left << std::setw(22) << "Name"
        << std::setw(12) << "Position"
        << std::setw(16) << "Phone"
        << std::setw(26) << "Email"
        << "Active\n";
    std::cout << std::string(90, '-') << "\n";
    for (const auto& p : players) {
        if (!p.active) continue;
        std::cout << std::left
            << std::setw(4) << p.id
            << std::setw(22) << p.name
            << std::setw(12) << p.position
            << std::setw(16) << p.phone
            << std::setw(26) << p.email
            << (p.active ? "Yes" : "No")
            << "\n";
    }
}

void LS_AddPlayerInteractive() {
    auto players = readAll<Player>(FILE_PLAYERS);
    Player p{};
    p.id = nextId(players);
    copyTo(p.name, sizeof(p.name), readLine("Isim: "));
    copyTo(p.position, sizeof(p.position), readLine("Pozisyon: "));
    copyTo(p.phone, sizeof(p.phone), readLine("Telefon: "));
    copyTo(p.email, sizeof(p.email), readLine("Email: "));
    p.active = 1;
    players.push_back(p);
    if (writeAll(FILE_PLAYERS, players)) std::cout << "Player eklendi. ID=" << p.id << "\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

void LS_EditPlayerInteractive() {
    auto players = readAll<Player>(FILE_PLAYERS);
    LS_ListPlayersInteractive();
    int id = readInt("Duzenlenecek Player ID: ");
    auto it = std::find_if(players.begin(), players.end(), [&](const Player& x) { return (int)x.id == id && x.active; });
    if (it == players.end()) { std::cout << "Bulunamadi.\n"; return; }

    std::string v;
    v = readLine("Isim (bos birak = ayni): ");        if (!v.empty()) copyTo(it->name, sizeof(it->name), v);
    v = readLine("Pozisyon (bos = ayni): ");          if (!v.empty()) copyTo(it->position, sizeof(it->position), v);
    v = readLine("Telefon (bos = ayni): ");           if (!v.empty()) copyTo(it->phone, sizeof(it->phone), v);
    v = readLine("Email (bos = ayni): ");             if (!v.empty()) copyTo(it->email, sizeof(it->email), v);

    if (writeAll(FILE_PLAYERS, players)) std::cout << "Guncellendi.\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

void LS_RemovePlayerInteractive() {
    auto players = readAll<Player>(FILE_PLAYERS);
    LS_ListPlayersInteractive();
    int id = readInt("Silinecek Player ID: ");
    auto it = std::find_if(players.begin(), players.end(), [&](const Player& x) { return (int)x.id == id && x.active; });
    if (it == players.end()) { std::cout << "Bulunamadi.\n"; return; }
    it->active = 0; // soft delete
    if (writeAll(FILE_PLAYERS, players)) std::cout << "Silindi (pasif).\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

// =================== GAMES ===================
void LS_ListGamesInteractive() {
    auto games = readAll<Game>(FILE_GAMES);
    std::cout << "\nID  " << std::left << std::setw(12) << "Date"
        << std::setw(8) << "Time"
        << std::setw(22) << "Opponent"
        << std::setw(22) << "Location"
        << std::setw(8) << "Played"
        << "Result\n";
    std::cout << std::string(90, '-') << "\n";
    for (const auto& g : games) {
        std::cout << std::left
            << std::setw(4) << g.id
            << std::setw(12) << g.date
            << std::setw(8) << g.time
            << std::setw(22) << g.opponent
            << std::setw(22) << g.location
            << std::setw(8) << (g.played ? "Yes" : "No")
            << g.result
            << "\n";
    }
}

void LS_AddGameInteractive() {
    auto games = readAll<Game>(FILE_GAMES);
    Game g{};
    g.id = nextId(games);
    copyTo(g.date, sizeof(g.date), readLine("Tarih (YYYY-MM-DD): "));
    copyTo(g.time, sizeof(g.time), readLine("Saat (HH:MM): "));
    copyTo(g.opponent, sizeof(g.opponent), readLine("Rakip: "));
    copyTo(g.location, sizeof(g.location), readLine("Lokasyon: "));
    g.played = 0; g.result[0] = '\0';
    games.push_back(g);
    if (writeAll(FILE_GAMES, games)) std::cout << "Mac eklendi. ID=" << g.id << "\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

void LS_RecordResultInteractive() {
    auto games = readAll<Game>(FILE_GAMES);
    LS_ListGamesInteractive();
    int id = readInt("Sonuc girilecek Game ID: ");
    auto it = std::find_if(games.begin(), games.end(), [&](const Game& x) { return (int)x.id == id; });
    if (it == games.end()) { std::cout << "Bulunamadi.\n"; return; }
    copyTo(it->result, sizeof(it->result), readLine("Sonuc (ornegin 2-1 W): "));
    it->played = 1;
    if (writeAll(FILE_GAMES, games)) std::cout << "Sonuc kaydedildi.\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

// =================== STATS ===================
void LS_RecordStatsInteractive() {
    auto games = readAll<Game>(FILE_GAMES);
    if (games.empty()) { std::cout << "Once bir mac ekleyin.\n"; return; }
    LS_ListGamesInteractive();
    int gid = readInt("Hangi Game ID icin istatistik? ");
    auto git = std::find_if(games.begin(), games.end(), [&](const Game& x) { return (int)x.id == gid; });
    if (git == games.end()) { std::cout << "Mac bulunamadi.\n"; return; }

    auto players = readAll<Player>(FILE_PLAYERS);
    std::vector<Player> active;
    for (auto& p : players) if (p.active) active.push_back(p);
    if (active.empty()) { std::cout << "Aktif oyuncu yok.\n"; return; }

    std::cout << "\nOyuncular:\n";
    for (const auto& p : active) {
        std::cout << "  " << p.id << ") " << p.name << " (" << p.position << ")\n";
    }
    int pid = readInt("Player ID: ");
    auto pit = std::find_if(active.begin(), active.end(), [&](const Player& x) { return (int)x.id == pid; });
    if (pit == active.end()) { std::cout << "Oyuncu bulunamadi.\n"; return; }

    auto stats = readAll<Stat>(FILE_STATS);
    Stat s{};
    s.id = nextId(stats);
    s.gameId = gid;
    s.playerId = pid;
    s.goals = readInt("Goals: ", 0, 100);
    s.assists = readInt("Assists: ", 0, 100);
    s.saves = readInt("Saves: ", 0, 100);
    s.yellow = readInt("Yellow cards: ", 0, 10);
    s.red = readInt("Red cards: ", 0, 10);

    stats.push_back(s);
    if (writeAll(FILE_STATS, stats)) std::cout << "Istatistik eklendi (Game " << gid << ", Player " << pid << ").\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}

void LS_ViewPlayerTotalsInteractive() {
    auto players = readAll<Player>(FILE_PLAYERS);
    auto stats = readAll<Stat>(FILE_STATS);

    struct Tot { uint32_t pid; int goals = 0, assists = 0, saves = 0, yellow = 0, red = 0; };
    std::vector<Tot> totals;
    for (const auto& p : players) {
        if (!p.active) continue;
        Tot t; t.pid = p.id;
        for (const auto& s : stats) {
            if (s.playerId == p.id) {
                t.goals += s.goals;
                t.assists += s.assists;
                t.saves += s.saves;
                t.yellow += s.yellow;
                t.red += s.red;
            }
        }
        totals.push_back(t);
    }

    std::sort(totals.begin(), totals.end(), [](const Tot& a, const Tot& b) { return a.goals > b.goals; });

    std::cout << "\nID  " << std::left << std::setw(22) << "Name"
        << std::setw(8) << "Goals"
        << std::setw(8) << "Assists"
        << std::setw(8) << "Saves"
        << std::setw(8) << "Yellow"
        << "Red\n";
    std::cout << std::string(70, '-') << "\n";

    for (const auto& t : totals) {
        auto it = std::find_if(players.begin(), players.end(), [&](const Player& x) { return x.id == t.pid; });
        if (it == players.end()) continue;
        std::cout << std::left
            << std::setw(4) << it->id
            << std::setw(22) << it->name
            << std::setw(8) << t.goals
            << std::setw(8) << t.assists
            << std::setw(8) << t.saves
            << std::setw(8) << t.yellow
            << t.red
            << "\n";
    }
}

// =================== COMMUNICATIONS ===================
void LS_ListMessagesInteractive() {
    auto msgs = readAll<Message>(FILE_MESSAGES);
    std::cout << "\nID  " << std::left << std::setw(18) << "Datetime"
        << "Message\n";
    std::cout << std::string(80, '-') << "\n";
    for (const auto& m : msgs) {
        std::cout << std::left
            << std::setw(4) << m.id
            << std::setw(18) << m.datetime
            << m.text << "\n";
    }
}

void LS_AddMessageInteractive() {
    auto msgs = readAll<Message>(FILE_MESSAGES);
    Message m{};
    m.id = nextId(msgs);
    copyTo(m.datetime, sizeof(m.datetime), nowDateTime());
    std::string text;
    do {
        text = readLine("Mesaj (1-150 karakter): ");
    } while (text.empty() || text.size() > 150);
    copyTo(m.text, sizeof(m.text), text);
    msgs.push_back(m);
    if (writeAll(FILE_MESSAGES, msgs)) std::cout << "Mesaj kaydedildi.\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
}
