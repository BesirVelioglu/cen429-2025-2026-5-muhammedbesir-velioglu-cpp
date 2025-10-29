// src/localsports.cpp
#include "localsports.h"

#include <iostream>
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

// =================== SQLite ===================
#include <sqlite3.h>
static sqlite3* g_db = nullptr;

// Veritabaný dosyasý (çalýþma klasöründe oluþturulur)
static const char* DB_PATH = "localsports.db";

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

// ---- SQLite helpers ----
static bool db_exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(g_db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << (err ? err : "(null)") << "\n";
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool db_prepare(sqlite3_stmt** out, const char* sql) {
    int rc = sqlite3_prepare_v2(g_db, sql, -1, out, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "prepare failed: " << sqlite3_errmsg(g_db) << "\n";
        return false;
    }
    return true;
}

// =================== INIT ===================
void LS_Init() {
    if (sqlite3_open(DB_PATH, &g_db) != SQLITE_OK) {
        std::cerr << "DB acilamadi: " << sqlite3_errmsg(g_db) << "\n";
        std::exit(1);
    }

    // Tablolar
    db_exec("PRAGMA journal_mode=WAL;");
    db_exec("CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "passhash INTEGER NOT NULL,"
        "role TEXT NOT NULL,"
        "active INTEGER NOT NULL DEFAULT 1);");

    db_exec("CREATE TABLE IF NOT EXISTS players ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "position TEXT NOT NULL,"
        "phone TEXT NOT NULL,"
        "email TEXT NOT NULL,"
        "active INTEGER NOT NULL DEFAULT 1);");

    db_exec("CREATE TABLE IF NOT EXISTS games ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "date TEXT NOT NULL,"
        "time TEXT NOT NULL,"
        "opponent TEXT NOT NULL,"
        "location TEXT NOT NULL,"
        "played INTEGER NOT NULL DEFAULT 0,"
        "result TEXT NOT NULL DEFAULT '');");

    db_exec("CREATE TABLE IF NOT EXISTS stats ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "gameId INTEGER NOT NULL,"
        "playerId INTEGER NOT NULL,"
        "goals INTEGER NOT NULL,"
        "assists INTEGER NOT NULL,"
        "saves INTEGER NOT NULL,"
        "yellow INTEGER NOT NULL,"
        "red INTEGER NOT NULL,"
        "FOREIGN KEY(gameId) REFERENCES games(id),"
        "FOREIGN KEY(playerId) REFERENCES players(id));");

    db_exec("CREATE TABLE IF NOT EXISTS messages ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "datetime TEXT NOT NULL,"
        "text TEXT NOT NULL);");

    // Varsayýlan admin (admin/admin)
    sqlite3_stmt* st = nullptr;
    if (db_prepare(&st, "SELECT COUNT(*) FROM users;")) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            int cnt = sqlite3_column_int(st, 0);
            sqlite3_finalize(st);
            if (cnt == 0) {
                sqlite3_stmt* ins = nullptr;
                if (db_prepare(&ins, "INSERT INTO users(username, passhash, role, active) VALUES(?, ?, 'admin', 1);")) {
                    const char* defUser = "admin";
                    uint64_t h = fnv1a64("admin");
                    sqlite3_bind_text(ins, 1, defUser, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ins, 2, (sqlite3_int64)h);
                    if (sqlite3_step(ins) != SQLITE_DONE) {
                        std::cerr << "admin eklenemedi: " << sqlite3_errmsg(g_db) << "\n";
                    }
                    sqlite3_finalize(ins);
                }
            }
        }
        else {
            sqlite3_finalize(st);
        }
    }
}

// =================== AUTH ===================
bool LS_AuthLoginInteractive() {
    std::string uname = readLine("Kullanici adi: ");
    std::string pwd = readLine("Sifre: ");
    uint64_t h = fnv1a64(pwd);

    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "SELECT username FROM users WHERE active=1 AND username=? AND passhash=?;"))
        return false;

    sqlite3_bind_text(st, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)h);

    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        ok = true;
        g_isAuthed = true;
        std::snprintf(g_currentUser, sizeof(g_currentUser), "%s", (const char*)sqlite3_column_text(st, 0));
        std::cout << "Giris basarili. Hos geldin, " << g_currentUser << "!\n";
    }
    else {
        std::cout << "Hatali kullanici adi ya da sifre.\n";
    }
    sqlite3_finalize(st);
    return ok;
}

void LS_AuthRegisterInteractive() {
    std::string uname;
    while (true) {
        uname = readLine("Yeni kullanici adi (3-31): ");
        if (uname.size() < 3 || uname.size() > 31) { std::cout << "Uzunluk hatasi.\n"; continue; }

        sqlite3_stmt* chk = nullptr;
        if (!db_prepare(&chk, "SELECT 1 FROM users WHERE username=? AND active=1;")) return;
        sqlite3_bind_text(chk, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = (sqlite3_step(chk) == SQLITE_ROW);
        sqlite3_finalize(chk);

        if (exists) { std::cout << "Bu kullanici adi zaten var.\n"; continue; }
        break;
    }

    std::string pwd1 = readLine("Sifre: ");
    std::string pwd2 = readLine("Sifre (tekrar): ");
    if (pwd1 != pwd2) { std::cout << "Sifreler eslesmiyor.\n"; return; }

    sqlite3_stmt* ins = nullptr;
    if (!db_prepare(&ins, "INSERT INTO users(username, passhash, role, active) VALUES(?, ?, 'member', 1);"))
        return;

    uint64_t h = fnv1a64(pwd1);
    sqlite3_bind_text(ins, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 2, (sqlite3_int64)h);

    if (sqlite3_step(ins) == SQLITE_DONE) {
        std::cout << "Kayit olusturuldu. ID=" << (int)sqlite3_last_insert_rowid(g_db) << "\n";
    }
    else {
        std::cout << "HATA: Kaydedilemedi.\n";
    }
    sqlite3_finalize(ins);
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
    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "SELECT id,name,position,phone,email,active FROM players WHERE active=1 ORDER BY id;"))
        return;

    std::cout << "\nID  " << std::left << std::setw(22) << "Name"
        << std::setw(12) << "Position"
        << std::setw(16) << "Phone"
        << std::setw(26) << "Email"
        << "Active\n";
    std::cout << std::string(90, '-') << "\n";

    while (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        const char* name = (const char*)sqlite3_column_text(st, 1);
        const char* pos = (const char*)sqlite3_column_text(st, 2);
        const char* phone = (const char*)sqlite3_column_text(st, 3);
        const char* email = (const char*)sqlite3_column_text(st, 4);
        int active = sqlite3_column_int(st, 5);
        std::cout << std::left
            << std::setw(4) << id
            << std::setw(22) << (name ? name : "")
            << std::setw(12) << (pos ? pos : "")
            << std::setw(16) << (phone ? phone : "")
            << std::setw(26) << (email ? email : "")
            << (active ? "Yes" : "No") << "\n";
    }
    sqlite3_finalize(st);
}

void LS_AddPlayerInteractive() {
    std::string name = readLine("Isim: ");
    std::string position = readLine("Pozisyon: ");
    std::string phone = readLine("Telefon: ");
    std::string email = readLine("Email: ");

    sqlite3_stmt* ins = nullptr;
    if (!db_prepare(&ins, "INSERT INTO players(name,position,phone,email,active) VALUES(?,?,?,?,1);"))
        return;

    sqlite3_bind_text(ins, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, position.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, phone.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 4, email.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(ins) == SQLITE_DONE) {
        std::cout << "Player eklendi. ID=" << (int)sqlite3_last_insert_rowid(g_db) << "\n";
    }
    else {
        std::cout << "HATA: Kaydedilemedi.\n";
    }
    sqlite3_finalize(ins);
}

void LS_EditPlayerInteractive() {
    LS_ListPlayersInteractive();
    int id = readInt("Duzenlenecek Player ID: ");

    // Var mý kontrol
    sqlite3_stmt* chk = nullptr;
    if (!db_prepare(&chk, "SELECT 1 FROM players WHERE id=? AND active=1;")) return;
    sqlite3_bind_int(chk, 1, id);
    bool ok = (sqlite3_step(chk) == SQLITE_ROW);
    sqlite3_finalize(chk);
    if (!ok) { std::cout << "Bulunamadi.\n"; return; }

    std::string v;

    v = readLine("Isim (bos birak = ayni): ");
    if (!v.empty()) {
        sqlite3_stmt* st = nullptr;
        db_prepare(&st, "UPDATE players SET name=? WHERE id=?;");
        sqlite3_bind_text(st, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, id);
        sqlite3_step(st); sqlite3_finalize(st);
    }

    v = readLine("Pozisyon (bos = ayni): ");
    if (!v.empty()) {
        sqlite3_stmt* st = nullptr;
        db_prepare(&st, "UPDATE players SET position=? WHERE id=?;");
        sqlite3_bind_text(st, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, id);
        sqlite3_step(st); sqlite3_finalize(st);
    }

    v = readLine("Telefon (bos = ayni): ");
    if (!v.empty()) {
        sqlite3_stmt* st = nullptr;
        db_prepare(&st, "UPDATE players SET phone=? WHERE id=?;");
        sqlite3_bind_text(st, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, id);
        sqlite3_step(st); sqlite3_finalize(st);
    }

    v = readLine("Email (bos = ayni): ");
    if (!v.empty()) {
        sqlite3_stmt* st = nullptr;
        db_prepare(&st, "UPDATE players SET email=? WHERE id=?;");
        sqlite3_bind_text(st, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, id);
        sqlite3_step(st); sqlite3_finalize(st);
    }

    std::cout << "Guncellendi.\n";
}

void LS_RemovePlayerInteractive() {
    LS_ListPlayersInteractive();
    int id = readInt("Silinecek Player ID: ");

    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "UPDATE players SET active=0 WHERE id=? AND active=1;"))
        return;

    sqlite3_bind_int(st, 1, id);

    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(g_db) > 0) {
        std::cout << "Silindi (pasif).\n";
    }
    else {
        std::cout << "Bulunamadi veya zaten pasif.\n";
    }
    sqlite3_finalize(st);
}

// =================== GAMES ===================
void LS_ListGamesInteractive() {
    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "SELECT id,date,time,opponent,location,played,result FROM games ORDER BY id;"))
        return;

    std::cout << "\nID  " << std::left << std::setw(12) << "Date"
        << std::setw(8) << "Time"
        << std::setw(22) << "Opponent"
        << std::setw(22) << "Location"
        << std::setw(8) << "Played"
        << "Result\n";
    std::cout << std::string(90, '-') << "\n";

    while (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        const char* date = (const char*)sqlite3_column_text(st, 1);
        const char* time = (const char*)sqlite3_column_text(st, 2);
        const char* opp = (const char*)sqlite3_column_text(st, 3);
        const char* loc = (const char*)sqlite3_column_text(st, 4);
        int played = sqlite3_column_int(st, 5);
        const char* res = (const char*)sqlite3_column_text(st, 6);

        std::cout << std::left
            << std::setw(4) << id
            << std::setw(12) << (date ? date : "")
            << std::setw(8) << (time ? time : "")
            << std::setw(22) << (opp ? opp : "")
            << std::setw(22) << (loc ? loc : "")
            << std::setw(8) << (played ? "Yes" : "No")
            << (res ? res : "")
            << "\n";
    }
    sqlite3_finalize(st);
}

void LS_AddGameInteractive() {
    std::string date = readLine("Tarih (YYYY-MM-DD): ");
    std::string time = readLine("Saat (HH:MM): ");
    std::string opponent = readLine("Rakip: ");
    std::string location = readLine("Lokasyon: ");

    sqlite3_stmt* ins = nullptr;
    if (!db_prepare(&ins, "INSERT INTO games(date,time,opponent,location,played,result) VALUES(?,?,?,?,0,'');"))
        return;

    sqlite3_bind_text(ins, 1, date.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, time.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, opponent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 4, location.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(ins) == SQLITE_DONE) {
        std::cout << "Mac eklendi. ID=" << (int)sqlite3_last_insert_rowid(g_db) << "\n";
    }
    else {
        std::cout << "HATA: Kaydedilemedi.\n";
    }
    sqlite3_finalize(ins);
}

void LS_RecordResultInteractive() {
    LS_ListGamesInteractive();
    int id = readInt("Sonuc girilecek Game ID: ");

    sqlite3_stmt* chk = nullptr;
    if (!db_prepare(&chk, "SELECT 1 FROM games WHERE id=?;")) return;
    sqlite3_bind_int(chk, 1, id);
    bool ok = (sqlite3_step(chk) == SQLITE_ROW);
    sqlite3_finalize(chk);
    if (!ok) { std::cout << "Bulunamadi.\n"; return; }

    std::string res = readLine("Sonuc (ornegin 2-1 W): ");

    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "UPDATE games SET result=?, played=1 WHERE id=?;")) return;
    sqlite3_bind_text(st, 1, res.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, id);

    if (sqlite3_step(st) == SQLITE_DONE) std::cout << "Sonuc kaydedildi.\n";
    else std::cout << "HATA: Kaydedilemedi.\n";
    sqlite3_finalize(st);
}

// =================== STATS ===================
void LS_RecordStatsInteractive() {
    // Oyun seçimi
    sqlite3_stmt* gst = nullptr;
    if (!db_prepare(&gst, "SELECT id,date,time,opponent FROM games ORDER BY id;")) return;
    std::cout << "\nMaclar:\n";
    while (sqlite3_step(gst) == SQLITE_ROW) {
        int id = sqlite3_column_int(gst, 0);
        const char* d = (const char*)sqlite3_column_text(gst, 1);
        const char* t = (const char*)sqlite3_column_text(gst, 2);
        const char* o = (const char*)sqlite3_column_text(gst, 3);
        std::cout << "  " << id << ") " << (d ? d : "") << " " << (t ? t : "") << " vs " << (o ? o : "") << "\n";
    }
    sqlite3_finalize(gst);
    int gid = readInt("Hangi Game ID icin istatistik? ");

    // Oyuncu seçimi
    sqlite3_stmt* pst = nullptr;
    if (!db_prepare(&pst, "SELECT id,name,position FROM players WHERE active=1 ORDER BY id;")) return;
    std::cout << "\nOyuncular:\n";
    while (sqlite3_step(pst) == SQLITE_ROW) {
        int id = sqlite3_column_int(pst, 0);
        const char* n = (const char*)sqlite3_column_text(pst, 1);
        const char* p = (const char*)sqlite3_column_text(pst, 2);
        std::cout << "  " << id << ") " << (n ? n : "") << " (" << (p ? p : "") << ")\n";
    }
    sqlite3_finalize(pst);
    int pid = readInt("Player ID: ");

    int goals = readInt("Goals: ", 0, 100);
    int assists = readInt("Assists: ", 0, 100);
    int saves = readInt("Saves: ", 0, 100);
    int yellow = readInt("Yellow cards: ", 0, 10);
    int red = readInt("Red cards: ", 0, 10);

    sqlite3_stmt* ins = nullptr;
    if (!db_prepare(&ins, "INSERT INTO stats(gameId,playerId,goals,assists,saves,yellow,red) VALUES(?,?,?,?,?,?,?);"))
        return;

    sqlite3_bind_int(ins, 1, gid);
    sqlite3_bind_int(ins, 2, pid);
    sqlite3_bind_int(ins, 3, goals);
    sqlite3_bind_int(ins, 4, assists);
    sqlite3_bind_int(ins, 5, saves);
    sqlite3_bind_int(ins, 6, yellow);
    sqlite3_bind_int(ins, 7, red);

    if (sqlite3_step(ins) == SQLITE_DONE) {
        std::cout << "Istatistik eklendi (Game " << gid << ", Player " << pid << ").\n";
    }
    else {
        std::cout << "HATA: Kaydedilemedi.\n";
    }
    sqlite3_finalize(ins);
}

void LS_ViewPlayerTotalsInteractive() {
    const char* SQL =
        "SELECT p.id, p.name, "
        "COALESCE(SUM(s.goals),0)   AS goals, "
        "COALESCE(SUM(s.assists),0) AS assists, "
        "COALESCE(SUM(s.saves),0)   AS saves, "
        "COALESCE(SUM(s.yellow),0)  AS yellow, "
        "COALESCE(SUM(s.red),0)     AS red "
        "FROM players p "
        "LEFT JOIN stats s ON s.playerId=p.id "
        "WHERE p.active=1 "
        "GROUP BY p.id, p.name "
        "ORDER BY goals DESC;";

    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, SQL)) return;

    std::cout << "\nID  " << std::left << std::setw(22) << "Name"
        << std::setw(8) << "Goals"
        << std::setw(8) << "Assists"
        << std::setw(8) << "Saves"
        << std::setw(8) << "Yellow"
        << "Red\n";
    std::cout << std::string(70, '-') << "\n";

    while (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        const char* name = (const char*)sqlite3_column_text(st, 1);
        int goals = sqlite3_column_int(st, 2);
        int assists = sqlite3_column_int(st, 3);
        int saves = sqlite3_column_int(st, 4);
        int yellow = sqlite3_column_int(st, 5);
        int red = sqlite3_column_int(st, 6);

        std::cout << std::left
            << std::setw(4) << id
            << std::setw(22) << (name ? name : "")
            << std::setw(8) << goals
            << std::setw(8) << assists
            << std::setw(8) << saves
            << std::setw(8) << yellow
            << red
            << "\n";
    }
    sqlite3_finalize(st);
}

// =================== COMMUNICATIONS ===================
void LS_ListMessagesInteractive() {
    sqlite3_stmt* st = nullptr;
    if (!db_prepare(&st, "SELECT id,datetime,text FROM messages ORDER BY id;"))
        return;

    std::cout << "\nID  " << std::left << std::setw(18) << "Datetime"
        << "Message\n";
    std::cout << std::string(80, '-') << "\n";

    while (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        const char* dt = (const char*)sqlite3_column_text(st, 1);
        const char* tx = (const char*)sqlite3_column_text(st, 2);
        std::cout << std::left
            << std::setw(4) << id
            << std::setw(18) << (dt ? dt : "")
            << (tx ? tx : "") << "\n";
    }
    sqlite3_finalize(st);
}

void LS_AddMessageInteractive() {
    std::string text;
    do {
        text = readLine("Mesaj (1-150 karakter): ");
    } while (text.empty() || text.size() > 150);

    std::string dt = nowDateTime();

    sqlite3_stmt* ins = nullptr;
    if (!db_prepare(&ins, "INSERT INTO messages(datetime,text) VALUES(?,?);"))
        return;

    sqlite3_bind_text(ins, 1, dt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, text.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(ins) == SQLITE_DONE) {
        std::cout << "Mesaj kaydedildi.\n";
    }
    else {
        std::cout << "HATA: Kaydedilemedi.\n";
    }
    sqlite3_finalize(ins);
}
