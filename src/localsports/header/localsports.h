// header/localsports.h
#ifndef LOCALSPORTS_H
#define LOCALSPORTS_H

#include <cstdint>

// --------- Binary file names (defined in .cpp) ----------
extern const char* FILE_PLAYERS;
extern const char* FILE_GAMES;
extern const char* FILE_STATS;
extern const char* FILE_MESSAGES;
extern const char* FILE_USERS;

// ---------------- Fixed-size records --------------------
#pragma pack(push, 1)
struct Player {
    uint32_t id;
    char name[64];
    char position[32];
    char phone[32];
    char email[64];
    uint8_t active; // 1 = active, 0 = removed
};

struct Game {
    uint32_t id;
    char date[11];   // "YYYY-MM-DD"
    char time[6];    // "HH:MM"
    char opponent[64];
    char location[64];
    uint8_t played;  // 1=played
    char result[16]; // e.g., "2-1 W"
};

struct Stat {
    uint32_t id;
    uint32_t gameId;
    uint32_t playerId;
    int32_t goals;
    int32_t assists;
    int32_t saves;
    int32_t yellow;
    int32_t red;
};

struct Message {
    uint32_t id;
    char datetime[20]; // "YYYY-MM-DD HH:MM"
    char text[160];
};

struct User {
    uint32_t id;
    char username[32];
    uint64_t passHash; // FNV-1a 64 (not cryptographic; security layer comes later)
    char role[16];     // "admin" / "member"
    uint8_t active;    // 1=active
};
#pragma pack(pop)

// --------------- Public API (used by app) ---------------
void LS_Init();

// Roster
void LS_ListPlayersInteractive();
void LS_AddPlayerInteractive();
void LS_EditPlayerInteractive();
void LS_RemovePlayerInteractive();

// Games
void LS_ListGamesInteractive();
void LS_AddGameInteractive();
void LS_RecordResultInteractive();

// Statistics
void LS_RecordStatsInteractive();
void LS_ViewPlayerTotalsInteractive();

// Communications
void LS_ListMessagesInteractive();
void LS_AddMessageInteractive();

// Authentication
bool LS_AuthLoginInteractive();
void LS_AuthRegisterInteractive();
void LS_AuthLogout();
bool LS_IsAuthenticated();
const char* LS_CurrentUsername();

#endif // LOCALSPORTS_H
