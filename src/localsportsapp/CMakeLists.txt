# LocalSportsapp/CMakeLists.txt
set(ROOT src)
set(APPNAME LocalSportsapp)

message(STATUS "[${ROOT}/${APPNAME}] Module Processing...")

# =============================================================
# === Kaynak ve header dosyalarını topla ======================
# =============================================================
file(GLOB APP_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/header/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/header/*.hpp")

file(GLOB APP_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

source_group("header" FILES ${APP_HEADERS})
source_group("src" FILES ${APP_SOURCES})

add_executable(${APPNAME} ${APP_HEADERS} ${APP_SOURCES})

target_include_directories(${APPNAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../utility/header
    ${CMAKE_CURRENT_SOURCE_DIR}/../LocalSports/header
    ${CMAKE_CURRENT_SOURCE_DIR}/header)

# =============================================================
# === Kütüphaneleri linkle ====================================
# =============================================================
target_link_libraries(${APPNAME} PRIVATE LocalSports utility)

# ✅ vcpkg'den gelen SQLite bağlantısı
find_package(unofficial-sqlite3 CONFIG REQUIRED)
target_link_libraries(${APPNAME} PRIVATE unofficial::sqlite3::sqlite3)

install(TARGETS ${APPNAME}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin)

message(STATUS "[${ROOT}/${APPNAME}] Added Executable target: ${APPNAME}")

# =============================================================
# === SQLite3 DLL copy (Windows için güvenli kopyalama) ========
# =============================================================
set(SQLITE_DEBUG_DLL "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin/sqlite3.dll")
set(SQLITE_RELEASE_DLL "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin/sqlite3.dll")

if(EXISTS "${SQLITE_DEBUG_DLL}")
    add_custom_command(TARGET ${APPNAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQLITE_DEBUG_DLL}"
            "$<TARGET_FILE_DIR:${APPNAME}>"
        COMMENT "Copying sqlite3.dll (debug) next to executable"
    )
elseif(EXISTS "${SQLITE_RELEASE_DLL}")
    add_custom_command(TARGET ${APPNAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQLITE_RELEASE_DLL}"
            "$<TARGET_FILE_DIR:${APPNAME}>"
        COMMENT "Copying sqlite3.dll (release) next to executable"
    )
else()
    message(WARNING "sqlite3.dll not found in vcpkg paths — skipping DLL copy.")
endif()

# EXE her zaman kendi klasörünü çalışma dizini olarak kullansın
set_target_properties(${APPNAME} PROPERTIES
  VS_DEBUGGER_WORKING_DIRECTORY "$<TARGET_FILE_DIR:${APPNAME}>")

