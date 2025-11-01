set(ROOT src)
set(LIBNAME LocalSports)

message(STATUS "[${ROOT}/${LIBNAME}] Module Processing...")

# =============================================================
# === Kaynak dosyalarını topla ================================
# =============================================================
file(GLOB LIB_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.hpp")

file(GLOB LIB_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

# =============================================================
# === Görünüm grupları (Visual Studio için) ===================
# =============================================================
source_group("header" FILES ${LIB_HEADERS})
source_group("src" FILES ${LIB_SOURCES})

# =============================================================
# === Kütüphane hedefi oluştur ================================
# =============================================================
add_library(${LIBNAME} STATIC ${LIB_HEADERS} ${LIB_SOURCES})

target_include_directories(${LIBNAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../utility/header
  ${CMAKE_CURRENT_SOURCE_DIR}/header)

# =============================================================
# === Gerekli bağlantılar =====================================
# =============================================================
target_link_libraries(${LIBNAME} PRIVATE utility)

# ✅ vcpkg'den gelen SQLite bağlantısı
find_package(unofficial-sqlite3 CONFIG REQUIRED)
target_link_libraries(${LIBNAME} PRIVATE unofficial::sqlite3::sqlite3)

# ✅ OpenSSL bağlantısı (security_layer için)
find_package(OpenSSL REQUIRED)
target_link_libraries(${LIBNAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# ✅ Platform-specific libraries for RASP
if(WIN32)
    target_link_libraries(${LIBNAME} PRIVATE psapi)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(${LIBNAME} PRIVATE dl pthread)
endif()

# Preprocessor definition (export)
add_compile_definitions("CORUH_LocalSports_LIB_EXPORTS")

# =============================================================
# === Kurulum çıktıları =======================================
# =============================================================
install(TARGETS ${LIBNAME}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)

# Header kopyalama (kütüphane kullanımı için)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/header/localsports.h
              ${CMAKE_CURRENT_SOURCE_DIR}/header/security_layer.h
              ${CMAKE_CURRENT_SOURCE_DIR}/header/security_hardening.h
              ${CMAKE_CURRENT_SOURCE_DIR}/header/rasp.h
              ${CMAKE_CURRENT_SOURCE_DIR}/header/security_config.h
  DESTINATION include)

message(STATUS "[${ROOT}/${LIBNAME}] Added library target: ${LIBNAME}")


