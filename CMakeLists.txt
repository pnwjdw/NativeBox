cmake_minimum_required(VERSION 3.25)
project(NativeBox VERSION 0.4.1 LANGUAGES CXX)
if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "NativeBox requires Windows and MSVC")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOGEN_PARALLEL 1)
include(scripts/msvc-dependencies.cmake)
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 NB_PRODUCT_VERSION="${PROJECT_VERSION}")
add_compile_options(/W4 /permissive- /utf-8 /EHsc)
find_package(Qt6 6.8.3 EXACT REQUIRED COMPONENTS Core Network Sql Concurrent Gui Qml Quick QuickControls2 QuickTemplates2)
qt_standard_project_setup(REQUIRES 6.8)
add_library(nativebox_runtime_core STATIC driverless/runtime/base.cpp driverless/runtime/files.cpp driverless/runtime/registry.cpp driverless/runtime/network.cpp)
target_include_directories(nativebox_runtime_core PUBLIC "${CMAKE_SOURCE_DIR}")
target_link_libraries(nativebox_runtime_core PUBLIC bcrypt advapi32 ws2_32)
set_target_properties(nativebox_runtime_core PROPERTIES AUTOMOC OFF)
add_library(nativebox_driverless STATIC driverless/common.cpp driverless/profile.cpp driverless/process.cpp driverless/store.cpp driverless/ipc.cpp driverless/snapshot.cpp driverless/redirected.cpp driverless/credentials.cpp driverless/telemetry.cpp driverless/proxy.cpp driverless/audit_client.cpp driverless/audit_protocol.cpp driverless/audit_export.cpp)
target_include_directories(nativebox_driverless PUBLIC "${CMAKE_SOURCE_DIR}")
target_link_libraries(nativebox_driverless PUBLIC Qt6::Core Qt6::Sql Qt6::Network Qt6::Concurrent nativebox_runtime_core advapi32 shell32 ole32)
set_target_properties(nativebox_driverless PROPERTIES AUTOMOC OFF)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(GLOB_RECURSE NATIVEBOX_RUNTIME_INPUTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/driverless/*")
list(APPEND NATIVEBOX_RUNTIME_INPUTS "${CMAKE_SOURCE_DIR}/third_party/offreg/x64/offreg.dll")
file(GLOB_RECURSE NATIVEBOX_LEGAL_INPUTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/licenses/*" "${CMAKE_SOURCE_DIR}/packaging/driverless/*")
add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/nativebox_runtime64.dll" "${CMAKE_BINARY_DIR}/nativebox_runtime32.dll" "${CMAKE_BINARY_DIR}/offreg.dll" "${CMAKE_BINARY_DIR}/runtime-artifacts.json"
  COMMAND "${Python3_EXECUTABLE}" -I -B "${CMAKE_SOURCE_DIR}/scripts/build-runtime.py" --source "${CMAKE_SOURCE_DIR}" --application-build "${CMAKE_BINARY_DIR}" --configuration "${CMAKE_BUILD_TYPE}" --cmake-child
  DEPENDS ${NATIVEBOX_RUNTIME_INPUTS} ${NATIVEBOX_LEGAL_INPUTS} "${CMAKE_SOURCE_DIR}/dependencies.lock.json" "${CMAKE_SOURCE_DIR}/CMakeLists.txt" "${CMAKE_SOURCE_DIR}/scripts/build-runtime.py" "${CMAKE_SOURCE_DIR}/scripts/prepare-runtime.py" "${CMAKE_SOURCE_DIR}/scripts/build-manifest.py" "${CMAKE_SOURCE_DIR}/scripts/build-driverless.py" "${CMAKE_SOURCE_DIR}/scripts/restore-driverless.py" "${CMAKE_SOURCE_DIR}/scripts/prepare-sqlite.py" "${CMAKE_SOURCE_DIR}/scripts/deploy-driverless.py" "${CMAKE_SOURCE_DIR}/scripts/package-driverless.py" "${CMAKE_SOURCE_DIR}/scripts/verify-nuget.py" "${CMAKE_SOURCE_DIR}/scripts/prepare-license-sources.py" "${CMAKE_SOURCE_DIR}/ui/Main.qml" "${CMAKE_SOURCE_DIR}/apps/desktop/controller.cpp" "${CMAKE_SOURCE_DIR}/apps/desktop/controller.h"
  VERBATIM)
add_custom_target(nativebox_runtimes ALL DEPENDS "${CMAKE_BINARY_DIR}/nativebox_runtime64.dll" "${CMAKE_BINARY_DIR}/nativebox_runtime32.dll" "${CMAKE_BINARY_DIR}/runtime-artifacts.json")
add_dependencies(nativebox_driverless nativebox_runtimes)
set(NATIVEBOX_DOWNLOAD_CACHE "${CMAKE_SOURCE_DIR}/.deps/.downloads" CACHE PATH "Pinned upstream source archive cache")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/dependencies.lock.json" "${CMAKE_SOURCE_DIR}/scripts/prepare-sqlite.py")
execute_process(COMMAND "${Python3_EXECUTABLE}" -I -B "${CMAKE_SOURCE_DIR}/scripts/prepare-sqlite.py"
  --source "${CMAKE_SOURCE_DIR}" --output "${CMAKE_BINARY_DIR}/sqlite-source" --cache "${NATIVEBOX_DOWNLOAD_CACHE}"
  OUTPUT_VARIABLE NB_SQLITE_PLAN ERROR_VARIABLE NB_SQLITE_ERROR RESULT_VARIABLE NB_SQLITE_RESULT)
if(NOT NB_SQLITE_RESULT EQUAL 0)
  message(FATAL_ERROR "Cannot prepare pinned SQLite sources: ${NB_SQLITE_ERROR}")
endif()
string(JSON NB_SQLITE_SOURCE GET "${NB_SQLITE_PLAN}" source)
include(ExternalProject)
ExternalProject_Add(nativebox_sqlite
  SOURCE_DIR "${NB_SQLITE_SOURCE}/src/plugins/sqldrivers"
  BINARY_DIR "${CMAKE_BINARY_DIR}/sqlite-build"
  CMAKE_ARGS -G Ninja "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}" "-DCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}"
    "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}" "-DCMAKE_PROJECT_INCLUDE=${CMAKE_SOURCE_DIR}/scripts/msvc-dependencies.cmake"
    -DFEATURE_system_sqlite=OFF -DFEATURE_sql_sqlite=ON -DFEATURE_sql_odbc=OFF -DFEATURE_sql_mysql=OFF -DFEATURE_sql_psql=OFF
    -DFEATURE_sql_oci=OFF -DFEATURE_sql_db2=OFF -DFEATURE_sql_ibase=OFF -DFEATURE_sql_mimer=OFF
  BUILD_COMMAND "${CMAKE_COMMAND}" --build <BINARY_DIR> --parallel 3
  INSTALL_COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/sqldrivers"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_BINARY_DIR}/sqlite-build/plugins/sqldrivers" "${CMAKE_BINARY_DIR}/sqldrivers")
add_dependencies(nativebox_driverless nativebox_sqlite)
qt_add_executable(nativebox_cli driverless/cli.cpp)
target_link_libraries(nativebox_cli PRIVATE nativebox_driverless)
qt_add_executable(nativebox_broker driverless/broker.cpp)
target_link_libraries(nativebox_broker PRIVATE nativebox_driverless)
qt_add_executable(nativebox_audit driverless/audit_host.cpp driverless/audit_etw.cpp)
target_link_libraries(nativebox_audit PRIVATE nativebox_driverless tdh advapi32)
qt_add_executable(nativebox WIN32 driverless/desktop.cpp apps/desktop/controller.cpp apps/desktop/controller.h apps/desktop/accessible_scrollbar.cpp apps/desktop/accessible_scrollbar.h)
target_link_libraries(nativebox PRIVATE nativebox_driverless Qt6::Gui Qt6::Qml Qt6::QuickPrivate Qt6::QuickControls2 Qt6::QuickTemplates2Private)
qt_add_qml_module(nativebox URI NativeBox VERSION 1.0 NO_IMPORT_SCAN QML_FILES ui/Main.qml)
install(TARGETS nativebox nativebox_cli nativebox_broker nativebox_audit RUNTIME DESTINATION .)
install(DIRECTORY "${CMAKE_BINARY_DIR}/sqldrivers/" DESTINATION sqldrivers FILES_MATCHING PATTERN "*.dll")
install(FILES licenses/NativeBox-MIT.txt DESTINATION licenses)
install(FILES "${CMAKE_BINARY_DIR}/nativebox_runtime64.dll" "${CMAKE_BINARY_DIR}/nativebox_runtime32.dll" "${CMAKE_BINARY_DIR}/offreg.dll" "${CMAKE_BINARY_DIR}/runtime-artifacts.json" DESTINATION .)
