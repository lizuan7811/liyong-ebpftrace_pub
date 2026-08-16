cmake_minimum_required(VERSION 3.20)
project(liyong_ebpftrace C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(STATIC_BUILD "Fully statically link xdp_fw / trace_exec" ON)

# =========================================================
# Toolchain & Setup (修正目錄層級)
# =========================================================
find_program(CLANG_EXE clang REQUIRED)
find_program(BPFTOOL_EXE bpftool REQUIRED)
set(BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})

# 因為現在檔案在 src/，上一層才是專案根目錄
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(LOCAL_SKEL_DIR ${SRC_DIR}/skel)
file(MAKE_DIRECTORY ${LOCAL_SKEL_DIR})

find_package(TBB REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# 輔助函式 (路徑調整為絕對路徑或基於 SRC_DIR)
function(add_static_import_lib TARGET_NAME LIB_PATH INC_PATH)
    add_library(${TARGET_NAME} STATIC IMPORTED)
    set_target_properties(${TARGET_NAME} PROPERTIES
            IMPORTED_LOCATION "${LIB_PATH}"
            INTERFACE_INCLUDE_DIRECTORIES "${INC_PATH}"
    )
endfunction()

# 第三方函式庫定義 (路徑修正)
add_static_import_lib(ndpi_lib "${SRC_DIR}/third_party/ndpi/lib/libndpi.a" "${SRC_DIR}/third_party/ndpi/include")
add_static_import_lib(curl_lib "${SRC_DIR}/third_party/curl-static/lib/libcurl.a" "${SRC_DIR}/third_party/curl-static/include")
add_static_import_lib(jitter_lib "${SRC_DIR}/third_party/jitterentropy/lib/libjitterentropy.a" "${SRC_DIR}/third_party/jitterentropy/include")

# eBPF Build Pipeline
file(GLOB ALL_BPF_SRCS "${SRC_DIR}/ebpf/*.c")
list(FILTER ALL_BPF_SRCS EXCLUDE REGEX "loader.c$")
set(ALL_SKEL_FILES "")
foreach (BPF_SRC ${ALL_BPF_SRCS})
    get_filename_component(BPF_NAME ${BPF_SRC} NAME_WE)
    set(BPF_OBJ ${BUILD_DIR}/${BPF_NAME}.bpf.o)
    set(BPF_SKEL ${BUILD_DIR}/${BPF_NAME}.skel.h)
    list(APPEND ALL_SKEL_FILES ${BPF_SKEL})
    add_custom_command(
            OUTPUT ${BPF_SKEL}
            COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86 -DDEBUG -I${SRC_DIR}/ebpf -I/usr/include/bpf -c ${BPF_SRC} -o ${BPF_OBJ}
            COMMAND ${BPFTOOL_EXE} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
            COMMAND ${CMAKE_COMMAND} -E copy ${BPF_SKEL} ${LOCAL_SKEL_DIR}/${BPF_NAME}.skel.h
            DEPENDS ${BPF_SRC}
            COMMENT "Building eBPF program: ${BPF_NAME}"
    )
endforeach ()
add_custom_target(bpf_gen DEPENDS ${ALL_SKEL_FILES})
configure_file(${SRC_DIR}/resource/config.json ${BUILD_DIR}/resource/config.json COPYONLY)

# 靜態系統庫 (路徑修正：指向根目錄下的庫或是系統路徑)
if (STATIC_BUILD)
    # 若 ssl/crypto 是在第三方目錄，需確保路徑正確
    foreach (LIB bpf elf pcap ssl crypto z zstd)
        find_library(LIB_${LIB} NAMES "lib${LIB}.a" REQUIRED)
        add_library(sys_${LIB} STATIC IMPORTED)
        set_target_properties(sys_${LIB} PROPERTIES IMPORTED_LOCATION ${LIB_${LIB}})
    endforeach ()
endif ()

# =========================================================
# Executables (檔案路徑修正，現在檔案就在 src/ 下，路徑不需要再補 src/)
# =========================================================
macro(setup_static_linker TARGET)
    if (STATIC_BUILD)
        target_link_options(${TARGET} PRIVATE -static-libgcc -static-libstdc++)
    endif ()
endmacro()

add_executable(xdp_fw
        user/main.cpp
        user/main.h
        user/config/xdp_fw_config.hpp
        user/config/xdp_fw_config.h
        user/config/simdjson.cpp
        user/config/simdjson.h
        user/config/Firewall.hpp
        user/util/RuleParser.cpp
        user/util/RuleParser.hpp
        user/util/LockFreeSPSCQueue.cpp
        user/util/LockFreeSPSCQueue.hpp
        user/servie/impl/L7FlowSession.cpp
        user/servie/L7FlowSession.hpp
        user/servie/L7DpiEngine.hpp
        user/servie/impl/L7DpiEngine.cpp
        user/servie/impl/L7FlowManager.cpp
        user/servie/L7FlowManager.hpp
        user/servie/IPlanInfoProducer.hpp
        user/config/user_log.h
        user/config/RiskFileUpdater.cpp
        user/config/RiskFileUpdater.hpp
        user/config/RiskFileSyncManager.cpp
        user/config/RiskFileSyncManager.hpp
        user/config/SyncRiskFileConfig.cpp
        user/config/SyncRiskFileConfig.hpp
        user/util/WriteCallBack.cpp
        user/util/WriteCallBack.hpp
        user/config/xdp_fw_config.cpp
        user/util/CommonUtil.cpp
        user/util/CommonUtil.hpp
        user/config/RiskIndicators.cpp
        user/config/RiskIndicators.hpp
        user/model/RiskMetricInfos.cpp
        user/model/RiskMetricInfos.hpp
        user/model/Common.h
        user/model/KsmFEMetricInfo.cpp
        user/model/KsmFEMetricInfo.hpp
        user/model/ksm_fileevent.h
)

target_compile_definitions(xdp_fw PRIVATE
        _LINUX_STAT_H
        ASIO_STANDALONE
        CROW_USE_BOOST=0
        CROW_ENABLE_SSL
#        CONFIG_PATH="${CMAKE_CURRENT_BINARY_DIR}/resource/config.json"
)

add_dependencies(xdp_fw bpf_gen)
target_include_directories(xdp_fw PRIVATE
        ${LOCAL_SKEL_DIR}
        ${SRC_DIR}
        ${SRC_DIR}/resource
        ${SRC_DIR}/third_party/crow
        /usr/include
        /usr/include/asio
)

target_link_libraries(xdp_fw PRIVATE
        "-Wl,--start-group"
        ndpi_lib
        curl_lib
        jitter_lib
        sys_bpf
        sys_elf
        sys_pcap
        sys_ssl
        sys_crypto
        sys_z
        sys_zstd
        "-Wl,--end-group"
        TBB::tbb
        pthread
        m
        dl
)
setup_static_linker(xdp_fw)