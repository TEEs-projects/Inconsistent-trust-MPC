include_directories(${CMAKE_SOURCE_DIR}/common/
                    ${CMAKE_SOURCE_DIR}/json/include)

add_library(evidence_generator_lib OBJECT ./evidence/evidence_generator.cpp)
add_library(evidence_verifier_lib_host OBJECT ./evidence/evidence_verifier.cpp)
add_library(evidence_verifier_lib_enclave OBJECT ./evidence/evidence_verifier.cpp)

target_compile_definitions(evidence_generator_lib PUBLIC OE_API_VERSION=2)
target_link_libraries(
    evidence_generator_lib PUBLIC openenclave::oeenclave openenclave::oecryptombedtls
                openenclave::oelibcxx)

target_link_libraries(evidence_verifier_lib_host openenclave::oehost OpenSSL::SSL)
target_link_libraries(evidence_verifier_lib_enclave 
    openenclave::oeenclave openenclave::oecryptoopenssl)
