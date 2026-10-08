if(APPLE)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    add_executable(anyps5-runner
        ${CMAKE_CURRENT_SOURCE_DIR}/macos/main.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/macos/ElfLoader.cpp
    )
    target_include_directories(anyps5-runner PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/macos
        ${CMAKE_SOURCE_DIR}/core/libs
    )
    set_target_properties(anyps5-runner PROPERTIES ENABLE_EXPORTS ON)
    target_link_libraries(anyps5-runner PRIVATE "-framework CoreFoundation")
    add_dependencies(anyps5-runner macos_runtime_libraries)
    target_link_options(anyps5-runner PRIVATE "LINKER:-rpath,@executable_path/libs")
    if(BUILD_TESTING AND Python3_Interpreter_FOUND)
        add_test(NAME macos_runner_entry COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/macos/test_runner.py
            $<TARGET_FILE:relinker> $<TARGET_FILE:anyps5-runner>
            ${CMAKE_BINARY_DIR}/core/libs/libs)
    endif()
endif()
