include("../../ida-cmake/cmake/IDA.cmake")

set(sources plugin.cpp python.cpp dialogs.cpp)

# Folder-layout install: <prefix>/plugins/ifred/{ida_palette64.*,
# ida-plugin.json}. IDA 9.x loads folder plugins via the manifest next to
# the binary, and the plugin keeps its writable data (palette/config.json,
# palette/theme/) beside it.
set(IDA_PLUGIN_INSTALL_SUBDIR "ifred" CACHE STRING "" FORCE)

add_ida_plugin(ida_palette ${sources})

install(FILES "${CMAKE_SOURCE_DIR}/ida-plugin.json"
        DESTINATION plugins/${IDA_PLUGIN_INSTALL_SUBDIR})

# Date-stamped version, refreshed on every configure. Deliberate: releases are
# stamped with their build date. Shown in the About dialog and embedded into
# the binary's version metadata below.
string(TIMESTAMP IFRED_VERSION "%Y.%m.%d")
target_compile_definitions(ida_palette PRIVATE "IFRED_VERSION=\"${IFRED_VERSION}\"")

# Numeric date components for the platform version fields. Leading zeros must
# go: rc.exe would parse 09 as (invalid) octal, and Mach-O current_version
# wants plain integers.
string(TIMESTAMP IFRED_VER_YEAR "%Y")
string(TIMESTAMP IFRED_VER_MONTH "%m")
string(TIMESTAMP IFRED_VER_DAY "%d")
string(REGEX REPLACE "^0" "" IFRED_VER_MONTH "${IFRED_VER_MONTH}")
string(REGEX REPLACE "^0" "" IFRED_VER_DAY "${IFRED_VER_DAY}")

if (WIN32)
    # VERSIONINFO resource: what Explorer shows under Properties > Details.
    if (IDA_EA_64)
        set(IFRED_DLL_NAME "ida_palette64.dll")
    else ()
        set(IFRED_DLL_NAME "ida_palette.dll")
    endif ()
    configure_file(version.rc.in version.rc @ONLY)
    target_sources(ida_palette PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/version.rc")
elseif (APPLE)
    # Mach-O dylibs carry a native current_version (X.Y.Z, Y/Z <= 255 - month
    # and day fit). Readable with: otool -L ida_palette64.dylib
    target_link_options(ida_palette PRIVATE
        "-Wl,-current_version,${IFRED_VER_YEAR}.${IFRED_VER_MONTH}.${IFRED_VER_DAY}")
endif ()
# Linux ELF has no version resource; the greppable ifred_version_tag string
# in dialogs.cpp is the cross-platform fallback there.

if(APPLE AND IDA_INSTALL_DIR)
    target_compile_definitions(ida_palette PUBLIC "QT_NAMESPACE=QT")
endif()

if (${PYTHON_SUPPORT})
    target_compile_definitions(ida_palette PRIVATE "PYTHON_SUPPORT=1")
else ()
    target_compile_definitions(ida_palette PRIVATE "PYTHON_SUPPORT=0")
endif ()

# In OSX, make ifred use @executable_path/python[64].dylib to use IDAPython bindings
# I'm not sure if it's a best way.
if ((${PYTHON_SUPPORT}) AND (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin"))
    if (IDA_EA_64)
        set(IDAPYTHON "${IDA_INSTALL_DIR}/plugins/idapython${PYTHON_VERSION_MAJOR}_64.dylib")
    else ()
        set(IDAPYTHON "${IDA_INSTALL_DIR}/plugins/idapython${PYTHON_VERSION_MAJOR}.dylib")
    endif ()
    target_link_libraries(ida_palette PRIVATE ${IDAPYTHON})
endif ()

# Link palette and python libraries
target_link_libraries(ida_palette PRIVATE palette ${python_libraries})
# On macOS with IDA, use Qt6 for headers (but don't link - we link IDA's Qt)
if(APPLE AND IDA_INSTALL_DIR)
    target_link_libraries(ida_palette PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
    set_target_properties(ida_palette PROPERTIES INTERFACE_LINK_LIBRARIES "")
else ()
    target_link_libraries(ida_palette
            PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets palette ${python_libraries})
endif()

# On macOS with IDA, link against IDA's Qt frameworks
if(APPLE AND IDA_INSTALL_DIR)
    get_filename_component(IDA_APP_DIR "${IDA_INSTALL_DIR}" DIRECTORY)
    set(QT_FRAMEWORK_PATH "${IDA_APP_DIR}/Frameworks")
    if(EXISTS "${QT_FRAMEWORK_PATH}/QtCore.framework")
        get_filename_component(QT_FRAMEWORK_PATH "${QT_FRAMEWORK_PATH}" ABSOLUTE)
        # Set framework search path for IDA's Qt
        target_link_options(ida_palette PRIVATE "-F${QT_FRAMEWORK_PATH}")
        # Link IDA's Qt frameworks
        target_link_libraries(ida_palette PRIVATE
            "-framework QtCore"
            "-framework QtGui"
            "-framework QtWidgets"
        )
    endif()
endif()

if(WIN32)
    target_link_options(ida_palette PRIVATE "$<$<CONFIG:Release>:/DEBUG:NONE>" "/NOCOFFGRPINFO")
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(APPLE)
        # Strip local symbols at LINK time (-Wl,-x = "no non-global symbols in
        # the output"). This is the proper way on macOS, Apple Silicon in
        # particular: the linker emits a well-formed, ad-hoc-signed dylib with
        # its LC_ID_DYLIB intact. Running a post-build `strip` instead removes
        # LC_ID_DYLIB and invalidates the signature, and dyld then refuses to
        # load the plugin ("MH_DYLIB is missing LC_ID_DYLIB"). External symbols
        # (the exported PLUGIN that IDA looks up) are kept.
        target_link_options(ida_palette PRIVATE "-Wl,-x")
    elseif(UNIX)
        add_custom_command(TARGET ida_palette POST_BUILD
            COMMENT "Stripping binary"
            COMMAND strip -s $<TARGET_FILE:ida_palette>
            VERBATIM
        )
    endif()
endif()
