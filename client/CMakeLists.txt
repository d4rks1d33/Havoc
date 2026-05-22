cmake_minimum_required( VERSION 3.15 )
project( Havoc )

##
## cmake sets
##
set( QT_VERSION 5 )
set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_AUTOMOC ON )
set( CMAKE_AUTORCC ON )
set( CMAKE_AUTOUIC ON )
set( CMAKE_CXX_FLAGS "-fpermissive" )
set( REQUIRED_LIBS Core Gui Widgets Network WebSockets Sql )
set( REQUIRED_LIBS_QUALIFIED Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::WebSockets Qt5::Sql )
set( APP_ICON_RESOURCE_WINDOWS "data/Havoc.qrc" )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY .. )
set( CMAKE_INCLUDE_CURRENT_DIR ON )

##
## On macOS: add Homebrew Qt5 to the search path automatically.
## On Linux: honour whatever is already in CMAKE_PREFIX_PATH.
##
if(APPLE)
    execute_process(
        COMMAND brew --prefix qt@5
        OUTPUT_VARIABLE BREW_QT5_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(BREW_QT5_PREFIX)
        list( APPEND CMAKE_PREFIX_PATH "${BREW_QT5_PREFIX}" )
        message( STATUS "macOS: Qt5 prefix set to ${BREW_QT5_PREFIX}" )
    endif()
endif()

##
## import includes and external libraries
##
include_directories( include  )
include_directories( external/spdlog/include )
include_directories( external/json/include )
include_directories( external/toml )

##
## find qt packages
##
find_package( Qt${QT_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED )

##
## Python support — macOS uses the framework layout, Linux uses pkg-config.
##
if(APPLE)
    # Prefer Python 3.12, fall back to whatever find_package resolves.
    set( Python_ADDITIONAL_VERSIONS 3.12 3.11 3.10 3.9 )
    find_package( Python3 COMPONENTS Interpreter Development REQUIRED )

    set( PYTHONLIBS_VERSION_STRING "${Python3_VERSION}" )
    set( PYTHON_INCLUDE_DIR        "${Python3_INCLUDE_DIRS}" )
    set( PYTHON_LIBRARIES          "${Python3_LIBRARIES}" )

    message( STATUS "macOS Python: ${Python3_VERSION}  includes=${Python3_INCLUDE_DIRS}  libs=${Python3_LIBRARIES}" )
elseif(UNIX)
    find_package( PythonLibs 3 REQUIRED )
else()
    set( PYTHONLIBS_VERSION_STRING $ENV{PY_VERSION} )
endif()

if(APPLE)
    include_directories( ${PYTHON_INCLUDE_DIR} )
elseif(UNIX)
    include_directories( ${PYTHON_INCLUDE_DIRS} )
endif()

set( HAVOC_INCLUDE

        # Misc
        include/Havoc/Connector.hpp
        include/Havoc/DBManager/DBManager.hpp
        include/Havoc/DemonCmdDispatch.h
        include/Havoc/Packager.hpp
        include/Havoc/Havoc.hpp
        include/Havoc/Service.hpp
        include/Havoc/CmdLine.hpp

        # Python Api
        include/Havoc/PythonApi/PythonApi.h
        include/Havoc/PythonApi/Event.h
        include/Havoc/PythonApi/HavocUi.h
        include/Havoc/PythonApi/PyAgentClass.hpp
        include/Havoc/PythonApi/UI/PyDialogClass.hpp
        include/Havoc/PythonApi/UI/PyLoggerClass.hpp
        include/Havoc/PythonApi/UI/PyTreeClass.hpp
        include/Havoc/PythonApi/UI/PyWidgetClass.hpp

        # Dialogs
        include/UserInterface/Dialogs/Payload.hpp
        include/UserInterface/Dialogs/About.hpp
        include/UserInterface/Dialogs/Connect.hpp
        include/UserInterface/Dialogs/Listener.hpp

        # small widgets
        include/UserInterface/SmallWidgets/EventViewer.hpp
        include/UserInterface/SmallWidgets/EventViewer.hpp

        # widgets
        include/UserInterface/Widgets/Chat.hpp
        include/UserInterface/Widgets/DemonInteracted.h
        include/UserInterface/Widgets/ListenerTable.hpp
        include/UserInterface/Widgets/ProcessList.hpp
        include/UserInterface/Widgets/PythonScript.hpp
        include/UserInterface/Widgets/SessionTable.hpp
        include/UserInterface/Widgets/SessionGraph.hpp
        include/UserInterface/Widgets/TeamserverTabSession.h
        include/UserInterface/Widgets/ScriptManager.h
        include/UserInterface/Widgets/LootWidget.h
        include/UserInterface/Widgets/FileBrowser.hpp
        include/UserInterface/Widgets/Teamserver.hpp
        include/UserInterface/Widgets/Store.hpp

        include/UserInterface/HavocUI.hpp
)

# src for UI
set(
        HAVOC_UI

        src/UserInterface/HavocUi.cc
        src/global.cc

        # Dialogs
        src/UserInterface/Dialogs/About.cc
        src/UserInterface/Dialogs/Connect.cc
        src/UserInterface/Dialogs/Listener.cc
        src/UserInterface/Dialogs/Payload.cc

        # Widgets
        src/UserInterface/Widgets/SessionTable.cc
        src/UserInterface/Widgets/SessionGraph.cc
        src/UserInterface/Widgets/Chat.cc
        src/UserInterface/Widgets/ListenersTable.cc
        src/UserInterface/Widgets/DemonInteracted.cc
        src/UserInterface/Widgets/TeamserverTabSession.cc
        src/UserInterface/Widgets/PythonScript.cc
        src/UserInterface/Widgets/ScriptManager.cc
        src/UserInterface/Widgets/LootWidget.cc
        src/UserInterface/Widgets/FileBrowser.cc
        src/UserInterface/Widgets/Teamserver.cc
        src/UserInterface/Widgets/Store.cc
        src/UserInterface/Widgets/ProcessList.cc

        # SmallWidgets
        src/UserInterface/SmallWidgets/EventViewer.cc
)

set(
        HAVOC_UTIL

        src/Util/ColorText.cpp
        src/Util/Base64.cpp
        src/Util/Base.cpp
)

# src for Havoc
set( HAVOC_SOURCE
        src/Main.cc

        src/Havoc/Packager.cc
        src/Havoc/Connector.cc
        src/Havoc/Service.cc

        src/Havoc/DBManger/DBManager.cc
        src/Havoc/DBManger/Teamserver.cc
        src/Havoc/DBManger/Scripts.cc

        src/Havoc/Demon/ConsoleInput.cc
        src/Havoc/Demon/CommandSend.cc
        src/Havoc/Demon/CommandOutput.cc
        src/Havoc/Demon/Commands.cc

        src/Havoc/PythonApi/PythonApi.cc
        src/Havoc/PythonApi/Havoc.cc
        src/Havoc/PythonApi/HavocUi.cc
        src/Havoc/PythonApi/UI/PyDialogClass.cc
        src/Havoc/PythonApi/UI/PyLoggerClass.cc
        src/Havoc/PythonApi/UI/PyTreeClass.cc
        src/Havoc/PythonApi/UI/PyWidgetClass.cc
        src/Havoc/PythonApi/PyDemonClass.cc
        src/Havoc/PythonApi/Event.cc
        src/Havoc/PythonApi/PyAgentClass.cc

        src/Havoc/Havoc.cc

    ${HAVOC_UI}
)

if(WIN32)
    add_executable( ${PROJECT_NAME} ${HAVOC_INCLUDE} ${HAVOC_SOURCE} ${HAVOC_UTIL} ${APP_ICON_RESOURCE_WINDOWS} data/Havoc.rc )
else()
    add_executable( ${PROJECT_NAME} ${HAVOC_INCLUDE} ${HAVOC_SOURCE} ${HAVOC_UTIL} ${APP_ICON_RESOURCE_WINDOWS} )
endif()
add_definitions( -DQT_NO_DEBUG_OUTPUT )

# Workaround: the bundled spdlog/fmt uses consteval which is broken with
# AppleClang 13+ when __apple_build_version__ is defined. Force the fallback.
#
# Also undefine _GNU_SOURCE on macOS: the toml11 submodule uses the GNU
# variant of strerror_r (returns char*) when _GNU_SOURCE is set, but macOS
# only provides the POSIX variant (returns int), causing a type error.
if(APPLE)
    add_definitions( -DFMT_CONSTEVAL= -DFMT_HAS_CONSTEVAL=0 )
endif()

target_link_libraries(
    ${PROJECT_NAME}
    ${REQUIRED_LIBS_QUALIFIED}
    ${PYTHON_LIBRARIES}
    # spdlog::spdlog
    # spdlog::spdlog_header_only
)
