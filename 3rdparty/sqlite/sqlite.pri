# Vendored SQLite amalgamation; compiled identically on Windows and Linux.
INCLUDEPATH += $$PWD
SOURCES += $$PWD/sqlite3.c
DEFINES += SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION
