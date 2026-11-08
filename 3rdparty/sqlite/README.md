# SQLite amalgamation

This directory vendors the official SQLite amalgamation, version 3.50.4 (2025-07-30),
from https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip.
SQLite is in the public domain. The upstream project and license information are at
https://www.sqlite.org/copyright.html.

The application compiles `sqlite3.c` directly via `sqlite.pri`; this keeps the Windows
(MinGW) and Linux builds self-contained and uses no system SQLite installation.
Update `sqlite3.c`, `sqlite3.h`, and `sqlite3ext.h` together when upgrading.
