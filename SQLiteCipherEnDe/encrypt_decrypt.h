#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sqlite3.h>

#include <string>

struct SqlCipherApi
{
    using OpenV2 = int(__cdecl*)(const char*, sqlite3**, int, const char*);
    using Exec = int(__cdecl*)(
        sqlite3*,
        const char*,
        int(__cdecl*)(void*, int, char**, char**),
        void*,
        char**);
    using Close = int(__cdecl*)(sqlite3*);
    using Errmsg = const char*(__cdecl*)(sqlite3*);
    using Free = void(__cdecl*)(void*);
    using Key = int(__cdecl*)(sqlite3*, const void*, int);
    using KeyV2 = int(__cdecl*)(sqlite3*, const char*, const void*, int);

    OpenV2 openV2 = nullptr;
    Exec exec = nullptr;
    Close close = nullptr;
    Errmsg errmsg = nullptr;
    Free free = nullptr;
    Key key = nullptr;
    KeyV2 keyV2 = nullptr;
};

extern SqlCipherApi g_sqlCipherApi;

bool initCryptoCipher();
bool clearupCryptoCipher();

bool encryptDatabase(
    const std::wstring& dbPath,
    const std::wstring& key,
    bool isHex,
    const std::string& version,
    bool isFolder,
    std::wstring& error);
bool decryptDatabase(
    const std::wstring& dbPath,
    const std::wstring& key,
    bool isHex,
    const std::string& version,
    bool isFolder,
    std::wstring& error);
