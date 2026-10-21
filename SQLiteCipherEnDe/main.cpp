#include <iostream>
#include <string>
#include <vector>

#include "encrypt_decrypt.h"
#include "utils.h"

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 9) {
        std::wcerr << L"Usage: SQLiteCipherEnDe.exe <mode> <version> -t <type_input> -p <path> -k <key>\n"
            L"If passing the key in hex format, use the format hex:<key_value>\n"
            L"Successful conversions replace the source and remove the temporary backup.\n";
        return 2;
    }

    if (std::wstring(argv[3]) != L"-t"
        || std::wstring(argv[5]) != L"-p"
        || std::wstring(argv[7]) != L"-k")
    {
        std::wcerr << L"Options must be provided in this order: -t, -p, -k.\n";
        return 2;
    }

    std::wstring error;
    if (!validateMode(argv[1], error))
    {
        std::wcerr << L"Invalid mode: " << error << L'\n';
        return 2;
    }
    if (!validateVersion(argv[2], error))
    {
        std::wcerr << L"Invalid version: " << error << L'\n';
        return 2;
    }
    if (!validateInputType(argv[4], error))
    {
        std::wcerr << L"Invalid input type: " << error << L'\n';
        return 2;
    }
    if (!validatePath(argv[4], argv[6], error))
    {
        std::wcerr << L"Invalid path: " << error << L'\n';
        return 2;
    }

    std::vector<unsigned char> keyBytes;
    bool isHex = false;
    std::wstring key = argv[8];
    if (!parseKey(key, keyBytes, isHex, error))
    {
        std::wcerr << L"Invalid key: " << error << L'\n';
        return 2;
    }

    std::wcout << L"Input validation passed.\n"
               << L"Mode: " << (std::wstring(argv[1]) == L"en" ? L"encrypt" : L"decrypt")
               << L" (" << argv[1] << L")\n"
               << L"Compatibility: " << argv[2] << L'\n'
               << L"Key: " << (isHex ? L"hex:" : L"string:") << key
               << L"  " << keyBytes.size() << L" bytes.\n";
    SecureZeroMemory(keyBytes.data(), keyBytes.size());

    if (!initCryptoCipher())
    {
        SecureZeroMemory(key.data(), key.size() * sizeof(wchar_t));
        return 1;
    }

    const std::string version = argv[2][0] == L'3' ? "3" : "4";
    const bool isFolder = std::wstring(argv[4]) == L"folder";
    const bool succeeded = argv[1][0] == L'e'
        ? encryptDatabase(argv[6], key, isHex, version, isFolder, error)
        : decryptDatabase(argv[6], key, isHex, version, isFolder, error);

    if (!succeeded)
    {
        std::wcerr << error << L'\n';
    }

    const bool unloaded = clearupCryptoCipher();
    SecureZeroMemory(key.data(), key.size() * sizeof(wchar_t));

    return succeeded && unloaded ? 0 : 1;
}
