#include <iostream>
#include <string>
#include <vector>

#include "encrypt_decrypt.h"
#include "utils.h"

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 9) {
        std::wcerr
            << L"Usage: SQLiteCipherEnDe.exe <mode> <version>"
            << L" -t <type_input> -p <path> -k <key>\n"
            << L"Options -t, -p, -k can be provided in any order.\n"
            << L"If passing the key in hex format, use the format hex:<key_value>\n"
            << L"Successful conversions replace the source and remove the temporary backup.\n";
        return 2;
    }

    std::wstring inputType;
    std::wstring path;
    std::wstring key;

    bool hasType = false;
    bool hasPath = false;
    bool hasKey = false;

    for (int i = 3; i < argc; i += 2) {
        std::wstring option = argv[i];

        if (i + 1 >= argc) {
            std::wcerr << L"Missing value for option: "
                << option << L'\n';
            return 2;
        }

        std::wstring value = argv[i + 1];

        if (option == L"-t") {
            if (hasType) {
                std::wcerr << L"Duplicate option: -t\n";
                return 2;
            }
            inputType = value;
            hasType = true;
        }
        else if (option == L"-p") {
            if (hasPath) {
                std::wcerr << L"Duplicate option: -p\n";
                return 2;
            }
            path = value;
            hasPath = true;
        }
        else if (option == L"-k") {
            if (hasKey) {
                std::wcerr << L"Duplicate option: -k\n";
                return 2;
            }
            key = value;
            hasKey = true;
        }
        else {
            std::wcerr << L"Unknown option: " << option << L'\n';
            return 2;
        }
    }

    if (!hasType || !hasPath || !hasKey) {
        std::wcerr
            << L"Missing required options. Required: -t, -p, -k.\n";
        return 2;
    }

    // Validate các argument
    std::wstring error;

    if (!validateMode(argv[1], error)) {
        std::wcerr << L"Invalid mode: " << error << L'\n';
        return 2;
    }

    if (!validateVersion(argv[2], error)) {
        std::wcerr << L"Invalid version: " << error << L'\n';
        return 2;
    }

    if (!validateInputType(inputType.c_str(), error)) {
        std::wcerr << L"Invalid input type: " << error << L'\n';
        return 2;
    }

    if (!validatePath(inputType.c_str(), path.c_str(), error)) {
        std::wcerr << L"Invalid path: " << error << L'\n';
        return 2;
    }

    std::vector<unsigned char> keyBytes;
    bool isHex = false;

    if (!parseKey(key, keyBytes, isHex, error)) {
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
