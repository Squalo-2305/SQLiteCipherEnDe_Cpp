#include "utils.h"

#include <limits>
#include <system_error>

namespace
{
    int hexValue(wchar_t character)
    {
        if (character >= L'0' && character <= L'9')
        {
            return character - L'0';
        }
        if (character >= L'a' && character <= L'f')
        {
            return character - L'a' + 10;
        }
        if (character >= L'A' && character <= L'F')
        {
            return character - L'A' + 10;
        }
        return -1;
    }

    bool toUtf8(
        const std::wstring& input,
        std::vector<unsigned char>& output,
        std::wstring& error)
    {
        if (input.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            error = L"Key is too long.";
            return false;
        }

        const int inputLength = static_cast<int>(input.size());
        const int byteCount = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            input.data(),
            inputLength,
            nullptr,
            0,
            nullptr,
            nullptr);
        if (byteCount == 0)
        {
            error = L"Key contains invalid Unicode characters.";
            return false;
        }

        output.resize(static_cast<std::size_t>(byteCount));
        if (WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                input.data(),
                inputLength,
                reinterpret_cast<char*>(output.data()),
                byteCount,
                nullptr,
                nullptr) != byteCount)
        {
            output.clear();
            error = L"Could not convert key to UTF-8.";
            return false;
        }
        return true;
    }
}

bool validateMode(const std::wstring& mode, std::wstring& error)
{
    if (mode == L"en" || mode == L"de")
    {
        error.clear();
        return true;
    }

    error = L"Mode must be 'en' or 'de'.";
    return false;
}

bool validateVersion(const std::wstring& version, std::wstring& error)
{
    if (version == L"3" || version == L"4")
    {
        error.clear();
        return true;
    }

    error = L"Version must be '3' or '4'.";
    return false;
}

bool validateInputType(const std::wstring& typeInput, std::wstring& error)
{
    if (typeInput == L"folder" || typeInput == L"file")
    {
        error.clear();
        return true;
    }

    error = L"Input type must be 'folder' or 'file'.";
    return false;
}

bool validatePath(
    const std::wstring& typeInput,
    const std::wstring& path,
    std::wstring& error)
{
    if (!validateInputType(typeInput, error))
    {
        return false;
    }
    if (path.empty())
    {
        error = L"Path must not be empty.";
        return false;
    }

    std::error_code errorCode;
    const std::filesystem::path inputPath(path);
    const bool correctType = typeInput == L"folder"
        ? std::filesystem::is_directory(inputPath, errorCode)
        : std::filesystem::is_regular_file(inputPath, errorCode);

    if (errorCode)
    {
        error = L"Cannot access path (system error "
            + std::to_wstring(errorCode.value()) + L").";
        return false;
    }
    if (!correctType)
    {
        error = typeInput == L"folder"
            ? L"Path must point to an existing folder."
            : L"Path must point to an existing file.";
        return false;
    }

    error.clear();
    return true;
}

bool parseKey(
    std::wstring& key,
    std::vector<unsigned char>& keyBytes,
    bool& isHex,
    std::wstring& error)
{
    keyBytes.clear();
    error.clear();
    isHex = key.compare(0, 4, L"hex:") == 0;

    if (!isHex)
    {
        if (key.empty())
        {
            error = L"Key must not be empty.";
            return false;
        }
        return toUtf8(key, keyBytes, error);
    }

    const std::wstring hex = key.substr(4);
    key = hex;
    if (hex.empty())
    {
        error = L"Hex key must contain at least one byte after 'hex:'.";
        return false;
    }
    if (hex.size() % 2 != 0)
    {
        error = L"Hex key must contain an even number of hexadecimal digits.";
        return false;
    }

    keyBytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const int high = hexValue(hex[i]);
        const int low = hexValue(hex[i + 1]);
        if (high < 0 || low < 0)
        {
            keyBytes.clear();
            error = L"Hex key may contain only characters 0-9, a-f, and A-F.";
            return false;
        }
        keyBytes.push_back(static_cast<unsigned char>((high << 4) | low));
    }

    error.clear();
    return true;
}

std::wstring windowsErrorMessage(DWORD errorCode)
{
    return L"Windows error " + std::to_wstring(errorCode) + L".";
}

bool wideToUtf8(
    const std::wstring& input,
    std::string& output,
    std::wstring& error)
{
    if (input.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    {
        error = L"Input is too long to convert to UTF-8.";
        return false;
    }

    const int inputLength = static_cast<int>(input.size());
    const int byteCount = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input.data(),
        inputLength,
        nullptr,
        0,
        nullptr,
        nullptr);
    if (byteCount == 0)
    {
        error = L"Input contains invalid Unicode characters.";
        return false;
    }

    output.resize(static_cast<std::size_t>(byteCount));
    if (WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        input.data(),
        inputLength,
        output.data(),
        byteCount,
        nullptr,
        nullptr) != byteCount)
    {
        output.clear();
        error = L"Could not convert input to UTF-8.";
        return false;
    }
    return true;
}

std::wstring utf8ToWide(const char* input)
{
    if (input == nullptr || input[0] == '\0')
    {
        return L"";
    }

    const int inputLength = static_cast<int>(std::char_traits<char>::length(input));
    const int characterCount = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        input,
        inputLength,
        nullptr,
        0);
    if (characterCount == 0)
    {
        return L"SQLite returned an error message that could not be decoded.";
    }

    std::wstring output(static_cast<std::size_t>(characterCount), L'\0');
    if (MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        input,
        inputLength,
        output.data(),
        characterCount) != characterCount)
    {
        return L"SQLite returned an error message that could not be decoded.";
    }
    return output;
}

bool executableDirectory(std::filesystem::path& directory, std::wstring& error)
{
    std::vector<wchar_t> buffer(32768);
    const DWORD length = GetModuleFileNameW(
        nullptr,
        buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size())
    {
        error = L"Cannot determine executable path: "
            + windowsErrorMessage(GetLastError());
        return false;
    }

    directory = std::filesystem::path(
        std::wstring(buffer.data(), static_cast<std::size_t>(length))).parent_path();
    return true;
}

bool makeKeyBytes(
    const std::wstring& key,
    bool isHex,
    std::vector<unsigned char>& keyBytes,
    std::wstring& error)
{
    keyBytes.clear();
    if (!isHex)
    {
        std::string utf8;
        if (key.empty() || !wideToUtf8(key, utf8, error))
        {
            if (key.empty())
            {
                error = L"Key must not be empty.";
            }
            return false;
        }
        keyBytes.assign(utf8.begin(), utf8.end());
        return true;
    }

    const std::wstring hex = key.compare(0, 4, L"hex:") == 0
        ? key.substr(4)
        : key;
    if (hex.empty() || hex.size() % 2 != 0)
    {
        error = L"Hex key must contain a non-empty even number of hexadecimal digits.";
        return false;
    }

    keyBytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const auto hexValue = [](wchar_t character) -> int
            {
                if (character >= L'0' && character <= L'9')
                {
                    return character - L'0';
                }
                if (character >= L'a' && character <= L'f')
                {
                    return character - L'a' + 10;
                }
                if (character >= L'A' && character <= L'F')
                {
                    return character - L'A' + 10;
                }
                return -1;
            };

        const int high = hexValue(hex[i]);
        const int low = hexValue(hex[i + 1]);
        if (high < 0 || low < 0)
        {
            keyBytes.clear();
            error = L"Hex key may contain only characters 0-9, a-f, and A-F.";
            return false;
        }
        keyBytes.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return true;
}

std::string toHex(const std::vector<unsigned char>& bytes)
{
    static const char digits[] = "0123456789ABCDEF";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (const unsigned char byte : bytes)
    {
        hex.push_back(digits[byte >> 4]);
        hex.push_back(digits[byte & 0x0F]);
    }
    return hex;
}