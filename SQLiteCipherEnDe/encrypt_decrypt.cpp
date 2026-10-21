#include "encrypt_decrypt.h"

#include <algorithm>
#include <limits>
#include <mutex>
#include <system_error>

#include "utils.h"

SqlCipherApi g_sqlCipherApi;

namespace
{
    HMODULE g_sqlCipherModule = nullptr;
    std::mutex g_sqlCipherMutex;
    std::atomic<unsigned long long> g_pathSequence{ 0 };

    struct KeyBytesWiper
    {
        explicit KeyBytesWiper(std::vector<unsigned char>& value)
            : bytes(value)
        {
        }

        ~KeyBytesWiper()
        {
            SecureZeroMemory(bytes.data(), bytes.size());
        }

        std::vector<unsigned char>& bytes;
    };

    void resetApi()
    {
        g_sqlCipherApi = SqlCipherApi{};
    }

    template <typename Function>
    bool loadFunction(
        const char* functionName,
        Function& function,
        std::wstring& error)
    {
        function = reinterpret_cast<Function>(
            GetProcAddress(g_sqlCipherModule, functionName));
        if (function != nullptr)
        {
            return true;
        }

        error = L"sqlcipher.dll is missing export "
            + utf8ToWide(functionName) + L".";
        return false;
    }

    bool ensureLoaded(std::wstring& error)
    {
        if (g_sqlCipherModule != nullptr)
        {
            return true;
        }

        std::filesystem::path directory;
        if (!executableDirectory(directory, error))
        {
            return false;
        }

        const std::filesystem::path dllPath = directory / L"sqlcipher.dll";
        g_sqlCipherModule = LoadLibraryExW(
            dllPath.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (g_sqlCipherModule == nullptr)
        {
            error = L"Cannot load "
                + dllPath.wstring() + L": "
                + windowsErrorMessage(GetLastError());
            return false;
        }

        if (!loadFunction("sqlite3_open_v2", g_sqlCipherApi.openV2, error)
            || !loadFunction("sqlite3_exec", g_sqlCipherApi.exec, error)
            || !loadFunction("sqlite3_close", g_sqlCipherApi.close, error)
            || !loadFunction("sqlite3_errmsg", g_sqlCipherApi.errmsg, error)
            || !loadFunction("sqlite3_free", g_sqlCipherApi.free, error)
            || !loadFunction("sqlite3_key", g_sqlCipherApi.key, error)
            || !loadFunction("sqlite3_key_v2", g_sqlCipherApi.keyV2, error))
        {
            FreeLibrary(g_sqlCipherModule);
            g_sqlCipherModule = nullptr;
            resetApi();
            return false;
        }
        return true;
    }

    std::wstring databaseError(sqlite3* db)
    {
        return g_sqlCipherApi.errmsg != nullptr
            ? utf8ToWide(g_sqlCipherApi.errmsg(db))
            : L"Unknown SQLCipher error.";
    }

    bool executeSql(sqlite3* db, const std::string& sql, std::wstring& error)
    {
        char* errorMessage = nullptr;
        const int result = g_sqlCipherApi.exec(db, sql.c_str(), nullptr, nullptr, &errorMessage);
        if (result == SQLITE_OK)
        {
            return true;
        }

        error = errorMessage != nullptr
            ? utf8ToWide(errorMessage)
            : databaseError(db);
        if (errorMessage != nullptr)
        {
            g_sqlCipherApi.free(errorMessage);
        }
        return false;
    }

    bool setCompatibility(
        sqlite3* db,
        const char* schema,
        const std::string& version,
        std::wstring& error)
    {
        const std::string sql = "PRAGMA " + std::string(schema)
            + ".cipher_compatibility = " + version + ";";
        return executeSql(db, sql, error);
    }

    bool setKey(
        sqlite3* db,
        const char* schema,
        const std::vector<unsigned char>& keyBytes,
        std::wstring& error)
    {
        if (keyBytes.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            error = L"Key is too long.";
            return false;
        }

        const int result = std::string(schema) == "main"
            ? g_sqlCipherApi.key(
                db,
                keyBytes.data(),
                static_cast<int>(keyBytes.size()))
            : g_sqlCipherApi.keyV2(
                db,
                schema,
                keyBytes.data(),
                static_cast<int>(keyBytes.size()));
        if (result == SQLITE_OK)
        {
            return true;
        }

        error = databaseError(db);
        return false;
    }

    bool quoteSqlString(const std::wstring& input, std::string& quoted, std::wstring& error)
    {
        std::string utf8;
        if (!wideToUtf8(input, utf8, error))
        {
            return false;
        }

        quoted.clear();
        quoted.reserve(utf8.size() + 2);
        quoted.push_back('\'');
        for (const char character : utf8)
        {
            if (character == '\'')
            {
                quoted.push_back('\'');
            }
            quoted.push_back(character);
        }
        quoted.push_back('\'');
        return true;
    }

    bool uniqueSiblingPath(
        const std::filesystem::path& source,
        const wchar_t* suffix,
        std::filesystem::path& candidate,
        std::wstring& error)
    {
        for (int attempt = 0; attempt < 100; ++attempt)
        {
            const unsigned long long sequence = ++g_pathSequence;
            candidate = source;
            candidate += std::wstring(suffix)
                + L"-" + std::to_wstring(GetCurrentProcessId())
                + L"-" + std::to_wstring(sequence);
            std::error_code errorCode;
            const bool exists = std::filesystem::exists(candidate, errorCode);
            if (errorCode)
            {
                error = L"Cannot inspect temporary path "
                    + candidate.wstring() + L": "
                    + utf8ToWide(errorCode.message().c_str());
                return false;
            }
            if (!exists)
            {
                return true;
            }
        }

        error = L"Could not generate a unique temporary path for "
            + source.wstring() + L".";
        return false;
    }

    bool closeDatabase(sqlite3*& db, std::wstring& error)
    {
        if (db == nullptr)
        {
            return true;
        }

        const int result = g_sqlCipherApi.close(db);
        if (result != SQLITE_OK)
        {
            error = L"Cannot close database: " + databaseError(db);
            return false;
        }
        db = nullptr;
        return true;
    }

    bool processOneDatabase(
        const std::filesystem::path& sourcePath,
        const std::vector<unsigned char>& keyBytes,
        const std::string& version,
        bool encrypt,
        std::wstring& error)
    {
        std::wstring sourcePathWide = sourcePath.wstring();
        std::filesystem::path temporaryPath;
        if (!uniqueSiblingPath(
                sourcePath,
                L".sqlcipher-temp",
                temporaryPath,
                error))
        {
            return false;
        }
        std::string temporaryPathSql;
        if (!quoteSqlString(temporaryPath.wstring(), temporaryPathSql, error))
        {
            return false;
        }
        std::string temporaryPathUtf8;
        if (!wideToUtf8(temporaryPath.wstring(), temporaryPathUtf8, error))
        {
            return false;
        }

        sqlite3* db = nullptr;
        std::string sourcePathUtf8;
        if (!wideToUtf8(sourcePathWide, sourcePathUtf8, error))
        {
            return false;
        }

        const int openResult = g_sqlCipherApi.openV2(
            sourcePathUtf8.c_str(),
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nullptr);
        if (openResult != SQLITE_OK)
        {
            error = L"Cannot open source database: "
                + (db != nullptr ? databaseError(db) : L"out of memory.");
            std::wstring closeError;
            if (!closeDatabase(db, closeError))
            {
                error += L" " + closeError;
            }
            return false;
        }

        bool attached = false;
        bool succeeded = true;

        if (!encrypt)
        {
            succeeded = setKey(db, "main", keyBytes, error)
                && setCompatibility(db, "main", version, error)
                && executeSql(db, "SELECT count(*) FROM main.sqlite_master;", error);
            if (!succeeded)
            {
                error = L"Could not open the encrypted source database: " + error;
            }
        }
        else
        {
            succeeded = executeSql(db, "SELECT count(*) FROM main.sqlite_master;", error);
            if (!succeeded)
            {
                error = L"Could not read the plaintext source database: " + error;
            }
        }

        if (succeeded)
        {
            sqlite3* temporaryDb = nullptr;
            const int createResult = g_sqlCipherApi.openV2(
                temporaryPathUtf8.c_str(),
                &temporaryDb,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                nullptr);
            if (createResult != SQLITE_OK)
            {
                error = L"Cannot create temporary output database: "
                    + (temporaryDb != nullptr
                        ? databaseError(temporaryDb)
                        : L"out of memory.");
                std::wstring closeError;
                if (!closeDatabase(temporaryDb, closeError))
                {
                    error += L" " + closeError;
                }
                succeeded = false;
            }
            else if (!closeDatabase(temporaryDb, error))
            {
                succeeded = false;
            }
        }

        if (succeeded)
        {
            succeeded = executeSql(
                db,
                "ATTACH DATABASE " + temporaryPathSql + " AS target"
                    + (encrypt ? ";" : " KEY '';"),
                error);
            attached = succeeded;
            if (!succeeded)
            {
                error = L"Could not attach the temporary output database: " + error;
            }
        }

        if (succeeded && encrypt)
        {
            succeeded = setKey(db, "target", keyBytes, error)
                && setCompatibility(db, "target", version, error);
            if (!succeeded)
            {
                error = L"Could not configure encryption for the output database: " + error;
            }
        }

        if (succeeded)
        {
            succeeded = executeSql(db, "SELECT sqlcipher_export('target');", error);
            if (!succeeded)
            {
                error = L"Could not copy database contents to the output: " + error;
            }
        }
        if (succeeded)
        {
            succeeded = executeSql(db, "SELECT count(*) FROM target.sqlite_master;", error);
        }
        if (attached)
        {
            std::wstring detachError;
            if (!executeSql(db, "DETACH DATABASE target;", detachError) && succeeded)
            {
                succeeded = false;
                error = L"Cannot detach output database: " + detachError;
            }
        }
        if (!closeDatabase(db, error))
        {
            succeeded = false;
        }
        if (!succeeded)
        {
            std::error_code removeError;
            std::filesystem::remove(temporaryPath, removeError);
            if (removeError)
            {
                error += L" Could not remove temporary output: "
                    + temporaryPath.wstring() + L".";
            }
            return false;
        }

        std::filesystem::path backupPath;
        if (!uniqueSiblingPath(sourcePath, L".backup", backupPath, error))
        {
            std::error_code removeError;
            std::filesystem::remove(temporaryPath, removeError);
            return false;
        }
        std::error_code renameError;
        std::filesystem::rename(sourcePath, backupPath, renameError);
        if (renameError)
        {
            error = L"Conversion succeeded, but cannot move original database to backup: "
                + utf8ToWide(renameError.message().c_str());
            std::error_code removeError;
            std::filesystem::remove(temporaryPath, removeError);
            return false;
        }

        std::filesystem::rename(temporaryPath, sourcePath, renameError);
        if (renameError)
        {
            std::error_code restoreError;
            std::filesystem::rename(backupPath, sourcePath, restoreError);
            error = L"Cannot replace original database with converted output: "
                + utf8ToWide(renameError.message().c_str());
            if (restoreError)
            {
                error += L" Original remains at backup path "
                    + backupPath.wstring()
                    + L"; restore failed: "
                    + utf8ToWide(restoreError.message().c_str()) + L".";
            }
            else
            {
                std::error_code removeError;
                std::filesystem::remove(temporaryPath, removeError);
            }
            return false;
        }

        std::error_code backupRemoveError;
        std::filesystem::remove(backupPath, backupRemoveError);
        if (backupRemoveError)
        {
            std::wcerr << L"Processed: " << sourcePathWide
                       << L", but could not remove temporary backup "
                       << backupPath.wstring() << L": "
                       << utf8ToWide(backupRemoveError.message().c_str()) << L'\n';
        }
        else
        {
            std::wcout << L"Processed: " << sourcePathWide << L'\n';
        }
        return true;
    }

    bool hasDatabaseExtension(const std::filesystem::path& path)
    {
        std::wstring extension = path.extension().wstring();
        std::transform(
            extension.begin(),
            extension.end(),
            extension.begin(),
            [](wchar_t character) { return static_cast<wchar_t>(std::towlower(character)); });
        return extension == L".db"
            || extension == L".sqlite"
            || extension == L".sqlite3";
    }

    bool processDatabasePath(
        const std::wstring& dbPath,
        const std::wstring& key,
        bool isHex,
        const std::string& version,
        bool isFolder,
        bool encrypt,
        std::wstring& error)
    {
        std::lock_guard<std::mutex> lock(g_sqlCipherMutex);
        if (!ensureLoaded(error))
        {
            return false;
        }
        if (version != "3" && version != "4")
        {
            error = L"SQLCipher version must be '3' or '4'.";
            return false;
        }

        std::vector<unsigned char> keyBytes;
        KeyBytesWiper keyBytesWiper(keyBytes);
        if (!makeKeyBytes(key, isHex, keyBytes, error))
        {
            return false;
        }

        const std::filesystem::path inputPath(dbPath);
        std::vector<std::filesystem::path> databasePaths;
        std::error_code filesystemError;
        if (isFolder)
        {
            if (!std::filesystem::is_directory(inputPath, filesystemError)
                || filesystemError)
            {
                error = L"Input path is not an accessible directory.";
                return false;
            }

            std::filesystem::recursive_directory_iterator iterator(
                inputPath,
                std::filesystem::directory_options::skip_permission_denied,
                filesystemError);
            const std::filesystem::recursive_directory_iterator end;
            if (filesystemError)
            {
                error = L"Cannot enumerate input directory: "
                    + utf8ToWide(filesystemError.message().c_str());
                return false;
            }
            while (iterator != end)
            {
                const auto entry = *iterator;
                std::error_code entryError;
                if (entry.is_regular_file(entryError) && !entryError
                    && hasDatabaseExtension(entry.path()))
                {
                    databasePaths.push_back(entry.path());
                }
                iterator.increment(filesystemError);
                if (filesystemError)
                {
                    std::wcerr << L"Cannot continue directory scan: "
                               << utf8ToWide(filesystemError.message().c_str()) << L'\n';
                    filesystemError.clear();
                }
            }
        }
        else
        {
            if (!std::filesystem::is_regular_file(inputPath, filesystemError)
                || filesystemError)
            {
                error = L"Input path is not an accessible database file.";
                return false;
            }
            databasePaths.push_back(inputPath);
        }

        if (databasePaths.empty())
        {
            error = L"No database files were found to process.";
            return false;
        }

        bool allSucceeded = true;
        std::wstring failures;
        for (const std::filesystem::path& databasePath : databasePaths)
        {
            std::wstring fileError;
            if (!processOneDatabase(
                    databasePath,
                    keyBytes,
                    version,
                    encrypt,
                    fileError))
            {
                allSucceeded = false;
                std::wcerr << L"Failed: " << databasePath.wstring()
                           << L"\n  " << fileError << L'\n';
                if (!failures.empty())
                {
                    failures += L"\n";
                }
                failures += databasePath.wstring() + L": " + fileError;
            }
        }

        SecureZeroMemory(keyBytes.data(), keyBytes.size());
        if (!allSucceeded)
        {
            error = L"One or more databases could not be processed:\n" + failures;
            return false;
        }

        error.clear();
        return true;
    }
}

bool initCryptoCipher()
{
    std::lock_guard<std::mutex> lock(g_sqlCipherMutex);
    std::wstring error;
    if (ensureLoaded(error))
    {
        return true;
    }

    std::wcerr << error << L'\n';
    return false;
}

bool clearupCryptoCipher()
{
    std::lock_guard<std::mutex> lock(g_sqlCipherMutex);
    if (g_sqlCipherModule == nullptr)
    {
        resetApi();
        return true;
    }

    if (FreeLibrary(g_sqlCipherModule) == FALSE)
    {
        std::wcerr << L"Cannot unload sqlcipher.dll: "
                   << windowsErrorMessage(GetLastError()) << L'\n';
        return false;
    }

    g_sqlCipherModule = nullptr;
    resetApi();
    return true;
}

bool encryptDatabase(
    const std::wstring& dbPath,
    const std::wstring& key,
    bool isHex,
    const std::string& version,
    bool isFolder,
    std::wstring& error)
{
    return processDatabasePath(
        dbPath,
        key,
        isHex,
        version,
        isFolder,
        true,
        error);
}

bool decryptDatabase(
    const std::wstring& dbPath,
    const std::wstring& key,
    bool isHex,
    const std::string& version,
    bool isFolder,
    std::wstring& error)
{
    return processDatabasePath(
        dbPath,
        key,
        isHex,
        version,
        isFolder,
        false,
        error);
}