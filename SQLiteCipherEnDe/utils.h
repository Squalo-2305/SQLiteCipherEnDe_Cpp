#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <atomic>
#include <cwctype>

bool validateMode(const std::wstring& mode, std::wstring& error);
bool validateVersion(const std::wstring& version, std::wstring& error);
bool validateInputType(const std::wstring& typeInput, std::wstring& error);
bool validatePath(const std::wstring& typeInput, const std::wstring& path, std::wstring& error);

bool parseKey(std::wstring& key, std::vector<unsigned char>& keyBytes, bool& isHex, std::wstring& error);

std::wstring windowsErrorMessage(DWORD errorCode);

bool wideToUtf8(const std::wstring& input, std::string& output, std::wstring& error);
std::wstring utf8ToWide(const char* input);

bool executableDirectory(std::filesystem::path& directory, std::wstring& error);

bool makeKeyBytes(const std::wstring& key, bool isHex, std::vector<unsigned char>& keyBytes, std::wstring& error);

std::string toHex(const std::vector<unsigned char>& bytes);
