#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <regex>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

static bool checkFormatting(const std::string& entry);
static void createMasterPassword();
static bool enterMasterPassword(std::string& masterPassword);
static std::string sha256(const std::string& input);
static std::string generateKey(const std::string& masterPassword);
static std::string encryptEntry(const std::string& entry, const std::string& key);
static std::string decryptEntry(const std::string& encryptedEntry, const std::string& key);
static std::string base64Encode(const unsigned char* data, int length);
static std::string base64Decode(const std::string& input);
static void viewEntries(std::string encryptionKey);

#endif
