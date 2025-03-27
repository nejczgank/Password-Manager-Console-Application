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
#include "Header.h"

int main() {
    std::cout << "Password manager 1.0" << std::endl;

    // Create file if it doesn't exist yet
    std::ifstream checkFile("masterpassword.txt");
    if (!checkFile) {
        std::ofstream masterpasswordFile("masterpassword.txt");
        masterpasswordFile.close();
    }
    checkFile.close();

    // Check if master password exists
    std::string line;
    std::ifstream masterpasswordFile("masterpassword.txt");
    getline(masterpasswordFile, line);
    masterpasswordFile.close();

    bool result = false;
    std::string masterPassword;

    if (line.empty()) {
        createMasterPassword();
        // After creation, program needs to be restarted to use the new password
        std::cout << "Master password created. Please restart the program.\n";
        return 0;
    }
    else {
        while (!result) {
            result = enterMasterPassword(masterPassword);
        }
    }

    std::string encryptionKey = generateKey(masterPassword);

    int run = 1;
    while (run > 0) {
        std::cout <<
            R"(
           1. view entry  
           2. add entry
           3. delete entry
           4. set new master password
           5. quit
        )";
        std::cout << "\nEnter the corresponding number: ";

        char choice;
        std::cin >> choice;
        std::cin.ignore();

        try {
            switch (choice) {
            // View entry
            case '1': {
                viewEntries(encryptionKey);
                break;
            }
            // Add entry
            case '2': {
                std::string entry;
                while (!checkFormatting(entry)) {
                    std::cout << "Add an entry:\nUse the following format -> (username*),(email*),(password),(phone number*),(webdomain*),(description*)" << std::endl;
                    std::cout << "All commas must be entered, optional fields can be omitted, email requires a '@' symbol and phone number accepts only numbers and special symbols" << std::endl;
                    std::cout << "-> ";
                    std::getline(std::cin, entry);
                    if (entry == "quit") {
                        break;
                    }
                    if ((!entry.empty() && !checkFormatting(entry)) || entry.empty()) {
                        std::cout << "Incorrect formatting, try again\n\n";
                    }
                }
                if (entry == "quit") break;

                std::string encryptedEntry = encryptEntry(entry, encryptionKey);
                std::ofstream entries("entries.txt", std::ios::app);
                entries << encryptedEntry << std::endl;
                entries.close();

                entry = "";
                break;
            }
            // Delete entry
            case '3': {
                std::cout << "Select a number corresponding to the entry...\n\n";
                viewEntries(encryptionKey);

                // Get user input
                int entryToDelete = -1;
                bool validInput = false;

                // Load entries to determine valid range
                std::vector<std::string> entriesList;
                std::ifstream inFile("entries.txt");
                if (!inFile) {
                    std::cout << "No entries found.\n";
                    break;
                }
                std::string encryptedLine;
                while (std::getline(inFile, encryptedLine)) {
                    entriesList.push_back(encryptedLine);
                }
                inFile.close();

                while (!validInput) {
                    std::cout << "Enter the number of the entry to delete (0 to cancel): ";
                    if (std::cin >> entryToDelete) { 
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        if (entryToDelete == 0) {
                            std::cout << "Deletion cancelled.\n";
                            break;
                        }
                        if (entryToDelete < 1 || entryToDelete > static_cast<int>(entriesList.size())) {
                            std::cout << "Invalid entry number! Must be between 1 and " << entriesList.size() << ".\n";
                        }
                        else {
                            validInput = true;
                        }
                    }
                    else {
                        std::cout << "Invalid input! Please enter a number.\n";
                        std::cin.clear();
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    }
                }

                // If cancelled, exit the case
                if (entryToDelete == 0) break;

                // Write back all entries except the one to delete
                std::ofstream outFile("entries.txt", std::ios::trunc);
                if (!outFile) {
                    std::cout << "Failed to open file for writing!\n";
                    break;
                }

                for (int i = 0; i < static_cast<int>(entriesList.size()); i++) {
                    if (i != entryToDelete - 1) {
                        outFile << entriesList[i] << std::endl;
                    }
                }
                outFile.close();

                std::cout << "Entry " << entryToDelete << " deleted successfully.\n";
                break;
            }
            case '4': {
                std::cout << "Set the new master password\n";

                // Read and decrypt all current entries with the old key
                std::vector<std::string> decryptedEntries;
                std::ifstream inFile("entries.txt");
                if (inFile) {
                    std::string encryptedLine;
                    while (std::getline(inFile, encryptedLine)) {
                        std::string decryptedEntry = decryptEntry(encryptedLine, encryptionKey);
                        if (!decryptedEntry.empty()) {
                            decryptedEntries.push_back(decryptedEntry);
                        }
                        else {
                            std::cout << "Warning: Failed to decrypt an entry. It will be skipped.\n";
                        }
                    }
                    inFile.close();
                }

                // Prompt for new master password
                createMasterPassword();

                // Reopen masterpassword.txt to get new password
                std::ifstream newMasterFile("masterpassword.txt");
                std::string newHashedPassword;
                std::getline(newMasterFile, newHashedPassword);
                newMasterFile.close();

                // Prompt user to enter new password to generate the new key
                std::string newMasterPassword;
                bool passwordSet = false;
                while (!passwordSet) {
                    passwordSet = enterMasterPassword(newMasterPassword);
                }

                // Generate new encryption key
                std::string newEncryptionKey = generateKey(newMasterPassword);

                // Re-encrypt all entries with the new key
                std::ofstream outFile("entries.txt", std::ios::trunc); // Overwrite the file
                if (!outFile) {
                    std::cout << "Failed to open entries.txt for writing!\n";
                    break;
                }

                for (const auto& entry : decryptedEntries) {
                    std::string reencryptedEntry = encryptEntry(entry, newEncryptionKey);
                    outFile << reencryptedEntry << std::endl;
                }
                outFile.close();

                std::cout << "Master password updated successfully. Please restart the program.\n";
                run = 0;
                break;
            }
            case '5':
                std::cout << "Quitting...";
                run = 0;
                break;
            }

            std::cout << "Press enter to continue...";
            std::cin.get();
            system("cls");
        }
        catch (const std::exception& e) {
            std::cout << "Caught exception: " << e.what() << std::endl;
            std::cout << "Press enter to continue...";
            std::cin.get();
            system("cls");
        }
    }

    return 0;
}

static bool checkFormatting(const std::string& entry) {
    std::regex pattern(R"(^([^,]*),([^,@]*@[^,@]*|),([^,]+),([0-9+\-. ]*),([^,]*),([^,]*)$)");
    return std::regex_match(entry, pattern);
}

static void createMasterPassword() {
    std::string masterPassword;
    std::regex pattern(R"(^[A-Za-z0-9!@#$%^&*()_+={}\[\]:;"'<>,.?/\\|-]{8,}$)");
    while (!std::regex_match(masterPassword, pattern)) {
        std::cout << "Password must contain at least 8 characters. Only words, numbers and most common symbols are permitted" << std::endl;
        std::cout << "Create master password: ";
        std::cin >> masterPassword;
    }

    std::string hashedMasterPassword = sha256(masterPassword);
    std::ofstream masterpasswordFile("masterpassword.txt");
    masterpasswordFile << hashedMasterPassword;
    masterpasswordFile.close();

    masterPassword = "";
}

static bool enterMasterPassword(std::string& masterPassword) {
    std::cout << "Enter your master password: ";
    std::string enteredPassword;
    std::cin >> enteredPassword;

    std::string hashedEnteredPassword = sha256(enteredPassword);
    std::string storedHash;
    std::ifstream masterpasswordFile("masterpassword.txt");
    getline(masterpasswordFile, storedHash);
    masterpasswordFile.close();

    bool passwordMatch = (storedHash == hashedEnteredPassword);
    if (passwordMatch) {
        //Store plaintext for key generation
        masterPassword = enteredPassword;
    }
    else {
        std::cout << "Password mismatch, try again!" << std::endl;
    }

    enteredPassword = "";
    return passwordMatch;
}

static std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

static std::string generateKey(const std::string& masterPassword) {
    std::string hashedKey = sha256(masterPassword);
    return hashedKey.substr(0, 32);
}

static std::string encryptEntry(const std::string& entry, const std::string& key) {
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int ciphertext_len = entry.size() + AES_BLOCK_SIZE;
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    int len;

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)entry.c_str(), entry.size())) {
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int ciphertext_len_partial = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = ciphertext_len_partial + len;

    std::string combined;
    combined.append(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    combined.append(reinterpret_cast<char*>(ciphertext), ciphertext_len);

    std::string result = base64Encode((unsigned char*)combined.c_str(), combined.size());

    delete[] ciphertext;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

static std::string decryptEntry(const std::string& encryptedEntry, const std::string& key) {
    if (encryptedEntry.empty()) {
        std::cout << "Empty encrypted entry.\n";
        return "";
    }

    std::string decodedEntry = base64Decode(encryptedEntry);
    if (decodedEntry.size() < AES_BLOCK_SIZE) {
        std::cout << "Invalid encrypted entry (too short after decoding).\n";
        return "";
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, decodedEntry.c_str(), AES_BLOCK_SIZE);

    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(decodedEntry.c_str() + AES_BLOCK_SIZE);
    int ciphertext_len = decodedEntry.size() - AES_BLOCK_SIZE;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int plaintext_len = ciphertext_len + AES_BLOCK_SIZE;
    unsigned char* plaintext = new unsigned char[plaintext_len];
    int len;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        delete[] plaintext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int plaintext_len_partial = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        std::cout << "Decryption failed: Possible padding issue.\n";
        delete[] plaintext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = plaintext_len_partial + len;

    std::string decrypted(reinterpret_cast<char*>(plaintext), plaintext_len);
    delete[] plaintext;
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

static std::string base64Encode(const unsigned char* data, int length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, length);
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return result;
}

static std::string base64Decode(const std::string& input) {
    if (input.empty()) return "";

    BIO* bio = BIO_new_mem_buf(input.c_str(), input.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decodeLen = input.length();
    unsigned char* buffer = new unsigned char[decodeLen + 1];
    int length = BIO_read(bio, buffer, input.length());

    if (length <= 0) {
        BIO_free_all(bio);
        delete[] buffer;
        return "";
    }

    std::string result(reinterpret_cast<char*>(buffer), length);
    BIO_free_all(bio);
    delete[] buffer;
    return result;
}

static void viewEntries(std::string encryptionKey) {
    std::ifstream entries("entries.txt");
    if (!entries) {
        std::cout << "No entries found.\n";
        return;
    }

    std::string encryptedLine;
    int count = 1;

    std::string fields[6] = { "Username: ", "Email: ", "Password: ", "Phone number: ", "Web domain: ", "Description: " };

    while (std::getline(entries, encryptedLine)) {
        std::string decryptedEntry = decryptEntry(encryptedLine, encryptionKey);
        if (!decryptedEntry.empty()) {
            std::cout << "-------- " << count << ". --------" << std::endl;
            std::string currentWord = "";
            int segmentCount = 0;

            for (int i = 0; i <= decryptedEntry.length(); i++) {
                if (i == decryptedEntry.length() || decryptedEntry[i] == ',') {
                    if (segmentCount < 6) {
                        std::cout << fields[segmentCount] << currentWord << std::endl;
                    }
                    segmentCount++;
                    currentWord = "";
                }
                else {
                    currentWord += decryptedEntry[i];
                }
            }
        }
        else {
            std::cout << count << ". Failed to decrypt entry\n";
        }
        count++;
    }
    entries.close();
    std::cout << "--------------------" << std::endl;
}
