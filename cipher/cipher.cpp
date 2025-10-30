#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

void printMenu() {
    cout << "=== Программа шифрования/дешифрования ===" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;
    cout << "3. Выход" << endl;
    cout << "Выберите режим работы: ";
}

string getPassword() {
    string password;
    cout << "Введите пароль: ";
    cin >> password;
    return password;
}

void deriveKeyIV(const string& password, byte* key, byte* iv) {
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    PKCS12_PBKDF<SHA256> pbkdf;
    
    // Генерируем ключ
    pbkdf.DeriveKey(key, AES::DEFAULT_KEYLENGTH, 
                   0,
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt),
                   1000, 0.0);
    
    // Генерируем IV из пароля (фиксированный для демонстрации)
    // В реальном приложении IV должен быть случайным и храниться с данными
    byte iv_salt[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    pbkdf.DeriveKey(iv, AES::BLOCKSIZE, 
                   1, // Другое назначение для IV
                   (byte*)password.data(), password.size(),
                   iv_salt, sizeof(iv_salt),
                   1000, 0.0);
}

void encryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        deriveKeyIV(password, key, iv);
        
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv);
        
        FileSource fs(inputFile.c_str(), true,
                     new StreamTransformationFilter(encryption,
                     new FileSink(outputFile.c_str())));
        
        cout << "Файл успешно зашифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        cerr << "Ошибка при шифровании: " << e.what() << endl;
    }
}

void decryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        byte key[AES::DEFAULT_KEYLENGTH];
        byte iv[AES::BLOCKSIZE];
        deriveKeyIV(password, key, iv);
        
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv);
        
        FileSource fs(inputFile.c_str(), true,
                     new StreamTransformationFilter(decryption,
                     new FileSink(outputFile.c_str())));
        
        cout << "Файл успешно расшифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        cerr << "Ошибка при дешифровании: " << e.what() << endl;
    }
}

int main() {
    int choice;
    string inputFile, outputFile, password;
    
    while (true) {
        printMenu();
        cin >> choice;
        
        switch (choice) {
            case 1: {
                cout << "Введите имя исходного файла: ";
                cin >> inputFile;
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;
                password = getPassword();
                encryptFile(inputFile, outputFile, password);
                break;
            }
            case 2: {
                cout << "Введите имя зашифрованного файла: ";
                cin >> inputFile;
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;
                password = getPassword();
                decryptFile(inputFile, outputFile, password);
                break;
            }
            case 3:
                cout << "Выход..." << endl;
                return 0;
            default:
                cout << "Неверный выбор!" << endl;
        }
        cout << endl;
    }
    
    return 0;
}
