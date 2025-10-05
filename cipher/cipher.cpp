// Стандартные библиотеки C++
#include <iostream>   // Для ввода/вывода (cout, cin, cerr)
#include <fstream>    // Для работы с файлами
#include <string>     // Для использования строк std::string

// Библиотека Crypto++ - заголовочные файлы
#include <cryptopp/cryptlib.h>  // Основные функции Crypto++
#include <cryptopp/aes.h>       // Алгоритм AES шифрования
#include <cryptopp/modes.h>     // Режимы работы (CBC, ECB и т.д.)
#include <cryptopp/filters.h>   // Фильтры для обработки данных
#include <cryptopp/pwdbased.h>  // Функции для работы с паролями (PBKDF)
#include <cryptopp/sha.h>       // Хэш-функции для генерации ключей
#include <cryptopp/hex.h>       // Кодирование в шестнадцатеричный формат
#include <cryptopp/osrng.h>     // Генераторы случайных чисел
#include <cryptopp/files.h>     // Работа с файлами (FileSource, FileSink)

// Используем стандартные пространства имен для упрощения кода
using namespace std;        // Стандартная библиотека C++
using namespace CryptoPP;   // Библиотека криптографии

// Функция для вывода меню программы
void printMenu() {
    cout << "=== Программа шифрования/дешифрования ===" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;
    cout << "3. Выход" << endl;
    cout << "Выберите режим работы: ";
}

// Функция для безопасного ввода пароля
string getPassword() {
    string password;
    cout << "Введите пароль: ";
    cin >> password;  // В реальном приложении лучше использовать скрытый ввод
    return password;
}

// Функция для генерации ключа и вектора инициализации (IV) из пароля
// Используется алгоритм PBKDF2 (Password-Based Key Derivation Function)
void deriveKeyIV(const string& password, byte* key, byte* iv) {
    // Соль (salt) для усиления безопасности - должна быть уникальной для каждого пароля
    // В реальном приложении соль должна генерироваться случайно и храниться с данными
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Создаем объект для генерации ключа из пароля
    PKCS12_PBKDF<SHA256> pbkdf;
    
    // Генерируем ключ из пароля
    pbkdf.DeriveKey(key,           // Буфер для ключа
                   AES::DEFAULT_KEYLENGTH,  // Длина ключа AES (16, 24 или 32 байта)
                   0,              // Назначение ключа (0 для шифрования)
                   (byte*)password.data(),  // Пароль как массив байт
                   password.size(), // Длина пароля
                   salt,           // Соль
                   sizeof(salt),   // Размер соли
                   1000,           // Количество итераций (увеличивает безопасность)
                   0.0);           // Время в секундах (0 - не используется)
}

// Функция для шифрования файла
void encryptFile(const string& inputFile,   // Имя исходного файла
                const string& outputFile,  // Имя зашифрованного файла
                const string& password) {  // Пароль для генерации ключа
    try {
        // Выделяем память для ключа и вектора инициализации
        byte key[AES::DEFAULT_KEYLENGTH];  // Ключ шифрования
        byte iv[AES::BLOCKSIZE];           // Вектор инициализации для режима CBC
        
        // Генерируем ключ и IV из пароля
        deriveKeyIV(password, key, iv);
        
        // Настраиваем шифрование AES в режиме CBC (Cipher Block Chaining)
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key,    // Ключ шифрования
                               sizeof(key),  // Длина ключа
                               iv);     // Вектор инициализации
        
        // Создаем цепочку обработки для шифрования:
        // FileSource → StreamTransformationFilter → FileSink
        FileSource fs(inputFile.c_str(),    // Исходный файл
                     true,                 // Читать весь файл
                     new StreamTransformationFilter(encryption,  // Фильтр шифрования
                     new FileSink(outputFile.c_str())));  // Запись в файл
        
        cout << "Файл успешно зашифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        // Обрабатываем ошибки шифрования
        cerr << "Ошибка при шифровании: " << e.what() << endl;
    }
}

// Функция для дешифрования файла
void decryptFile(const string& inputFile,   // Имя зашифрованного файла
                const string& outputFile,  // Имя расшифрованного файла
                const string& password) {  // Пароль для генерации ключа
    try {
        // Выделяем память для ключа и вектора инициализации
        byte key[AES::DEFAULT_KEYLENGTH];  // Ключ шифрования
        byte iv[AES::BLOCKSIZE];           // Вектор инициализации
        
        // Генерируем ключ и IV из пароля (должны быть такие же как при шифровании)
        deriveKeyIV(password, key, iv);
        
        // Настраиваем дешифрование AES в режиме CBC
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key,    // Ключ шифрования
                               sizeof(key),  // Длина ключа
                               iv);     // Вектор инициализации
        
        // Создаем цепочку обработки для дешифрования:
        // FileSource → StreamTransformationFilter → FileSink
        FileSource fs(inputFile.c_str(),    // Зашифрованный файл
                     true,                 // Читать весь файл
                     new StreamTransformationFilter(decryption,  // Фильтр дешифрования
                     new FileSink(outputFile.c_str())));  // Запись в файл
        
        cout << "Файл успешно расшифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        // Обрабатываем ошибки дешифрования (неверный пароль, поврежденный файл и т.д.)
        cerr << "Ошибка при дешифровании: " << e.what() << endl;
    }
}

// Главная функция программы
int main() {
    int choice;                    // Переменная для выбора пользователя
    string inputFile, outputFile;  // Имена файлов
    string password;               // Пароль
    
    // Основной цикл программы
    while (true) {
        // Выводим меню
        printMenu();
        cin >> choice;  // Читаем выбор пользователя
        
        // Обрабатываем выбор пользователя
        switch (choice) {
            case 1: {
                // Режим шифрования
                cout << "Введите имя исходного файла: ";
                cin >> inputFile;
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;
                password = getPassword();  // Получаем пароль
                encryptFile(inputFile, outputFile, password);  // Шифруем файл
                break;
            }
            case 2: {
                // Режим дешифрования
                cout << "Введите имя зашифрованного файла: ";
                cin >> inputFile;
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;
                password = getPassword();  // Получаем пароль
                decryptFile(inputFile, outputFile, password);  // Дешифруем файл
                break;
            }
            case 3:
                // Выход из программы
                cout << "Выход..." << endl;
                return 0;  // Завершаем программу
            default:
                // Неверный выбор
                cout << "Неверный выбор!" << endl;
        }
        cout << endl;  // Пустая строка для читаемости
    }
    
    return 0;  // Программа завершена
}
