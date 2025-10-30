// Подключение стандартных библиотек C++
#include <iostream>       // Для ввода-вывода (cout, cin, cerr)
#include <fstream>        // Для работы с файлами
#include <string>         // Для использования строк std::string

// Подключение заголовочных файлов библиотеки Crypto++
#include <cryptopp/cryptlib.h>  // Основные функции и исключения Crypto++
#include <cryptopp/aes.h>       // Реализация алгоритма AES
#include <cryptopp/modes.h>     // Режимы работы блочных шифров (CBC, ECB и др.)
#include <cryptopp/filters.h>   // Фильтры для обработки данных
#include <cryptopp/pwdbased.h>  // Функции для генерации ключей из паролей (PBKDF)
#include <cryptopp/sha.h>       // Хэш-функции (SHA-256 для PBKDF)
#include <cryptopp/hex.h>       // Кодирование в шестнадцатеричный формат
#include <cryptopp/osrng.h>     // Генераторы случайных чисел
#include <cryptopp/files.h>     // Работа с файлами (FileSource, FileSink)

// Использование стандартных пространств имен для упрощения кода
using namespace std;        // Стандартная библиотека C++
using namespace CryptoPP;   // Библиотека криптографии

// Функция вывода меню программы на экран
void printMenu() {
    cout << "=== Программа шифрования/дешифрования ===" << endl;
    cout << "1. Зашифровать файл" << endl;
    cout << "2. Расшифровать файл" << endl;
    cout << "3. Выход" << endl;
    cout << "Выберите режим работы: ";
}

// Функция для получения пароля от пользователя
string getPassword() {
    string password;                    // Переменная для хранения пароля
    cout << "Введите пароль: ";         // Запрос пароля
    cin >> password;                    // Чтение пароля из стандартного ввода
    return password;                    // Возврат введенного пароля
}

// Функция генерации ключа и вектора инициализации (IV) из пароля
void deriveKeyIV(const string& password, // Входной пароль
                 byte* key,              // Выходной буфер для ключа
                 byte* iv) {             // Выходной буфер для вектора инициализации
    // Соль для генерации ключа - увеличивает безопасность против атак по словарям
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Создание объекта для генерации ключа на основе пароля (PBKDF2)
    PKCS12_PBKDF<SHA256> pbkdf;
    
    // Генерация ключа шифрования из пароля
    pbkdf.DeriveKey(key,                // Выходной буфер для ключа
                   AES::DEFAULT_KEYLENGTH, // Длина ключа AES (16, 24 или 32 байта)
                   0,                   // Назначение ключа (0 для шифрования)
                   (byte*)password.data(), // Пароль как массив байт
                   password.size(),     // Длина пароля в байтах
                   salt,                // Соль для усиления безопасности
                   sizeof(salt),        // Размер соли
                   1000,                // Количество итераций (увеличивает стойкость)
                   0.0);                // Время в секундах (0 - не используется)
    
    // Другая соль для генерации вектора инициализации
    byte iv_salt[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    
    // Генерация вектора инициализации (IV) из пароля
    pbkdf.DeriveKey(iv,                 // Выходной буфер для IV
                   AES::BLOCKSIZE,      // Размер IV равен размеру блока AES (16 байт)
                   1,                   // Другое назначение (1 для IV)
                   (byte*)password.data(), // Пароль как массив байт
                   password.size(),     // Длина пароля в байтах
                   iv_salt,             // Соль для IV
                   sizeof(iv_salt),     // Размер соли
                   1000,                // Количество итераций
                   0.0);                // Время в секундах
}

// Функция шифрования файла
void encryptFile(const string& inputFile,   // Имя исходного файла
                const string& outputFile,  // Имя зашифрованного файла
                const string& password) {  // Пароль для генерации ключа
    try {
        // Выделение памяти для ключа и вектора инициализации
        byte key[AES::DEFAULT_KEYLENGTH];  // Буфер для ключа шифрования
        byte iv[AES::BLOCKSIZE];           // Буфер для вектора инициализации
        
        // Генерация ключа и IV из пароля
        deriveKeyIV(password, key, iv);
        
        // Настройка шифрования AES в режиме CBC (Cipher Block Chaining)
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key,        // Установка ключа шифрования
                               sizeof(key), // Длина ключа
                               iv);         // Установка вектора инициализации
        
        // Создание цепочки обработки данных для шифрования:
        // FileSource → StreamTransformationFilter → FileSink
        FileSource fs(inputFile.c_str(),    // Исходный файл для чтения
                     true,                 // Флаг: читать весь файл сразу
                     new StreamTransformationFilter(encryption, // Фильтр шифрования
                     new FileSink(outputFile.c_str()))); // Приемник для записи результата
        
        // Сообщение об успешном завершении шифрования
        cout << "Файл успешно зашифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        // Обработка ошибок шифрования (файл не найден, ошибки чтения и т.д.)
        cerr << "Ошибка при шифровании: " << e.what() << endl;
    }
}

// Функция дешифрования файла
void decryptFile(const string& inputFile,   // Имя зашифрованного файла
                const string& outputFile,  // Имя расшифрованного файла
                const string& password) {  // Пароль для генерации ключа
    try {
        // Выделение памяти для ключа и вектора инициализации
        byte key[AES::DEFAULT_KEYLENGTH];  // Буфер для ключа шифрования
        byte iv[AES::BLOCKSIZE];           // Буфер для вектора инициализации
        
        // Генерация ключа и IV из пароля (должны совпадать с использованными при шифровании)
        deriveKeyIV(password, key, iv);
        
        // Настройка дешифрования AES в режиме CBC
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key,        // Установка ключа дешифрования
                               sizeof(key), // Длина ключа
                               iv);         // Установка вектора инициализации
        
        // Создание цепочки обработки данных для дешифрования:
        // FileSource → StreamTransformationFilter → FileSink
        FileSource fs(inputFile.c_str(),    // Зашифрованный файл для чтения
                     true,                 // Флаг: читать весь файл сразу
                     new StreamTransformationFilter(decryption, // Фильтр дешифрования
                     new FileSink(outputFile.c_str()))); // Приемник для записи результата
        
        // Сообщение об успешном завершении дешифрования
        cout << "Файл успешно расшифрован: " << outputFile << endl;
        
    } catch (const Exception& e) {
        // Обработка ошибок дешифрования (неверный пароль, поврежденный файл и т.д.)
        cerr << "Ошибка при дешифровании: " << e.what() << endl;
    }
}

// Главная функция программы
int main() {
    int choice;                    // Переменная для выбора пользователя из меню
    string inputFile, outputFile;  // Переменные для имен входного и выходного файлов
    string password;               // Переменная для хранения пароля
    
    // Бесконечный цикл для работы с меню
    while (true) {
        // Вывод меню на экран
        printMenu();
        // Чтение выбора пользователя
        cin >> choice;
        
        // Обработка выбора пользователя с помощью оператора switch
        switch (choice) {
            case 1: {
                // Режим шифрования
                cout << "Введите имя исходного файла: ";
                cin >> inputFile;                    // Чтение имени исходного файла
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;                   // Чтение имени выходного файла
                password = getPassword();            // Получение пароля от пользователя
                encryptFile(inputFile, outputFile, password); // Вызов функции шифрования
                break;                              // Выход из case
            }
            case 2: {
                // Режим дешифрования
                cout << "Введите имя зашифрованного файла: ";
                cin >> inputFile;                    // Чтение имени зашифрованного файла
                cout << "Введите имя выходного файла: ";
                cin >> outputFile;                   // Чтение имени выходного файла
                password = getPassword();            // Получение пароля от пользователя
                decryptFile(inputFile, outputFile, password); // Вызов функции дешифрования
                break;                              // Выход из case
            }
            case 3:
                // Выход из программы
                cout << "Выход..." << endl;
                return 0;                           // Завершение программы с кодом 0
            default:
                // Обработка неверного выбора
                cout << "Неверный выбор!" << endl;
        }
        cout << endl;  // Печать пустой строки для улучшения читаемости вывода
    }
    
    return 0;  // Завершение программы (эта строка никогда не выполнится из-за бесконечного цикла)
}
