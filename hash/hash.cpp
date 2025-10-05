#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Использование: " << argv[0] << " <имя_файла>" << endl;
        return 1;
    }

    string filename = argv[1];
    
    try {
        SHA256 hash;
        string digest;
        
        FileSource file(filename.c_str(), true, 
                      new HashFilter(hash,
                      new HexEncoder(
                      new StringSink(digest))));
        
        cout << "SHA-256 хэш файла '" << filename << "':" << endl;
        cout << digest << endl;
        
    } catch (const Exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
