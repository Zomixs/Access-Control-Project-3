#include <iostream>
#include <cstdlib>

void genUsers() {
    std::cout << "\n[1] generating users\n";
    system("g++ generate_users.cpp -o generate_users -lssl -lcrypto");
    system("./generate_users");
}

void encShareKey() {
    std::cout << "\n[2] encrypting shared key\n";
    system("g++ encrypt_shared_key.cpp -o encrypt_shared_key -lssl -lcrypto");
    system("./encrypt_shared_key");
}

void encFile() {
    std::cout << "\n[3] encrypting file\n";
    system("g++ encrypt_file.cpp -o encrypt_file -lssl -lcrypto");
    system("./encrypt_file");
}

void decryptTest() {
    std::cout << "\n[4] decrypt test\n";
    system("g++ user_decrypt.cpp -o user_decrypt -lssl -lcrypto");
    system("./user_decrypt");
}

int main() {

    int choice;

    while (true) {

        std::cout << "\n----------------------\n";
        std::cout << "ABAC MENU\n";
        std::cout << "----------------------\n";
        std::cout << "1. generate users\n";
        std::cout << "2. encrypt shared key\n";
        std::cout << "3. encrypt file\n";
        std::cout << "4. decrypt test\n";
        std::cout << "5. exit\n";
        std::cout << "choice: ";
        std::cin >> choice;

        if (choice == 1) {
            genUsers();
        }
        else if (choice == 2) {
            encShareKey();
        }
        else if (choice == 3) {
            encFile();
        }
        else if (choice == 4) {
            decryptTest();
        }
        else if (choice == 5) {
            std::cout << "exiting...\n";
            break;
        }
        else {
            std::cout << "invalid input\n";
        }
    }

    return 0;
}