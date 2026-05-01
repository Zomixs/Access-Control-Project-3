#include <openssl/evp.h>
#include <openssl/pem.h>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>

struct User {
    std::string name;
    std::vector<std::string> attributes;
};

void generateUserFile(const User& user) {

    FILE* check = fopen((user.name + "_private.pem").c_str(), "r");
    if (check) {
        fclose(check);
        return;
    }

    EVP_PKEY* pkey = EVP_RSA_gen(2048);

    if (!pkey) {
        std::cout << "key failed for " << user.name << "\n";
        return;
    }

    FILE* pubFile = fopen((user.name + "_public.pem").c_str(), "w");
    PEM_write_PUBKEY(pubFile, pkey);
    fclose(pubFile);

    FILE* privFile = fopen((user.name + "_private.pem").c_str(), "w");
    PEM_write_PrivateKey(privFile, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(privFile);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    char* data;
    long len = BIO_get_mem_data(bio, &data);

    std::ofstream file(user.name + "_ca.txt");

    file << "public key:\n";
    file.write(data, len);

    file << "\nprivate key:\n";
    file << "stored in pem file\n";

    file << "\nattributes: ";

    for (size_t i = 0; i < user.attributes.size(); i++) {
        file << user.attributes[i];
        if (i != user.attributes.size() - 1)
            file << ", ";
    }

    file.close();

    BIO_free(bio);
    EVP_PKEY_free(pkey);
}

int main() {

    std::vector<User> users = {
        {"Alice", {"Att1", "Att2", "Att5"}},
        {"Bob", {"Att1", "Att3", "Att4"}},
        {"Charlie", {"Att4", "Att5"}},
        {"Daisy", {"Att1", "Att2"}},
        {"Emmy", {"Att1", "Att2", "Att3", "Att4", "Att5"}}
    };

    for (auto& u : users) {
        generateUserFile(u);
    }

    std::cout << "users generated\n";
    return 0;
}