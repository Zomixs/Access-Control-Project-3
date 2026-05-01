#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <vector>

std::vector<unsigned char> loadKey() {
    std::ifstream file("secret.key", std::ios::binary);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

std::vector<unsigned char> genKey() {
    std::vector<unsigned char> key(32);
    RAND_bytes(key.data(), 32);
    return key;
}

void saveKey(const std::vector<unsigned char>& key) {
    std::ofstream file("secret.key", std::ios::binary);
    file.write((char*)key.data(), key.size());
}

EVP_PKEY* loadPub(const std::string& fileName) {
    FILE* fp = fopen(fileName.c_str(), "r");
    if (!fp) return nullptr;

    EVP_PKEY* key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

std::vector<unsigned char> rsaEnc(EVP_PKEY* key,
                                   const std::vector<unsigned char>& data) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) return {};

    if (EVP_PKEY_encrypt_init(ctx) <= 0) return {};
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t len = 0;
    EVP_PKEY_encrypt(ctx, NULL, &len, data.data(), data.size());

    std::vector<unsigned char> out(len);

    if (EVP_PKEY_encrypt(ctx, out.data(), &len, data.data(), data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    out.resize(len);
    EVP_PKEY_CTX_free(ctx);

    return out;
}

void saveBin(const std::string& fileName,
             const std::vector<unsigned char>& data) {

    std::ofstream file(fileName, std::ios::binary);
    file.write((char*)data.data(), data.size());
}

int main() {

    std::vector<unsigned char> K;

    std::ifstream test("secret.key", std::ios::binary);

    if (!test.good()) {
        K = genKey();
        saveKey(K);
    } else {
        K = loadKey();
    }

    struct User {
        std::string name;
        std::string pub;
    };

    std::vector<User> users = {
        {"Alice", "Alice_public.pem"},
        {"Bob", "Bob_public.pem"},
        {"Charlie", "Charlie_public.pem"},
        {"Daisy", "Daisy_public.pem"},
        {"Emmy", "Emmy_public.pem"}
    };

    for (auto& u : users) {

        EVP_PKEY* pkey = loadPub(u.pub);

        if (!pkey) {
            std::cout << "missing key: " << u.pub << "\n";
            continue;
        }

        auto enc = rsaEnc(pkey, K);

        if (enc.empty()) {
            std::cout << "rsa failed for " << u.name << "\n";
            EVP_PKEY_free(pkey);
            continue;
        }

        saveBin(u.name + "_sharekey.bin", enc);

        EVP_PKEY_free(pkey);
    }

    std::cout << "done\n";
    return 0;
}