#include <openssl/evp.h>
#include <openssl/pem.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#include <cstring>

std::map<std::string, std::vector<std::string>> userAttr = {
    {"Alice",   {"Att1","Att2","Att5"}},
    {"Bob",     {"Att1","Att3","Att4"}},
    {"Charlie", {"Att4","Att5"}},
    {"Daisy",   {"Att1","Att2"}},
    {"Emmy",    {"Att1","Att2","Att3","Att4","Att5"}}
};

bool checkPolicy(const std::vector<std::string>& attrs) {

    auto has = [&](const std::string& a) {
        return std::find(attrs.begin(), attrs.end(), a) != attrs.end();
    };

    return (has("Att1") && has("Att2")) ||
           (has("Att3") && has("Att4") && has("Att5"));
}

std::vector<unsigned char> loadFile(const std::string& f) {

    std::ifstream file(f, std::ios::binary);

    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

EVP_PKEY* loadPrivateKey(const std::string& file) {

    FILE* fp = fopen(file.c_str(), "r");
    if (!fp) return nullptr;

    EVP_PKEY* key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    return key;
}

std::vector<unsigned char> rsaDecrypt(EVP_PKEY* pkey,
                                      const std::vector<unsigned char>& enc) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return {};

    if (EVP_PKEY_decrypt_init(ctx) <= 0) return {};
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    size_t len = 0;

    if (EVP_PKEY_decrypt(ctx, NULL, &len, enc.data(), enc.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> out(len);

    if (EVP_PKEY_decrypt(ctx, out.data(), &len, enc.data(), enc.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    out.resize(len);
    EVP_PKEY_CTX_free(ctx);

    return out;
}

std::string aesDecrypt(const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& data) {

    if (data.size() <= 16) return "";

    unsigned char iv[16];
    memcpy(iv, data.data(), 16);

    std::vector<unsigned char> cipher(data.begin() + 16, data.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<unsigned char> out(cipher.size());

    int len = 0;
    int total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key.data(), iv);

    EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), cipher.size());
    total += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result;
    result.assign((char*)out.data(), total);

    return result;
}

int main() {

    std::string user;
    std::cout << "Input user: ";
    std::cin >> user;

    auto attrs = userAttr[user];

    if (!checkPolicy(attrs)) {
        std::cout << "Output: None\n";
        return 0;
    }

    EVP_PKEY* priv = loadPrivateKey(user + "_private.pem");

    if (!priv) {
        std::cout << "missing private key\n";
        return 1;
    }

    auto encKey = loadFile(user + "_sharekey.bin");
    auto K = rsaDecrypt(priv, encKey);

    if (K.size() != 32) {
        std::cout << "invalid AES key\n";
        return 1;
    }

    auto encFile = loadFile("plaintext.txt.enc");
    auto plaintext = aesDecrypt(K, encFile);

    std::cout << "output:\n" << plaintext << "\n";

    EVP_PKEY_free(priv);

    return 0;
}