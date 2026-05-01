#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <vector>

// Load AES key
std::vector<unsigned char> loadKey() {
    std::ifstream file("secret.key", std::ios::binary);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

// Load plaintext
std::vector<unsigned char> loadFile(const std::string& name) {
    std::ifstream file(name, std::ios::binary);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

// AES encrypt
std::vector<unsigned char> encryptAES(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& data,
    unsigned char* iv) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    std::vector<unsigned char> out(data.size() + 16);
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb128(), NULL, key.data(), iv);

    EVP_EncryptUpdate(ctx, out.data(), &len, data.data(), data.size());

    int total = len;

    EVP_EncryptFinal_ex(ctx, out.data() + len, &len);
    total += len;

    EVP_CIPHER_CTX_free(ctx);

    out.resize(total);
    return out;
}

int main() {

    // Load AES key
    std::vector<unsigned char> key = loadKey();

    // Load plaintext
    std::vector<unsigned char> plaintext = loadFile("plaintext.txt");

    if (plaintext.empty()) {
        std::cout << "plaintext.txt missing or empty\n";
        return 1;
    }

    // Generate IV
    unsigned char iv[16];
    RAND_bytes(iv, 16);

    // Encrypt
    std::vector<unsigned char> ciphertext = encryptAES(key, plaintext, iv);

    // Write output file
    std::ofstream out("plaintext.txt.enc", std::ios::binary);

    // ONLY BINARY OUTPUT (NO TEXT)
out.write((char*)iv, 16);
out.write((char*)ciphertext.data(), ciphertext.size());

    out.close();

    std::cout << "Encryption complete.\n";

    return 0;
}