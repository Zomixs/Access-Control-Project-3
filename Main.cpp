/*
 Project 3 - ABAC Encryption Thing

 So this program is kinda like a secure file system.
 It uses RSA + AES and checks if users are allowed to open a file.

 Policy:
 (Att1 AND Att2) OR (Att3 AND Att4 AND Att5)

 not everyone can access it, depends on attributes
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// base64 encode (just so it prints readable)
std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, data, (int)len);
    BIO_flush(b64);

    BUF_MEM* buf;
    BIO_get_mem_ptr(b64, &buf);

    std::string result(buf->data, buf->length);
    BIO_free_all(b64);

    return result;
}

// base64 decode (reverse of above)
std::vector<unsigned char> base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded.data(), (int)encoded.size());

    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> buf(encoded.size());
    int len = BIO_read(mem, buf.data(), (int)buf.size());

    BIO_free_all(mem);

    buf.resize(len > 0 ? len : 0);
    return buf;
}

// check policy (this is the main rule part)
bool evaluate_policy(const std::set<std::string>& attrs) {
    bool p1 = attrs.count("Att1") && attrs.count("Att2");
    bool p2 = attrs.count("Att3") && attrs.count("Att4") && attrs.count("Att5");

    return p1 || p2; // if either is true then access
}

// simple file read
std::string read_file(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// user struct (basic)
struct UserInfo {
    std::string name;
    std::set<std::string> attributes;
};

int main() {

    std::cout << "==== ABAC Project ====\n\n";

    // define users (hardcoded for now)
    std::vector<UserInfo> users = {
        {"Alice",   {"Att1", "Att2", "Att5"}},
        {"Bob",     {"Att1", "Att3", "Att4"}},
        {"Charlie", {"Att4", "Att5"}},
        {"Daisy",   {"Att1", "Att2"}},
        {"Emmy",    {"Att1", "Att2", "Att3", "Att4", "Att5"}}
    };

    // generate AES key (main key for file)
    unsigned char aes_key[32];
    RAND_bytes(aes_key, sizeof(aes_key)); // hope this works lol

    std::cout << "Generated secret key (AES)\n\n";

    // read file (if empty we just use default text)
    std::string content = read_file("plaintext.txt");
    if (content.empty()) {
        content = "default secret file content\n";
    }

    std::cout << "Encrypting file...\n"; // not actually showing full encryption here

    // loop users and test access
    for (auto& user : users) {

        std::cout << "\nUser: " << user.name << "\n";

        // step 1 check attributes
        if (!evaluate_policy(user.attributes)) {
            std::cout << "Access denied (attributes dont match policy)\n";
            continue;
        }

        std::cout << "Access granted\n";

        // step 2 pretend to decrypt key
        std::string fakeKey = base64_encode(aes_key, sizeof(aes_key));
        std::cout << "Decrypted Key: " << fakeKey.substr(0, 20) << "... \n";

        // step 3 pretend decrypt file
        std::cout << "File content:\n";
        std::cout << content << "\n";

        std::cout << "---- end ----\n";
    }

    std::cout << "\nDone.\n";

    return 0;
}
