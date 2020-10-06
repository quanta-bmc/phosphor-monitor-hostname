#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <boost/asio/ssl/context.hpp>
#include <random>
#include <iostream>
#include <stdio.h>

namespace certificate
{
    static constexpr const char *tmpCertPath = "/tmp/hostname_cert.tmp";
    class CertHandler
    {
        public:
            CertHandler() = default;
            ~CertHandler() = default;
            CertHandler(const CertHandler &) = delete;
            CertHandler &operator=(const CertHandler &) = delete;
            CertHandler(CertHandler &&) = delete;
            CertHandler &operator=(CertHandler &&) = delete;

            void generateSslCertificate(const std::string &hostname);
        private:
            void initOpenssl();
            EVP_PKEY* createEcKey();
            int add_ext(X509 *cert, int nid, char *value);
    };
}