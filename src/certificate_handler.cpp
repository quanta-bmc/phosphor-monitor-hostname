#include <certificate_handler.hpp>

namespace certificate
{
    void CertHandler::generateSslCertificate(const std::string &hostname)
    {
        std::cerr << "Generating x509 Certificate: " << hostname << std::endl;
        initOpenssl();

        EVP_PKEY* pPrivKey = createEcKey();
        if (pPrivKey != nullptr)
        {
            // Use this code to directly generate a certificate
            X509* x509 = X509_new();
            if (x509 != nullptr)
            {
                X509_set_version(x509, 2);
                // get a random number from the RNG for the certificate serial
                // number If this is not random, regenerating certs throws broswer
                // errors
                std::random_device rd;
                int serial = static_cast<int>(rd());
                while (serial < 0)
                {
                    serial = static_cast<int>(rd());
                }
                ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

                // not before this moment
                X509_gmtime_adj(X509_get_notBefore(x509), 0);
                // Cert is valid for 10 years
                X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60L * 24L * 365L * 10L);

                // set the public key to the key we just generated
                X509_set_pubkey(x509, pPrivKey);

                // get the subject name
                X509_NAME* name;
                name = X509_get_subject_name(x509);

                X509_NAME_add_entry_by_txt(
                    name, "C", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
                X509_NAME_add_entry_by_txt(
                    name, "ST", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("California"), -1, -1, 0);
                X509_NAME_add_entry_by_txt(
                    name, "L", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("Mountain View"), -1, -1, 0);
                X509_NAME_add_entry_by_txt(
                    name, "O", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("Google"), -1, -1, 0);
                X509_NAME_add_entry_by_txt(
                    name, "OU", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("Platforms"), -1, -1, 0);
                X509_NAME_add_entry_by_txt(
                    name, "CN", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>(hostname.c_str()), -1, -1, 0);
                // set the CSR options
                X509_set_issuer_name(x509, name);

                add_ext(x509, NID_basic_constraints, "critical,CA:TRUE");
                add_ext(x509, NID_subject_key_identifier, "hash");
                add_ext(x509, NID_authority_key_identifier, "keyid");
                add_ext(x509, NID_key_usage, "digitalSignature, keyEncipherment, keyAgreement, keyCertSign, cRLSign");
                add_ext(x509, NID_ext_key_usage, "serverAuth");
                add_ext(x509, NID_netscape_cert_type, "server, sslCA, emailCA, objCA");

                // Sign the certificate with our private key
                X509_sign(x509, pPrivKey, EVP_sha256());

                FILE* pFile = fopen(tmpCertPath, "wt");
                if (pFile != nullptr)
                {
                    PEM_write_PrivateKey(pFile, pPrivKey, nullptr, nullptr, 0, nullptr, nullptr);

                    PEM_write_X509(pFile, x509);
                    fclose(pFile);
                    pFile = nullptr;
                }
                X509_free(x509);
            }

            EVP_PKEY_free(pPrivKey);
            pPrivKey = nullptr;
        }
    }

    EVP_PKEY* CertHandler::createEcKey()
    {
        EVP_PKEY* pKey = nullptr;
        int eccgrp = 0;
        eccgrp = OBJ_txt2nid("secp384r1");

        EC_KEY* myecc = EC_KEY_new_by_curve_name(eccgrp);
        if(myecc != nullptr)
        {
            EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
            EC_KEY_generate_key(myecc);
            pKey = EVP_PKEY_new();
            if(pKey != nullptr)
            {
                if(EVP_PKEY_assign_EC_KEY(pKey, myecc) <= 0)
                {
                    std::cerr << "EVP_PKEY_assign_EC_KEY failed." << std::endl;
                    EVP_PKEY_free(pKey);
                    pKey = nullptr;
                    return pKey;
                }
                /* pKey owns myecc from now */
                if(EC_KEY_check_key(myecc) <= 0)
                {
                    std::cerr << "EC_check_key failed." << std::endl;
                    EVP_PKEY_free(pKey);
                    pKey = nullptr;
                    return pKey;
                }
            }
            else
            {
                EC_KEY_free(myecc);
            }
        }
        return pKey;
    }

    void CertHandler::initOpenssl()
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
#endif
    }

    int CertHandler::add_ext(X509 *cert, int nid, char *value)
    {
        X509_EXTENSION *ex = NULL;
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
        if(!ex)
        {
            std::cerr << "Error: In X509V3_EXT_conf_nidn: " << value << std::endl;
            return -1;
        }

        X509_add_ext(cert,ex,-1);
        X509_EXTENSION_free(ex);

        return 0;
    }
}