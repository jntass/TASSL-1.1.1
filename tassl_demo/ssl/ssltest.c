/*
 * ++
 * FACILITY:
 *
 *      Simplest TLS Server
 *
 * ABSTRACT:
 *
 *   This is an example of a SSL server with minimum functionality.
 *   The socket APIs are used to handle TCP/IP operations.
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/engine.h"
#include "openssl/sm2.h"
#include "openssl/cmac.h"
#include "openssl/hmac.h"

#define DEFAULT_PORT 8020
#define MAX_BUF_LEN (32*1024)
#define LF "\n"

#define RETURN_NULL(x) if ((x)==NULL) { ERR_print_errors_fp(stderr); goto error; }
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); goto error; }
#define RETURN_SSL(err) if ((err)!=1) { ERR_print_errors_fp(stderr); goto error; }

#define USAGE "Usage : \n\
\t -h/--help \t\t Display this summary\n\
\t -p port \t\t listen port\n\
\t -e engine \t\t engine name\n\
\t -sc cert \t\t sign cert\n\
\t -sk key \t\t sign key\n\
\t -ec cert \t\t enc cert\n\
\t -ek key \t\t enc key\n\
\t -ca cert \t\t CA cert\n\
\t -ca_path path \t\t CA path\n\
\t --verify \t\t verify peer\n\
\t -textlen len \t\t text length\n\
\t -bits len \t\t bits length\n\
\t -alg alg \t\t algorithms\n\
\t --speed \t\t speed test\n\
\t --keypair \t\t keypair test\n\
\t --cmac \t\t cmac test\n\
\t --hmac \t\t hmac test\n\
\t --rsa \t\t\t rsa test\n\
\t --sm2 \t\t\t sm2 test\n\
\t --sm3 \t\t\t sm3 test\n\
\t --sm4 \t\t\t sm4 test\n\
\t --enc \t\t\t encrypt test\n\
\t --dec \t\t\t decrypt test\n\
\t --sign \t\t sign test\n\
\t --ver \t\t\t verify test\n\
\t --ecb \t\t\t ecb test\n\
\t --cbc \t\t\t cbc test\n\
\t --client \t\t ssl client test\n\
\t --server \t\t ssl server test\n\
\t --gmssl \t\t use gmssl\n\
\t --data \t\t ssl data test\n\
\t --rand \t\t rand test\n\
\t --version \t\t show version\n\
\t --state \t\t show state\n\
\t --init \t\t init\n\
\t -threads num\t\t multithread\n\
\t -s host:port\t\t server address\n\
\t -total_times times\t test times\n"

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("对端证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    } else
        printf("无对端证书信息！\n");
}

static int cmac = 0, hmac = 0, rsa = 0, sm2 = 0, sm3 = 0, sm4 = 0, rand1 = 0;
static size_t text_len = 0;
static const char *alg = NULL;
static int total_times = 1, bits = 1024;
static int speed = 0, keypair = 0, enc = 0, dec = 0, sign = 0, verify = 0;
static int version = 0, state = 0, init = 0, inited = 0;
static int ecb = 0, cbc = 0;
static int client = 0, server = 0, gmssl = 0, data = 0;
static int verify_peer = 0; /* To verify peer certificate, set ON */
static char *sign_cert = NULL, *sign_key = NULL;
static char *enc_cert = NULL, *enc_key = NULL;
static char *ca_cert = NULL, *ca_path = NULL;
static char *host = NULL;
static char *engine_name = NULL;
static short int s_port = DEFAULT_PORT;

void *thread_routine(void *arg)
{
	int err, i, opt = 1;
	int listen_sock = -1;
	int sock = -1;
    int len;
	struct sockaddr_in sa_serv;
	char buf[MAX_BUF_LEN];
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
    BIGNUM *pub_exp = NULL;
    BIO *bio_out = NULL, *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char *text = NULL, *der = NULL, *bin = NULL, *decipher = NULL;;
    const unsigned char *p = NULL;
    size_t derlen = 0, binlen = 0, decipherlen = 0;
    unsigned char pub_key_buf[65];
    unsigned char pri_key_buf[32];
    SM2_Ciphertext *sm2_ctext = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    struct timeval begin, end;
    int counts = 0, send_counts = 0, outlen = 0;
    int connect_times = 1, send_times = 1;
    long  retval = -1;
    
    bio_out = BIO_new_fp(stdout, 0);
    RETURN_NULL(bio_out);

    if( !keypair && (cmac || hmac || sm2 || sm3 || sm4 || rand1) )
    {
        text = OPENSSL_malloc(text_len);
        RETURN_NULL(text);

        if( !rand1 )
        {
            err = RAND_bytes(text, text_len);
            RETURN_SSL(err);
        }
    }

    if( rand1 )
    {
        gettimeofday(&begin, NULL);
        
        for( counts = 0; counts < total_times; counts++ )
        {
            unsigned char rand_path[64] = {0};
            FILE *fw = NULL;

            sprintf(rand_path, "%s/%s_%03d", "./random", "rand", counts);

            err = RAND_bytes(text, text_len);
            RETURN_SSL(err);

            fw = fopen(rand_path, "w");
            if( NULL == fw )
            {
                fprintf(stderr, "fopen error, %s", strerror(errno));
                goto error;
            }

            if( text_len != fwrite(text, 1, text_len, fw) )
            {
                fprintf(stderr, "fwrite error, %s", strerror(errno));
                goto error;
            }
            fclose(fw);
            
            if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
            {
                gettimeofday(&end, NULL);
                BIO_printf(bio_out, "thread %ld rand speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                            pthread_self(),
                            (counts+1), 
                            (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                            (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                            ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
            }
        }
    }
    else if( sm2 || rsa )
    {
        if( !keypair )
        {
            pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
            RETURN_NULL(pkey_ctx);

            err = EVP_PKEY_keygen_init(pkey_ctx);
            RETURN_SSL(err);

            err = EVP_PKEY_keygen(pkey_ctx, &pkey);
            RETURN_SSL(err);

            EVP_PKEY_CTX_free(pkey_ctx); pkey_ctx = NULL;
        }

        if( keypair )
        {
            pkey_ctx = EVP_PKEY_CTX_new_id(sm2 ? EVP_PKEY_SM2 : EVP_PKEY_RSA, NULL);
            RETURN_NULL(pkey_ctx);

            err = EVP_PKEY_keygen_init(pkey_ctx);
            RETURN_SSL(err);

            if( rsa )
            {
                pub_exp = BN_bin2bn("\x01\x00\x01", 3, NULL);
                RETURN_NULL(pub_exp);

                err = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, bits);
                RETURN_SSL(err);

                err = EVP_PKEY_CTX_set_rsa_keygen_pubexp(pkey_ctx, pub_exp);
                RETURN_SSL(err);

                pub_exp = NULL;
            }

            /* nothing meaning, just avoid coredump */
            if( rsa )
              text_len = bits/8;
            else
              text_len = 32;

            gettimeofday(&begin, NULL);
            
            for( counts = 0; counts < total_times; counts++ )
            {
                if( pkey )
                {
                    EVP_PKEY_free(pkey); pkey = NULL;
                }
                
                err = EVP_PKEY_keygen(pkey_ctx, &pkey);
                RETURN_SSL(err);

                if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
                {
                    gettimeofday(&end, NULL);
                    BIO_printf(bio_out, "thread %ld %s keypair speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                pthread_self(),
                                sm2 ? "sm2" : "rsa",
                                (counts+1), 
                                (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                }
            }

            EVP_PKEY_CTX_free(pkey_ctx); pkey_ctx = NULL;
        
            if( !speed )
            {
                if( 65 != EC_POINT_point2oct(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)), 
                                EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)), 
                                POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL) )
                  goto error;

                if( 32 != BN_bn2binpad(EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey)), pri_key_buf, 32) )
                  goto error;

                BIO_printf(bio_out, "公钥= ");
                for( i = 0; i < 64; i++ )
                {
                    BIO_printf(bio_out, "%02X", pub_key_buf[i+1] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "私钥= ");
                for( i = 0; i < 32; i++ )
                {
                    BIO_printf(bio_out, "%02X", pri_key_buf[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
            }
        }
        else if( enc || dec )
        {
            derlen = text_len + 64 + 32 + 256;

            der = OPENSSL_malloc(derlen);
            RETURN_NULL(der);

            binlen = text_len + 64 + 32;

            bin = OPENSSL_malloc(binlen);
            RETURN_NULL(bin);

            decipher = OPENSSL_malloc(text_len);
            RETURN_NULL(decipher);
 
            pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
            RETURN_NULL(pkey_ctx);
                
            if( !enc )
            {
                err = EVP_PKEY_encrypt_init(pkey_ctx);
                RETURN_SSL(err);

                err = EVP_PKEY_encrypt(pkey_ctx, der, &derlen, text, text_len);
                RETURN_SSL(err);
            }

            if( enc )
              err = EVP_PKEY_encrypt_init(pkey_ctx);
            else
              err = EVP_PKEY_decrypt_init(pkey_ctx);
            RETURN_SSL(err);
            
            gettimeofday(&begin, NULL);

            for( counts = 0; counts < total_times; counts++ )
            {
                if( enc )
                {
                    /* buffer length */
                    derlen = text_len + 64 + 32 + 256;

                    err = EVP_PKEY_encrypt(pkey_ctx, der, &derlen, text, text_len);
                    RETURN_SSL(err);
                }
                else
                {
                    /* buffer length */
                    decipherlen = text_len;

                    err = EVP_PKEY_decrypt(pkey_ctx, decipher, &decipherlen, der, derlen);
                    RETURN_SSL(err);

                    if( decipherlen != text_len
                                || 0 != memcmp(decipher, text, decipherlen) )
                      goto error;
                }

                if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
                {
                    gettimeofday(&end, NULL);
                    BIO_printf(bio_out, "thread %ld sm2 %s speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                pthread_self(),
                                enc ? "enc" : "dec",
                                (counts+1), 
                                (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                }
            }

            EVP_PKEY_CTX_free(pkey_ctx); pkey_ctx = NULL;

            if( !speed )
            {
                if( 65 != EC_POINT_point2oct(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)), 
                                EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)), 
                                POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL) )
                  goto error;

                if( 32 != BN_bn2binpad(EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey)), pri_key_buf, 32) )
                  goto error;

                p = der;
                outlen = 0;

                sm2_ctext = (SM2_Ciphertext *)d2i_SM2_Ciphertext(NULL, &p, derlen);
                RETURN_NULL(sm2_ctext);

                if( 32 != BN_bn2binpad(SM2_Ciphertext_get0_C1x(sm2_ctext), bin + outlen, 32) )
                  goto error;
                outlen += 32;

                if( 32 != BN_bn2binpad(SM2_Ciphertext_get0_C1y(sm2_ctext), bin + outlen, 32) )
                  goto error;
                outlen += 32;

                memcpy(bin + outlen, ASN1_STRING_get0_data(SM2_Ciphertext_get0_C3(sm2_ctext)), 
                            ASN1_STRING_length(SM2_Ciphertext_get0_C3(sm2_ctext)));
                outlen += ASN1_STRING_length(SM2_Ciphertext_get0_C3(sm2_ctext));

                memcpy(bin + outlen, ASN1_STRING_get0_data(SM2_Ciphertext_get0_C2(sm2_ctext)), 
                            ASN1_STRING_length(SM2_Ciphertext_get0_C2(sm2_ctext)));
                outlen += ASN1_STRING_length(SM2_Ciphertext_get0_C2(sm2_ctext));

                BIO_printf(bio_out, "公钥= ");
                for( i = 0; i < 64; i++ )
                {
                    BIO_printf(bio_out, "%02X", pub_key_buf[i+1] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "私钥= ");
                for( i = 0; i < 32; i++ )
                {
                    BIO_printf(bio_out, "%02X", pri_key_buf[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                BIO_printf(bio_out, "明文长度= ");
                BIO_printf(bio_out, "%08X", (unsigned int)text_len);
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "密文= ");
                for( i = 0; i < outlen; i++ )
                {
                    BIO_printf(bio_out, "%02X", bin[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                BIO_printf(bio_out, "明文= ");
                for( i = 0; (size_t)i < text_len; i++ )
                {
                    BIO_printf(bio_out, "%02X", text[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "\n\n\n\n");
            }
        }
        else if( sign || verify )
        {
            unsigned char sig[128] = {0};
            size_t siglen = sizeof(sig);

            binlen = 64;
            bin = OPENSSL_malloc(binlen);
            RETURN_NULL(bin);

            pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
            RETURN_NULL(pkey_ctx);

            if( !sign )
            {
                err = EVP_PKEY_sign_init(pkey_ctx);
                RETURN_SSL(err);

                err = EVP_PKEY_sign(pkey_ctx, sig, &siglen, text, text_len);
                RETURN_SSL(err);
            }

            if( sign )
              err = EVP_PKEY_sign_init(pkey_ctx);
            else
              err = EVP_PKEY_verify_init(pkey_ctx);
            RETURN_SSL(err);

            gettimeofday(&begin, NULL);

            for( counts = 0; counts < total_times; counts++ )
            {
                if( sign )
                {
                    /* buffer length */
                    siglen = sizeof(sig);

                    err = EVP_PKEY_sign(pkey_ctx, sig, &siglen, text, text_len);
                    RETURN_SSL(err);
                }
                else
                {
                    err = EVP_PKEY_verify(pkey_ctx, sig, siglen, text, text_len);
                    RETURN_SSL(err);
                }

                if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
                {
                    gettimeofday(&end, NULL);
                    BIO_printf(bio_out, "thread %ld sm2 %s speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                pthread_self(),
                                sign ? "sign" : "verify",
                                (counts+1), 
                                (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                }
            }

            EVP_PKEY_CTX_free(pkey_ctx); pkey_ctx = NULL;

            if( !speed )
            {
                if( 65 != EC_POINT_point2oct(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)), 
                                EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)), 
                                POINT_CONVERSION_UNCOMPRESSED, pub_key_buf, sizeof(pub_key_buf), NULL) )
                  goto error;
                
                if( 32 != BN_bn2binpad(EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey)), pri_key_buf, 32) )
                  goto error;
                
                p = sig;
                outlen = 0;

                ecdsa_sig = (ECDSA_SIG *)d2i_ECDSA_SIG(NULL, &p, siglen);
                if( 32 != BN_bn2binpad(ECDSA_SIG_get0_r(ecdsa_sig), bin + outlen, 32) )
                {
                    goto error;
                }
                outlen += 32;

                if( 32 != BN_bn2binpad(ECDSA_SIG_get0_s(ecdsa_sig), bin + outlen, 32) )
                {
                    goto error;
                }
                outlen += 32;

                BIO_printf(bio_out, "公钥= ");
                for( i = 0; i < 64; i++ )
                {
                    BIO_printf(bio_out, "%02X", pub_key_buf[i+1] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "私钥= ");
                for( i = 0; i < 32; i++ )
                {
                    BIO_printf(bio_out, "%02X", pri_key_buf[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                BIO_printf(bio_out, "签名数据e= ");
                for( i = 0; (size_t)i < text_len; i++ )
                {
                    BIO_printf(bio_out, "%02X", text[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                BIO_printf(bio_out, "签名结果= ");
                for( i = 0; i < outlen; i++ )
                {
                    BIO_printf(bio_out, "%02X", bin[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");
                
                BIO_printf(bio_out, "\n\n\n\n");
            }
        }
        else
        {
            goto error;
        }
    }
    else if( sm3 )
    {
        unsigned char md[64];
        unsigned int md_len;

        md_ctx = EVP_MD_CTX_new();
        RETURN_NULL(md_ctx);

        gettimeofday(&begin, NULL);

        for( counts = 0; counts < total_times; counts++ )
        {
            err = EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL);
            RETURN_SSL(err);
            
            err = EVP_DigestUpdate(md_ctx, text, text_len);
            RETURN_SSL(err);

            err = EVP_DigestFinal_ex(md_ctx, md, &md_len);
            RETURN_SSL(err);

            if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
            {
                gettimeofday(&end, NULL);
                BIO_printf(bio_out, "thread %ld sm3 speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                            pthread_self(),
                            (counts+1), 
                            (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                            (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                            ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
            }
        }

        EVP_MD_CTX_free(md_ctx); md_ctx = NULL;

        if( !speed )
        {
            BIO_printf(bio_out, "消息长度= ");
            BIO_printf(bio_out, "%08X", (unsigned int)text_len);
            BIO_printf(bio_out, "\n\n");

            BIO_printf(bio_out, "消息= ");
            for( i = 0; (size_t)i < text_len; i++ )
            {
                BIO_printf(bio_out, "%02X", text[i] & 0xff);
            }
            BIO_printf(bio_out, "\n\n");

            BIO_printf(bio_out, "杂凑值= ");
            for( i = 0; i < md_len; i++ )
            {
                BIO_printf(bio_out, "%02X", md[i] & 0xff);
            }
            BIO_printf(bio_out, "\n\n");
            
            BIO_printf(bio_out, "\n\n\n\n");
        }
    }
    else if( sm4 )
    {
        unsigned char key[16], iv[16];
        unsigned char *plain_data = NULL, *cipher_data = NULL;
        int plain_len, cipher_len;
        EVP_CIPHER_CTX *cipher_ctx = NULL;
        
        err = RAND_bytes(key, sizeof(key));
        RETURN_SSL(err);
        
        if( cbc )
        {
            err = RAND_bytes(iv, sizeof(iv));
            RETURN_SSL(err);
        }
        
        plain_data = malloc(text_len);
        RETURN_NULL(plain_data);

        cipher_data = malloc(text_len);
        RETURN_NULL(cipher_data);
        
        if( ecb || cbc )
        {
            cipher_ctx = EVP_CIPHER_CTX_new();
            RETURN_NULL(cipher_ctx);

            if( enc )
              err = EVP_EncryptInit_ex(cipher_ctx, ecb ? EVP_sm4_ecb() : EVP_sm4_cbc(), NULL, key, ecb ? NULL : iv);
            else
              err = EVP_DecryptInit_ex(cipher_ctx, ecb ? EVP_sm4_ecb() : EVP_sm4_cbc(), NULL, key, ecb ? NULL : iv);
            RETURN_SSL(err);

            err = EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
            RETURN_SSL(err);
        
            gettimeofday(&begin, NULL);
            
            for( counts = 0; counts < total_times; counts++ )
            {
                if( enc )
                {
                    err = EVP_EncryptUpdate(cipher_ctx, cipher_data, &cipher_len, text, text_len);
                    RETURN_SSL(err);
                }
                else
                {
                    err = EVP_DecryptUpdate(cipher_ctx, plain_data, &plain_len, text, text_len);
                    RETURN_SSL(err);
                }

                if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
                {
                    gettimeofday(&end, NULL);
                    BIO_printf(bio_out, "thread %ld sm4 %s %s speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                pthread_self(),
                                ecb ? "ecb" : "cbc",
                                enc ? "enc" : "dec",
                                (counts+1), 
                                (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                }
            }

            EVP_CIPHER_CTX_free(cipher_ctx); cipher_ctx = NULL;

            if( !speed )
            {
                BIO_printf(bio_out, "密钥= ");
                for( i = 0; (size_t)i < 16; i++ )
                {
                    BIO_printf(bio_out, "%02X", key[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                if( cbc )
                {
                    BIO_printf(bio_out, "IV= ");
                    for( i = 0; (size_t)i < 16; i++ )
                    {
                        BIO_printf(bio_out, "%02X", iv[i] & 0xff);
                    }
                    BIO_printf(bio_out, "\n\n");
                }

                if( enc )
                  BIO_printf(bio_out, "明文长度= ");
                else
                  BIO_printf(bio_out, "密文长度= ");
                BIO_printf(bio_out, "%08X", (unsigned int)text_len);
                BIO_printf(bio_out, "\n\n");

                if( enc )
                  BIO_printf(bio_out, "明文= ");
                else
                  BIO_printf(bio_out, "密文= ");
                for( i = 0; (size_t)i < text_len; i++ )
                {
                    BIO_printf(bio_out, "%02X", text[i] & 0xff);
                }
                BIO_printf(bio_out, "\n\n");

                if( enc )
                {
                    BIO_printf(bio_out, "密文= ");
                    for( i = 0; i < cipher_len; i++ )
                    {
                        BIO_printf(bio_out, "%02X", cipher_data[i] & 0xff);
                    }
                    BIO_printf(bio_out, "\n\n");
                }
                else
                {
                    BIO_printf(bio_out, "明文= ");
                    for( i = 0; i < plain_len; i++ )
                    {
                        BIO_printf(bio_out, "%02X", plain_data[i] & 0xff);
                    }
                    BIO_printf(bio_out, "\n\n");
                }
                    
                BIO_printf(bio_out, "\n\n\n\n");
            }
        }
        else
        {
            goto error;
        }
        
        if( plain_data ) OPENSSL_free(plain_data);
        if( cipher_data ) OPENSSL_free(cipher_data);
        if( cipher_ctx ) EVP_CIPHER_CTX_free(cipher_ctx);
    }
    else if( cmac || hmac )
    {
        unsigned char mac_key[128] = {0};
        int mac_keylen = 0;
        const void *mac_alg = NULL;
        unsigned char mac[256] = {0};
        size_t maclen;
        void *mac_ctx = NULL;

        void *(*ctx_new)(void) = NULL;
        void (*ctx_free)(void *) = NULL;
        int (*ctx_init)(void *, const void *, size_t, const void *, void *) = NULL;
        int (*ctx_update)(void *, const void *, size_t) = NULL;
        int (*ctx_final)(void *ctx, unsigned char *, size_t *) = NULL;

        if( cmac )
        {
            ctx_new = (void *(*)(void))CMAC_CTX_new;
            ctx_free = (void (*)(void *))CMAC_CTX_free;
            ctx_init = (int (*)(void *, const void *, size_t, const void *, void *))CMAC_Init;
            ctx_update = (int (*)(void *, const void *, size_t))CMAC_Update;
            ctx_final = (int (*)(void *ctx, unsigned char *, size_t *))CMAC_Final;

            mac_alg = EVP_get_cipherbyname(alg);
            RETURN_NULL(mac_alg);
            
            mac_keylen = EVP_CIPHER_key_length(mac_alg);
        }
        else
        {
            ctx_new = (void *(*)(void))HMAC_CTX_new;
            ctx_free = (void (*)(void *))HMAC_CTX_free;
            ctx_init = (int (*)(void *, const void *, size_t, const void *, void *))HMAC_Init_ex;
            ctx_update = (int (*)(void *, const void *, size_t))HMAC_Update;
            ctx_final = (int (*)(void *ctx, unsigned char *, size_t *))HMAC_Final;

            mac_alg = EVP_get_digestbyname(alg);
            RETURN_NULL(mac_alg);
            
            mac_keylen = EVP_MD_block_size(mac_alg);
        }

        err = RAND_bytes(mac_key, mac_keylen);
        RETURN_SSL(err);

        mac_ctx = ctx_new();
        RETURN_NULL(mac_ctx);

        err = ctx_init(mac_ctx, mac_key, mac_keylen, mac_alg, NULL);
        RETURN_SSL(err);

        gettimeofday(&begin, NULL);

        for( counts = 0; counts < total_times; counts++ )
        {
            maclen = sizeof(mac);

            err = ctx_init(mac_ctx, NULL, 0, NULL, NULL);
            RETURN_SSL(err);

            err = ctx_update(mac_ctx, text, text_len);
            RETURN_SSL(err);

            err = ctx_final(mac_ctx, mac, &maclen);
            RETURN_SSL(err);

            if( 10 <= total_times && 0 == (counts+1)%(total_times/10) )
            {
                gettimeofday(&end, NULL);
                BIO_printf(bio_out, "thread %ld %s %s speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                            pthread_self(),
                            cmac ? "cmac" : "hmac",
                            alg,
                            (counts+1), 
                            (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                            (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                            ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
            }
        }
        ctx_free(mac_ctx);
    }
    else if( client || server )
    {
        /* Create a SSL_CTX structure */
        if( client )
        {
            if( gmssl )
            {
                /* use GMTLSv1.1 */
                ctx = SSL_CTX_new(CNTLS_client_method());
                RETURN_NULL(ctx);
            }
            else
            {
                /* we use TLSv1.2 */
                ctx = SSL_CTX_new(TLS_client_method());
                RETURN_NULL(ctx);
                err = SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
                RETURN_SSL(err);
            }
        }
        else
        {
            /* Create a SSL_CTX structure */
            ctx = SSL_CTX_new(TLS_server_method());
            RETURN_NULL(ctx);
        }

        /* Load sign cert and sign key */
        if( NULL != sign_cert && NULL != sign_key )
        {
            /* Load the sign certificate into the SSL_CTX structure */
            err = SSL_CTX_use_certificate_file(ctx, sign_cert, SSL_FILETYPE_PEM);
            RETURN_SSL(err);

            {
                /* Load common private key file*/
                BIO *in = NULL;

                in = BIO_new(BIO_s_file());
                RETURN_NULL(in);

                err = BIO_read_filename(in, sign_key);
                RETURN_SSL(err);

                pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
                RETURN_NULL(pkey);

                BIO_free(in);
            }

            /* Use the private-key corresponding to the sign certificate */
            err = SSL_CTX_use_PrivateKey(ctx, pkey);
            RETURN_SSL(err);

            /* Check if the certificate and private-key matches */
            err = SSL_CTX_check_private_key(ctx);
            RETURN_SSL(err);

            EVP_PKEY_free(pkey); pkey = NULL;
        }

        /* Load enc cert and enc key */
        if( NULL != enc_cert && NULL != enc_key )
        {
            /* Load the encrypt certificate into the SSL_CTX structure */
            err = SSL_CTX_use_certificate_file(ctx, enc_cert, SSL_FILETYPE_PEM);
            RETURN_SSL(err);

            {
                /* Load common private key file*/
                BIO *in = NULL;

                in = BIO_new(BIO_s_file());
                RETURN_NULL(in);

                err = BIO_read_filename(in, enc_key);
                RETURN_SSL(err);

                pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
                RETURN_NULL(pkey);

                BIO_free(in);
            }

            /* Use the private-key corresponding to the encrypt certificate */
            err = SSL_CTX_use_PrivateKey(ctx, pkey);
            RETURN_SSL(err);

            /* Check if the encrypt certificate and private-key matches */
            err = SSL_CTX_check_private_key(ctx);
            RETURN_SSL(err);

            EVP_PKEY_free(pkey); pkey = NULL;
        }

        if ( NULL != ca_cert || NULL != ca_path )
        {
            /* Load the CA certificate into the SSL_CTX structure */
            err = SSL_CTX_load_verify_locations(ctx, ca_cert, ca_path);
            RETURN_SSL(err);
        }

        if ( verify_peer )
        {
            /* Set to verify peer certificate */
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

            /* Set the verification depth to 1 */
            SSL_CTX_set_verify_depth(ctx, 1);
        }

        if( server )
        {
            /* ----------------------------------------------- */
            memset(&sa_serv, '\0', sizeof(sa_serv));
            sa_serv.sin_family      = AF_INET;
            sa_serv.sin_addr.s_addr = INADDR_ANY;
            sa_serv.sin_port        = htons(s_port);          /* Server Port number */

            /* TLS use TCP */
            listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            RETURN_ERR(listen_sock, "socket");

            /* reuse port */
            setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, ( void *)&opt, sizeof(opt));

            /* bind server address */
            err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
            RETURN_ERR(err, "bind");

            /* Wait for an incoming TCP connection. */
            err = listen(listen_sock, 5);
            RETURN_ERR(err, "listen");

            //close(listen_sock);
        }

        if( data )
          send_times = total_times;
        else
          connect_times = total_times;

        gettimeofday(&begin, NULL);
        
        for( counts = 0; counts < connect_times; counts++ )
        {
            if( client )
            {
                err = SSL_CTX_set_cipher_list(ctx, "ECC-SM4-SM3");
                RETURN_SSL(err);

                /* TLS use TCP, Connect to address:port */
                bio = BIO_new_connect(host);
                RETURN_NULL(bio);

                err = BIO_do_connect(bio);
                RETURN_SSL(err);
            }
            else
            {
                /* Socket for a TCP/IP connection is created */
                sock = accept(listen_sock, NULL, NULL);
                RETURN_ERR(sock, "accept");
            }

            //SSL_CTX_set_psk_use_session_callback(ctx, psk_cb);

            SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);

            ssl = SSL_new(ctx);
            RETURN_NULL(ssl);

            if( client )
            {
                SSL_set_bio(ssl, bio, bio);

                err = SSL_connect(ssl);
                RETURN_SSL(err);
            }
            else
            {
                /* Assign the socket into the SSL structure*/
                bio = BIO_new(BIO_s_socket());
                RETURN_NULL(bio);

                err = BIO_set_fd(bio, sock, BIO_CLOSE);
                RETURN_SSL(err);

                SSL_set_bio(ssl, bio, bio);

                /* Perform SSL Handshake on the SSL server */
                err = SSL_accept(ssl);
                RETURN_SSL(err);
            }

            if( !speed )
            {
                /* Informational output (optional) */
                fprintf(stdout, "SSL connection using %s, %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));
                ShowCerts(ssl);
            }

            if( data )
              gettimeofday(&begin, NULL);

            for( send_counts = 0; send_counts < send_times; send_counts++ )
            {
                if( client )
                {
                    memset(buf, 0x00, sizeof(buf));
                    sprintf(buf, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: %s\r\n\r\n", host, data ? "keep-alive" : "close");
                    if (SSL_write(ssl, buf, strlen(buf)) != strlen(buf))
                    {
                        ERR_print_errors_fp(stderr);
                        exit(1);
                    }

                    /* Receive data from the SSL client */
                    memset(buf, 0x00, sizeof(buf));
                    len = SSL_read(ssl, buf, sizeof(buf) - 1);
                    if( len <= 0 )
                    {
                        ERR_print_errors_fp(stderr);
                        exit(1);
                    }
                    if( !speed )
                      fprintf(stdout, "recv %d bytes : %s\n", len, buf);
                }
                else
                {
                    /* Receive data from the SSL client */
                    memset(buf, 0x00, sizeof(buf));
                    len = SSL_read(ssl, buf, sizeof(buf) - 1);
                    if( len <= 0 )
                    {
                        ERR_print_errors_fp(stderr);
                        exit(1);
                    }
                    if( !speed )
                      fprintf(stdout, "recv %d bytes : %s\n", len, buf);
                    
                    memset(buf, 0x00, sizeof(buf));
                    sprintf(buf, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-Length: 5\r\n\r\nhello", data ? "keep-alive" : "close");
                    if (SSL_write(ssl, buf, strlen(buf)) != strlen(buf))
                    {
                        ERR_print_errors_fp(stderr);
                        exit(1);
                    }
                }

                if( 0 == text_len )
                {
                    /* http body length */
                    text_len = strlen(buf) - (strstr(buf, "\r\n\r\n") + 4 - buf);
                }
                else
                {
                    /* simple check, make sure GET the same home page length each time */
                    if( text_len != (strlen(buf) - (strstr(buf, "\r\n\r\n") + 4 - buf)) )
                      goto error;
                }
               
                if( data )
                {
                    if( 10 <= send_times && 0 == (send_counts+1)%(send_times/10) )
                    {
                        gettimeofday(&end, NULL);
                        BIO_printf(bio_out, "thread %ld ssl data speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                    pthread_self(),
                                    (send_counts+1), 
                                    (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                    (send_counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                    ((send_counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                    }
                }
            }

            /*--------------- SSL closure ---------------*/
            /* Shutdown this side (server) of the connection. */
            SSL_shutdown(ssl);

            SSL_free(ssl); ssl = NULL;

            if( !data )
            {
                if( 10 <= connect_times && 0 == (counts+1)%(connect_times/10) )
                {
                    gettimeofday(&end, NULL);
                    BIO_printf(bio_out, "thread %ld ssl connect speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                                pthread_self(),
                                (counts+1), 
                                (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                                (counts+1)/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                                ((counts+1)*text_len/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
                }
            }
        }

        if( server )
          close(listen_sock);
        
        /* Terminate communication on a socket */
    }
    else if( version )
    {
        BIO_printf(bio_out, "version : %s\n", OpenSSL_version(TASSL_VERSION));
    }
    else if( state )
    {
        if( inited )
          BIO_printf(bio_out, "state : already inited\n");
        else
          BIO_printf(bio_out, "state : not inited\n");
    }
    else if( init )
    {
        inited = 1;
        BIO_printf(bio_out, "TASSL init success!\n");
    }
    else
    {
        goto error;
    }

    retval = 0;
    
error:
    //if( bio ) BIO_free(bio);
    if( ssl ) SSL_free(ssl);
    if( ctx ) SSL_CTX_free(ctx);
    if( bin ) OPENSSL_free(bin);
    if( der ) OPENSSL_free(der);
    if( text ) OPENSSL_free(text);
    if( pub_exp ) BN_free(pub_exp);
    if( decipher ) OPENSSL_free(decipher);
    if( bio_out ) BIO_free(bio_out);
    if( pkey ) EVP_PKEY_free(pkey);
    if( md_ctx ) EVP_MD_CTX_free(md_ctx);
    if( pkey_ctx ) EVP_PKEY_CTX_free(pkey_ctx);
    if( ecdsa_sig ) ECDSA_SIG_free(ecdsa_sig);
    if( sm2_ctext ) SM2_Ciphertext_free(sm2_ctext);
    pthread_exit((void *)retval);
}

int process(int argc, char **argv)
{
	int err, i;
    int threads = 1;
    BIO *bio_out = NULL;
    ENGINE *engine = NULL;
    struct timeval begin, end;
    pthread_t *threads_id = NULL;
    long  retval;

    /* for openssl memory debug */
    //CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    /**************************/
    
    sm2 = 0, sm3 = 0, sm4 = 0, rand1 = 0;
    text_len = 0;
    total_times = 1;
    speed = 0, enc = 0, verify = 0;
    version = 0, state = 0, init = 0;
    ecb = 0, cbc = 0;
    client = 0, server = 0, gmssl = 0, data = 0;
    verify_peer = 0; /* To verify peer certificate, set ON */
    sign_cert = NULL, sign_key = NULL;
    enc_cert = NULL, enc_key = NULL;
    ca_cert = NULL, ca_path = NULL;
    host = NULL;
    engine_name = NULL;
    s_port = DEFAULT_PORT;

    /* options */
    for (err = 1; err < argc; err++)
    {
        if (!strcasecmp(argv[err], "--help") || !strcasecmp(argv[err], "-h") )
        {
            fprintf(stdout, "%s", USAGE);
            exit(0);
        }
        else if (!strcasecmp(argv[err], "-e"))
        {
            engine_name = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-sc"))
        {
            sign_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-sk"))
        {
            sign_key = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ec"))
        {
            enc_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ek"))
        {
            enc_key = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca"))
        {
            ca_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca_path"))
        {
            ca_path = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-p"))
        {
            s_port = atoi(argv[++err]);
            if (s_port <= 0) s_port = DEFAULT_PORT;
        }
        else if (!strcasecmp(argv[err], "--verify"))
        {
            verify_peer = 1;
        }
        else if (!strcasecmp(argv[err], "-textlen"))
        {
            text_len = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "-bits"))
        {
            bits = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "--speed"))
        {
            speed = 1;
        }
        else if (!strcasecmp(argv[err], "--cmac"))
        {
            cmac = 1;
        }
        else if (!strcasecmp(argv[err], "--hmac"))
        {
            hmac = 1;
        }
        else if (!strcasecmp(argv[err], "--rsa"))
        {
            rsa = 1;
        }
        else if (!strcasecmp(argv[err], "--sm2"))
        {
            sm2 = 1;
        }
        else if (!strcasecmp(argv[err], "--sm3"))
        {
            sm3 = 1;
        }
        else if (!strcasecmp(argv[err], "--sm4"))
        {
            sm4 = 1;
        }
        else if (!strcasecmp(argv[err], "--client"))
        {
            client = 1;
        }
        else if (!strcasecmp(argv[err], "--server"))
        {
            server = 1;
        }
        else if (!strcasecmp(argv[err], "--rand"))
        {
            rand1 = 1;
        }
        else if (!strcasecmp(argv[err], "--version"))
        {
            version = 1;
        }
        else if (!strcasecmp(argv[err], "--state"))
        {
            state = 1;
        }
        else if (!strcasecmp(argv[err], "--init"))
        {
            init = 1;
        }
        else if (!strcasecmp(argv[err], "-threads"))
        {
            threads = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "-alg"))
        {
            alg = argv[++err];
        }
        else if (!strcasecmp(argv[err], "--gmssl"))
        {
            gmssl = 1;
        }
        else if (!strcasecmp(argv[err], "--data"))
        {
            data = 1;
        }
        else if (!strcasecmp(argv[err], "-s"))
        {
            host = argv[++err];
        }
        else if (!strcasecmp(argv[err], "--keypair"))
        {
            keypair = 1;
        }
        else if (!strcasecmp(argv[err], "--enc"))
        {
            enc = 1;
        }
        else if (!strcasecmp(argv[err], "--dec"))
        {
            dec = 1;
        }
        else if (!strcasecmp(argv[err], "--sign"))
        {
            sign = 1;
        }
        else if (!strcasecmp(argv[err], "--ver"))
        {
            verify = 1;
        }
        else if (!strcasecmp(argv[err], "--ecb"))
        {
            ecb = 1;
        }
        else if (!strcasecmp(argv[err], "--cbc"))
        {
            cbc = 1;
        }
        else if (!strcasecmp(argv[err], "-total_times"))
        {
            total_times = atoi(argv[++err]);
        }
        else
        {
            fprintf(stderr, "unknown options, use --help\n");
            exit(1);
        }
    }

	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();
    
    bio_out = BIO_new_fp(stdout, 0);
    RETURN_NULL(bio_out);
        
    /* Load engine if use it */
    if( engine_name )
    {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);

        if( rand1 )
        {
            err = ENGINE_set_default(engine, ENGINE_METHOD_ALL);
            RETURN_SSL(err);
        }
    }

    threads_id = (pthread_t *)OPENSSL_malloc(threads * sizeof(pthread_t));
    RETURN_NULL(threads_id);

    gettimeofday(&begin, NULL);
    
    for( i = 0; i < threads; i++ )
    {
        if( 0 != pthread_create(&threads_id[i], NULL, thread_routine, NULL) )
          goto error;
    }
    
    for( i = 0; i < threads; i++ )
    {
        if( 0 != pthread_join(threads_id[i], (void **)&retval)
                    || 0 != retval )
          goto error;
    }
    
    if( 10 <= total_times )
    {
        gettimeofday(&end, NULL);
        BIO_printf(bio_out, "total speed, counts = %d, time=%.2lf, tps=%.2lf, bps=%.2lfMb\n",
                    total_times*threads, 
                    (end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000), 
                    total_times*threads/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)),
                    (total_times*text_len*threads/((end.tv_sec+(double)end.tv_usec/1000000)-(begin.tv_sec+(double)begin.tv_usec/1000000)))*8/(1024*1024));
    }

error:
    if( engine )
    {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    
    if( bio_out ) BIO_free(bio_out);

    if( threads_id ) OPENSSL_free(threads_id);

    /*for openssl memory debug*/
    //CRYPTO_mem_leaks_fp(stderr);
    /**************************/

	return 0;
}

int main(int argc, char **argv)
{
    if( argc >= 2 )
      process(argc, argv);
    else
    {
        while(1)
        {
            char buf[1024] = {0};
            char *p = buf;
            char option = 1;
            int argc1 = argc;
            char **argv1 = malloc(sizeof(char *) * argc1);
            if( !argv1 )
              return -1;

            memcpy(argv1, argv, sizeof(char *) * argc1);
            fprintf(stdout, "\nplease input options : ");
            if( fgets(buf, sizeof(buf), stdin) )
            {
                buf[strlen(buf)-1] = '\0';
                while(*p)
                {
                    if( *p == ' ' )
                    {
                        *p = '\0';
                        option = 1;
                    }
                    else
                    {
                        if( option )
                        {
                            argc1++;
                            argv1 = realloc(argv1, sizeof(char *) * argc1);
                            argv1[argc1-1] = p;
                            option = 0;
                        }
                    }
                    p++;
                }
            }
            process(argc1, argv1);
            free(argv1);
        }
    }
    
err:
    return 0;
}
