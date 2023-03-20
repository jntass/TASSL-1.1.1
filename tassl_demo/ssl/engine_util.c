#include <string.h>

#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/engine.h"

#define RETURN_NULL(x) if ((x)==NULL) { ERR_print_errors_fp(stderr); goto error; }
#define RETURN_SSL(err) if ((err)!=1) { ERR_print_errors_fp(stderr); goto error; }

int generate_keypair( 
            int nid,
            char *key,
            char *engine_name,
            unsigned int e,
            unsigned int bits
            )
{
    int rv = 0, err;
    BIO *bio = NULL;
    ENGINE *engine = NULL;
    BIGNUM *rsa_e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    /* Load engine if use it */
    if( NULL != engine_name ) {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(nid, engine);
    RETURN_NULL(pkey_ctx);

    err = EVP_PKEY_keygen_init(pkey_ctx);
    RETURN_SSL(err);

    if( NID_rsaEncryption == nid ) {
        /* set RSA keygen params, e and modulus */
        rsa_e = BN_new();
        RETURN_NULL(rsa_e);

        err = BN_set_word(rsa_e, e);
        RETURN_SSL(err);

        err = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, bits);
        RETURN_SSL(err);

        err = EVP_PKEY_CTX_set_rsa_keygen_pubexp(pkey_ctx, rsa_e);
        RETURN_SSL(err);
        
        rsa_e = NULL;
    } else if( NID_sm2 == nid ) {
        /* set SM2 keygen params */
        err = EVP_PKEY_CTX_ctrl(pkey_ctx, -1, EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, NID_sm2, NULL);
        RETURN_SSL(err);

        err = EVP_PKEY_CTX_ctrl(pkey_ctx, -1, EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                    EVP_PKEY_CTRL_EC_PARAM_ENC, OPENSSL_EC_NAMED_CURVE, NULL);
        RETURN_SSL(err);
    } else {
        printf("nid error\n");
        goto error;
    }

    /* key index */
    if( engine && atoi(key) != 0 )
      EVP_PKEY_CTX_set_app_data(pkey_ctx, key);

    /* generate key */
    err = EVP_PKEY_keygen(pkey_ctx, &pkey);
    RETURN_SSL(err);

    /* export keyfile if need */
    if( atoi(key) == 0 ) {
        bio = BIO_new_file(key, "w+");
        RETURN_NULL(bio);

        if( NID_rsaEncryption == nid )
          err = PEM_write_bio_RSAPrivateKey(bio, EVP_PKEY_get0_RSA(pkey), NULL, NULL, 0, NULL, NULL);
        else if ( NID_sm2 == nid )
          err = PEM_write_bio_ECPrivateKey(bio, EVP_PKEY_get0_EC_KEY(pkey), NULL, NULL, 0, NULL, NULL);
        else {
            printf("nid error\n");
            goto error;
        }
        RETURN_SSL(err);
    }
    rv = 1;

error:
    if( bio ) BIO_free(bio);
    if( rsa_e ) BN_free(rsa_e);
    if( pkey ) EVP_PKEY_free(pkey);
    if( pkey_ctx ) EVP_PKEY_CTX_free(pkey_ctx);
    if( engine ) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    return rv;
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
static X509_NAME *parse_name(const char *cp, long chtype, int canmulti)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL)
        goto err;

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            continue;
        }
        if (*valstr == '\0') {
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0))
            goto err;
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

int generate_csr(
            char *key,
            int hash_nid,
            char *engine_name,
            char *csrfile,
            const char *dn
            )
{
    int rv = 0, err;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    X509_NAME *n = NULL;
    X509_REQ *req = NULL;
    ENGINE *engine = NULL;

    /* Load engine if use it */
    if( NULL != engine_name ) {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }

    req = X509_REQ_new();
    RETURN_NULL(req);

    /* setup version number, version 1 */
    err = X509_REQ_set_version(req, 0L);
    RETURN_SSL(err);

    n = parse_name(dn, MBSTRING_ASC, 0);
    RETURN_NULL(n);

    err = X509_REQ_set_subject_name(req, n);
    RETURN_SSL(err);

    if( engine ) {
        pkey = ENGINE_load_private_key(engine, key, NULL, NULL);
        RETURN_NULL(pkey);
    } else {
        /* Load common private key file*/
        bio = BIO_new(BIO_s_file());
        RETURN_NULL(bio);

        err = BIO_read_filename(bio, key);
        RETURN_SSL(err);

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        RETURN_NULL(pkey);

        BIO_free(bio); bio = NULL;
    }

    err = X509_REQ_set_pubkey(req, pkey);
    RETURN_SSL(err);

    err = X509_REQ_sign(req, pkey, EVP_get_digestbynid(hash_nid));
    if( err <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* output certificate sign request */
    bio = BIO_new_file(csrfile, "w+");
    RETURN_NULL(bio);

    /* encode certificate sign request to pem format*/
    err = PEM_write_bio_X509_REQ(bio, req);
    RETURN_SSL(err);

    rv = 1;

error:
    if( bio ) BIO_free(bio);
    if( n ) X509_NAME_free(n);
    if( req ) X509_REQ_free(req);
    if( pkey ) EVP_PKEY_free(pkey);
    if( engine ) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    return rv;
}

int sign_crt(
            char *csr,
            char *issuer,
            char *issuer_key,
            char *extfile,
            char *extensions,
            char *crt,
            int hash_nid,
            char *engine_name,
            unsigned char *serial,
            int serial_len,
            int days
            )
{
    int rv = 0, err;
    X509V3_CTX ctx;
    BIO *bio = NULL;
    CONF *conf = NULL;
    X509 *x = NULL, *issuer_x = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *sno_bn = NULL;
    ENGINE *engine = NULL;
    ASN1_INTEGER *sno = NULL;

    /* Load engine if use it */
    if( NULL != engine_name ) {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }

    /* load certificate request */
    bio = BIO_new_file(csr, "r");
    RETURN_NULL(bio);

    req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    RETURN_NULL(req);

    BIO_free(bio); bio = NULL;

    /* construct x509 certificate */
    x = X509_new();
    RETURN_NULL(x);

    sno_bn = BN_bin2bn(serial, serial_len, NULL);
    RETURN_NULL(sno_bn);

    sno = BN_to_ASN1_INTEGER(sno_bn, NULL);
    RETURN_NULL(sno);

    /* set serial number */
    err = X509_set_serialNumber(x, sno);
    RETURN_SSL(err);

    /* set issuer name */
    if( issuer ) {
        bio = BIO_new_file(issuer, "r");
        RETURN_NULL(bio);

        issuer_x = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        RETURN_NULL(issuer_x);

        BIO_free(bio); bio = NULL;
        
        err = X509_set_issuer_name(x, X509_get_subject_name(issuer_x));
        RETURN_SSL(err);
    } else {
        /* selfsign */
        err = X509_set_issuer_name(x, X509_REQ_get_subject_name(req));
        RETURN_SSL(err);
    }

    /* set subject name */
    err = X509_set_subject_name(x, X509_REQ_get_subject_name(req));
    RETURN_SSL(err);

    /* set time not before */
    if( !X509_time_adj_ex(X509_getm_notBefore(x), 0, 0, NULL) ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* set time not after */
    if( !X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL) ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    /* set public key */
    err = X509_set_pubkey(x, X509_REQ_get0_pubkey(req));
    RETURN_SSL(err);

    if( extfile ) {
        /* set version 3 */
        X509_set_version(x, 2);

        bio = BIO_new_file(extfile, "r");
        RETURN_NULL(bio);

        conf = NCONF_new(NULL);
        RETURN_NULL(conf);

        err = NCONF_load_bio(conf, bio, NULL);
        if( err <= 0 ) {
            ERR_print_errors_fp(stderr);
            goto error;
        }

        X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx, conf);
        
        err = X509V3_EXT_add_nconf(conf, &ctx, extensions, x);
        RETURN_SSL(err);

        BIO_free(bio); bio = NULL;
    }

    if( engine ) {
        pkey = ENGINE_load_private_key(engine, issuer_key, NULL, NULL);
        RETURN_NULL(pkey);
    } else {
        /* Load common private key file*/
        bio = BIO_new(BIO_s_file());
        RETURN_NULL(bio);

        err = BIO_read_filename(bio, issuer_key);
        RETURN_SSL(err);

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        RETURN_NULL(pkey);

        BIO_free(bio); bio = NULL;
    }

    err = X509_sign(x, pkey, EVP_get_digestbynid(hash_nid));
    if( err <= 0 ) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    bio = BIO_new_file(crt, "w+");
    RETURN_NULL(bio);

    /* encode certificate to pem format*/
    err = PEM_write_bio_X509(bio, x);
    RETURN_SSL(err);

    BIO_free(bio); bio = NULL;

    rv = 1;

error:
    if( bio ) BIO_free(bio);
    if( conf ) NCONF_free(conf);
    if( pkey ) EVP_PKEY_free(pkey);
    if( req ) X509_REQ_free(req);
    if( x ) X509_free(x);
    if( issuer_x ) X509_free(issuer_x);
    if( sno_bn ) BN_free(sno_bn);
    if( sno ) ASN1_INTEGER_free(sno);
    if( engine ) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    return rv;
}

int data_sign(
            char *key,
            char *engine_name,
            int nid,
            int hash_nid,
            unsigned char *data,
            size_t datalen,
            unsigned char *sign,
            size_t *signlen
            )
{
    int rv = 0, err;
    BIO *bio = NULL;
    ENGINE *engine = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned int tbslen;
    unsigned char *tbs = NULL, *z = NULL;

    /* Load engine if use it */
    if( NULL != engine_name ) {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }
    
    if( engine ) {
        pkey = ENGINE_load_private_key(engine, key, NULL, NULL);
        RETURN_NULL(pkey);
    } else {
        /* Load common private key file*/
        bio = BIO_new(BIO_s_file());
        RETURN_NULL(bio);

        err = BIO_read_filename(bio, key);
        RETURN_SSL(err);

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        RETURN_NULL(pkey);

        BIO_free(bio); bio = NULL;
    }

    /* digest before sign */
    md_ctx = EVP_MD_CTX_new();
    RETURN_NULL(md_ctx);

    err = EVP_DigestInit_ex(md_ctx, EVP_get_digestbynid(hash_nid), NULL);
    RETURN_SSL(err);

    if( NID_sm2 == nid )
    {
        /* SM2, H = SM3(Z||M) */
        z = OPENSSL_malloc(EVP_MD_size(EVP_get_digestbynid(hash_nid)));
        RETURN_NULL(z);

        err = sm2_compute_z_digest(z, EVP_get_digestbynid(hash_nid),
                    (const uint8_t *)SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), EVP_PKEY_get0_EC_KEY(pkey));
        RETURN_SSL(err);
        
        err = EVP_DigestUpdate(md_ctx, z, EVP_MD_CTX_size(md_ctx));
        RETURN_SSL(err);
    }

    err = EVP_DigestUpdate(md_ctx, data, datalen);
    RETURN_SSL(err);
    
    tbs = OPENSSL_malloc(EVP_MD_CTX_size(md_ctx));
    RETURN_NULL(tbs);

    err = EVP_DigestFinal_ex(md_ctx, tbs, &tbslen);
    RETURN_SSL(err);
    
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    RETURN_NULL(pkey_ctx);

    err = EVP_PKEY_sign_init(pkey_ctx);
    RETURN_SSL(err);

    err = EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_get_digestbynid(hash_nid));
    RETURN_SSL(err);

    /* sign */
    err = EVP_PKEY_sign(pkey_ctx, sign, signlen, tbs, tbslen);
    RETURN_SSL(err);

    rv = 1;

error:
    if( z ) OPENSSL_free(z);
    if( bio ) BIO_free(bio);
    if( tbs ) OPENSSL_free(tbs);
    if( pkey ) EVP_PKEY_free(pkey);
    if( pkey_ctx ) EVP_PKEY_CTX_free(pkey_ctx);
    if( md_ctx ) EVP_MD_CTX_free(md_ctx);
    if( engine ) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    return rv;
}

int data_verify(
            char *key,
            char *engine_name,
            int nid,
            int hash_nid,
            unsigned char *data,
            size_t datalen,
            unsigned char* sign,
            size_t signlen
            )
{
    int rv = 0, err;
    BIO *bio = NULL;
    ENGINE *engine = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *tbs = NULL, *z = NULL;
    int tbslen;

    /* Load engine if use it */
    if( NULL != engine_name ) {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }
    
    if( engine ) {
        pkey = ENGINE_load_private_key(engine, key, NULL, NULL);
        RETURN_NULL(pkey);
    } else {
        /* Load common private key file*/
        bio = BIO_new(BIO_s_file());
        RETURN_NULL(bio);

        err = BIO_read_filename(bio, key);
        RETURN_SSL(err);

        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        RETURN_NULL(pkey);

        BIO_free(bio); bio = NULL;
    }

    /* digest before verify */
    md_ctx = EVP_MD_CTX_new();
    RETURN_NULL(md_ctx);

    err = EVP_DigestInit_ex(md_ctx, EVP_get_digestbynid(hash_nid), NULL);
    RETURN_SSL(err);

    tbs = OPENSSL_malloc(EVP_MD_CTX_size(md_ctx));
    RETURN_NULL(tbs);

    if( NID_sm2 == nid )
    {
        /* SM2, H = SM3(Z||M) */
        z = OPENSSL_malloc(EVP_MD_size(EVP_get_digestbynid(hash_nid)));
        RETURN_NULL(z);

        err = sm2_compute_z_digest(z, EVP_get_digestbynid(hash_nid),
                    (const uint8_t *)SM2_DEFAULT_USERID, strlen(SM2_DEFAULT_USERID), EVP_PKEY_get0_EC_KEY(pkey));
        RETURN_SSL(err);
        
        err = EVP_DigestUpdate(md_ctx, z, EVP_MD_CTX_size(md_ctx));
        RETURN_SSL(err);
    }

    err = EVP_DigestUpdate(md_ctx, data, datalen);
    RETURN_SSL(err);
    
    err = EVP_DigestFinal_ex(md_ctx, tbs, (unsigned int *)&tbslen);
    RETURN_SSL(err);
    
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    RETURN_NULL(pkey_ctx);

    err = EVP_PKEY_verify_init(pkey_ctx);
    RETURN_SSL(err);

    err = EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_get_digestbynid(hash_nid));
    RETURN_SSL(err);
    
    /* verify */
    err = EVP_PKEY_verify(pkey_ctx, sign, signlen, tbs, tbslen);
    RETURN_SSL(err);
    
    rv = 1;

error:
    if( bio ) BIO_free(bio);
    if( z ) OPENSSL_free(z);
    if( tbs ) OPENSSL_free(tbs);
    if( pkey ) EVP_PKEY_free(pkey);
    if( pkey_ctx ) EVP_PKEY_CTX_free(pkey_ctx);
    if( md_ctx ) EVP_MD_CTX_free(md_ctx);
    if( engine ) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    return rv;
}

static int Transfer( const char *lmk_pri, const char *der_pub, const char *out, int rsa )
{
    BIO *bio = NULL;
    RSA *rsakey = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *pri_key = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL;
    BIGNUM *bn_dp = NULL, *bn_dq = NULL, *bn_qinv = NULL;
    const uint8_t *p = NULL;
    uint8_t *pri_key_buf = NULL;
    long pri_key_len;
    uint8_t *pub_key_buf = NULL;
    long pub_key_len;
    int err, rv = 0;

    //First. get private key encrypted by LMK
    pri_key_buf = OPENSSL_hexstr2buf(lmk_pri, &pri_key_len);
    RETURN_NULL(pri_key_buf);

    //BIN to BN
    pri_key = BN_bin2bn(pri_key_buf, pri_key_len, NULL);
    RETURN_NULL(pri_key);

    //Second. get public key encoded to DER
    pub_key_buf = OPENSSL_hexstr2buf(der_pub, &pub_key_len);
    RETURN_NULL(pub_key_buf);
   
    //BIN DER public key to internal KEY
    p = pub_key_buf;

    if( rsa )
    {
        rsakey = d2i_RSAPublicKey(NULL, &p, pub_key_len);
        RETURN_NULL(rsakey);

        /* set private key */
        err = RSA_set0_key(rsakey, NULL, NULL, pri_key);
        RETURN_SSL(err);
        pri_key = NULL;

        /* no meaning, just for construct ASN1 format */
        if( 1 != BN_asc2bn(&bn_p, "1")
                    || 1 != BN_asc2bn(&bn_q, "1")
                    || 1 != BN_asc2bn(&bn_dp, "1")
                    || 1 != BN_asc2bn(&bn_dq, "1")
                    || 1 != BN_asc2bn(&bn_qinv, "1") )
        {
            printf("BN_asc2bn error\n");
            goto error;
        }

        err = RSA_set0_factors(rsakey, bn_p, bn_q);
        RETURN_SSL(err);
        bn_p = bn_q = NULL;

        err = RSA_set0_crt_params(rsakey, bn_dp, bn_dq, bn_qinv);
        RETURN_SSL(err);
        bn_dp = bn_dq = bn_qinv = NULL;

        /* set flag(for export cipher key file) */
        RSA_set_flags(rsakey, RSA_FLAG_TASSHSM_ENGINE);
    }
    else
    {
        eckey = d2i_EC_PUBKEY(NULL, &p, pub_key_len);
        RETURN_NULL(eckey);

        /* set private key to EC KEY */
        err = EC_KEY_set_private_key(eckey, pri_key);
        RETURN_SSL(err);

        /* note: before write key that 
         * generated by tasshsm engine 
         * to PEM, must set this flag */
        EC_KEY_set_flags(eckey, EC_FLAG_TASSHSM_ENGINE);
    }

    //Third. write PEM
    bio = BIO_new_file(out, "w");
    RETURN_NULL(bio);

    if( rsa )
      err = PEM_write_bio_RSAPrivateKey(bio, rsakey, NULL, NULL, 0, NULL, NULL);
    else
      err = PEM_write_bio_ECPrivateKey(bio, eckey, NULL, NULL, 0, NULL, NULL);
    RETURN_SSL(err);

    rv = 1;

error:
    if(bio) BIO_free(bio);
    if(bn_p) BN_free(bn_p);
    if(bn_q) BN_free(bn_q);
    if(bn_dp) BN_free(bn_dp);
    if(bn_dq) BN_free(bn_dq);
    if(bn_qinv) BN_free(bn_qinv);
    if(rsakey) RSA_free(rsakey);
    if(eckey) EC_KEY_free(eckey);
    if(pri_key) BN_free(pri_key);
    if(pri_key_buf) OPENSSL_free(pri_key_buf);
    if(pub_key_buf) OPENSSL_free(pub_key_buf);
    return rv;
}

#define USAGE "Usage : \n\
    --GenKey            generate sm2 key\n\
    --SignCSR           sign csr\n\
    --SignCRT           sign crt\n\
    --DataSignVerify    data sign and verify\n\
    --RSA               rsa\n\
    -key index/file     keyindex or keyfile\n\
    -engine name        use engine\n\
    -e exp              rsa e\n\
    -bits num           rsa bits\n\
    -dn name            set csr dn\n\
    -serial num         crt serial\n\
    -days num           crt validity\n\
    -extfile            extensions file\n\
    -ext                extensions\n\
    -csr file           csr file\n\
    -crt file           crt file\n\
    -ca crt             CA certificate\n\
    -ca_key key         CA key\n"

#define TEST_DATA "12345678"
#define TEST_DATA_LEN strlen(TEST_DATA)

int main( int argc, char *argv[] )
{
    int err;
    unsigned char sign[256] = {0};
    size_t signlen = sizeof(sign);

    int GenKey = 0, SignCSR = 0, SignCRT = 0, DataSignVerify = 0, TransferKey = 0;
    char *key = NULL, *engine = NULL;
    unsigned int e = 65537, bits = 2048;
    int rsa = 0, sm2 = 0, hsm = 0;
    const char *dn = NULL, *serial = NULL;
    char *extfile = NULL, *ext = NULL;
    char *csr = NULL, *crt = NULL;
    char *ca = NULL, *ca_key = NULL;
    unsigned char *serial_tmp = NULL;
    long serial_len = 16;
    int days = 365;
    char *lmk_pri = NULL, *der_pub = NULL, *out = NULL;

    /* options */
    for (err = 1; err < argc; err++)
    {
        if (!strcasecmp(argv[err], "--help") || !strcasecmp(argv[err], "-h") )
        {
            printf("%s", USAGE);
            goto error;
        }
        else if (!strcasecmp(argv[err], "--GenKey"))
        {
            GenKey = 1;
        }
        else if (!strcasecmp(argv[err], "--SignCSR"))
        {
            SignCSR = 1;
        }
        else if (!strcasecmp(argv[err], "--SignCRT"))
        {
            SignCRT = 1;
        }
        else if (!strcasecmp(argv[err], "--DataSignVerify"))
        {
            DataSignVerify = 1;
        }
        else if (!strcasecmp(argv[err], "tassl_pem_key"))
        {
            TransferKey = 1;
        }
        else if (!strcasecmp(argv[err], "--RSA") || !strcasecmp(argv[err], "-rsa"))
        {
            rsa = 1;
        }
        else if (!strcasecmp(argv[err], "--SM2") || !strcasecmp(argv[err], "-sm2"))
        {
            sm2 = 1;
        }
        else if (!strcasecmp(argv[err], "-key"))
        {
            key = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-engine"))
        {
            engine = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-e"))
        {
            e = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "-bits"))
        {
            bits = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "-dn"))
        {
            dn = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-serial"))
        {
            serial = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-days"))
        {
            days = atoi(argv[++err]);
        }
        else if (!strcasecmp(argv[err], "-extfile"))
        {
            extfile = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ext"))
        {
            ext = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-csr"))
        {
            csr = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-crt"))
        {
            crt = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca"))
        {
            ca = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca_key"))
        {
            ca_key = argv[++err];
        } 
        else if( 0 == strcasecmp(argv[err], "-hsm") )
        {
            hsm = 1;
        }
        else if( 0 == strcasecmp(argv[err], "-lmk_pri") )
        {
            lmk_pri = argv[++err];
        }
        else if( 0 == strcasecmp(argv[err], "-der_pub") )
        {
            der_pub = argv[++err];
        }
        else if( 0 == strcasecmp(argv[err], "-out") )
        {
            out = argv[++err];
        }
        else
        {
            printf("unknown options, use --help\n");
            goto error;
        }
    }

    ENGINE_load_builtin_engines();

    if( GenKey )
    {
        err = generate_keypair(rsa ? NID_rsaEncryption : NID_sm2, key, engine, e, bits);
        if( 1 != err ) {
            printf("generate_keypair error\n");
            goto error;
        }
        printf("generate_keypair success\n");
    }

    if( SignCSR )
    {
        err = generate_csr(key, rsa ? NID_sha256 : NID_sm3, engine, csr, dn);
        if( 1 != err ) {
            printf("generate_csr error\n");
            goto error;
        }
        printf("generate_csr success\n");
    }

    if( SignCRT )
    {
        if( serial )
        {
            serial_tmp = OPENSSL_hexstr2buf(serial, &serial_len);
        }
        else
        {
            serial_tmp = OPENSSL_malloc(serial_len);
            RETURN_NULL(serial_tmp);

            err = RAND_bytes(serial_tmp, serial_len);
            RETURN_SSL(err)
        }
        
        err = sign_crt(csr, ca, ca_key, extfile, ext, crt, rsa ? NID_sha256 : NID_sm3, engine, serial_tmp, serial_len, days);
        if( 1 != err ) {
            printf("sign_crt error\n");
            goto error;
        }
        printf("sign_crt success\n");
    }

    if( DataSignVerify )
    {
        /* data sign */
        err = data_sign(key, engine, 
                    rsa ? NID_rsaEncryption : NID_sm2, 
                    rsa ? NID_sha256 : NID_sm3, 
                    TEST_DATA, TEST_DATA_LEN, sign, &signlen);
        if( 1 != err ) {
            printf("data_sign error\n");
            goto error;
        }
        printf("data_sign success\n");

        /* verify signature */
        err = data_verify(key, engine, 
                    rsa ? NID_rsaEncryption : NID_sm2, 
                    rsa ? NID_sha256 : NID_sm3, 
                    TEST_DATA, TEST_DATA_LEN, sign, signlen);
        if( 1 != err ) {
            printf("data_verify error\n");
            goto error;
        }
        printf("data_verify success\n");
    }

    if( TransferKey )
    {
        err = Transfer(lmk_pri, der_pub, out, rsa);
        if( 1 != err ) {
            printf("TransferKey error\n");
            goto error;
        }
        printf("PEM key write success\n");
    }

error:
    if( serial_tmp ) OPENSSL_free(serial_tmp);
    return 0;
}
