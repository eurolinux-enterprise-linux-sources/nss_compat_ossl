/*    
 *  Copyright (C) 2007 Red Hat, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the
 *  "Software"), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sublicense, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject
 *  to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 * 
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
*/

#ifndef NSS_COMPAT_OSSL_H
#define NSS_COMPAT_OSSL_H 1

#undef HAVE_OPENSSL
#undef HAVE_OSSL_ENGINE_H

#include <nspr.h>
#include <nss.h>
#include <pk11pub.h>
#include <sechash.h>
#include <ssl.h>
#include <base64.h>
#include <keyhi.h>
#include <sslproto.h>
#include <pk11func.h>
#include <cert.h>

#include <secerr.h>
#include <sslerr.h>


/* extra stuff we made up ... */

#define SSLeay_version(x) "nss-3.11.4" /* FIXME: hack job */
#define SSLEAY_VERSION_NUMBER 0x0922
#define OPENSSL_VERSION_NUMBER 0x0090802fL
#define NO_RSA 1 /* FIXME: ? */
#define USE_NSS 1 /* FIXME: autoconf? */

#define PEM_BUFSIZE 1024

/* FIXME: need to map from SSL -> SSL_CTX */
#define OSSL_SSL2CTX(x) ((SSL_CTX *)NULL)
#define OSSL_X509_STORE_CTX2CERT(x) NULL
#define OSSL_X509_STORE_CTX2ERROR_DEPTH(x) 0
#define OSSL_X509_STORE_CTX2ERROR(x) NULL
#define OSSL_X509_REVOKED2SERIAL_NUMBER(x) NULL

/* defs. mapping... */
#define CRYPTO_LOCK 1
#define CRYPTO_NUM_LOCKS 1

/* hack: PR uses PR_SHUTDOWN_BOTH instead of Or'ig the flags... *sigh */
#define SSL_SENT_SHUTDOWN     0x1 /* PR_SHUTDOWN_SEND */
#define SSL_RECEIVED_SHUTDOWN 0x2 /* PR_SHUTDOWN_RCV */

#define SSL_ERROR_NONE             0
#define SSL_ERROR_WANT_WRITE       1
#define SSL_ERROR_WANT_READ        2
#define SSL_ERROR_WANT_X509_LOOKUP 3
#define SSL_ERROR_SYSCALL          4
#define SSL_ERROR_ZERO_RETURN      5
#define SSL_ERROR_SSL              6

#define SSL_DEFAULT_CIPHER_LIST "RSA"

#define SSL_VERIFY_NONE 0
#define SSL_VERIFY_PEER 1
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 2
#define SSL_VERIFY_CLIENT_ONCE 4

#define SSL_CB_LOOP              0x01
#define SSL_CB_EXIT              0x02
#define SSL_CB_READ              0x04
#define SSL_CB_WRITE             0x08
#define SSL_CB_ALERT             0x10
#define SSL_CB_HANDSHAKE_DONE    0x20


#define SSL_SESS_CACHE_BOTH 1

#define X509_FILETYPE_PEM  1
#define X509_FILETYPE_ASN1 2
#define X509_FILETYPE_ENGINE 3
#define X509_FILETYPE_PKCS12 4

#define SSL_FILETYPE_PEM  X509_FILETYPE_PEM
#define SSL_FILETYPE_ASN1 X509_FILETYPE_ASN1
#define SSL_FILETYPE_ENGINE X509_FILETYPE_ENGINE
#define SSL_FILETYPE_PKCS12 X509_FILETYPE_PKCS12

/* FIXME: These are ignored */
#define SSL_MODE_ENABLE_PARTIAL_WRITE 1
#define SSL_MODE_AUTO_RETRY 2

#define SSL_ST_OK              0x01
#define SSL_ST_CONNECT         0x02
#define SSL_ST_ACCEPT          0x04

#define X509_LU_X509 1
#define X509_LU_CRL  2

#define X509_V_OK                                       SEC_ERROR_CERT_VALID
#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            SEC_ERROR_UNKNOWN_ISSUER
#define X509_V_ERR_UNABLE_TO_GET_CRL                    SEC_ERROR_CRL_NOT_FOUND
#define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     SEC_ERROR_BAD_SIGNATURE
#define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      SEC_ERROR_CRL_BAD_SIGNATURE
#define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   SEC_ERROR_INVALID_KEY
#define X509_V_ERR_CERT_SIGNATURE_FAILURE               SEC_ERROR_BAD_SIGNATURE
#define X509_V_ERR_CRL_SIGNATURE_FAILURE                SEC_ERROR_CRL_BAD_SIGNATURE
#define X509_V_ERR_CERT_NOT_YET_VALID                   SEC_ERROR_CERT_NOT_VALID
#define X509_V_ERR_CERT_HAS_EXPIRED                     SEC_ERROR_EXPIRED_CERTIFICATE
#define X509_V_ERR_CRL_NOT_YET_VALID                    SEC_ERROR_CRL_INVALID
#define X509_V_ERR_CRL_HAS_EXPIRED                      SEC_ERROR_CRL_EXPIRED
#define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       SEC_ERROR_INVALID_TIME
#define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        SEC_ERROR_INVALID_TIME
#define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       SEC_ERROR_INVALID_TIME
#define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       SEC_ERROR_INVALID_TIME
#define X509_V_ERR_OUT_OF_MEM                           SEC_ERROR_NO_MEMORY
#define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          SEC_ERROR_UNTRUSTED_ISSUER
#define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            SEC_ERROR_UNTRUSTED_ISSUER
#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    SEC_ERROR_UNKNOWN_ISSUER
#define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      SEC_ERROR_UNTRUSTED_CERT
#define X509_V_ERR_CERT_CHAIN_TOO_LONG                  SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID
#define X509_V_ERR_CERT_REVOKED                         SEC_ERROR_REVOKED_CERTIFICATE
#define X509_V_ERR_INVALID_CA                           SEC_ERROR_CA_CERT_INVALID
#define X509_V_ERR_PATH_LENGTH_EXCEEDED                 SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID
#define X509_V_ERR_INVALID_PURPOSE                      SEC_ERROR_CERT_USAGES_INVALID
#define X509_V_ERR_CERT_UNTRUSTED                       SEC_ERROR_UNTRUSTED_CERT
#define X509_V_ERR_CERT_REJECTED                        SEC_ERROR_CERT_NOT_VALID
#define X509_V_ERR_SUBJECT_ISSUER_MISMATCH              SEC_ERROR_CERT_ADDR_MISMATCH
#define X509_V_ERR_AKID_SKID_MISMATCH                   SEC_ERROR_INVALID_KEY
#define X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          SEC_ERROR_REUSED_ISSUER_AND_SERIAL
#define X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 SEC_ERROR_CERT_USAGES_INVALID
#define X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             SEC_ERROR_CRL_INVALID
#define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION
#define X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 SEC_ERROR_CRL_INVALID
#define X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     SEC_ERROR_CRL_INVALID
#define X509_V_ERR_INVALID_NON_CA                       SEC_ERROR_CERT_NOT_VALID
#define X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        SEC_ERROR_CRL_BAD_SIGNATURE
#define X509_V_ERR_INVALID_EXTENSION                    SEC_ERROR_EXTENSION_VALUE_INVALID

#define NID_commonName       SEC_OID_AVA_COMMON_NAME
#define NID_subject_alt_name SEC_OID_X509_SUBJECT_ALT_NAME

#define EVP_R_BAD_DECRYPT 1

/* Type mapping ... */

#define SSL_CTX    PRFileDesc
#define SSL        PRFileDesc
#define SSL_METHOD PRFileDesc

#define SSL_SESSION SECItem

typedef struct x509_st
{
    CERTCertificate *cert;
    PLArenaPool     *arena;
} X509;

typedef struct
{
    X509 *current_cert;
    SSL *ssl__;
    int error;
} X509_STORE_CTX;

#define X509_OBJECT    SECItem
#define X509_LOOKUP    SECItem
#define X509_LOOKUP_METHOD SECItem
#define X509_STORE     SECItem
#define X509_NAME      CERTName
#define X509_REVOKED   SECItem
#define X509_CRL       SECItem
#define EVP_PKEY       SECItem

/*
 * BIO stuff
 */
typedef struct bio_method_st BIO_METHOD;

typedef struct bio_st
{
    void *ptr;
    BIO_METHOD *m;
} BIO;

struct bio_method_st
{
    int type;
    const char *name;
    int	   (*bwrite) (BIO *bio,  const char *data, int len);
    int    (*bread)  (BIO *bio, char *data,       int len);
    int    (*bputs)  (BIO *bio, const char *data);
    int    (*bgets)  (BIO *bio, char *data,       int len);
    int    (*ctrl)   (BIO *bio, int, long, void *);
    int    (*create) (BIO *bio);
    int    (*destroy)(BIO *bio);
};

#define BIO_C_GET_FD 207
#define BIO_C_GET_PEERNAME 209

BIO *BIO_new(BIO_METHOD *);
int SSL_set_bio(SSL *, BIO *, BIO *);

typedef struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    long flags;
} ASN1_STRING;

#define ASN1_TIME         ASN1_STRING
#define ASN1_UTCTIME      ASN1_STRING
#define ASN1_INTEGER      ASN1_STRING
#define V_ASN1_UTF8STRING ASN1_STRING

/* ASN1 types */
#define V_ASN1_INTEGER 1
#define V_ASN1_UTCTIME 2

#define STACK_OF(name) void
#define STACK_OF(name) void
#define STACK int

#define SSL_CIPHER PRFileDesc

#define SSL_OP_MICROSOFT_SESS_ID_BUG                    0x00000001L
#define SSL_OP_NETSCAPE_CHALLENGE_BUG                   0x00000002L
#define SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG         0x00000008L
#define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG              0x00000010L
#define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER               0x00000020L
#define SSL_OP_MSIE_SSLV2_RSA_PADDING                   0x00000040L
#define SSL_OP_SSLEAY_080_CLIENT_DH_BUG                 0x00000080L
#define SSL_OP_TLS_D5_BUG                               0x00000100L
#define SSL_OP_TLS_BLOCK_PADDING_BUG                    0x00000200L
#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS              0x00000800L
#define SSL_OP_ALL                                      0x00000FF7L
#define SSL_OP_NO_QUERY_MTU                             0x00001000L
#define SSL_OP_COOKIE_EXCHANGE                          0x00002000L
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   0x00010000L
#define SSL_OP_SINGLE_ECDH_USE                          0x00080000L
#define SSL_OP_SINGLE_DH_USE                            0x00100000L
#define SSL_OP_EPHEMERAL_RSA                            0x00200000L
#define SSL_OP_CIPHER_SERVER_PREFERENCE                 0x00400000L
#define SSL_OP_TLS_ROLLBACK_BUG                         0x00800000L
#define SSL_OP_NO_SSLv2                                 0x01000000L
#define SSL_OP_NO_SSLv3                                 0x02000000L
#define SSL_OP_NO_TLSv1                                 0x04000000L
#define SSL_OP_PKCS1_CHECK_1                            0x08000000L
#define SSL_OP_PKCS1_CHECK_2                            0x10000000L
#define SSL_OP_NETSCAPE_CA_DN_BUG                       0x20000000L
#define SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG          0x40000000L

struct NSS__missing_engine_API;
typedef struct NSS__missing_engine_API NSS__missing_engine_API;

#define ENGINE NSS__missing_engine_API

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

/* Functions ... */

#if 0
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_s_mem(void);

BIO *BIO_new(BIO_METHOD *)
BIO *BIO_new(BIO_METHOD *)
#endif

#if 0
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04
#endif

/* Library initialization */

#define OpenSSL_add_ssl_algorithms() SSL_library_init()
#define SSLeay_add_ssl_algorithms()  SSL_library_init()
#define SSLeay_add_all_algorithms()  SSL_library_init()

int SSL_library_init(void);

/* SSL context handling */

SSL_CTX *SSL_CTX_new(SSL_METHOD *passed);
void SSL_CTX_free(SSL_CTX *s);
int SSL_CTX_set_default_verify_paths (SSL_CTX * ctx);
int SSL_CTX_use_certificate_file (SSL_CTX * ctx, const char *certfile,
                                  int type);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
long SSL_CTX_set_options(SSL_CTX *ctx, long mode);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
                        int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
        const char *CApath);
void SSL_CTX_set_info_callback(SSL_CTX *ctx, void(*cb)());
long SSL_CTX_set_session_cache_mode(SSL_CTX *c, long i);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
int PEM_def_callback(char *buf, int num, int w, void *key);

/* SSL context statistics */

long SSL_CTX_set_timeout(SSL_CTX *s, long tm);
long SSL_CTX_sess_number(SSL_CTX *s);
long SSL_CTX_sess_connect(SSL_CTX *s);
long SSL_CTX_sess_connect_good(SSL_CTX *s);
long SSL_CTX_sess_connect_renegotiate(SSL_CTX *s);
long SSL_CTX_sess_accept(SSL_CTX *s);
long SSL_CTX_sess_accept_good(SSL_CTX *s);
long SSL_CTX_sess_accept_renegotiate(SSL_CTX *s);
long SSL_CTX_sess_hits(SSL_CTX *s);
long SSL_CTX_sess_misses(SSL_CTX *s);
long SSL_CTX_sess_timeouts(SSL_CTX *s);

/* SSL structure handling */

SSL *SSL_new(SSL_CTX *templ_s);
void SSL_free(SSL *s);
void SSL_load_error_strings(void);
int SSL_get_error(SSL *s, int i);
int SSL_set_fd(SSL *s, int fd);
int SSL_set_rfd(SSL *s, int fd);
int SSL_set_wfd(SSL *s, int fd);
void SSL_set_connect_state(SSL *s);
void SSL_set_accept_state(SSL *s);
void SSL_set_verify(SSL *s, int mode,
                    int (*callback)(int ok,X509_STORE_CTX *ctx));
long SSL_get_verify_result(const SSL *ssl);

#define OPENSSL_free(addr) CRYPTO_free(addr)
void CRYPTO_free(void *);
void CRYPTO_cleanup_all_ex_data(void);

/* SSL basic I/O functions */

int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_pending(SSL *s);
int SSL_read(SSL *, void *, int); 
int SSL_write(SSL *, const void *, int); 
int SSL_shutdown(SSL *s);
int SSL_get_shutdown(SSL *s);
int SSL_set_shutdown(SSL *ssl, int flags);
int SSL_want(SSL *s);
int SSL_peek(SSL *ssl, void *buf, int num);

#define SSL_NOTHING     1
#define SSL_WRITING     2
#define SSL_READING     3
#define SSL_X509_LOOKUP 4

#define SSL_want_nothing(s) (SSL_want(s) == SSL_NOTHING)
#define SSL_want_read(s) (SSL_want(s) == SSL_READING)
#define SSL_want_write(s) (SSL_want(s) == SSL_WRITING)
#define SSL_want_x509_lookup(s) (SSL_want(s) == SSL_X509_LOOKUP)

/* SSL_METHOD */

SSL_METHOD *SSLv2_client_method(void);
SSL_METHOD *SSLv3_client_method(void);
SSL_METHOD *SSLv23_client_method(void);
SSL_METHOD *TLSv1_client_method(void);
SSL_METHOD *SSLv2_server_method(void);
SSL_METHOD *SSLv23_server_method(void);
SSL_METHOD *SSLv3_server_method(void);
SSL_METHOD *TLSv1_server_method(void);

/* Cipher functions */

SSL_CIPHER *SSL_get_current_cipher(SSL *s);
void SSL_CIPHER_description(SSL_CIPHER *c, char *s, int len);
const char *SSL_CIPHER_get_name(SSL_CIPHER *c);
int SSL_CIPHER_get_bits(SSL_CIPHER *c, int *bits);
char *SSL_CIPHER_get_version(SSL_CIPHER *c);
#define SSL_get_cipher(s) \
               SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_cipher_name(s) \
               SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_cipher_bits(s,np) \
               SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)
#define SSL_get_cipher_version(s) \
               SSL_CIPHER_get_version(SSL_get_current_cipher(s))


/* X509 */
#define X509_L_FILE_LOAD        1
#define X509_L_ADD_DIR          2

#define X509_LU_X509            1

X509 *d2i_X509(void *reserved, unsigned char **data, int len);
X509_NAME *X509_get_issuer_name(X509 *x);
X509_NAME *X509_get_subject_name(X509 *x);
void *X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx);
ASN1_TIME *X509_get_notBefore(X509 *x);
ASN1_TIME *X509_get_notAfter(X509 *x);
ASN1_INTEGER * X509_get_serialNumber(X509 *x);
char *i2s_ASN1_INTEGER(void *, ASN1_INTEGER *);
X509 *SSL_get_certificate(SSL *ssl);
X509 *SSL_get_peer_certificate(SSL *s);
const char *X509_verify_cert_error_string(long n);
int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf,int len);

#define X509_LOOKUP_load_file(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

#define X509_LOOKUP_add_dir(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(long)(type),NULL)

X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
int X509_STORE_get_by_subject(X509_STORE_CTX *vs, int type, X509_NAME *name,
                              X509_OBJECT *ret);
int SSL_get_ex_data_X509_STORE_CTX_idx(void);
void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx);

/* Other */

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);

char *X509_NAME_oneline(X509_NAME *x, char *s, int len);
void X509_free(X509 *x);
char *SSL_get_version(SSL *ssl);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
        const char *CApath);

/* Error handling */

#define ERR_GET_REASON(l)       (int)((l)&0xfffL)
unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);
char *ERR_error_string_n(unsigned long e, char *buf, size_t len);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_last_error(void);
void ERR_remove_state(unsigned long pid);
void ERR_free_strings(void);
void EVP_cleanup(void);

/* Callback types for crypto.h */

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

struct crypto_ex_data_st
        {
        void *sk;
        int dummy; /* gcc is screwing up this data structure :-( */
        };

typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                        int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                        int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
                                        int idx, long argl, void *argp);


int SSL_set_ex_data(SSL *ssl,int idx,void *data);
void *SSL_get_ex_data(const SSL *ssl,int idx);
int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

int SSL_set_session_id_context(SSL *ssl,
                                             const unsigned char *sid_ctx,
                                             unsigned int sid_ctx_len);

SSL_SESSION *SSL_get_session(SSL *ssl);
#define SSL_get0_session(s) SSL_get_session(s)
#define SSL_get1_session(s) SSL_get_session(s)
int SSL_set_session(SSL *to, SSL_SESSION *session);
long SSL_session_reused(SSL *s);
void SSL_SESSION_free(SSL_SESSION *sess);

#if 0
int ENGINE_init(ENGINE *);

void ENGINE_register_all_complete(void);

int ENGINE_set_default(ENGINE *, int);

ENGINE *ENGINE_by_id(const char *);

int ENGINE_ctrl_cmd_string(ENGINE *, const char *, const char *, const char *);

void ENGINE_finish(ENGINE *);
void ENGINE_free(ENGINE *);
#endif

const char *SSL_alert_type_string_long(int value);
const char *SSL_alert_desc_string_long(int value);

const char *SSL_state_string_long(const SSL *s);

void CRYPTO_set_id_callback(unsigned long (*func)(void));
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
                                              const char *file, int line));

/* RNG */

#define RAND_bytes(b,n) PK11_GenerateRandom(b,n)
#define RAND_pseudo_bytes(b,n) PK11_GenerateRandom(b,n)
void RAND_add(const void *buf, int num, double entropy);
int RAND_status(void);
void RAND_seed(const void *buf, int num);
int RAND_load_file(const char *file, long max_bytes);
int RAND_write_file(const char *file);
const char *RAND_file_name(char *file, size_t num);
int RAND_egd(const char *path);

const char *nss_error(int error);

/* ASN1 funcs */
unsigned char * ASN1_STRING_data(ASN1_STRING *x);
int ASN1_STRING_type(ASN1_STRING *x);
int ASN1_STRING_length(ASN1_STRING *x);

#endif /* NSS_COMPAT_OSSL_H */
