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

#include <unistd.h>
#include <stdio.h>
#include "nss_compat_ossl.h"
#include <secder.h>
#include <secmod.h>
#include <termios.h> /* for echo on/off */
#include <sys/stat.h>
#include <errno.h>
#include <private/pprio.h>

typedef struct {
    PRFileDesc         *pssl;
    PRBool              server;
    int                 shutdown_flags;
    PLHashTable        *appdata;
    int                 error;
    long                session_timeout;
    int                 verify_mode;
    int                 verify_result;
    void               *info_cb;
    void               *verify_cb;
    PLArenaPool        *arena;
    CK_SLOT_ID          slotID;
    char               *nickname;
    char               *slotname;
} ossl_ctx_t;

#define PK11_SETATTRS(x,id,v,l) (x)->type = (id); \
                (x)->pValue=(v); (x)->ulValueLen = (l);

#define CERT_NewTempCertificate __CERT_NewTempCertificate

/* functions for handling token passwords */
static char * nss_password_prompt(PK11SlotInfo *slot, PRBool retry, void *arg);
static char * nss_no_password(PK11SlotInfo *slot, PRBool retry, void *arg);
static char * nss_get_password(FILE *input, FILE *output, PK11SlotInfo *slot, PRBool (*ok)(unsigned char *), PRUint32 retry);
static PRBool nss_check_password(unsigned char *cp);
static void echoOff(int fd);
static void echoOn(int fd);

/* Global variables for the NSPR I/O layer */
static PRDescIdentity    gIdentity = PR_INVALID_IO_LAYER;
static PRDescIdentity    gBioIdentity = PR_INVALID_IO_LAYER;
static PRIOMethods       gMethods;
static PRIOMethods       gBioMethods;

/* Global for the password prompt */
static char * prompt;

/* Global for per-application data storage */
static int ex_data_index = 0;

/* Declarations for functions to handle per-connection data */
static ossl_ctx_t * nss_get_private(PRFileDesc *fd);
static int nss_set_private(PRFileDesc *fd, PRFilePrivate *data);

int is_initialized = 0;
static const char* pem_library = "libnsspem.so";
static const char* root_certs_library = "libnssckbi.so";

static SECMODModule* pemMod = NULL;
static SECMODModule* rootMod = NULL;
CK_SLOT_ID slotCount = 1;

#define DEF_SSL2_TIMEOUT        100L  /* seconds */
#define DEF_SSL3_TIMEOUT      86400L  /* 24 hours */

/* Cipher definitions */
typedef struct
{
    char *ossl_name;    /* The OpenSSL cipher name */
    int num;            /* The cipher id */
    int attr;           /* cipher attributes: algorithms, etc */
    int version;        /* protocol version valid for this cipher */
    int bits;           /* bits of strength */
    int alg_bits;       /* bits of the algorithm */
    int strength;       /* LOW, MEDIUM, HIGH */
    int enabled;        /* Enabled by default? */
    int client_only;    /* Allowed only on clients */
} cipher_properties;

#define ciphernum 22

/* Some local cipher definitions I don't want to share with apps */

/* cipher attributes  */
#define SSL_kRSA  0x00000001L
#define SSL_aRSA  0x00000002L
#define SSL_aDSS  0x00000004L
#define SSL_DSS   SSL_aDSS
#define SSL_eNULL 0x00000008L
#define SSL_DES   0x00000010L
#define SSL_3DES  0x00000020L
#define SSL_RC4   0x00000040L
#define SSL_RC2   0x00000080L
#define SSL_AES   0x00000100L
#define SSL_MD5   0x00000200L
#define SSL_SHA1  0x00000400L
#define SSL_SHA   SSL_SHA1
#define SSL_RSA   (SSL_kRSA|SSL_aRSA)
#define SSL_kEDH  0x00000800L
#define SSL_EDH   (SSL_kEDH)

/* cipher strength */
#define SSL_NULL      0x00000001L
#define SSL_EXPORT40  0x00000002L
#define SSL_EXPORT56  0x00000004L
#define SSL_LOW       0x00000008L
#define SSL_MEDIUM    0x00000010L
#define SSL_HIGH      0x00000020L

#define SSL2  0x00000001L
#define SSL3  0x00000002L
/* OpenSSL treats SSL3 and TLSv1 the same */
#define TLS1  SSL3

/* Cipher translation */
static cipher_properties ciphers_def[ciphernum] =
{
    /* SSL 2 ciphers */
    {"DES-CBC3-MD5", SSL_EN_DES_192_EDE3_CBC_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_MD5, SSL2, 168, 168, SSL_HIGH, SSL_ALLOWED, PR_FALSE},
    {"RC2-CBC-MD5", SSL_EN_RC2_128_CBC_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSL2, 128, 128, SSL_MEDIUM, SSL_ALLOWED, PR_FALSE},
    {"RC4-MD5", SSL_EN_RC4_128_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSL2, 128, 128, SSL_MEDIUM, SSL_ALLOWED, PR_FALSE},
    {"DES-CBC-MD5", SSL_EN_DES_64_CBC_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_DES|SSL_MD5, SSL2, 56, 56, SSL_LOW, SSL_ALLOWED, PR_FALSE},
    {"EXP-RC2-CBC-MD5", SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSL2, 40, 128, SSL_EXPORT40, SSL_ALLOWED, PR_FALSE},
    {"EXP-RC4-MD5", SSL_EN_RC4_128_EXPORT40_WITH_MD5, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSL2, 40, 128, SSL_EXPORT40, SSL_ALLOWED, PR_FALSE},

    /* SSL3 ciphers */
    {"RC4-MD5", SSL_RSA_WITH_RC4_128_MD5, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSL3, 128, 128, SSL_MEDIUM, SSL_ALLOWED, PR_FALSE},
    {"RC4-SHA", SSL_RSA_WITH_RC4_128_SHA, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA1, SSL3, 128, 128, SSL_MEDIUM, SSL_NOT_ALLOWED, PR_FALSE},
    {"DES-CBC3-SHA", SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL_kRSA|SSL_aRSA|SSL_3DES|SSL_SHA1, SSL3, 168, 168, SSL_HIGH, SSL_ALLOWED, PR_FALSE},
    {"DES-CBC-SHA", SSL_RSA_WITH_DES_CBC_SHA, SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1, SSL3, 56, 56, SSL_LOW, SSL_ALLOWED, PR_FALSE},
    {"EXP-RC4-MD5", SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5, SSL3, 40, 128, SSL_EXPORT40, SSL_ALLOWED, PR_FALSE},
    {"EXP-RC2-CBC-MD5", SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5, SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5, SSL3, 0, 0, SSL_EXPORT40, SSL_ALLOWED, PR_FALSE},
    {"NULL-MD5", SSL_RSA_WITH_NULL_MD5, SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_MD5, SSL3, 0, 0, SSL_NULL, SSL_NOT_ALLOWED, PR_FALSE},
    {"NULL-SHA", SSL_RSA_WITH_NULL_SHA, SSL_kRSA|SSL_aRSA|SSL_eNULL|SSL_SHA1, SSL3, 0, 0, SSL_NULL, SSL_NOT_ALLOWED, PR_FALSE},

    /* TLSv1 ciphers */
    {"EXP1024-DES-CBC-SHA", TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA, TLS1, 56, 56, SSL_EXPORT56, SSL_ALLOWED, PR_FALSE},
    {"EXP1024-RC4-SHA", TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA, TLS1, 56, 56, SSL_EXPORT56, SSL_ALLOWED, PR_FALSE},
    {"AES128-SHA", TLS_RSA_WITH_AES_128_CBC_SHA, SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA, TLS1, 128, 128, SSL_HIGH, SSL_ALLOWED, PR_FALSE},
    {"AES256-SHA", TLS_RSA_WITH_AES_256_CBC_SHA, SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA, TLS1, 256, 256, SSL_HIGH, SSL_ALLOWED, PR_FALSE},

    /* Diffie-Hellman ciphers for clients only */
    {"DHE-DSS-AES256-SHA", TLS_DH_DSS_WITH_AES_256_CBC_SHA, SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA, TLS1, 256, 256, SSL_HIGH, SSL_ALLOWED, PR_TRUE},
    {"DHE-RSA-AES256-SHA", TLS_RSA_WITH_AES_256_CBC_SHA, SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA, TLS1, 256, 256, SSL_HIGH, SSL_ALLOWED, PR_TRUE},
    {"DHE-DSS-AES128-SHA",TLS_DHE_DSS_WITH_AES_128_CBC_SHA,  SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA, TLS1, 128, 128, SSL_HIGH, SSL_ALLOWED, PR_TRUE},
    {"DHE-RSA-AES128-SHA",TLS_DHE_RSA_WITH_AES_128_CBC_SHA,  SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA, TLS1, 128, 128, SSL_HIGH, SSL_ALLOWED, PR_TRUE},

};

/*
 * cipher_list is an integer array with the following values:
 *   -1: never enable this cipher
 *    0: cipher disabled
 *    1: cipher enabled
 */
int nss_parse_ciphers(const char *cipherstr, int cipher_list[ciphernum])
{
    int i;
    char *cipher;
    char *ciphers;
    char *ciphertip;
    int action;
    int rv;

    /* All disabled to start */
    for (i=0; i<ciphernum; i++)
        cipher_list[i] = 0;

    ciphertip = strdup(cipherstr);
    cipher = ciphers = ciphertip;

    while (ciphers && (strlen(ciphers)))
    {
        while ((*cipher) && (isspace(*cipher)))
            ++cipher;

        action = 1;
        switch(*cipher)
        {
            case '+': /* Add something */
                action = 1;
                cipher++;
                break;
            case '-': /* Subtract something */
                action = 0;
                cipher++;
                break;
            case '!':  /* Disable something */
                action = -1;
                cipher++;
                break;
            default:
               /* do nothing */
                break;
        }

        if ((ciphers = strchr(cipher, ':'))) {
            *ciphers++ = '\0';
        }

        /* Do the easy one first */
        if (!strcmp(cipher, "ALL")) {
            for (i=0; i<ciphernum; i++) {
                if (!(ciphers_def[i].attr & SSL_eNULL))
                    cipher_list[i] = action;
            }
        } else if (!strcmp(cipher, "COMPLEMENTOFALL")) {
            for (i=0; i<ciphernum; i++) {
                if ((ciphers_def[i].attr & SSL_eNULL))
                    cipher_list[i] = action;
            }
        } else if (!strcmp(cipher, "DEFAULT")) {
            for (i=0; i<ciphernum; i++) {
                cipher_list[i] = ciphers_def[i].enabled == SSL_ALLOWED ? 1 : 0;
            }
        } else {
            int mask = 0;
            int strength = 0;
            int protocol = 0;
            char *c;

            c = cipher;
            while (c && (strlen(c))) {

                if ((c = strchr(cipher, '+'))) {
                    *c++ = '\0';
                }

                if (!strcmp(cipher, "RSA")) {
                    mask |= SSL_RSA;
                } else if (!strcmp(cipher, "EDH")) {
                    mask |= SSL_EDH;
                } else if ((!strcmp(cipher, "NULL")) || (!strcmp(cipher, "eNULL"))) {
                    mask |= SSL_eNULL;
                } else if (!strcmp(cipher, "AES")) {
                    mask |= SSL_AES;
                } else if (!strcmp(cipher, "3DES")) {
                    mask |= SSL_3DES;
                } else if (!strcmp(cipher, "DES")) {
                    mask |= SSL_DES;
                } else if (!strcmp(cipher, "RC4")) {
                    mask |= SSL_RC4;
                } else if (!strcmp(cipher, "RC2")) {
                    mask |= SSL_RC2;
                } else if (!strcmp(cipher, "MD5")) {
                    mask |= SSL_MD5;
                } else if ((!strcmp(cipher, "SHA")) || (!strcmp(cipher, "SHA1"))) {
                    mask |= SSL_SHA1;
                } else if (!strcmp(cipher, "SSLv2")) {
                    protocol |= SSL2;
                } else if (!strcmp(cipher, "SSLv3")) {
                    protocol |= SSL3;
                } else if (!strcmp(cipher, "TLSv1")) {
                    protocol |= TLS1;
                } else if (!strcmp(cipher, "HIGH")) {
                    strength |= SSL_HIGH;
                } else if (!strcmp(cipher, "MEDIUM")) {
                    strength |= SSL_MEDIUM;
                } else if (!strcmp(cipher, "LOW")) {
                    strength |= SSL_LOW;
                } else if ((!strcmp(cipher, "EXPORT")) || (!strcmp(cipher, "EXP"))) {
                    strength |= SSL_EXPORT40|SSL_EXPORT56;
                } else if (!strcmp(cipher, "EXPORT40")) {
                    strength |= SSL_EXPORT40;
                } else if (!strcmp(cipher, "EXPORT56")) {
                    strength |= SSL_EXPORT56;
                }

                if (c)
                    cipher = c;

            } /* while */

            /* If we have a mask, apply it. If not then perhaps they provided
             * a specific cipher to enable.
             */
            if (mask || strength || protocol) 
                for (i=0; i<ciphernum; i++) {
                    if (((ciphers_def[i].attr & mask) ||
                     (ciphers_def[i].strength & strength) ||
                     (ciphers_def[i].version & protocol)) &&
                     (cipher_list[i] != -1)) {
                        /* Enable the NULL ciphers only if explicity
                         * requested */
                        if (ciphers_def[i].attr & SSL_eNULL) {
                            if (mask & SSL_eNULL)
                                cipher_list[i] = action;
                        } else
                            cipher_list[i] = action;
                    }
                }
            else {
                for (i=0; i<ciphernum; i++) {
                    if (!strcmp(ciphers_def[i].ossl_name, cipher) &&
                        cipher_list[1] != -1)
                        cipher_list[i] = action;
                }
            }
        }

        if (ciphers)
            cipher = ciphers;
   
    }

    /* See if any ciphers were enabled */
    rv = 0;
    for (i=0; i<ciphernum; i++) {
        if (cipher_list[i] == 1)
            rv = 1;
    }

    free(ciphertip);

    return rv;
}

static PRStatus PR_CALLBACK
layer_close(PRFileDesc *fd)
{
    return PR_SUCCESS;
}


/* Hashing function for application-specific data (ex_data). */
static PLHashNumber HashFunc(const void * key)
{
   return (PLHashNumber) key;
}

ossl_ctx_t *new_ossl(PRFileDesc *s)
{
    ossl_ctx_t *ossl;

    ossl = (ossl_ctx_t *)malloc(sizeof(ossl_ctx_t));

    ossl->pssl = (PRFileDesc *)s;
    ossl->shutdown_flags = 0;
    ossl->appdata = PL_NewHashTable(10, HashFunc, PL_CompareValues, PL_CompareValues, NULL, NULL);;
    ossl->slotID = -1;
    ossl->slotname = NULL;
    ossl->error = 0;
    ossl->session_timeout = -1;
    ossl->verify_mode = 0;
    ossl->verify_result = 0;
    ossl->server = 0;
    ossl->info_cb = NULL;
    ossl->verify_cb = NULL;
    ossl->arena = PORT_NewArena(1024); /* This size is arbitrary */
    ossl->nickname = NULL;

    return ossl;
}

int free_ossl(ossl_ctx_t *ossl)
{
    if (!ossl)
        return 0;

    PL_HashTableDestroy(ossl->appdata);

    PORT_FreeArena(ossl->arena, PR_FALSE);

    free(ossl);

    return 0;
}

SECStatus
BadCertHandler(void *arg, PRFileDesc *ssl)
{
    SECStatus success = SECSuccess;
    PRErrorCode err;
    ossl_ctx_t *ossl;

    if (!ssl) {
        return SECFailure;
    }

    ossl = nss_get_private(ssl);

    err = PORT_GetError();

    switch (err) {
    case SEC_ERROR_CERT_VALID:
    case SSL_ERROR_BAD_CERT_DOMAIN: /* We don't set set the hostname so we can
                                     * safely ignore this. In OpenSSL the
                                     * caller is responsible. */
        err = X509_V_OK;
        break;   
    /* let the handshake continue unless otherwise specified */
    case SEC_ERROR_UNTRUSTED_ISSUER:
    case SEC_ERROR_UNKNOWN_ISSUER:
    case SEC_ERROR_EXPIRED_CERTIFICATE:
        if (ossl->verify_mode & SSL_VERIFY_PEER)
            success = SECFailure;
        break;
    default:
        /* FIXME: There must be some circumstances where the handshake will
         * fail?
         */
        success = SECFailure;
        break;
    }

    ossl->verify_result = err;

    return success;
}

SECStatus
AuthCertificateHandler(void *arg, PRFileDesc *ssl,
                       PRBool checksig, PRBool isServer)
{
    ossl_ctx_t *ossl;
    int rv;
    SECStatus status;
    int (*verify_callback)(int preverify_ok, X509_STORE_CTX *x509_ctx);

    ossl = nss_get_private(ssl);

    status = SSL_AuthCertificate(arg, ssl, checksig, isServer);

    /* If the user has requested their own verification callback them
     * use it. Otherwise fall back to the one provided by NSS.
     */
    if (ossl->verify_cb != NULL) {
	X509_STORE_CTX ctx;

        verify_callback = ossl->verify_cb;

	ctx.current_cert = SSL_get_peer_certificate(ssl);
	ctx.error = PORT_GetError();
        rv = verify_callback((status == SECSuccess) ? 1 : 0, &ctx);
	X509_free(ctx.current_cert);

        if (rv == 1) {
            ossl->verify_result = X509_V_OK;
            return SECSuccess;
        } else {
            ossl->verify_result = PR_GetError();
            return SECFailure;
        }
    } 

    return status;
}

/*
 * Duplicated, non-exported function from NSS that compares 2 certificate
 * times.
 */
PRBool
cert_IsNewer(CERTCertificate *certa, CERTCertificate *certb)
{
    PRTime notBeforeA, notAfterA, notBeforeB, notAfterB, now;
    SECStatus rv;
    PRBool newerbefore, newerafter;

    newerbefore = newerafter = PR_FALSE;

    rv = CERT_GetCertTimes(certa, &notBeforeA, &notAfterA);
    if ( rv != SECSuccess ) {
        return(PR_FALSE);
    }

    rv = CERT_GetCertTimes(certb, &notBeforeB, &notAfterB);
    if ( rv != SECSuccess ) {
        return(PR_TRUE);
    }

    if ( LL_CMP(notBeforeA, >, notBeforeB) ) {
        newerbefore = PR_TRUE;
    }

    if ( LL_CMP(notAfterA, >, notAfterB) ) {
        newerafter = PR_TRUE;
    }

    if ( newerbefore && newerafter ) {
        return(PR_TRUE);
    }

    if ( ( !newerbefore ) && ( !newerafter ) ) {
        return(PR_FALSE);
    }

    /* get current UTC time */
    now = PR_Now();

    if ( newerbefore ) {
        /* cert A was issued after cert B, but expires sooner */
        /* if A is expired, then pick B */ 
        if ( LL_CMP(notAfterA, <, now ) ) {
            return(PR_FALSE);
        }
        return(PR_TRUE);
    } else {
        /* cert B was issued after cert A, but expires sooner */
        /* if B is expired, then pick A */
        if ( LL_CMP(notAfterB, <, now ) ) {
            return(PR_TRUE);
        }
        return(PR_FALSE);
    }
}

/*
 * Given a nickname, find the "best" certificate available for that
 * certificate (for the case of multiple CN's with different usages, a
 * renewed cert that is not yet valid, etc). The best is defined as the
 * newest, valid server certificate.
 */
CERTCertificate*
FindServerCertFromNickname(const char* name)
{
    CERTCertList* clist;
    CERTCertificate* bestcert = NULL;

    CERTCertListNode *cln;
    PRUint32 bestCertMatchedUsage = 0;
    PRBool bestCertIsValid = PR_FALSE;

    if (name == NULL)
        return NULL;

    clist = PK11_ListCerts(PK11CertListUser, NULL);

    for (cln = CERT_LIST_HEAD(clist); !CERT_LIST_END(cln,clist);
        cln = CERT_LIST_NEXT(cln)) {
        CERTCertificate* cert = cln->cert;
        const char* nickname = (const char*) cln->appData;
        if (!nickname) {
            nickname = cert->nickname;
        }
        if (strcmp(name, nickname) == 0) {
            PRUint32 matchedUsage = 0;
            PRBool isValid = PR_FALSE;
            PRBool swapcert = PR_FALSE;
            /* We still need to check key usage. Dual-key certs appear
             * as 2 certs in the list with different usages. We want to pick
             * the "best" one, preferrably the one with certUsageSSLServer.
             * Otherwise just return the cert if the nickname matches.
             */
            if (CERT_CheckCertUsage(cert, certUsageSSLServer) == SECSuccess) {
                matchedUsage = 2;
            } else {
                if (CERT_CheckCertUsage(cert, certUsageEmailRecipient) == SECSuccess)
                {
                    matchedUsage = 1;
                }
            } 

            if (secCertTimeValid == CERT_CheckCertValidTimes(cert, PR_Now(), PR_FALSE))
            {
                /* This is a valid certificate. */
                isValid = PR_TRUE;
            }
            if (!bestcert) {
                /* We didn't have a cert picked yet, automatically choose this
                 * one.
                 */
                swapcert = PR_TRUE;
            } else {
                if (matchedUsage > bestCertMatchedUsage) {
                    /* The cert previously picked didn't have the correct
                     * usage, but this one does. Choose this one.
                     */
                    swapcert = PR_TRUE;
                } else {
                    if ( (bestCertMatchedUsage == matchedUsage) &&
                    (((PR_FALSE == bestCertIsValid) && (PR_TRUE == isValid)) ||
                    ((PR_TRUE == bestCertIsValid == isValid) && (PR_TRUE == cert_IsNewer(cert, bestcert))))) {
                        /* The cert previously picked was invalid but this one
                         * is. Or they were both valid but this one is newer.
                         */
                        swapcert = PR_TRUE;
                    }
                }
            }

            if (swapcert == PR_TRUE)
            {
                bestcert = cert;
                bestCertMatchedUsage = matchedUsage;
                bestCertIsValid = isValid;
            }
        }
    }
    if (bestcert) {
        bestcert = CERT_DupCertificate(bestcert); 
    }
    if (clist) {
        CERT_DestroyCertList(clist);
    }
    return bestcert;
}

/*
 * Executed automatically when the SSL handshake is completed.
 * Call the final handshake callback if one was set.
 */
SECStatus nss_HandshakeCallback(PRFileDesc *ssl, void *arg)
{
    ossl_ctx_t *ossl;
    void (*info_callback)(const SSL *ssl, int type, int val);

    ossl = nss_get_private(ssl);

    info_callback = ossl->info_cb;

    if (info_callback)
        info_callback(ssl, SSL_CB_HANDSHAKE_DONE, 1);

    return SECSuccess;
}

SECStatus nss_Init_Tokens()
{
    PK11SlotList        *slotList;
    PK11SlotListElement *listEntry;
    SECStatus ret, status = SECSuccess;
    int retryCount = 0;

    PK11_SetPasswordFunc(nss_password_prompt);

    slotList = PK11_GetAllTokens(CKM_INVALID_MECHANISM, PR_FALSE, PR_TRUE, NULL);

    for (listEntry = PK11_GetFirstSafe(slotList);
        listEntry;
        listEntry = listEntry->next)
    {
        PK11SlotInfo *slot = listEntry->slot;

        if (PK11_NeedLogin(slot) && PK11_NeedUserInit(slot)) {
#if 0
            if (slot == PK11_GetInternalKeySlot()) {
                log("The server key database has not been initialized.");
            } else {
                log("The token %s has not been initialized.", PK11_GetTokenName(slot));
            }
#endif
            PK11_FreeSlot(slot);
            continue;
        }

        ret = PK11_Authenticate(slot, PR_TRUE, &retryCount);
        if (SECSuccess != ret) {
#if 0
            log("Password for slot %s is incorrect.", PK11_GetTokenName(slot));
#endif
            PK11_FreeSlot(slot);
            return SECFailure;
        }
        retryCount = 0; /* reset counter to 0 for the next token */
        PK11_FreeSlot(slot);
    }

#if 0
    /*
     * reset NSS password callback to blank, so that the server won't prompt
     * again after initialization is done.
     */
    PK11_SetPasswordFunc(nss_no_password);
#endif

    return status;
}

/*
 * Wrapper callback function that prompts the user for the token password
 * up to 3 times.
 */
static char *
nss_password_prompt(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char *passwd = NULL;
    int *pRetryCount = (int *)arg;

    if (pRetryCount && retry) {
        (*pRetryCount)++;
    }
    prompt = PR_smprintf("Please enter password for \"%s\" token:", PK11_GetTokenName(slot));
    if (pRetryCount == NULL) {
        /* should not happen */
        passwd = nss_get_password(stdin, stdout, slot, nss_check_password, 0);
    } else {
        if (*pRetryCount > 2) {
            passwd = NULL; /* abort after 2 retries (3 failed attempts) */
        } else {
            passwd = nss_get_password(stdin, stdout, slot, nss_check_password, *pRetryCount);
        }
    }

    return passwd;
}

static PRBool nss_check_password(unsigned char *cp)
{
    unsigned int i;
    int nchar = 0;      /* number of characters */
    int ntrail = 0;     /* number of trailing bytes to follow */
    int ndigit = 0;     /* number of decimal digits */
    int nlower = 0;     /* number of ASCII lowercase letters */
    int nupper = 0;     /* number of ASCII uppercase letters */
    int nnonalnum = 0;  /* number of ASCII non-alphanumeric characters */
    int nnonascii = 0;  /* number of non-ASCII characters */
    int nclass;         /* number of character classes */
    int ulPinLen;

    ulPinLen = strlen((char *)cp);

    /* We'll give non-FIPS users a pass */
    if (!PK11_IsFIPS())
        return PR_TRUE;

    for (i = 0; i < ulPinLen; i++) {
        unsigned int byte = cp[i];

        if (ntrail) {
            if ((byte & 0xc0) != 0x80) {
                /* illegal */
                nchar = -1;
                break;
            }
            if (--ntrail == 0) {
                nchar++;
                nnonascii++;
            }
            continue;
        }
        if ((byte & 0x80) == 0x00) {
            /* single-byte (ASCII) character */
            nchar++;
            if (isdigit(byte)) {
                if (i < ulPinLen - 1) {
                    ndigit++;
                }
            } else if (islower(byte)) {
                nlower++;
            } else if (isupper(byte)) {
                if (i > 0) {
                    nupper++;
                }
            } else {
                nnonalnum++;
            }
        } else if ((byte & 0xe0) == 0xc0) {
            /* leading byte of two-byte character */
            ntrail = 1;
        } else if ((byte & 0xf0) == 0xe0) {
            /* leading byte of three-byte character */
            ntrail = 2;
        } else if ((byte & 0xf8) == 0xf0) {
            /* leading byte of four-byte character */
            ntrail = 3;
        } else {
            /* illegal */
            nchar = -1;
            break;
        }
    }

    if (nchar == -1) {
        /* illegal UTF8 string */
        return PR_FALSE;
    }
    if (nchar < 7) {
        return PR_FALSE;
    }
    nclass = (ndigit != 0) + (nlower != 0) + (nupper != 0) +
             (nnonalnum != 0) + (nnonascii != 0);
    if (nclass < 3) {
        return PR_FALSE;
    }
    return PR_TRUE;
}

/*
 * Password callback so the user is not prompted to enter the password
 * after the server starts.
 */
static char * nss_no_password(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    return NULL;
}

/*
 * Password callback to prompt the user for a password. This requires
 * twiddling with the tty. Alternatively, if the file password.conf
 * exists then it may be used to store the token password(s).
 */
static char *nss_get_password(FILE *input, FILE *output,
                                       PK11SlotInfo *slot,
                                       PRBool (*ok)(unsigned char *),
                                       PRUint32 retry)
{
    char *token_name = NULL;
#ifdef RETRIEVE_PASSWORD_FROM_FILE
    int tmp;
    char *pwdstr = NULL;
    FILE *pwd_fileptr;
    char *ptr;
    char line[1024];
#endif
    unsigned char phrase[200];
    int infd = fileno(input);
    int isTTY = isatty(infd);

    token_name = PK11_GetTokenName(slot);

#ifdef RETRIEVE_PASSWORD_FROM_FILE
        /* Try to get the passwords from the password file if it exists.
         * THIS IS UNSAFE and is provided for convenience only. Without this
         * capability the server would have to be started in foreground mode.
         */
        if ((*parg->mc->pphrase_dialog_path != '\0') &&
           ((pwd_fileptr = fopen(parg->mc->pphrase_dialog_path, "r")) != NULL)) {
            while(fgets(line, 1024, pwd_fileptr)) {
                if (PL_strstr(line, token_name) == line) {
                    tmp = PL_strlen(line) - 1;
                    while((line[tmp] == ' ') || (line[tmp] == '\n'))
                        tmp--;
                    line[tmp+1] = '\0';
                    ptr = PL_strchr(line, ':');
                    if (ptr == NULL) {
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                           "Malformed password entry for token %s. Format should be token:password", token_name);
                        continue;
                    }
                    for(tmp=1; ptr[tmp] == ' '; tmp++) {}
                    pwdstr = strdup(&(ptr[tmp]));
                }
            }
            fclose(pwd_fileptr);
        } else {
            log_error("Unable to open password file %s", parg->mc->pphrase_dialog_path);
        }
    }
#endif

    for (;;) {
        /* Prompt for password */
        if (isTTY) {
            if (retry > 0) {
                fprintf(output, "Password incorrect. Please try again.\n");
            }
            fprintf(output, "%s", prompt);
            echoOff(infd);
        }
        fgets((char*) phrase, sizeof(phrase), input);
        if (isTTY) {
            fprintf(output, "\n");
            echoOn(infd);
        }
        /* stomp on newline */
        phrase[strlen((char*)phrase)-1] = 0;

        /* Validate password */
        if (!(*ok)(phrase)) {
            /* Not weird enough */
            if (!isTTY) return 0;
            fprintf(output, "Password must be at least 7 characters long with a mix\n");
            fprintf(output, "of upper-case, lower-case, digits, punctuation and\n");
            fprintf(output, "non-ASCII characters.\n");
            continue;
        }
        return (char*) PORT_Strdup((char*)phrase);
    }
}

/*
 * Turn the echoing off on a tty.
 */
static void echoOff(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag &= ~ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

/*
 * Turn the echoing on on a tty.
 */
static void echoOn(int fd)
{
    if (isatty(fd)) {
        struct termios tio;
        tcgetattr(fd, &tio);
        tio.c_lflag |= ECHO;
        tcsetattr(fd, TCSAFLUSH, &tio);
        tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

/**
 *
 * Callback to pick the SSL client certificate.
 */
SECStatus nss_SelectClientCert(void *arg, PRFileDesc * fd,
                               struct CERTDistNamesStr * caNames,
                               struct CERTCertificateStr ** pRetCert,
                               struct SECKEYPrivateKeyStr ** pRetKey)
{
    CERTCertificate *cert;
    SECKEYPrivateKey *privKey;
    ossl_ctx_t *ossl = (ossl_ctx_t *)arg;
    void *proto_win = NULL;
    SECStatus secStatus = SECFailure;

    proto_win = SSL_RevealPinArg(fd);

    cert = PK11_FindCertFromNickname(ossl->nickname, proto_win);
    if (cert) {
        if (ossl->slotname != NULL) {
            PK11SlotInfo *slot;
            slot = PK11_FindSlotByName(ossl->slotname);
            privKey = PK11_FindPrivateKeyFromCert(slot, cert, NULL);
            PK11_FreeSlot(slot);
        } else {
            privKey = PK11_FindKeyByAnyCert(cert, proto_win);
        }
        if (privKey) {
            secStatus = SECSuccess;
        }
        else {
            CERT_DestroyCertificate(cert);
        }
  }

  if (secStatus == SECSuccess) {
      *pRetCert = cert;
      *pRetKey = privKey;
  }

  return secStatus;
}

/*
 * See if the file exists.
 *
 * If file exists returns 1 
 * otherwise return 0
 */
static int file_exists(const char *filename) {
  struct stat st;

  if (filename == NULL)
    return 0;

  if (stat(filename, &st) == 0) {
    if (S_ISREG(st.st_mode))
      return 1;
  }
  return 0;
}

static int
nss_set_server_cert(SSL_CTX *ctx, const char *filename, PRBool cacert)
{
    ossl_ctx_t *ossl;
    CERTCertificate *cert;
    void *proto_win = NULL;
#ifdef PKCS11_PEM_MODULE
    CK_SLOT_ID slotID = 0;
    PK11SlotInfo * slot = NULL;
    PK11GenericObject *rv;
    CK_ATTRIBUTE *attrs;
    CK_ATTRIBUTE theTemplate[20];
    CK_BBOOL cktrue = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    char nickname[256];
#endif
    char *n;

    ossl = nss_get_private(ctx);
    if (!ossl) {
        return 0;
    }

    /* If there is no slash in the filename it is assumed to be a regular
     * NSS nickname.
     */
    if (file_exists(filename)) {
        n = strrchr(filename, '/');
        if (n) {
            n++;
        }
        if (pemMod == NULL) /* we have a file-based cert but no PEM module */
            return 1;
    } else {
        if (cacert)
            return 0; /* You can't specify an NSS CA nickname this way */
        /* A nickname from the NSS internal database */
        ossl->nickname = strdup(filename);
        goto done;
    }
    
#ifdef PKCS11_PEM_MODULE
    attrs = theTemplate;

    /* All CA and trust objects go into slot 0. Other slots are used
     * for storing certificates. With each new user certificate we increment
     * the slot count.
     */
    if (cacert) {
        slotID = 0;
    } else if (ossl->slotID == -1) {
        ossl->slotID = slotCount++;
        slotID = ossl->slotID;
    }

    ossl->slotname = PORT_ArenaAlloc(ossl->arena, 32);
    snprintf(ossl->slotname, 32, "PEM Token #%ld", slotID);
    snprintf(nickname, 256, "PEM Token #%ld:%s", slotID, n);

    slot = PK11_FindSlotByName(ossl->slotname);

    if (!slot)
        return 0;

    PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
    PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)filename, strlen(filename)+1); attrs++;
    if (cacert) {
        PK11_SETATTRS(attrs, CKA_TRUST, &cktrue, sizeof(CK_BBOOL) ); attrs++;
    } else {
        PK11_SETATTRS(attrs, CKA_TRUST, &ckfalse, sizeof(CK_BBOOL) ); attrs++;
    }

    /* This load the certificate in our PEM module into the appropriate
     * slot.
     */
    rv = PK11_CreateGenericObject(slot, theTemplate, 4, PR_FALSE /* isPerm */);
    if (rv == NULL) {
        return 0;
    }

    if (!cacert)
        ossl->nickname = strdup(nickname);

    PK11_FreeSlot(slot);

#else
    /* For the case where we don't have the PKCS#11 driver this could be
     * NULL if the filename has a slash in it
     */
    if (ossl->nickname == NULL)
        ossl->nickname = strdup(filename);
#endif

done:
    if (!cacert) {
        /* Double-check that the certificate or nickname requested exists in
         * either the token or the NSS certificate database.
         */
        cert = PK11_FindCertFromNickname((char *)ossl->nickname, proto_win);

        /* An invalid nickname was passed in */
        if (cert == NULL) {
            PR_SetError(SEC_ERROR_UNKNOWN_CERT, 0);
            return 0;
        }

        CERT_DestroyCertificate(cert);
    }

    return 1;
}

static int
nss_set_client_cert(SSL_CTX *ctx, const char *filename)
{
    CERTCertificate *cert;
    void *proto_win = NULL;
    ossl_ctx_t *ossl;
    CK_SLOT_ID slotID;
#ifdef PKCS11_PEM_MODULE
    PK11SlotInfo * slot = NULL;
    PK11GenericObject *rv;
    CK_ATTRIBUTE *attrs;
    CK_ATTRIBUTE theTemplate[20];
    CK_BBOOL cktrue = CK_TRUE;
    CK_BBOOL ckfalse = CK_FALSE;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
#endif
    char nickname[256];
    char *n;

    ossl = nss_get_private(ctx);
    if (!ossl) {
        return 0;
    }

    /* If there is no slash in the filename it is assumed to be a regular
     * NSS nickname.
     */
    n = strrchr(filename, '/');
    if (n) {
        n++;
        ossl->slotID = slotCount++;
        slotID = ossl->slotID;
        snprintf(nickname, 256, "PEM Token #%ld:%s", slotID, n);
    } else {
        /* A nickname from the NSS internal database */
        ossl->nickname = strdup(filename);
        goto done;
    }

#ifdef PKCS11_PEM_MODULE
    attrs = theTemplate;

    if (ossl->slotname == NULL)
        ossl->slotname = PORT_ArenaAlloc(ossl->arena, 32);

    snprintf(ossl->slotname, 32, "PEM Token #%ld", slotID);
        
    slot = PK11_FindSlotByName(ossl->slotname);

    if (!slot)
        return 0;

    PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
    PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)filename, strlen(filename)+1); attrs++;
    PK11_SETATTRS(attrs, CKA_TRUST, &ckfalse, sizeof(CK_BBOOL) ); attrs++;

    /* This load the certificate in our PEM module into the appropriate
     * slot.
     */
    rv = PK11_CreateGenericObject(slot, theTemplate, 4, PR_FALSE /* isPerm */);

    PK11_FreeSlot(slot);

    if (!rv)
        return 0;

    ossl->nickname = strdup(nickname);
#endif

done:

    cert = PK11_FindCertFromNickname((char *)ossl->nickname, proto_win);

    /* An invalid nickname was passed in */
    if (cert == NULL)
        return 0;

    CERT_DestroyCertificate(cert);

    if (SSL_GetClientAuthDataHook(ctx,
                                 (SSLGetClientAuthData) nss_SelectClientCert,
                                 (void *)ossl) != SECSuccess)
        return 0;
    else
        return 1;
    return 0;
}

/*
 * Get the data stored in the OSSL translation layer
 */
static ossl_ctx_t *
nss_get_private(PRFileDesc *fd)
{
    PRFileDesc *layer;

    if (!fd)
        return NULL;

    layer = PR_GetIdentitiesLayer(fd, gIdentity);
    if (!layer)
        return NULL;

    return (ossl_ctx_t *)layer->secret;
}

/*
 * Set the data stored in the OSSL translation layer
 */
static int
nss_set_private(PRFileDesc *fd, PRFilePrivate *data)
{
    PRFileDesc *layer;

    if (!fd)
        return PR_FAILURE;

    layer = PR_GetIdentitiesLayer(fd, gIdentity);
    if (!layer)
        return PR_FAILURE;

    layer->secret = data;

    return PR_SUCCESS;
}

/*
 * Is it better do to the NSS_Init() here or let the user pass in the
 * database location via the command-line?
 *
 * The SSL_library_init() man page actually advocates ignoring the return
 * value. There isn't much we can do about this if the NSS_Init() fails.
 * 
 * The error will appear elsewhere.
 */
int SSL_library_init(void)
{
    const PRIOMethods *defaultMethods;
    char *certDir = NULL;
    SECStatus status;
#ifdef PKCS11_PEM_MODULE
    char *configstring = NULL;
#endif

    if (is_initialized)
        return 1;

    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

    certDir = getenv("SSL_DIR"); /* Look in $SSL_DIR */

    if (!certDir) {
        certDir = "/etc/pki/nssdb";
    }

    if (certDir) {
        if (NSS_Init(certDir) != SECSuccess) {
            return 1;
        }
    } else {
        if (NSS_NoDB_Init(NULL) != SECSuccess) {
            return 1;
        }
    }
 
    if (nss_Init_Tokens() != SECSuccess) {
        return 1;
    }

    status = NSS_SetDomesticPolicy();

    gIdentity = PR_GetUniqueIdentity("NSS_COMPAT_OSSL_Layer");
    if (gIdentity == PR_INVALID_IO_LAYER) {
//        log("Failed to init NSS stub layer");
    }

    defaultMethods = PR_GetDefaultIOMethods();
    if (defaultMethods == NULL) {
//        log("Failed to init NSS stub layer");
    }

    /* Our layer has few methods. We use it for storage only */
    gMethods = *defaultMethods;

    /* We still need to be able to call PR_Close() so we can free stuff */
    gMethods.close = layer_close;

#ifdef PKCS11_PEM_MODULE
    /* Load our PKCS#11 module */
    configstring = (char *)malloc(4096);   

    PR_snprintf(configstring, 4096, "library=%s name=PEM parameters=\"\"", pem_library);

    pemMod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
    if (!pemMod || !pemMod->loaded) {
        if (pemMod) {
            SECMOD_DestroyModule(pemMod);
            pemMod = NULL;
        }
        free(configstring);
        return 1;
    }
    free(configstring);
#endif

    is_initialized = 1;
    
    return 1; /* always returns 1 */
}

static BIO *
nspr_get_bio(PRFileDesc *fd)
{
    if (fd->identity != gBioIdentity) {
        return NULL;
    }
    return (BIO *) fd->secret;
}

static void
nspr_set_bio(PRFileDesc *fd, BIO *bio)
{
    if (fd->identity != gBioIdentity) {
        return;
    }
    fd->secret = (PRFilePrivate *) bio;
}

static PRInt32
nspr_bio_write(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    BIO *bio = nspr_get_bio(fd);
    if (!bio) {
        return -1;
    }

    return bio->m->bwrite(bio, buf, amount);
}

static PRInt32
nspr_bio_send(PRFileDesc *fd, const void *buf, PRInt32 amount, 
				PRIntn flags, PRIntervalTime timeout)
{
    BIO *bio = nspr_get_bio(fd);
    if (!bio) {
        return -1;
    }

    return bio->m->bwrite(bio, buf, amount);
}

static PRInt32
nspr_bio_read(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    BIO *bio = nspr_get_bio(fd);

    if (!bio) {
        return -1;
    }

    return bio->m->bread(bio, buf, amount);
}

static PRInt32
nspr_bio_recv(PRFileDesc *fd, void *buf, PRInt32 amount, 
				PRIntn flags, PRIntervalTime timeout)
{
    BIO *bio = nspr_get_bio(fd);

    if (!bio) {
        return -1;
    }

    return bio->m->bread(bio, buf, amount);
}

void 
npsr_map_error(int err)
{
    PRErrorCode prError;

    switch (err ) {
        case EACCES:
            prError = PR_NO_ACCESS_RIGHTS_ERROR;
            break;
        case EADDRINUSE:
            prError = PR_ADDRESS_IN_USE_ERROR;
            break;
        case EADDRNOTAVAIL:
            prError = PR_ADDRESS_NOT_AVAILABLE_ERROR;
            break;
        case EAFNOSUPPORT:
            prError = PR_ADDRESS_NOT_SUPPORTED_ERROR;
            break;
        case EAGAIN:
            prError = PR_WOULD_BLOCK_ERROR;
            break;
        /*
         * On QNX and Neutrino, EALREADY is defined as EBUSY.
         */
#if EALREADY != EBUSY
        case EALREADY:
            prError = PR_ALREADY_INITIATED_ERROR;
            break;
#endif
        case EBADF:
            prError = PR_BAD_DESCRIPTOR_ERROR;
            break;
#ifdef EBADMSG
        case EBADMSG:
            prError = PR_IO_ERROR;
            break;
#endif
        case EBUSY:
            prError = PR_FILESYSTEM_MOUNTED_ERROR;
            break;
        case ECONNABORTED:
            prError = PR_CONNECT_ABORTED_ERROR;
            break;
        case ECONNREFUSED:
            prError = PR_CONNECT_REFUSED_ERROR;
            break;
        case ECONNRESET:
            prError = PR_CONNECT_RESET_ERROR;
            break;
        case EDEADLK:
            prError = PR_DEADLOCK_ERROR;
            break;
#ifdef EDIRCORRUPTED
        case EDIRCORRUPTED:
            prError = PR_DIRECTORY_CORRUPTED_ERROR;
            break;
#endif
#ifdef EDQUOT
        case EDQUOT:
            prError = PR_NO_DEVICE_SPACE_ERROR;
            break;
#endif
        case EEXIST:
            prError = PR_FILE_EXISTS_ERROR;
            break;
        case EFAULT:
            prError = PR_ACCESS_FAULT_ERROR;
            break;
        case EFBIG:
            prError = PR_FILE_TOO_BIG_ERROR;
            break;
        case EHOSTUNREACH:
            prError = PR_HOST_UNREACHABLE_ERROR;
            break;
        case EINPROGRESS:
            prError = PR_IN_PROGRESS_ERROR;
            break;
        case EINTR:
            prError = PR_PENDING_INTERRUPT_ERROR;
            break;
        case EINVAL:
            prError = PR_INVALID_ARGUMENT_ERROR;
            break;
        case EIO:
            prError = PR_IO_ERROR;
            break;
        case EISCONN:
            prError = PR_IS_CONNECTED_ERROR;
            break;
        case EISDIR:
            prError = PR_IS_DIRECTORY_ERROR;
            break;
        case ELOOP:
            prError = PR_LOOP_ERROR;
            break;
        case EMFILE:
            prError = PR_PROC_DESC_TABLE_FULL_ERROR;
            break;
        case EMLINK:
            prError = PR_MAX_DIRECTORY_ENTRIES_ERROR;
            break;
        case EMSGSIZE:
            prError = PR_INVALID_ARGUMENT_ERROR;
            break;
#ifdef EMULTIHOP
        case EMULTIHOP:
            prError = PR_REMOTE_FILE_ERROR;
            break;
#endif
        case ENAMETOOLONG:
            prError = PR_NAME_TOO_LONG_ERROR;
            break;
        case ENETUNREACH:
            prError = PR_NETWORK_UNREACHABLE_ERROR;
            break;
        case ENFILE:
            prError = PR_SYS_DESC_TABLE_FULL_ERROR;
            break;
        /*
         * On SCO OpenServer 5, ENOBUFS is defined as ENOSR.
         */
#if defined(ENOBUFS) && (ENOBUFS != ENOSR)
        case ENOBUFS:
            prError = PR_INSUFFICIENT_RESOURCES_ERROR;
            break;
#endif
        case ENODEV:
            prError = PR_FILE_NOT_FOUND_ERROR;
            break;
        case ENOENT:
            prError = PR_FILE_NOT_FOUND_ERROR;
            break;
        case ENOLCK:
            prError = PR_FILE_IS_LOCKED_ERROR;
            break;
#ifdef ENOLINK 
        case ENOLINK:
            prError = PR_REMOTE_FILE_ERROR;
            break;
#endif
        case ENOMEM:
            prError = PR_OUT_OF_MEMORY_ERROR;
            break;
        case ENOPROTOOPT:
            prError = PR_INVALID_ARGUMENT_ERROR;
            break;
        case ENOSPC:
            prError = PR_NO_DEVICE_SPACE_ERROR;
            break;
#ifdef ENOSR
        case ENOSR:
            prError = PR_INSUFFICIENT_RESOURCES_ERROR;
            break;
#endif
        case ENOTCONN:
            prError = PR_NOT_CONNECTED_ERROR;
            break;
        case ENOTDIR:
            prError = PR_NOT_DIRECTORY_ERROR;
            break;
        case ENOTSOCK:
            prError = PR_NOT_SOCKET_ERROR;
            break;
        case ENXIO:
            prError = PR_FILE_NOT_FOUND_ERROR;
            break;
        case EOPNOTSUPP:
            prError = PR_NOT_TCP_SOCKET_ERROR;
            break;
#ifdef EOVERFLOW
        case EOVERFLOW:
            prError = PR_BUFFER_OVERFLOW_ERROR;
            break;
#endif
        case EPERM:
            prError = PR_NO_ACCESS_RIGHTS_ERROR;
            break;
        case EPIPE:
            prError = PR_CONNECT_RESET_ERROR;
            break;
#ifdef EPROTO
        case EPROTO:
            prError = PR_IO_ERROR;
            break;
#endif
        case EPROTONOSUPPORT:
            prError = PR_PROTOCOL_NOT_SUPPORTED_ERROR;
            break;
        case EPROTOTYPE:
            prError = PR_ADDRESS_NOT_SUPPORTED_ERROR;
            break;
        case ERANGE:
            prError = PR_INVALID_METHOD_ERROR;
            break;
        case EROFS:
            prError = PR_READ_ONLY_FILESYSTEM_ERROR;
            break;
        case ESPIPE:
            prError = PR_INVALID_METHOD_ERROR;
            break;
        case ETIMEDOUT:
            prError = PR_IO_TIMEOUT_ERROR;
            break;
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
            prError = PR_WOULD_BLOCK_ERROR;
            break;
#endif
        case EXDEV:
            prError = PR_NOT_SAME_DEVICE_ERROR;
            break;
        default:
            prError = PR_UNKNOWN_ERROR;
            break;
    }
    PR_SetError(prError, err);
}

static PRStatus
nspr_bio_getpeername(PRFileDesc *fd, PRNetAddr *addr)
{
    BIO *bio = nspr_get_bio(fd);
    int osfd;
    int ret;
    PRUint32 addrlen;

    if (!bio) {
        return -1;
    }
    ret = bio->m->ctrl(bio, BIO_C_GET_PEERNAME, sizeof(PRNetAddr), addr);
    if (ret > 0) {
	return PR_SUCCESS;
    }
	
    ret = bio->m->ctrl(bio, BIO_C_GET_FD, sizeof(osfd), &osfd);
    if (ret <= 0) {
	PR_SetError(PR_BAD_DESCRIPTOR_ERROR, EBADF);
	return PR_FAILURE;
    }
    ret = getpeername(osfd, (struct sockaddr *) addr, &addrlen);
    if (ret < 0) {
	npsr_map_error(errno);
    }
    
    return ret == 0 ? PR_SUCCESS : PR_FAILURE;
}


static PRStatus
nspr_bio_close(PRFileDesc *fd)
{
   BIO *bio = nspr_get_bio(fd);

   if (!bio) {
        return PR_FAILURE;
   }

   nspr_set_bio(fd, NULL);
   bio->m->destroy(bio);
   PR_Free(bio);
   return PR_SUCCESS;
}

static void
ssl_init_bio()
{
    const PRIOMethods *defaultMethods;
    gBioIdentity = PR_GetUniqueIdentity("NSS_COMPAT_OSSL_BIO_Layer");
    if (gIdentity == PR_INVALID_IO_LAYER) {
//        log("Failed to init NSS stub layer");
    }

    defaultMethods = PR_GetDefaultIOMethods();
    if (defaultMethods == NULL) {
//        log("Failed to init NSS stub layer");
    }

    /* Our layer has few methods. We use it for storage only */
    gBioMethods = *defaultMethods;
    gBioMethods.write = nspr_bio_write;
    gBioMethods.read = nspr_bio_read;
    gBioMethods.close = nspr_bio_close;
    gBioMethods.send = nspr_bio_send;
    gBioMethods.recv = nspr_bio_recv;
    gBioMethods.getpeername = nspr_bio_getpeername;
}

void SSL_load_error_strings(void)
{
   /* NOOP */
}

int SSL_read(SSL *ssl, void *buf, int sz)
{
    int rv;
    int flags;
    ossl_ctx_t *ossl;

    if (ssl) {
        ossl = nss_get_private(ssl);
        flags = SSL_get_shutdown(ssl);

        /* The SSL connection has been shut down */
        if (flags & SSL_RECEIVED_SHUTDOWN) {
            ossl->error = SSL_ERROR_ZERO_RETURN;
            return 0;
        }
    }

    rv = PR_Read(ssl, buf, sz);

    return rv;
}

int SSL_write(SSL *ssl, const void *buf, int num)
{ 
    int rv;
    int flags;
    ossl_ctx_t *ossl;

    /* If SSL is not enabled then PR_Write will do the right thing */
    if (ssl) {
        ossl = nss_get_private(ssl);
        flags = SSL_get_shutdown(ssl);

        /* The SSL connection has been shut down */
        if (flags & SSL_SENT_SHUTDOWN) {
            ossl->error = SSL_ERROR_ZERO_RETURN;
            return 0;
        }
    } 

    rv = PR_Write(ssl, buf, num);

    return rv;
}

SSL_METHOD *create_context(PRBool ssl2, PRBool ssl3, PRBool tlsv1, 
                           PRBool server)
{
    PRFileDesc *s = NULL;
    PRFileDesc *layer;
    ossl_ctx_t *ossl;
    int i;

    if (PR_TRUE != NSS_IsInitialized()) {
        PR_SetError(SEC_ERROR_NOT_INITIALIZED, 0);
        goto error;
    }

    /* Create socket -- used as template */
    s = PR_NewTCPSocket();

    /* Stick our storage layer in */
    layer = PR_CreateIOLayerStub(gIdentity, &gMethods);
    if (layer == NULL)
        goto error;
    if (PR_PushIOLayer(s, PR_TOP_IO_LAYER, layer) != PR_SUCCESS)
        goto error;
  
    s = SSL_ImportFD(NULL, s);
    if (s == NULL)
        goto error;

    /* Initialize the storage structure in our storage layer */
    ossl = new_ossl(NULL);
    ossl->server = server;

    nss_set_private(s, (PRFilePrivate *)ossl);

    if (SSL_OptionSet(s, SSL_SECURITY, PR_TRUE) != SECSuccess)
        goto error;
  
    if (SSL_OptionSet(s, SSL_HANDSHAKE_AS_CLIENT, !server) != SECSuccess)
        goto error;

    if (SSL_OptionSet(s, SSL_HANDSHAKE_AS_SERVER, server) != SECSuccess)
        goto error;

    if (SSL_OptionSet(s, SSL_ENABLE_SSL2, ssl2) != SECSuccess)
        goto error;

    if (SSL_OptionSet(s, SSL_V2_COMPATIBLE_HELLO, ssl2) != SECSuccess)
        goto error;

    if (SSL_OptionSet(s, SSL_ENABLE_SSL3, ssl3)  != SECSuccess)
        goto error;

    if (SSL_OptionSet(s, SSL_ENABLE_TLS,  tlsv1) != SECSuccess)
        goto error;

    /* Set up callbacks for use by clients */
    if (!server) {
        if (SSL_OptionSet(s, SSL_NO_CACHE, PR_TRUE) != SECSuccess)
            goto error;

        if (SSL_BadCertHook(s, (SSLBadCertHandler)BadCertHandler, NULL)
         != SECSuccess)
            goto error;
    }

    /* Callback for authenticating certificate */
    if (SSL_AuthCertificateHook(s, AuthCertificateHandler, CERT_GetDefaultCertDB()) != SECSuccess)
            goto error;

    /* Disable all ciphers */
    for (i = 0; i < SSL_NumImplementedCiphers; i++)
    {
        SSL_CipherPrefSet(s, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);
    }

    /* Enable the ones we want on by default */
    for (i = 0; i < SSL_NumImplementedCiphers; i++)
    {
        SSLCipherSuiteInfo suite;
        PRBool enabled;
       
        if (SSL_GetCipherSuiteInfo(ciphers_def[i].num, &suite, sizeof suite)
            == SECSuccess)
        {
            enabled = ciphers_def[i].enabled;
            if (enabled == SSL_ALLOWED)
            {
                if (PK11_IsFIPS() && !suite.isFIPS)    
                    enabled = SSL_NOT_ALLOWED;
            }
            SSL_CipherPrefSet(s, ciphers_def[i].num, enabled);
        }
    }

    return (s);

    error:
        if (s)
            PR_Close(s);

    return (NULL);
}

SSL_METHOD *SSLv2_client_method(void)
{
    return create_context(PR_TRUE, PR_FALSE, PR_FALSE, PR_FALSE);
}

SSL_METHOD *SSLv23_client_method(void)
{
    return create_context(PR_TRUE, PR_TRUE, PR_TRUE, PR_FALSE);
}

SSL_METHOD *SSLv3_client_method(void) 
{
    return create_context(PR_FALSE, PR_TRUE, PR_FALSE, PR_FALSE);
}

SSL_METHOD *TLSv1_client_method(void)
{
    return create_context(PR_FALSE, PR_FALSE, PR_TRUE, PR_FALSE);
}

SSL_METHOD *SSLv2_server_method(void)
{
    return create_context(PR_TRUE, PR_FALSE, PR_FALSE, PR_TRUE);
}

SSL_METHOD *SSLv23_server_method(void)
{ 
    return create_context(PR_TRUE, PR_TRUE, PR_TRUE, PR_TRUE);
}

SSL_METHOD *SSLv3_server_method(void)
{ 
    return create_context(PR_FALSE, PR_TRUE, PR_FALSE, PR_TRUE);
}

SSL_METHOD *TLSv1_server_method(void)
{ 
    return create_context(PR_FALSE, PR_FALSE, PR_TRUE, PR_TRUE);
}

SSL_CTX *SSL_CTX_new(SSL_METHOD *passed)
{
    /* real work done in SSL*_method() */
    return passed;
}

void SSL_CTX_free(SSL_CTX *ssl)
{
    ossl_ctx_t *ossl;

    if (ssl) {
        ossl = nss_get_private(ssl);
        free_ossl(ossl);
        PR_Close(ssl);
    }
}

long SSL_CTX_set_timeout(SSL_CTX *ssl, long tm)
{
    ossl_ctx_t *ossl;
    int prev;

    if (tm < 0)
        return 0;

    if (ssl) {
        ossl = nss_get_private(ssl);

        if (ossl->session_timeout != -1) {
            /* The cache is already initialized, shut it down */
            SSL_ShutdownServerSessionIDCache();
            prev = ossl->session_timeout;
        } else 
            prev = DEF_SSL3_TIMEOUT;

        SSL_ConfigServerSessionIDCache(0, tm, tm, NULL);
        ossl->session_timeout = tm;

        return prev;
    }

    return 0; /* with no context this is really undefined */
}

/*
 * return 1 if any cipher could be selected and 0 on complete failure.
 */
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
    int cipher_state[ciphernum];
    int rv, i;
    PRBool client = PR_FALSE;

    if (!ctx)
        return 0;

    rv = nss_parse_ciphers(str, cipher_state);

    if (rv) {
        /* First disable everything */
        for (i = 0; i < SSL_NumImplementedCiphers; i++)
            SSL_CipherPrefSet(ctx, SSL_ImplementedCiphers[i], SSL_NOT_ALLOWED);

        if (SSL_OptionGet(ctx, SSL_HANDSHAKE_AS_CLIENT, &client) != SECSuccess)
            return 0; /* failure */

        /* Need to be careful here. We can't rely on the return value
         * of nss_parse_ciphers() to determine if this call is succesful
         * or not. Since we touch the allowed ciphers we need to
         * re-calculate whether any ciphers were enabled.
         */
        rv = 0;

        /* Now enable what was requested */
        for (i=0; i<ciphernum; i++) {
            SSLCipherSuiteInfo suite;
            PRBool enabled;
       
            if (SSL_GetCipherSuiteInfo(ciphers_def[i].num, &suite, sizeof suite)
                == SECSuccess)
            {
                enabled = cipher_state[i] < 0 ? 0 : cipher_state[i];
                /* nss_parse_ciphers() may return ciphers that are not
                 * allowed in our context, don't set them.
                 */
                if (ciphers_def[i].client_only && !client) {
                    enabled = SSL_NOT_ALLOWED;
                }
                if (enabled == SSL_ALLOWED)
                {
                    if (PK11_IsFIPS() && !suite.isFIPS)    
                        enabled = SSL_NOT_ALLOWED;
                    else {
                        rv = 1;
                    }
                }
                SSL_CipherPrefSet(ctx, ciphers_def[i].num, enabled);
            }
        }
    }
        
    return rv;
}

/* API for OpenSSL statistics */

long SSL_CTX_sess_number(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_connect(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_connect_good(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_connect_renegotiate(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_accept(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_accept_good(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_accept_renegotiate(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_hits(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_misses(SSL_CTX *s)
{
    return 0;
}

long SSL_CTX_sess_timeouts(SSL_CTX *s)
{
    return 0;
}
    
SSL *SSL_new(SSL_CTX *templ_s)
{
    PRFileDesc *s;
    PRFileDesc *layer;
    ossl_ctx_t *ossl;
    ossl_ctx_t *ossl_templ;

    if (templ_s == NULL) {
        return NULL;
    }

    /* This layer contains the TCP/IP functions we need */
    s = PR_NewTCPSocket();
    if (s == NULL)
        return NULL;

    /* Stick our storage layer in */
    layer = PR_CreateIOLayerStub(gIdentity, &gMethods);
    if (layer == NULL)
        return NULL;
    if (PR_PushIOLayer(s, PR_TOP_IO_LAYER, layer) != PR_SUCCESS)
        return NULL;

    /* And finally add SSL on using the template passed in */
    s = SSL_ImportFD(templ_s, s);

    /* Initialize the storage structure in our storage layer */
    ossl = new_ossl(s);

    ossl_templ = nss_get_private(templ_s);
    ossl->server = ossl_templ->server;
    ossl->info_cb = ossl_templ->info_cb;
    ossl->verify_cb = ossl_templ->verify_cb;
    ossl->verify_mode = ossl_templ->verify_mode;
    ossl->nickname = ossl_templ->nickname;
    ossl->slotID = ossl_templ->slotID;
    ossl->slotname = ossl_templ->slotname;

    nss_set_private(s, (PRFilePrivate *)ossl);

    if (ossl->server && ossl->session_timeout == -1) {
        SSL_ConfigServerSessionIDCache(0, DEF_SSL2_TIMEOUT, DEF_SSL3_TIMEOUT, NULL);
        ossl->session_timeout = DEF_SSL3_TIMEOUT;
    }

    return s;
}

void SSL_free(SSL *ssl)
{
    ossl_ctx_t *ossl;

    if (ssl) {
        ossl = nss_get_private(ssl);
        free_ossl(ossl);

        PR_Close(ssl);
    }
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    return SSL_CTX_use_certificate_chain_file(ctx, file);
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
    ossl_ctx_t *ossl;
    int rv;

    if (!ctx)
        return 0;

    ossl = nss_get_private(ctx);

    /* FIXME: Load all certs in the file */
    if (ossl->server)
        rv = nss_set_server_cert(ctx, file, PR_FALSE);
    else
        rv = nss_set_client_cert(ctx, file);

    SSL_HandshakeCallback(ctx, (SSLHandshakeCallback)nss_HandshakeCallback, NULL);

    return rv;
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *filename, int type)
{
#ifdef PKCS11_PEM_MODULE
    ossl_ctx_t *ossl;
    PK11SlotInfo * slot = NULL;
    PK11GenericObject *rv;
    CK_ATTRIBUTE *attrs;
    CK_ATTRIBUTE theTemplate[20];
    CK_BBOOL cktrue = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    int retryCount = 0;
#endif

    if (!ctx)
        return 0;

    /* It is probably empty because they are using the NSS database. */
    if (filename == NULL)
        return 1;

#ifdef PKCS11_PEM_MODULE
    /* FIXME: grok the various file types */

    ossl = nss_get_private(ctx);
    if (!ossl) {
        return 0;
    }
    
    attrs = theTemplate;

    if (ossl->slotID == -1)
        ossl->slotID = slotCount++;

    /* May already exist if the cert is loaded */
    if (ossl->slotname == NULL) {
        ossl->slotname = PORT_ArenaAlloc(ossl->arena, 32);
        snprintf(ossl->slotname, 32, "PEM Token #%ld", ossl->slotID);
    }

    slot = PK11_FindSlotByName(ossl->slotname);

    if (!slot)
        return 0;

    PK11_SETATTRS(attrs, CKA_CLASS, &objClass, sizeof(objClass) ); attrs++;
    PK11_SETATTRS(attrs, CKA_TOKEN, &cktrue, sizeof(CK_BBOOL) ); attrs++;
    PK11_SETATTRS(attrs, CKA_LABEL, (unsigned char *)filename, strlen(filename)+1); attrs++;

    /* When adding an encrypted key the PKCS#11 will be set as removed */
    rv = PK11_CreateGenericObject(slot, theTemplate, 3, PR_FALSE /* isPerm */);
    if (rv == NULL) {
        PR_SetError(SEC_ERROR_BAD_KEY, 0);
        return 0;
    }

    /* This will force the token to be seen as re-inserted */
    SECMOD_WaitForAnyTokenEvent(pemMod, 0, 0);
    PK11_IsPresent(slot);

    if (PK11_Authenticate(slot, PR_TRUE, &retryCount) != SECSuccess) {
       return 0;
    }

    return 1;
#else
    /* The key is already available if we're using the NSS database and not
     * the PEM-reading PKCS#11 module.
     */
    return 1;
#endif
}

/*
 * We have to wait until the last minute to run this to be sure that all
 * CA certificates have been loaded.
 */
int configureserver(SSL *ssl)
{
    ossl_ctx_t *ossl;
    CERTCertificate *servercert;
    SSLKEAType KEAtype;
    SECKEYPrivateKey  *serverkey;
    PK11SlotInfo * slot = NULL;

    ossl = nss_get_private(ssl);
    if (!ossl) {
        return 0;
    }

    if (ossl->slotname) {
        /* Go ahead and re-create this to be sure we have the right slot */
        snprintf(ossl->slotname, 32, "PEM Token #%ld", ossl->slotID);
        slot = PK11_FindSlotByName(ossl->slotname);
    } else
        slot = PK11_GetInternalKeySlot();

    if (slot == NULL) {
        PR_SetError(SSL_ERROR_TOKEN_SLOT_NOT_FOUND, 0);
        return 0;
    }

    servercert = FindServerCertFromNickname(ossl->nickname);

    if (servercert == NULL) {
        PR_SetError(SEC_ERROR_UNKNOWN_CERT, 0);
        return 0;
    }

    serverkey = PK11_FindPrivateKeyFromCert(slot, servercert, NULL);

    if (serverkey == NULL) {
        PR_SetError(SEC_ERROR_NO_KEY, 0);
        return 0;
    }

    KEAtype = NSS_FindCertKEAType(servercert);

    if (SSL_ConfigSecureServer(ssl, servercert, serverkey, KEAtype) !=
         SECSuccess) {
//        log("SSL error configuring server: '%s'", file);
        return 0;
    }

    CERT_DestroyCertificate(servercert);
    SECKEY_DestroyPrivateKey(serverkey);

    return 1;
}

int SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
    /* FIXME: What can we check here? */
    return 1; /* success */
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
{
    return 0;
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
}

X509 *SSL_get_certificate(SSL *ssl)
{
    CERTCertificate *cert = NULL;
    X509 *x;

    if (ssl)
        cert = SSL_LocalCertificate(ssl);

    x = (X509 *)malloc(sizeof(X509));

    x->cert = cert;

    /* This arena/memory pool is used for allocating attributes of the
     * certificate such as dates, etc. */
    x->arena = PORT_NewArena(1024); /* This size is arbitrary */

    return x;
}

X509 *SSL_get_peer_certificate(SSL *ssl)
{
    CERTCertificate *cert = NULL;
    X509 *x;

    if (ssl)
        cert = SSL_PeerCertificate(ssl);

    if (cert == NULL)
	return NULL;

    x = (X509 *)malloc(sizeof(X509));

    x->cert = cert;
    x->arena = PORT_NewArena(1024); /* This size is arbitrary */

    return x;
}

X509 *d2i_X509(void *reserved, unsigned char **data, int len)
{
    CERTCertificate *cert = NULL;
    SECItem derCert;
    CERTCertDBHandle *handle;
    X509 *x;

    handle = CERT_GetDefaultCertDB();
    derCert.data = *data;
    derCert.len = len;
    cert = CERT_NewTempCertificate(handle, &derCert, NULL, PR_FALSE, PR_TRUE);
    if (!cert) {
        return NULL;
    }

    x = (X509 *)malloc(sizeof(X509));

    x->cert = cert;

    /* This arena/memory pool is used for allocating attributes of the
     * certificate such as dates, etc. */
    x->arena = PORT_NewArena(1024); /* This size is arbitrary */

    return x;
}


X509_NAME *X509_get_issuer_name(X509 *x)
{
    if (x->cert) {
        return &x->cert->issuer;
    }

    return NULL;
}

X509_NAME *X509_get_subject_name(X509 *x)
{
    if (x->cert) {
        return &x->cert->subject;
    }

    return NULL;
}

void *X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx)
{
    /* FIXME: stub */
    return NULL;
}

ASN1_TIME *X509_get_notBefore(X509 *x)
{
    PRExplodedTime   printableTime;
    char             timeString[256];
    PRTime           notBefore, notAfter;
    ASN1_TIME       *result;

    CERT_GetCertTimes(x->cert, &notBefore, &notAfter);

    PR_ExplodeTime(notBefore, PR_GMTParameters, &printableTime);

    PR_FormatTime(timeString, 256, "%y%m%d%H%M%SZ", &printableTime);

    result = PORT_ArenaAlloc(x->arena, sizeof(ASN1_TIME));

    result->type = V_ASN1_UTCTIME; 
    result->length = strlen(timeString);
    result->data = (unsigned char *)PORT_ArenaStrdup(x->arena, timeString);

    return result;
}

ASN1_TIME *X509_get_notAfter(X509 *x)
{
    PRExplodedTime   printableTime;
    char             timeString[256];
    PRTime           notBefore, notAfter;
    ASN1_TIME       *result;

    CERT_GetCertTimes(x->cert, &notBefore, &notAfter);

    PR_ExplodeTime(notAfter, PR_GMTParameters, &printableTime);

    PR_FormatTime(timeString, 256, "%y%m%d%H%M%SZ", &printableTime);

    result = PORT_ArenaAlloc(x->arena, sizeof(ASN1_TIME));

    result->type = V_ASN1_UTCTIME;
    result->length = strlen(timeString);
    result->data = (unsigned char *)PORT_ArenaStrdup(x->arena, timeString);

    return result;
}

ASN1_INTEGER *X509_get_serialNumber(X509 *x)
{
    ASN1_TIME *result;

    result = PORT_ArenaAlloc(x->arena, sizeof(ASN1_TIME));

    result->type = V_ASN1_INTEGER;
    result->length = x->cert->serialNumber.len;
    result->data = x->cert->serialNumber.data;

    return result;
}

/*
 * convert a byte buffer into an array of longs.
 */
static void
load_words(unsigned long *words, int len, unsigned char *bytes, int blen)
{

    /*
     * the first word may have an odd number of bytes. we know this from
     * blen. */
    *words = 0;
    switch (blen % 4) {
    case 0:
        break;
    case 3:
        *words = ((unsigned long) *bytes) << 16;
        bytes++;
    case 2:
        *words |= ((unsigned long) *bytes) << 8;
        bytes++;
    case 1:
        *words |= (unsigned long) *bytes;
        bytes++;
        words++; len--;
        break;
    }
    /* at this point the rest of the bytes are a multiple of 4, crank through
     * them */
    while (len > 0) {
        *words++ = (((unsigned long)bytes[0]) << 24) |
                   (((unsigned long)bytes[1]) << 16) |
                   (((unsigned long)bytes[2]) << 8) |
                   (((unsigned long)bytes[3]) << 16);
        len--; bytes += 4;
    }
}

/*
 * helper function to divide 2 longs by a long. This function only works if
 * div <= 0xffff, and high is < 0xffff. remander will always be less than div
 * (and thus less than 0xffff) */
static unsigned long
longdiv(unsigned long high, unsigned long low, unsigned long div, 
                unsigned long *premainder)
{
    unsigned long temp, remainder, result;
    if (high == 0) {
        result = low/div;
        *premainder = low % div;
        return result;
    }
    /* safe because the upper half of high is always zero */
    temp = ((high << 16) | (low >> 16));
    /* result is going to be less than 0xffff because high is always less
     * then div, which means temp is less than div*0x10000 */
    result = temp/div;
    remainder = temp % div;
    /* again, temp/div is less than 0xffff because remainder is less than div */
    temp = ((remainder << 16) | (low & 0xffff));
    *premainder = temp % div;
    result = result << 16;
    return result | temp/div;
}

/*
 * divide an array by a number. NOTE: div must be less that 0xffff
 */
static unsigned long
div_words(unsigned long **pwords, int *plen, unsigned long div)
{
    unsigned long remainder = 0;
    unsigned long result;
    unsigned long *words=*pwords;
    int len = *plen;
    int i;

    for (i=0; i < len; i++) {
        result = longdiv(remainder, words[i], div, &remainder);
        words[i] = result;
    }
    while ((*words == 0) && len > 0) {
        words++; len--;
    }
    *pwords = words;
    *plen = len;

    return remainder;
}
            
char *i2s_ASN1_INTEGER(void *reserved, ASN1_INTEGER *asn1Int)
{
    /* output an integer as a decimal value */
    unsigned long decimal_result;
    unsigned long *words, *space;
    unsigned long power10=10000; /* power of ten less than 0x10000 */
    int len = (asn1Int->length + (sizeof(unsigned long)-1))
                /sizeof(unsigned long);
    int bufLen;
    char *buf, *result;

    space = words = PORT_NewArray(unsigned long, len);
    bufLen = len*8*4+1; /* definitely big enough */
    buf = PORT_Alloc(bufLen);
    buf[bufLen-1] = 0;
    bufLen -= 1;

    load_words(words, len, asn1Int->data, asn1Int->length);

    while (len > 0) {
        char tmpbuf[5];
            decimal_result = div_words(&words, &len, power10);
        sprintf(tmpbuf,"%04d",(int)decimal_result);
        memcpy(&buf[bufLen-4],tmpbuf, 4); /* loose the terminating null */
        bufLen -= 4;
    }
    /* drop leading zeros */
    while (buf[bufLen] == '0') {
        bufLen++;
    }
    /* special case '0' */
    if (buf[bufLen] == 0) {
        bufLen--;
    }
    /* return a properly aligned and freeable string to the user */
    result = PORT_Strdup(&buf[bufLen]);

    PORT_Free(space);
    PORT_Free(buf);
    return result;
}

char *X509_NAME_oneline(X509_NAME *x, char *s, int len)
{
    char *value = NULL;

    if (!x)
        return NULL;

    value = CERT_NameToAscii(x);

    if (s)
        s = PL_strncpyz(s, value, len);
    else
        s = PORT_ArenaStrdup(x->arena, value);

    return s;
}

void X509_free(X509 *x)
{
    if (x->cert)
        CERT_DestroyCertificate(x->cert);
    if (x->arena)
        PORT_FreeArena(x->arena, PR_FALSE);
    free(x);
}

/* Not thread-safe */
const char *X509_verify_cert_error_string(long n)
{
    return nss_error(n);
}

int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len)
{
    switch (nid)
    {
        case NID_commonName:
            strncpy(buf, CERT_GetCommonName(name), len);
            break;
        default:
            strncpy(buf, "Unknown", len);
            break;
    }
    return 0;
}

SSL_CIPHER *SSL_get_current_cipher(SSL *s)
{
    return s;
}

int SSL_CIPHER_get_bits(SSL_CIPHER *c, int *alg_bits)
{
    int on, keySize, secretKeySize;
    char *cipher, *issuer, *subject;
    SECStatus secstatus = SECFailure;
    
    if (!c)
        return 0;

    secstatus = SSL_SecurityStatus((PRFileDesc *)c, &on, &cipher,
                                   &keySize, &secretKeySize, &issuer,
                                   &subject);

    if (secstatus != SECSuccess)
        return 0;

    if (alg_bits != NULL)
        *alg_bits = keySize;

    return secretKeySize;
}

char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
{
    return SSL_get_version(cipher);
}

void SSL_CIPHER_description(SSL_CIPHER *c, char *s, int len)
{
    SSLChannelInfo      channel;
    SSLCipherSuiteInfo  suite;

    if (SSL_GetChannelInfo(c, &channel, sizeof channel) ==
        SECSuccess && channel.length == sizeof channel &&
        channel.cipherSuite)
    {
        if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
            &suite, sizeof suite) == SECSuccess)
        {
            /* The space here is because stunnel plays with the string */
            snprintf(s, len, "%s ", suite.cipherSuiteName);
        }
    }
    return;
}

const char *SSL_CIPHER_get_name(SSL_CIPHER *c)
{
    SSLChannelInfo      channel;
    SSLCipherSuiteInfo  suite;
    char                buf[128];
    ossl_ctx_t         *ossl;

    ossl = nss_get_private(c);

    if (SSL_GetChannelInfo(c, &channel, sizeof channel) ==
        SECSuccess && channel.length == sizeof channel &&
        channel.cipherSuite)
    {
        if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
            &suite, sizeof suite) == SECSuccess)
        {
            /* The space here is because stunnel plays with the string */
            snprintf(buf, 128, "%s ", suite.cipherSuiteName);
        }
    }

    return PORT_ArenaStrdup(ossl->arena, buf);
}

int SSL_get_shutdown(SSL *ssl)
{
    ossl_ctx_t *ossl;

    if (!ssl)
        return 0;

    ossl = nss_get_private(ssl);

    return ossl->shutdown_flags;
}

PRStatus SSL_set_shutdown(SSL *ssl, int flags)
{
    int both = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    PRStatus status = PR_SUCCESS;
    ossl_ctx_t *ossl;

    if (!ssl)
        return 0; /* returns no diagnostic info */

    ossl = nss_get_private(ssl);
    ossl->shutdown_flags = flags;
  
    if ((flags & both) == both)
        status = PR_Shutdown(ssl, PR_SHUTDOWN_BOTH);

    else if ((flags & SSL_SENT_SHUTDOWN) == SSL_SENT_SHUTDOWN)
        status = PR_Shutdown(ssl, PR_SHUTDOWN_SEND);

    else if ((flags & SSL_RECEIVED_SHUTDOWN) == SSL_RECEIVED_SHUTDOWN)
        status = PR_Shutdown(ssl, PR_SHUTDOWN_RCV);

    return 0; /* returns no diagnostic info */
}

char *SSL_get_version(SSL *ssl)
{
    SSLChannelInfo      channel;
    SSLCipherSuiteInfo  suite;
    ossl_ctx_t         *ossl;
    char               *protocol = NULL;

    if (!ssl)
        return "unknown";

    ossl = nss_get_private(ssl);

    if (SSL_GetChannelInfo(ssl, &channel, sizeof channel) ==
        SECSuccess && channel.length == sizeof channel &&
        channel.cipherSuite) {
        if (SSL_GetCipherSuiteInfo(channel.cipherSuite,
                                &suite, sizeof suite) == SECSuccess) {
            switch (channel.protocolVersion) {
                case SSL_LIBRARY_VERSION_2:
                    protocol = PORT_ArenaStrdup(ossl->arena, "SSLv2");
                    break;
                case SSL_LIBRARY_VERSION_3_0:
                    protocol = PORT_ArenaStrdup(ossl->arena, "SSLv3");
                    break;
                case SSL_LIBRARY_VERSION_3_1_TLS:
                    protocol = PORT_ArenaStrdup(ossl->arena, "TLSv1");
                    break;
            }
        }
    }

    return protocol;
}

int SSL_set_session(SSL *to, SSL_SESSION *session)
{
    return -1;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
        const char *CApath)
{
    int         rv = 1;
#ifdef PKCS11_PEM_MODULE
    struct stat st;
    PRDir      *dir;
    PRDirEntry *entry;
#endif

    if (!ctx)
        return 0;

    if (CAfile != NULL)
        rv = nss_set_server_cert(ctx, CAfile, PR_TRUE);

#ifdef PKCS11_PEM_MODULE
    if (CApath == NULL)
        return rv;

    if (stat(CApath, &st) == -1)
        return -1;

    if (S_ISDIR(st.st_mode)) {
        dir = PR_OpenDir(CApath);
        int rv;
        do {
            entry = PR_ReadDir(dir, PR_SKIP_BOTH | PR_SKIP_HIDDEN);

            if (entry) {
                char fullpath[1024];

                snprintf(fullpath, 1024, "%s/%s", CApath, entry->name);
                rv = nss_set_server_cert(ctx, fullpath, PR_TRUE);
            }
        /* This is purposefully tolerant of errors so non-PEM files
         * can be in the same directory */
        } while (entry != NULL);
    }

    PR_CloseDir(dir);
#endif

    return rv;
}

int SSL_CTX_set_default_verify_paths(SSL_CTX * ctx) {
    if (PR_FALSE == SECMOD_HasRootCerts()) {
        char configstring[64];

        /* try to load root certs module */
        PR_snprintf(configstring, 64, "library=%s name=\"Root Certs\" parameters=\"\"", root_certs_library);
        rootMod = SECMOD_LoadUserModule(configstring, NULL, PR_FALSE);
        if (rootMod || !rootMod->loaded) {
            SECMOD_DestroyModule(rootMod);
            rootMod = NULL;
        }
    }
}

void SSL_set_verify(SSL *ssl, int mode,
                    int (*callback)(int ok, X509_STORE_CTX *ctx))
{
#if 0
    ossl_ctx_t * ossl = NULL;
    if (!ssl)
        return;

    ossl = nss_get_private((SSL *)ssl);

    ossl->verify_mode = mode;
    /* FIXME: save the callback fn */

    return;
#endif
    return SSL_CTX_set_verify(ssl, mode, callback);
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*callback)(int ok, X509_STORE_CTX *))
{
    ossl_ctx_t * ossl = NULL;
    if (!ctx)
        return;

    ossl = nss_get_private((SSL *)ctx);

    /* The NSS tuning knobs for verification are server-only. But we
     * will save the mode for use in BadCertHandler(). */
    if (!ossl->server)
        goto done;

    /* According to the man page, mode should either be SSL_VERIFY_NONE
     * or SSL_VERIFY_PEER (which may be modified). So lets check for
     * either of those first and punt if neither is found.
     */

    if (mode == SSL_VERIFY_NONE) {
        /* On the off-chance that this function is called twice, go ahead and 
         * turn off all verification rather than assuming it is already off.
         */
        SSL_OptionSet(ctx, SSL_REQUEST_CERTIFICATE, PR_FALSE);
        SSL_OptionSet(ctx, SSL_REQUIRE_CERTIFICATE, PR_FALSE);
        return;
    }
 
    if (!(mode & SSL_VERIFY_PEER)) return;

    /* SSL_VERIFY_PEER - request certificate */
    SSL_OptionSet(ctx, SSL_REQUEST_CERTIFICATE, PR_TRUE);
    SSL_OptionSet(ctx, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_NO_ERROR); /* ensures a full handshake */

    if (mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        SSL_OptionSet(ctx, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_ALWAYS);

    if (mode & SSL_VERIFY_CLIENT_ONCE)
        SSL_OptionSet(ctx, SSL_REQUIRE_CERTIFICATE, SSL_REQUIRE_FIRST_HANDSHAKE);

done:
    ossl->verify_mode = mode;
    ossl->verify_cb = callback;

    return;
}

long SSL_get_verify_result(const SSL *ssl)
{
    ossl_ctx_t * ossl = NULL;
    if (!ssl)
        return -1;

    ossl = nss_get_private((SSL *)ssl);

    return ossl->verify_result;
}

void CRYPTO_free(void *data)
{
    if (data)
        PORT_Free(data);
}

void CRYPTO_cleanup_all_ex_data(void)
{
}

/*
 * Set the native file descriptor for use in the SSL connection.
 */
int SSL_set_fd(SSL *s, int fd)
{
    PRFileDesc *new;

    /* Close the original handle created by PR_NewTCPSocket() so we don't
     * leak fds.
     */
    close(PR_FileDesc2NativeHandle(s));

    /* Grab the NSPR layer and replace the file descriptor */
    new = PR_GetIdentitiesLayer(s, PR_NSPR_IO_LAYER);
    PR_ChangeFileDescNativeHandle(new, fd);

    return 1;
}
/*
 * Set the native file descriptor for use in the SSL connection.
 */
int SSL_set_bio(SSL *s, BIO *bio, BIO *bio1)
{
    PRFileDesc *old;
    PRFileDesc *new;

    if (bio != bio1) {
        return -1;
    }


    if (gBioIdentity == PR_INVALID_IO_LAYER) {
        ssl_init_bio();
    }

    /* close the previous layer */
    old = PR_GetIdentitiesLayer(s, gBioIdentity);
    if (old) {
	PR_PopIOLayer(s, gBioIdentity);
        old->dtor(old);
    }

    /* Stick our storage layer in */
    new = PR_CreateIOLayerStub(gBioIdentity, &gBioMethods);
    if (new == NULL)
        goto error;
    nspr_set_bio(new , bio);
    if (PR_PushIOLayer(s, PR_GetLayersIdentity(s->lower), new) != PR_SUCCESS)
        goto error;

    return 1;

error:
    return -1;
}

BIO *
BIO_new(BIO_METHOD *bm)
{
   BIO *bio;

   bio = PR_NEW(BIO);
   if (!bio) {
        return NULL;
   }
   bio->m = bm;
   bm->create(bio);
   return bio;
}

int BIO_clear_retry_flags(BIO *b)
{
   return 0;
}

int BIO_set_retry_read(BIO *b)
{
   return 0;
}

int BIO_set_retry_write(BIO *b)
{
   return 0;
}


int SSL_set_rfd(SSL *ssl, int fd)
{
    return -1;
}

int SSL_set_wfd(SSL *ssl, int fd)   
{
    return -1;
}

int SSL_set_ex_data(SSL *ssl, int idx, void *data)
{
    ossl_ctx_t * ossl;

    if (ssl) {
        ossl = nss_get_private(ssl);
        if (PL_HashTableAdd(ossl->appdata, (void *)idx, (void *)data))
            return 0;
        else
            return -1; /* man page is unclear what to return on error */
    }
    return -1;
}

void *SSL_get_ex_data(const SSL *ssl, int idx)
{
    ossl_ctx_t * ossl;
    void * rval = NULL;

    if (ssl) {
        ossl = nss_get_private((SSL *)ssl);
        rval = PL_HashTableLookup(ossl->appdata, (void *)idx);
    }

    return NULL;
}

int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
                                         unsigned int sid_ctx_len)
{
    return 0;
}

void SSL_set_connect_state(SSL *s)
{
    /* NOOP */
}

void SSL_set_accept_state(SSL *s)
{
    /* NOOP */
}

int SSL_accept(SSL *ssl)
{
    PRPollDesc pollset[2];

    if (!configureserver(ssl))
        return 0;

    SSL_ResetHandshake(ssl, PR_TRUE); /* reset as server */

    /* Force the handshake */
    pollset[0].in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
    pollset[0].out_flags = 0;
    pollset[0].fd = ssl;
    while(1)
    {
        PRStatus status;
        PRInt32 filesReady;

        SSL_ForceHandshake(ssl);
        filesReady = PR_Poll(pollset, 1, PR_INTERVAL_NO_TIMEOUT);
        if (filesReady < 0) {
            goto error;
        }
        if (filesReady == 0) { /* shouldn't happen! */
            goto error;
        }
        status = PR_ConnectContinue(ssl, pollset[0].out_flags);
        if (status == PR_SUCCESS)
            break;
        if (PR_GetError() != PR_IN_PROGRESS_ERROR)
            goto error;
    }

    error:

    return 1;
}

int SSL_connect(SSL *ssl)
{
    if (SSL_ResetHandshake(ssl, PR_FALSE /* reset as client */) !=
        SECSuccess)
        return 0;

    /* Make the handshake happen now */
    if (SSL_ForceHandshake(ssl) == SECSuccess)
        return 1;
    else
        return 0;
}

int SSL_pending(SSL *ssl)
{
    /* Never any data pending. NSS does this behind the scenes. */
    return 0;
}

int SSL_shutdown(SSL *ssl)
{
    PRStatus status;
    ossl_ctx_t *ossl;

    if (!ssl)
        return -1;

    ossl = nss_get_private(ssl);
    ossl->shutdown_flags = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

    status = PR_Shutdown(ssl, PR_SHUTDOWN_BOTH);

    /* We don't want to PR_Close() it here */

    if (status == PR_SUCCESS)
        return 1;
    else
        return -1;
}

int SSL_want(SSL *s)
{
    /* I read this as: there is SSL data to operate on, not user data.
     * If this is the case then this will always be zero as NSS
     * hides this detail.
     */

    return SSL_NOTHING;
}

int SSL_peek(SSL *ssl, void *buf, int num)
{
    int flags;

    if (ssl) {
        flags = SSL_get_shutdown(ssl);
        if (flags & SSL_RECEIVED_SHUTDOWN)
            return 0;
    }

    /* FIXME: Timeout should not be hardcoded */
    return PR_Recv(ssl, buf, num, PR_MSG_PEEK, PR_SecondsToInterval(1));
}

int SSL_get_error(SSL *ssl, int i)
{
    if (ssl) {
        ossl_ctx_t *ossl = nss_get_private(ssl);
        if (ossl && ossl->error)
            return ossl->error;
    }

    return PR_GetError();
}

SSL_SESSION *SSL_get_session(SSL *ssl)
{
    /* NSS manages sessions for us */
    return NULL;
}

void SSL_SESSION_free(SSL_SESSION *sess)
{
    return;  
}

#if 0
int ENGINE_init(ENGINE *);

void ENGINE_register_all_complete(void);

int ENGINE_set_default(ENGINE *, int);

ENGINE *ENGINE_by_id(const char *);

int ENGINE_ctrl_cmd_string(ENGINE *, const char *, const char *, const char *);

void ENGINE_finish(ENGINE *);
void ENGINE_free(ENGINE *);
#endif

#define ERR_GET_REASON(l)       (int)((l)&0xfffL)
unsigned long ERR_get_error(void)
{
    long err;

    err = PR_GetError();
    /* OpenSSL has a stack of errors. We provide just one, so clear it out */
    PR_SetError(0, 0);
    return err;
}

unsigned long ERR_peek_error(void)
{
    return PR_GetError();
}

unsigned long ERR_peek_last_error(void)
{
    return PR_GetError();
}

void ERR_remove_state(unsigned long pid)
{ 
    return; /* NSS has no queue to free */
}

char *ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
    PL_strncpyz(buf, nss_error(e), len);
    return buf;
}

/* Not thread-safe */
char *ERR_error_string(unsigned long e, char *buf)
{
    static char errbuf[256]; /* 256 is arbitrary */
    if (buf) {
        /* FIXME: ack, how do we know how long buf is?  */
        ERR_error_string_n(e, buf, 256);
        return buf;
    } else { 
        ERR_error_string_n(e, errbuf, 256);
        return errbuf;
    }
}

void ERR_free_strings(void)
{
    return;
}

void EVP_cleanup(void)
{
    return;
}

const char *SSL_alert_type_string_long(int value)
{
    return (NULL);
}

const char *SSL_alert_desc_string_long(int value)
{
    return (NULL);
}

const char *SSL_state_string_long(const SSL *s)
{
    /* We have no visibility into the current NSS handshake state */
    return "Unknown";
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx, void(*cb)())
{
    ossl_ctx_t *ossl;

    if (!ctx)
        return;

    ossl = nss_get_private(ctx);

    ossl->info_cb = cb;

    return;
}

/* SSL_*ctrl */
long SSL_CTX_set_options(SSL_CTX *c, long i)
{
  return 0;
}

long SSL_CTX_set_session_cache_mode(SSL_CTX *c, long i)
{
  return 0;
}

long SSL_CTX_set_mode(SSL_CTX *ctx, long mode)
{
    return 0;
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
    /* FIXME: should we call this or not? */
    return;
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
    /* FIXME: save the data sent */
    return;
}

/* SSL_CTX_set_default_passwd_cb* is ignored */
int PEM_def_callback(char *buf, int num, int w, void *key)
{
    *buf = 0;
    return 0;
}

long SSL_session_reused(SSL *s)
{
  return 0;
}

X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx)
{
    return ctx->current_cert;
}

#define X509_STORE_CTX_EX_DATA_SSL_IDX 42
int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    return X509_STORE_CTX_EX_DATA_SSL_IDX;
}

void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx)
{
    if (idx == X509_STORE_CTX_EX_DATA_SSL_IDX)
	return ctx->ssl__;
    return NULL;
}


int X509_STORE_get_by_subject(X509_STORE_CTX *vs, int type, X509_NAME *name,
			      X509_OBJECT *ret)
{
    PRArenaPool *arena;
    CERTCertificate * cert;
    SECItem *subject;

    (void)vs;
    if (type != X509_LU_X509)
	return 0;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL)
	return 0;
    subject = SEC_ASN1EncodeItem(arena, NULL, name, CERT_NameTemplate);
    cert = NULL;
    if (subject != NULL)
	cert = CERT_FindCertByName(CERT_GetDefaultCertDB(), subject);
    PORT_FreeArena(arena, PR_FALSE);
    if (cert == NULL)
	return 0;
    /* FIXME: a more useful representation of the certificate, e.g. one that
       does not leak? */
    ret->type = siBuffer;
    ret->data = (unsigned char *)cert;
    ret->len = sizeof (*cert);
    return 1;
}


void CRYPTO_set_id_callback(unsigned long (*func)(void))
{
}

void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
					      const char *file, int line))
{
}

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
        CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
    /* FIXME: need to handle the 3 functions as well */
    return ex_data_index++;
}

unsigned char * ASN1_STRING_data(ASN1_STRING *x)
{
    return x->data;
}

int ASN1_STRING_type(ASN1_STRING *x)
{
    return x->type;
}

int ASN1_STRING_length(ASN1_STRING *x)
{
    return x->length;
}
