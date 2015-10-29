/* Stuff we always want */
#include <Rinternals.h>
#include <string.h>

/* Suppress warnings on OSX */
#if __APPLE__
#include <AvailabilityMacros.h>
#ifdef  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
#endif

/* OpenSSL includes */
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>

/* Convenience macros */
#define auto_error(...) Rf_errorcall(auto_cleanup(), __VA_ARGS__)
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* error.c */
#define auto_check(success) auto_check_generic((long) (success))
void auto_check_generic(long success);
#define auto_return(x) SEXP __returnval__ = (x); auto_cleanup(); return __returnval__
SEXP auto_cleanup();
void raise_ssl_error();

/* freemelater.c */
#define auto_add(...) auto_add_generic((void(*)(void*)) __VA_ARGS__)
void auto_add_generic(void (*fun)(void *target), void *ptr);
void auto_free();
void* auto_malloc();

/* protect.c */
SEXP auto_protect(SEXP s);
void auto_unprotect();

/* types.c */
BIGNUM *new_auto_bignum();
BIO *new_auto_bio(BIO_METHOD *type);
BIGNUM *r2bignum(SEXP x);
SEXP bignum2r(BIGNUM *val);
X509 *new_auto_x509_cert();
X509_STORE *new_auto_x509_store();
X509_STORE_CTX *new_auto_x509_store_ctx();
BN_CTX *new_auto_bn_ctx();
RSA *auto_rsa_new();

