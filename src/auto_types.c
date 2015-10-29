#include "utils.h"

BIGNUM *new_auto_bignum(){
  BIGNUM *val = BN_new();
  auto_add(BN_free, val);
  return val;
}

BN_CTX *new_auto_bn_ctx(){
  BN_CTX *ctx = BN_CTX_new();
  auto_add(BN_CTX_free, ctx);
  return ctx;
}

BIGNUM *r2bignum(SEXP x){
  if(!inherits(x, "bignum"))
    error("Argument is not valid bignum");
  BIGNUM *val = BN_bin2bn(RAW(x), LENGTH(x), NULL);
  auto_check(val != NULL);
  auto_add(BN_free, val);
  return val;
}

SEXP bignum2r(BIGNUM *val){
  SEXP out = auto_protect(allocVector(RAWSXP, BN_num_bytes(val)));
  auto_check(BN_bn2bin(val, RAW(out)) >= 0);
  setAttrib(out, R_ClassSymbol, mkString("bignum"));
  return out;
}

BIO* new_auto_bio(BIO_METHOD *type){
  BIO * val = BIO_new(type);
  auto_add(BIO_free_all, val);
  return val;
}

X509 *new_auto_x509_cert(){
  X509 *cert = X509_new();
  auto_add(X509_free, cert);
  return cert;
}

X509_STORE *new_auto_x509_store(){
  X509_STORE *store = X509_STORE_new();
  auto_add(X509_STORE_CTX_free, store);
  return store;
}

X509_STORE_CTX *new_auto_x509_store_ctx(){
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  auto_add(X509_STORE_CTX_free, ctx);
  return ctx;
}

RSA *auto_rsa_new(){
  RSA *rsa = RSA_new();
  auto_add(RSA_free, rsa);
  return rsa;
}
