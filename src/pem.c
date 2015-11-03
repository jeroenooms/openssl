#include "utils.h"
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

int password_cb(char *buf, int max_size, int rwflag, void *ctx){
  if(!ctx)
    auto_error("No password callback supplied.");

  SEXP cb = (SEXP) ctx;
  int len;

  /* case where password is a hardcoded string */
  if(isString(cb)){
    len = LENGTH(STRING_ELT(cb, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(cb, 0)), len);
    return len;
  }

  /* case where password is an R function */
  if(isFunction(cb)){
    int err;
    SEXP call = auto_protect(LCONS(cb, LCONS(mkString("Please enter private key passphrase: "), R_NilValue)));
    SEXP res = auto_protect(R_tryEval(call, R_GlobalEnv, &err));
    if(err || !isString(res))
      auto_error("Password callback did not return a string value");

    len = LENGTH(STRING_ELT(res, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(res, 0)), len);

    auto_cleanup();
    return len;
  }
  error("Callback must be string or function");
}

SEXP R_write_pkcs8(RSA *rsa){
  //Rprintf("Public key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSA_PUBKEY(rsa, NULL);
  auto_check(len);
  SEXP res = allocVector(RAWSXP, len);
  unsigned char *ptr = RAW(res);
  auto_check(i2d_RSA_PUBKEY(rsa, &(ptr)));
  return res;
}

SEXP R_write_dsa(DSA *dsa){
  int len = i2d_DSA_PUBKEY(dsa, NULL);
  auto_check(len);
  SEXP res = allocVector(RAWSXP, len);
  unsigned char *ptr = RAW(res);
  auto_check(i2d_DSA_PUBKEY(dsa, &(ptr)));
  return res;
}

SEXP R_write_rsa_private(RSA *rsa){
  //Rprintf("Private key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSAPrivateKey(rsa, NULL);
  auto_check(len);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  auto_check(i2d_RSAPrivateKey(rsa, &(ptr)));
  return res;
}

SEXP R_write_ecdsa(EC_KEY *pubkey){
  int len = i2d_EC_PUBKEY(pubkey, NULL);
  auto_check(len);
  SEXP res = allocVector(RAWSXP, len);
  unsigned char *ptr = RAW(res);
  auto_check(i2d_EC_PUBKEY(pubkey, &(ptr)));
  return res;
}

SEXP R_priv2pub(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin)));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs1(SEXP input, SEXP type){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  auto_check(PEM_read_bio_RSAPublicKey(mem, &rsa, password_cb, NULL));
  auto_check(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs8(SEXP input){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  auto_check(PEM_read_bio_RSA_PUBKEY(mem, &rsa, password_cb, NULL));
  auto_check(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_rsa_private(SEXP input, SEXP password){
  EVP_PKEY *key = EVP_PKEY_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  auto_check(PEM_read_bio_PrivateKey(mem, &key, password_cb, password));
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  return R_write_rsa_private(rsa);
}

SEXP R_rsa_build(SEXP expdata, SEXP moddata){
  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  auto_check(BN_bin2bn(RAW(expdata), LENGTH(expdata), rsa->e));
  auto_check(BN_bin2bn(RAW(moddata), LENGTH(moddata), rsa->n));
  return R_write_pkcs8(rsa);
}

// https://tools.ietf.org/html/rfc4253
// ... the "ssh-des" key format has the following ...
SEXP R_dsa_build(SEXP p, SEXP q, SEXP g, SEXP y){
  DSA *dsa = DSA_new();
  dsa->p = r2bignum(p);
  dsa->q = r2bignum(q);
  dsa->g = r2bignum(g);
  dsa->pub_key = r2bignum(y);
  return R_write_dsa(dsa);
}

SEXP R_ecdsa_build(SEXP x, SEXP y){
  EC_KEY *pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!EC_KEY_set_public_key_affine_coordinates(pubkey, r2bignum(x), r2bignum(y)))
    error("Failed to construct EC key. Perhaps invalid point or curve.");
  return R_write_ecdsa(pubkey);
}

SEXP R_rsa_pk_decompose(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(bin)));
  SEXP res = auto_protect(allocVector(VECSXP, 2));
  SET_VECTOR_ELT(res, 0, bignum2r(rsa->e));
  SET_VECTOR_ELT(res, 1, bignum2r(rsa->n));
  auto_return(res);
}

SEXP R_rsa_sk_decompose(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin)));
  SEXP res = auto_protect(allocVector(VECSXP, 5));
  SET_VECTOR_ELT(res, 0, bignum2r(rsa->e));
  SET_VECTOR_ELT(res, 1, bignum2r(rsa->n));
  SET_VECTOR_ELT(res, 2, bignum2r(rsa->p));
  SET_VECTOR_ELT(res, 3, bignum2r(rsa->q));
  SET_VECTOR_ELT(res, 4, bignum2r(rsa->d));
  auto_return(res);
}


SEXP R_cert2pub(SEXP bin){
  X509 *cert = X509_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(!!d2i_X509(&cert, &ptr, LENGTH(bin)));
  EVP_PKEY *key = X509_get_pubkey(cert);
  if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
    error("Key is not RSA key");
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  return R_write_pkcs8(rsa);
}

SEXP R_guess_type(SEXP bin){
  RSA *rsa = RSA_new();
  X509 *cert = X509_new();
  const unsigned char *ptr = RAW(bin);
  if(d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin))) {
    return mkString("key");
  } else if(d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(bin))) {
    return mkString("pubkey");
  } else if(d2i_X509(&cert, &ptr, LENGTH(bin))) {
    return mkString("cert");
  }
  return R_NilValue;
}

SEXP R_parse_x509(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  X509 *cert = PEM_read_bio_X509(mem, NULL, password_cb, NULL);
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  auto_check(len > 0);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(res), buf, len);
  setAttrib(res, R_ClassSymbol, mkString("x509"));
  UNPROTECT(1);
  free(buf);
  return res;
}

SEXP R_parse_key(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem, NULL, password_cb, NULL);
  BIO_free(mem);
  if(pkey == NULL)
    Rf_error("Failed to parse private key");
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  if(!len)
    Rf_error("Failed to serialize private key");
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(res), buf, len);
  setAttrib(res, R_ClassSymbol, mkString("key"));
  setAttrib(res, install("type"), ScalarInteger(EVP_PKEY_type(pkey->type)));
  free(buf);
  UNPROTECT(1);
  return res;
}

SEXP R_parse_pubkey(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(mem, &pkey, password_cb, NULL);
  BIO_free(mem);
  if(pkey == NULL)
    Rf_error("Failed to parse public key");
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  if(!len)
    Rf_error("Failed to serialize public key");
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(res), buf, len);
  setAttrib(res, R_ClassSymbol, mkString("pubkey"));
  setAttrib(res, install("type"), ScalarInteger(EVP_PKEY_type(pkey->type)));
  free(buf);
  UNPROTECT(1);
  return res;
}

SEXP R_parse_der_pubkey(SEXP input){
  const unsigned char *ptr = RAW(input);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(input));
  if(pkey == NULL)
    Rf_error("Failed to parse public key");
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  if(!len)
    Rf_error("Failed to serialize public key");
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(res), buf, len);
  setAttrib(res, R_ClassSymbol, mkString("pubkey"));
  setAttrib(res, install("type"), ScalarInteger(EVP_PKEY_type(pkey->type)));
  free(buf);
  UNPROTECT(1);
  return res;
}

SEXP R_parse_der_key(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  if(pkey == NULL)
    Rf_error("Failed to parse private key");
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  if(!len)
    Rf_error("Failed to serialize private key");
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(res), buf, len);
  setAttrib(res, R_ClassSymbol, mkString("key"));
  setAttrib(res, install("type"), ScalarInteger(EVP_PKEY_type(pkey->type)));
  free(buf);
  UNPROTECT(1);
  return res;
}
