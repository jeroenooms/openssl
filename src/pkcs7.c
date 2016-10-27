#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include "utils.h"
#include "compatibility.h"

SEXP R_parse_pem_pkcs7(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  PKCS7 *p7 = PEM_read_bio_PKCS7(mem, NULL, password_cb, NULL);
  unsigned char *buf = NULL;
  int len = i2d_PKCS7(p7, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
}

SEXP R_parse_der_pkcs7(SEXP input){
  const unsigned char *ptr = RAW(input);
  PKCS7 *p7 = d2i_PKCS7(NULL, &ptr, LENGTH(input));
  bail(!!p7);
  STACK_OF(X509) *ca = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  PKCS7_dataDecode(p7, NULL, NULL, cert);
  bail(!!cert);
  //bail(PKCS7_decrypt(p7, NULL, NULL, msg, 0));
  //PKCS7_verify(p7, NULL, NULL, NULL, msg, PKCS7_NOVERIFY);
  PKCS7_get0_signers(p7, ca, PKCS7_NOVERIFY);
  bail(!!ca);
  PKCS7_free(p7);
  unsigned char *buf = NULL;
  int len = 0;
  SEXP res = PROTECT(allocVector(VECSXP, 3));
  if (cert != NULL) {
    len = i2d_X509(cert, &buf);
    X509_free(cert);
    bail(len);
    SET_VECTOR_ELT(res, 0, allocVector(RAWSXP, len));
    memcpy(RAW(VECTOR_ELT(res, 0)), buf, len);
    free(buf);
    buf = NULL;
  }
  if(pkey != NULL){
    len = i2d_PrivateKey(pkey, &buf);
    EVP_PKEY_free(pkey);
    bail(len);
    SET_VECTOR_ELT(res, 1, allocVector(RAWSXP, len));
    memcpy(RAW(VECTOR_ELT(res, 1)), buf, len);
    free(buf);
    buf = NULL;
  }
  if(ca && sk_X509_num(ca)){
    int ncerts = sk_X509_num(ca);
    SEXP bundle = PROTECT(allocVector(VECSXP, ncerts));
    for(int i = 0; i < ncerts; i++){
      cert = sk_X509_value(ca, (ncerts - i - 1)); //reverse order to match PEM/SSL
      len = i2d_X509(cert, &buf);
      bail(len);
      SET_VECTOR_ELT(bundle, i, allocVector(RAWSXP, len));
      memcpy(RAW(VECTOR_ELT(bundle, i)), buf, len);
      free(buf);
      buf = NULL;
    }
    sk_X509_pop_free(ca, X509_free);
    SET_VECTOR_ELT(res, 2, bundle);
    UNPROTECT(1);
  }
  UNPROTECT(1);
  return res;
}
