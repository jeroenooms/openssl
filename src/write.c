#include "utils.h"
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

SEXP R_write_pem_rsa_pubkey(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(d2i_RSAPublicKey(&rsa, &ptr, LENGTH(bin)));
  BIO *bio = new_auto_bio(BIO_s_mem());
  auto_check(PEM_write_bio_RSA_PUBKEY(bio, rsa));

  //Get the output
  BUF_MEM *buf;
  BIO_get_mem_ptr(bio, &buf);
  auto_add(BUF_MEM_free, buf);

  //return a character vector
  SEXP out = auto_protect(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLen(buf->data, buf->length));

  //Cleanup and return
  auto_return(out);
}


SEXP R_write_pem_dsa_pubkey(SEXP bin){
  DSA *dsa = DSA_new();
  const unsigned char *ptr = RAW(bin);
  auto_check(d2i_DSAPublicKey(&dsa, &ptr, LENGTH(bin)));
  BIO *bio = new_auto_bio(BIO_s_mem());
  auto_check(PEM_write_bio_DSA_PUBKEY(bio, dsa));

  //Get the output
  BUF_MEM *buf;
  BIO_get_mem_ptr(bio, &buf);
  auto_add(BUF_MEM_free, buf);

  //return a character vector
  SEXP out = auto_protect(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLen(buf->data, buf->length));

  //Cleanup and return
  auto_return(out);
}
