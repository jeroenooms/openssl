#include "utils.h"
#include <openssl/pem.h>

SEXP R_certinfo(SEXP bin){
  X509 *cert = new_auto_x509_cert();
  const unsigned char *ptr = RAW(bin);
  auto_check(!!d2i_X509(&cert, &ptr, LENGTH(bin)));

  //out list
  int bufsize = 8192;
  char buf[bufsize];
  int len;
  X509_NAME *name;
  SEXP out = auto_protect(allocVector(VECSXP, 5));

  //subject name
  name = X509_get_subject_name(cert);
  X509_NAME_oneline(name, buf, bufsize);
  SET_VECTOR_ELT(out, 0, mkString(buf));
  X509_NAME_free(name);

  //issuer name name
  name = X509_get_issuer_name(cert);
  X509_NAME_oneline(name, buf, bufsize);
  SET_VECTOR_ELT(out, 1, mkString(buf));
  X509_NAME_free(name);

  //sign algorithm
  OBJ_obj2txt(buf, sizeof(buf), cert->sig_alg->algorithm, 0);
  SET_VECTOR_ELT(out, 2, mkString(buf));

  //start date
  BIO *b = new_auto_bio(BIO_s_mem());
  auto_check(ASN1_TIME_print(b, cert->cert_info->validity->notBefore));
  len = BIO_read(b, buf, bufsize);
  auto_check(len);
  buf[len] = '\0';
  SET_VECTOR_ELT(out, 3, mkString(buf));

  //expiration date
  BIO *b2 = new_auto_bio(BIO_s_mem());
  auto_check(ASN1_TIME_print(b2, cert->cert_info->validity->notAfter));
  len = BIO_read(b2, buf, bufsize);
  auto_check(len);
  buf[len] = '\0';
  SET_VECTOR_ELT(out, 4, mkString(buf));

  //return
  auto_cleanup();
  return out;
}

SEXP R_verify_cert(SEXP certdata, SEXP cadata) {
  /* load cert */
  const unsigned char *ptr = RAW(certdata);
  X509 *cert = new_auto_x509_cert();
  X509 *ca = new_auto_x509_cert();
  auto_check(!!d2i_X509(&cert, &ptr, LENGTH(certdata)));

  /* init ca bundle store */
  X509_STORE *store = new_auto_x509_store();
  X509_STORE_CTX *ctx = new_auto_x509_store_ctx();
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  /* cadata is either path to bundle or cert */
  if(isString(cadata)){
    auto_check(X509_STORE_load_locations(store, CHAR(STRING_ELT(cadata, 0)), NULL));
  } else {
    ptr = RAW(cadata);
    auto_check(!!d2i_X509(&ca, &ptr, LENGTH(cadata)));
    auto_check(X509_STORE_add_cert(store, ca));
  }

  if(X509_verify_cert(ctx) < 1)
    auto_error("Certificate validation failed: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

  auto_return(ScalarLogical(1));
}
