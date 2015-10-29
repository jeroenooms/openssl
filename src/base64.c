#include "utils.h"
#include <openssl/evp.h>
#include <openssl/buffer.h>

SEXP R_base64_encode(SEXP bin, SEXP linebreaks){
  //setup encoder
  BIO *bio = BIO_push(new_auto_bio(BIO_f_base64()), BIO_new(BIO_s_mem()));

  //No linebreaks
  if(!asLogical(linebreaks))
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_write(bio, RAW(bin), length(bin));
  BIO_flush(bio);

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

SEXP R_base64_decode(SEXP text){
  int len = LENGTH(STRING_ELT(text, 0));
  BIO *bio = BIO_push(new_auto_bio(BIO_f_base64()), BIO_new_mem_buf((void*) CHAR(STRING_ELT(text, 0)), len));

  //Assume on linebreaks
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  //binary size is always smaller than base64 msg
  unsigned char *bin = auto_malloc(len);
  int bin_len = BIO_read(bio, bin, len);

  //create raw output vector
  SEXP out = auto_protect(allocVector(RAWSXP, bin_len));
  memcpy(RAW(out), bin, bin_len);

  //cleanup and return
  auto_return(out);
}
