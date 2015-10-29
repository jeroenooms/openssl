#include "utils.h"
#include <openssl/err.h>

SEXP auto_cleanup(){
  auto_free();
  auto_unprotect();
  return R_NilValue;
}

void raise_ssl_error(){
  unsigned long err = ERR_get_error();
  auto_error("OpenSSL error in %s: %s", ERR_func_error_string(err), ERR_reason_error_string(err));
}

void auto_check_generic(long success){
  if(!success)
    raise_ssl_error();
}
