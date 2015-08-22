#include <Rinternals.h>
#include <openssl/opensslv.h>

SEXP R_openssl_version() {
  return mkString(OPENSSL_VERSION_TEXT);
}
