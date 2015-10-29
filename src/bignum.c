#include <Rinternals.h>
#include "utils.h"
#include <openssl/ec.h>

SEXP R_parse_bignum(SEXP x, SEXP hex){
  BIGNUM *val = new_auto_bignum();
  if(TYPEOF(x) == RAWSXP){
    auto_check(NULL != BN_bin2bn(RAW(x), LENGTH(x), val));
  } else if(asLogical(hex)){
    auto_check(BN_hex2bn(&val, CHAR(STRING_ELT(x, 0))));
  } else {
    auto_check(BN_dec2bn(&val, CHAR(STRING_ELT(x, 0))));
  }
  auto_return(bignum2r(val));
}

SEXP R_bignum_as_character(SEXP x, SEXP hex){
  BIGNUM *val = r2bignum(x);
  char *str = NULL;
  if(asLogical(hex)){
    auto_check(str = BN_bn2hex(val));
  } else {
    auto_check(str = BN_bn2dec(val));
  }
  SEXP res = mkString(str);
  OPENSSL_free(str);
  auto_return(res);
}

SEXP R_bignum_add(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_add(out, r2bignum(x), r2bignum(y)));
  auto_return(bignum2r(out));
}

SEXP R_bignum_subtract(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_sub(out, r2bignum(x), r2bignum(y)));
  auto_return(bignum2r(out));
}

SEXP R_bignum_multiply(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_mul(out, r2bignum(x), r2bignum(y), new_auto_bn_ctx()));
  auto_return(bignum2r(out));
}

SEXP R_bignum_devide(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_div(out, NULL, r2bignum(x), r2bignum(y), new_auto_bn_ctx()));
  auto_return(bignum2r(out));
}

SEXP R_bignum_mod(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_mod(out, r2bignum(x), r2bignum(y), new_auto_bn_ctx()));
  auto_return(bignum2r(out));
}

SEXP R_bignum_exp(SEXP x, SEXP y){
  BIGNUM *out = new_auto_bignum();
  auto_check(BN_exp(out, r2bignum(x), r2bignum(y), new_auto_bn_ctx()));
  auto_return(bignum2r(out));
}

SEXP R_bignum_compare(SEXP x, SEXP y){
  auto_return(ScalarInteger(BN_cmp(r2bignum(x), r2bignum(y))));
}
