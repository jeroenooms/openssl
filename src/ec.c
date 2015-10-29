#include "utils.h"
#include <openssl/ec.h>

SEXP R_ec_new_curve(SEXP a_, SEXP b_, SEXP p_){
  BIGNUM *a = r2bignum(a_);
  BIGNUM *b = r2bignum(b_);
  BIGNUM *p = r2bignum(p_);
  BN_CTX *ctx = new_auto_bn_ctx();
  EC_GROUP *curve = EC_GROUP_new(EC_GFp_simple_method());
  auto_check(curve);
  auto_add(EC_GROUP_free, curve);
  auto_check(EC_GROUP_set_curve_GFp(curve, p, a, b, ctx));

  unsigned char *buf;
  int len = i2d_ECPKParameters(curve, &buf);
  auto_check(len > -1);
  auto_add(free, buf);

  SEXP res = auto_protect(allocVector(RAWSXP, len));
  memcpy(res, buf, len);
  setAttrib(res, R_ClassSymbol, mkString("ec_curve"));
  auto_return(res);
}
