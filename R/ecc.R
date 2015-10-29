#' Eliptic Curves
#'
#' Bla bla stuff
#'
#' @export
#' @rdname ec
#' @name ec
#' @param a bignum a
#' @param b bignum b
#' @param p bignum p
#' @useDynLib openssl R_ec_new_curve
ec_curve <- function(a, b, p) {
  .Call(R_ec_new_curve, bn(a), bn(b), bn(p))
}

#' @export
#' @rdname ec
ec_secp256k1 <- function(){
  p <- bignum(2)^256 - sum(rep(2, 7) ^ c(32, 9, 8, 7, 6, 4, 0))
  ec_curve(a = 0, b = 7, p = p)
}

ec_key <- function(size = 32){
  bignum(rand_bytes(size))
}

get_pubkey <- function(key, curve = ec_secp256k1()){
  #derive pubkey
}
