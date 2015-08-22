#' OpenSSL version
#'
#' Shows OpenSSL version number.
#'
#' @export
#' @name version
#' @rdname version
#' @useDynLib openssl R_openssl_version
openssl_version <- function(){
  .Call(R_openssl_version)
}
