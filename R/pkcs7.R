#' @export
#' @rdname read_key
read_pkcs7 <- function(file, der = is.raw(file)){
  buf <- read_input(file)
  if(!isTRUE(der)){
    buf <- parse_pem_pkcs7(buf)
  }
  data <- parse_der_pkcs7(buf)
  out <- list(cert = NULL, key = NULL, ca = NULL)
  if(length(data[[1]]))
    out$cert <- read_cert(data[[1]], der = TRUE)
  if(length(data[[2]]))
    out$key <- read_key(data[[2]], der = TRUE)
  if(length(data[[3]]))
    out$ca <- lapply(data[[3]], read_cert, der = TRUE)
  return(out)
}

#' @useDynLib openssl R_parse_der_pkcs7
parse_der_pkcs7 <- function(buf){
  .Call(R_parse_der_pkcs7, buf)
}

#' @useDynLib openssl R_parse_pem_pkcs7
parse_pem_pkcs7 <- function(buf){
  .Call(R_parse_pem_pkcs7, buf)
}
