/* a simple counter for temporary protect statements */

#include <Rinternals.h>

int auto_protect_count;

SEXP auto_protect(SEXP s){
  auto_protect_count++;
  return PROTECT(s);
}

void auto_unprotect() {
  #ifdef DEBUG
  printf("Unprotecting %d items\n", auto_protect_count);
  #endif
  UNPROTECT(auto_protect_count);
  auto_protect_count = 0;
}
