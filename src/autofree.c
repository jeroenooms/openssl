/* Jeroen Ooms 2015
 * Automatically queue objects to be free later with their corresponding
 * free() function.
 */

#include <stdlib.h>
#include <stdio.h>

struct node {
  void (*fun)(void *target);
  void *ptr;
  struct node *parent;
};

struct node *head;

#define auto_add(target, ptr) auto_add_generic((void(*)(void*)) (target), (ptr))

void auto_add_generic(void (*fun)(void *target), void *ptr){
  struct node *x = malloc( sizeof(struct node) );
  x->parent = head;
  x->fun = fun;
  x->ptr = ptr;
  head = x;
}

void auto_free(){
  while(head != NULL){
    struct node *old = head;
    if(head->ptr != NULL)
      head->fun(head->ptr); //free the target object if not null
    head = head->parent;
    free(old); //free the node struct itself
    #ifdef DEBUG
    printf("freeing something...\n");
    #endif
  }
  #ifdef DEBUG
  printf("clean up done.\n");
  #endif
}

/* optional autofree functions */
void* auto_malloc (size_t size){
  void *ptr = malloc(size);
  auto_add(free, ptr);
  return ptr;
}
