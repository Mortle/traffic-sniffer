#include "sniffer.h"


int main(int argc, char *argv[]) {

  /* Requires filter argument */
  // if(argc != 2) {
  //   fprintf(stdout, "Usage: %s \"expression\"\n", argv[0]);
  //   return 0;
  // }

  sniffer(NULL, NULL, 10);

  return 0;
}
