#include "utils_t.h"
#include "Enclave_t.h"

#include "sgx_trts.h" // sgx_read_rand

#include <string.h>
#include <stdio.h> // vsnprintf

void eprintf(const char* fmt, ...)
{
  char buf[BUFSIZ] = { '\0' };
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
}

void draw_rand(void* r, int len)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  ret = sgx_read_rand((uint8_t*)r, len);
}

