#include "ets_sys.h"

struct PNLBuffer{
  char mac[6];
  uint8_t ssid_size;
  char ssid_buf[32];
};
