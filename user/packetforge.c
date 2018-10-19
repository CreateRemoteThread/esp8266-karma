#include "ets_sys.h"
#include "osapi.h"
#include "mem.h"
#include "packetforge.h"

uint8_t forge_timestamp[8] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

int saveForgedTimestamp(uint8_t *timestamp)
{
  int i = 0;
  for(i = 0;i < 8;i++)
  {
    forge_timestamp[i] = timestamp[i];
  }
}

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

// update the sequence number in place and increment by 1.
void dirtyhack_update_seqn(uint8_t *buf)
{
  uint16_t seqnPacket = (((unsigned int)buf[23] << 8) + buf[22] ) >> 4;
  uint16_t newSeqnPacket = ((seqnPacket + 1) << 4) & 0xFFF0;
  buf[22] = newSeqnPacket % 0x100; // bug in original karma source
  buf[23] = newSeqnPacket / 0x100;
  return;
}

// create a new object for a beacon frame.
// remember to clean this shit up or get OOM'ed.
uint8_t *dirtyhack_duplicate_and_beacon(uint8_t *buf,int size)
{
  uint8_t *ibuf = (uint8_t *)os_malloc(size);
  int i = 0;
  for(i = 0;i < size;i++)
  {
    ibuf[i] = buf[i];
  }
  ibuf[0] = 0x80;
  for (i=0; i<6; i++) ibuf[i+4] = 0xFF;
  return ibuf;
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
  internal_buf[++l] = 0x04; // DSSS Current Channel
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

uint16_t beaconresp(uint8_t *buf, uint8_t *client, uint8_t *ap, uint16_t seq,uint8_t ssid_len, char *ssid)
{
    int i=0;

    buf[0] = 0x80; // probe_response
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
