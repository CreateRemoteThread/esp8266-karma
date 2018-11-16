int tag_supportedSSID(uint8_t *buf,int posn,uint8_t *orig_ssid,int orig_ssidlen);
void dirtyhack_update_seqn(uint8_t *buf);
uint8_t *dirtyhack_duplicate_and_beacon(uint8_t *buf,int size);
int tag_supportedRates(uint8_t *buf,int posn);
int tag_supportedChannels(uint8_t *buf,int posn,uint8_t chan);
int tag_ERPInformation(uint8_t *buf,int posn);
int tag_extendedSupportedRates(uint8_t *buf, int posn);
uint16_t beaconresp(uint8_t *buf, uint8_t *client, uint8_t *ap, uint16_t seq,uint8_t ssid_len, char *ssid,uint8_t chan);
uint16_t proberesp(uint8_t *buf, uint8_t *client, uint8_t *ap, uint16_t seq,uint8_t ssid_len, char *ssid,uint8_t chan);
int saveForgedTimestamp(uint8_t *timestamp);

void dirtyhack_update_seqn(uint8_t *buf);
uint8_t *dirtyhack_duplicate_and_beacon(uint8_t *buf,int size);
