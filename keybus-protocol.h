#ifndef KEYBUS_PROTOCOL
#define KEYBUS_PROTOCOL

int check_crc(char *packet, int len);
int parse_status_flags(int flags, char *buffer);
int parse_05(char *packet, char *buffer);
int parse_keybus(char *packet, char *buffer, int len, int *crc_error);
int is_interesting_packet(char *packet);
int packet_to_bits(char *packet, char *buffer, int bit_count, int has_stop_bit);

#endif
