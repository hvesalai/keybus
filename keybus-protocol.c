#include <linux/kernel.h>
#include "keybus-protocol.h"


// Developed against Power832 from circa year 2000

#define PACKET_BIT(nr, packet) ((packet[((nr) >> 3)] & (1 << (7 - ((nr) & 0x7)))) != 0)

static char *STATUS_FLAGS[8] = { "Backlight", "Fire", "Program", "Error", "Bypass", "Memory", "Armed", "Ready" };
/*
static char *TROUBLE_CONDITIONS[8] = { "Service Required", "AC Failure", "Telephone Line Fault", "Filure to Communicate",
				       "Zone Fault", "Zone Tamper", "Loss of System Time" };
static char *SERVICE_CONDITIONS[8] = { "Low battery", "Bell Circuit", "System Trouble", "System Tamper",
				       "Module Supervision", "RF Jam Detected", "PC5204 Low Battery", "PC5204 AC Failure"}; 
*/
static char *SENSORS1[8] = {"Sensor8", "Sensor7", "Sensor6", "Sensor5", "Sensor4", "Sensor3", "Sensor2", "Sensor1"};
static char *SENSORS2[8] = {"Sensor16", "Sensor15", "Sensor14", "Sensor13", "Sensor12", "Sensor11", "Sensor10", "Sensor9",};
static char *SENSORS3[8] = {"Sensor24", "Sensor23", "Sensor22", "Sensor21", "Sensor20", "Sensor19", "Sensor18", "Sensor17",};
static char *SENSORS4[8] = {"Sensor32", "Sensor31", "Sensor30", "Sensor29", "Sensor28", "Sensor27", "Sensor26", "Sensor25"};

// TODO: door chime : press *4 to turn on , # off

static char *COMMANDS[256] = {
    NULL, NULL, NULL, NULL, NULL, "STATUS", NULL, NULL,         NULL, NULL, "PROGRAM MODE", NULL, NULL, NULL, NULL, NULL,
    NULL, "QUERY", NULL, NULL, NULL, NULL, NULL, NULL,   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, "STATUS 1",         NULL, NULL, NULL, NULL, NULL, "STATUS 2", NULL, NULL,
    NULL, NULL, NULL, NULL, "STATUS 3", NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, "STATUS 4", NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, "ALARM MEM 1", NULL, NULL,
    NULL, NULL, NULL, "ALARM MEM 2", "BEEP CMD 1", NULL, NULL, NULL,         NULL, "BEEP CMD 2", NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, "TIMESTAMP", NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, "SENSOR CFG", NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/** 
 * append the names of the set bits to buffer, returns the number of
 * chars added 
 */
static int append_bits(unsigned int bits, char **names, char *buffer) {
    int i;
    char *buf = buffer;
    
    for (i = 0; i < 8; i++) {
        if (((bits & (1 << (7-i))) != 0) && names[i]) {
            buf += sprintf(buf, "%s%s", (buf == buffer ? "" : ", "), names[i]);
        }
    }

    return buf - buffer;
}

static int packet_bits(int startbit, char *packet, int count) {
    unsigned int bits = 0;
    unsigned int i = 0;

    // brute force it
    while (count-- > 0) {
        bits |= PACKET_BIT(startbit + count, packet) << i++;
    }

    return bits;
}

// returns the packet byte number nr, skipping the stop bit, which is expected
static int packet_byte(int nr, char *packet) {
    if (nr == 0) {
        return packet[0];
    } else {
        // skip stop bit at position 8
        return ((packet[nr] << 1) | ((packet[nr + 1] & 0x80) >> 7)) & 0xff;
    }
}

// return 0 for crc ok, 1 for crc error, -1 for no crc
int check_crc(char *packet, int len) {
    int crc, b;
    int bytes;

    if (len >= 20 && (len & 0x07) == 2) { // has stop bits       
        bytes = (len - 2) >> 3;

        crc = packet_byte(--bytes, packet); // last byte is crc

        while (bytes-- > 0) {
            b = packet_byte(bytes, packet);
            crc -= b;
        }

        return crc & 0xff;
        
    } else {
        return -1;
    }
}

int parse_status_flags(int flags, char *buffer) {
    return append_bits(flags, STATUS_FLAGS, buffer);
}

int parse_05(char *packet, char *buffer) {
    // 00000101 0 10000001 00000001 10000001 11000111 00
    // CMD-----   STATUS-- 
    int command = packet[0];
    int ret = sprintf(buffer, "%02X [%s]: ", command, COMMANDS[command]);

    ret += parse_status_flags(packet_bits(9, packet, 8), buffer + ret);

    ret += sprintf(buffer + ret, "\n");

    return ret;
}

static int parse_27_or_2D(char *packet, char *buffer, char **sensors) {
    // 00100111 0 10010001 00000010 10010001 11000111 00001100 00011110 0 // backlight, error, ready
    // 00100111 0 10001010 00000100 10000001 11000111 00000000 11111101 0 // backlight, bypass, armed (stay in)
    // 00100111 0 10000001 00000001 10000001 11000111 00000100 11110101 0 // backlight, ready
    // CMD----- S STATUS--                            SENSORS- CRC----- S
    int command = packet[0];
    int ret = sprintf(buffer, "%02X [%s]: ", command, COMMANDS[command]);
    int sensor_bits = packet_bits(41, packet, 8);

    ret += append_bits(packet_bits(9, packet, 8), STATUS_FLAGS, buffer + ret);

    if (sensor_bits) {
        ret += sprintf(buffer + ret, ", ");

        ret += append_bits(sensor_bits, sensors, buffer + ret);
    }

    ret += sprintf(buffer + ret, "\n");

    return ret;
}

/**
 * parses command 0xA5 from the given packet into the given buffer, 
 * which is expected to be long enough
 */
static int parse_A5(char *packet, char *buffer) {
    // 10100101 0 00011000 00000100 01010010 10010000 00000000 00000000 10100011 0 // basic timestamp
    // 10100101 0 00011000 01000100 01010010 01000000 10101101 11111111 00111111 0 // arm by user 21
    // 10100101 0 00011000 01000100 01010100 00001100 10111001 11111111 00011001 0 // arm by user 33
    // 10100101 0 00010110 01001110 00101001 11011000 10111011 11111111 11000100 0 // arm by user 40
    // 10100101 0 00010110 01001110 00101001 11011010 10011011 00000000 10100111 0 // arm, away
    // 10100101 0 00010110 01001110 00101000 00101010 10011010 00000000 11110101 1 // arm, stay
    // 10100101 0 00010110 01001110 00101010 10010010 01101000 00000000 00101101 1 // fire sensor reset with command *72
    // 10100101 0 00011000 01000100 01010010 01000100 11010100 11111111 01101010 0 // disarm by user 21
    // 10100101 0 00011000 01000100 01010100 00010100 11100000 11111111 01001000 0 // disarm by user 33
    // 10100101 0 00010110 01001110 00101000 00101100 11100010 11111111 00111110 0 // disarm by user 40
    // 10100101 0 00011000 01000100 01010011 00001100 11100111 11111111 01000110 0 // battery failure
    // 10100101 0 00011000 01000100 01010011 00100000 11101111 11111111 01100010 0 // battery reset

    // Possible alternatives
    // CMD----- S Y1--Y2-- EEMMMMDD DDDHHHHH MMMMMMFF ACTION--          CRC----- S 
    // CMD----- S Y1--Y2-- 00MMMMDD DDDHHHHH MMMMMM                     CRC----- S // timestamp

    int command = packet[0]; // CMD-----
    int event = packet_bits(17, packet, 2); // PP
    int flag = packet_bits(39, packet, 2); // FF
    int action = packet_bits(41, packet, 8); // ACTION
    int userId;
    char extra[32] = {0}; // 32 chars is enough for any message

    // Users:
    // 40: One master code
    // 01-32: 32 general access codes
    // 33-34: Two duress codes
    // 41-42: Two supervisor codes
        
    if (event > 0) {
	if (flag == 0) {
	    // TODO: action in (0x00 - 0x98, 0xbf, 0xe5, 0xe6, 0xe8-0xee, 0xf0-0xff)
	    if (action >= 0x99 && action < 0xbf) {
		userId = action - 0x99 + 1;
	    
		if (userId > 34) userId += 5; // masters 40, supervisor 41, 42
	
		sprintf(extra, " arming by %02d (%s)", userId, 
			userId >= 40 ? "master" : "user");
	    } else if (action >= 0xc0 && action < 0xe5) {
		userId = action - 0xc0 + 1;
	    
		if (userId > 34) userId += 5; // masters 40, supervisor 41, 42
	
		sprintf(extra, " disarmed by %02d (%s)", userId, 
			userId >= 40 ? "master" : "user");
	    } else if (action == 0xe7) {
		sprintf(extra, " error (possibly battery)");
	    } else if (action == 0xef) {
		sprintf(extra, " error resolved");
	    }
	} else if (flag == 2) {
	    if (action == 0x98) {
		sprintf(extra, " armed (stay)");
	    } else if (action == 0x99) {
		sprintf(extra, " armed (away)");
	    }
	}
    }

    return sprintf(buffer,
                   "%02X [%s]: 20%u%u-%02u-%02uT%02u:%02u%s\n",
                   command,
                   COMMANDS[command],
                   packet_bits(9, packet, 4), // Y
                   packet_bits(13, packet, 4), // Y
                   packet_bits(19, packet, 4), // MM
                   packet_bits(23, packet, 5), // dd
                   packet_bits(28, packet, 5), // hh
                   packet_bits(33, packet, 6), // mm
                   extra // extra message (armed, disarmed, etc)
                   );
}

int parse_keybus(char *packet, char *buffer, int len, int *crc_error) {
    unsigned int command = packet[0];
    char *command_name = COMMANDS[command];
    int crc;

    *crc_error = 0; 

    // check CRC
    switch (command) {
    case 0x05:
    case 0x11:
    case 0xD5:
        // these don't have crc
        break;
    default:
        // the rest should have
        if ((crc = check_crc(packet, len)) != 0) {
            *crc_error = 1;
            return sprintf(buffer, "CRC ERROR %d (possibly %02X [%s])\n", 
                           crc,
                           command, 
                           command_name ? command_name : "UNKNOWN");
        }
    }

    // parse packet
    switch (command) {
    case 0x05:
        return parse_05(packet, buffer);
    case 0x27:
        return parse_27_or_2D(packet, buffer, SENSORS1);
    case 0x2D:
        return parse_27_or_2D(packet, buffer, SENSORS2);
    case 0x34:
        return parse_27_or_2D(packet, buffer, SENSORS3);
    case 0x3E:
        return parse_27_or_2D(packet, buffer, SENSORS4);
    case 0xA5:
        return parse_A5(packet, buffer);
    default:
        return sprintf(buffer, "%02X [%s]\n", command, 
                       command_name ? command_name : "UNKNOWN");
    }
}

int is_interesting_packet(char *packet) {
    unsigned int command = packet[0];

    int i,ret;
    
    switch (command) {
    case 0x11: // QUERY
        // never intersting
        return 0;
    case 0x5D: // MEM 1
    case 0x63: // MEM 2
        // Not interesting if all empty
        // 01100011 0 00000000 00000000 00000000 00000000 00000000 01100011 0
	// 01011101 0 00000010 00000000 00000000 00000000 00000000 01011111 0
        for (i = 1, ret = 0; i < 6; i++) {
            ret |= packet_byte(i, packet);
        }
        return ret > 0;
    case 0xB1: // CONFIG
        // Not interesting if all configs normal
        // 10110001 0 11111111 00000000 00000000 00000000 00000000 00000000 00000000 00000000 10110000 0
        if (packet_byte(1, packet) != 0xff) {
            return 1;
        } else {
            for (i = 2, ret = 0; i < 9; i++) {
                ret |= packet_byte(i, packet);
            }
            return ret > 0;
        }
    default: 
        // all else is interesting
        return 1;
    }
}

int packet_to_bits(char *packet, char *buffer, int bit_count, int has_stop_bit) {
    int i, pos;

    for (i = 0, pos = 0; i < bit_count; i++) {
        if ((i > 7 && ((i - has_stop_bit) & 0x7) == 0) || (has_stop_bit && i == 8)) {
            buffer[pos++] = ' ';
        }

        buffer[pos++] = PACKET_BIT(i, packet) ? '1' : '0';
    }

    buffer[pos] = '\0';

    return pos;
}
