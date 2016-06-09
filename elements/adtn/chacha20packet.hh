#ifndef CLICK_CHACHA20_PACKET_HH
#define CLICK_CHACHA20_PACKET_HH
#include <click/element.hh>
#include <click/glue.hh>

CLICK_DECLS

#define IV_SIZE 16
#define ENC_SIZE 1468
#define MAC_SIZE 16

class Chacha20Packet {
  public:

	uint8_t Initialization_vector[IV_SIZE];
    uint8_t Encrypted_segment[ENC_SIZE];
    uint8_t Message_authentication_code[MAC_SIZE];

    Chacha20Packet() {
	memset(this, 0, sizeof(*this));
    }

    Chacha20Packet(const void * iv , const void * mac)
    {
    	memset(this, 0, sizeof(*this));
		memcpy(Initialization_vector, iv, IV_SIZE);
		memcpy(Message_authentication_code, mac, MAC_SIZE);
    }
} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
