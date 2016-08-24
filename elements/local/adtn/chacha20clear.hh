#ifndef CLICK_CHACHA20_CLEAR_HH
#define CLICK_CHACHA20_CLEAR_HH
#include <click/element.hh>
#include <click/glue.hh>

CLICK_DECLS

#define PAYLOAD_PADDING_SIZE 1466

class Chacha20Clear {
  public:

	uint16_t Payload_length;
    uint8_t Payload_Padding[PAYLOAD_PADDING_SIZE];

    Chacha20Clear() {
    	memset(this, 0, sizeof(*this));
    }

} CLICK_SIZE_PACKED_ATTRIBUTE;

CLICK_ENDDECLS
#endif
