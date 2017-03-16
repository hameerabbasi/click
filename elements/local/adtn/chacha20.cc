#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <sodium.h>
#include "chacha20.hh"
#include "chacha20packet.hh"
#include "chacha20clear.hh"

CLICK_DECLS
#ifdef __cplusplus
extern "C" {
#endif

Chacha20::Chacha20()
	: _op(0)
{
}

Chacha20::~Chacha20()
{
}

Chacha20::Chacha20(int decrypt)
{
    _op = decrypt;
}

int
Chacha20::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int dec_int;
    if (Args(conf, this, errh).read_mp("ENCRYPT", dec_int).complete() < 0)
        return -1;

    if (dec_int != CHACHA20_DECRYPT && dec_int != CHACHA20_ENCRYPT)
    	return -1;

    int sodiuminit = sodium_init();

    if (sodiuminit != 0 && sodiuminit != 1)
        return -1;

    _op = dec_int;
    return 0;
}

int
Chacha20::initialize(ErrorHandler *)
{
    return 0;
}

void Chacha20::push(int port, Packet *p)
{
	// If it is the data port:
	if (port == 0)
	{
		const void* p_data = p->data();
		uint8_t ad[0];
		const int adlen = 0;

		if (_op == CHACHA20_DECRYPT)
		{

			Chacha20Packet* formatted_packet = (Chacha20Packet*)p_data;
			Chacha20Clear clear_packet;


			if (crypto_aead_chacha20poly1305_decrypt_detached(
						(unsigned char*)&clear_packet,
                                                (unsigned char*)NULL,
						(unsigned char*)formatted_packet->Encrypted_segment,
						ENC_SIZE,
						(unsigned char*)formatted_packet->Message_authentication_code,
						(unsigned char*)ad, adlen,
						(unsigned char*)formatted_packet->Initialization_vector,
						(unsigned char*)_key.key
					) == 0 && clear_packet.Payload_length <= PAYLOAD_PADDING_SIZE)
			{
				WritablePacket* p_decrypted = Packet::make(clear_packet.Payload_length);
				memcpy(p_decrypted->data(), clear_packet.Payload_Padding, clear_packet.Payload_length);

				output(0).push(p_decrypted);
			}
		}
		else
		{
			const uint32_t segment_size = PAYLOAD_PADDING_SIZE;
			uint32_t i = 0; // Segment number
			while (i * segment_size < p->length())
			{
				uint32_t start_idx = i * segment_size;
				uint32_t end_idx = start_idx+segment_size-1;

				if (p->length() < end_idx)
					end_idx = p->length();

				uint32_t slen = end_idx - start_idx + 1;

				Chacha20Clear clear_packet;
				WritablePacket* p_encrypted = Packet::make(sizeof(Chacha20Packet));

				Chacha20Packet* formatted_packet = (Chacha20Packet*) p_encrypted->data();
				randombytes_buf(formatted_packet->Initialization_vector,
						sizeof(formatted_packet->Initialization_vector));
				memcpy(clear_packet.Payload_Padding, (uint8_t*)p_data + start_idx, slen);
				memset(clear_packet.Payload_Padding + slen, 0, segment_size - slen);
				clear_packet.Payload_length = slen;

				unsigned long long maclen_p;

				if (crypto_aead_chacha20poly1305_encrypt_detached(
						(unsigned char*)formatted_packet->Encrypted_segment,
						(unsigned char*)formatted_packet->Message_authentication_code,
						&maclen_p,
						(unsigned char*)&clear_packet, ENC_SIZE,
						(unsigned char*)ad, adlen, NULL,
						(unsigned char*)formatted_packet->Initialization_vector,
						(unsigned char*)_key.key) == 0)
					{
						output(0).push(p_encrypted);
					}
					else
					{
						p_encrypted->kill();
					}

				i++;
			}
		}
	}
	// If it is the "key" port
	else if (port == 1)
	{
		if (p->length() == sizeof(Chacha20Key))
		{
			// Just copy the data to the key struct.
			const void* keyFromPacket = p->data();
			memcpy(&_key, keyFromPacket, sizeof(_key));
		}
	}

	p->kill();
}

#ifdef __cplusplus
}
#endif

CLICK_ENDDECLS
EXPORT_ELEMENT(Chacha20)
ELEMENT_LIBS(`pkg-config --libs libsodium`)
