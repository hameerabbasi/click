#include <click/config.h>
#include "chacha20.hh"
#include <click/error.hh>
#include <click/glue.hh>


CLICK_DECLS

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
		void* p_data = p->data();

		if (_op == CHACHA20_DECRYPT)
		{
			WritablePacket* p_decrypted = new WritablePacket(1468);
			Chacha20Packet* formatted_packet = (Chacha20Packet*)p_data;

			// Decrypting part goes here
			// passthrough for now
			memcpy(p_decrypted->data(), formatted_packet->Encrypted_segment, sizeof(formatted_packet->Encrypted_segment));


			output(0).push(p_decrypted);
		}
		else
		{
			WritablePacket* p_encrypted = new WritablePacket(1500);
			Chacha20Packet* formatted_packet = (Chacha20Packet*) p_encrypted->data();

			// Encrypting the packet goes here
			// Passthrough for now
			memcpy(formatted_packet->Encrypted_segment, p_data, sizeof(formatted_packet->Encrypted_segment));

			// Random initialization vector goes here, whatever is in memory for now.

			memcpy(p_encrypted->data(), &formatted_packet, sizeof(formatted_packet));

			output(0).push(p_encrypted);
		}
		p->kill();
	}
	// If it is the "key" port
	else if (port == 1)
	{
		// Just copy the data to the key struct.
		void* keyFromPacket = p->data();
		memcpy(&_key, keyFromPacket, sizeof(_key));
		p->kill();
	}
}

CLICK_ENDDECLS
