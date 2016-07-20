#ifndef CLICK_ADTNCHACHA20_HH
#define CLICK_ADTNCHACHA20_HH
#include <click/element.hh>
#include <click/glue.hh>

CLICK_DECLS

struct Chacha20Key {
public:
    uint8_t key[8];
};

class Chacha20 : public Element {
public:
    Chacha20();
    Chacha20(int);
    ~Chacha20();

    const char *class_name() const	{ return "aDTNChaCha20"; }
    const char *port_count() const	{ return "2/1"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;

    void push(int port, Packet *p);

    enum { CHACHA20_DECRYPT = 0, CHACHA20_ENCRYPT = 1 };

private:
    unsigned _op;
    Chacha20Key _key;
};

CLICK_ENDDECLS
#endif
