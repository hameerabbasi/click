// -*- c-basic-offset: 4 -*-
#ifndef CLICK_DRR_HH
#define CLICK_DRR_HH
#include <click/element.hh>
#include <click/notifier.hh>
CLICK_DECLS

/*
 * =c
 * DRRSched
 * =s packet scheduling
 * pulls from inputs with deficit round robin scheduling
 * =io
 * One output, zero or more inputs
 * =d
 * Schedules packets with deficit round robin scheduling, from
 * Shreedhar and Varghese's SIGCOMM 1995 paper "Efficient Fair
 * Queuing using Deficit Round Robin."
 *
 * The inputs usually come from Queues or other pull schedulers.
 * DRRSched uses notification to avoid pulling from empty inputs.
 *
 * =n
 * 
 * DRRSched is a notifier signal, active iff any of the upstream notifiers
 * are active.
 *
 * =a PrioSched, StrideSched, RoundRobinSched
 */

class DRRSched : public Element, public PassiveNotifier { public:
  
    DRRSched();
    ~DRRSched();
  
    const char *class_name() const		{ return "DRRSched"; }
    const char *processing() const		{ return PULL; }
    void *cast(const char *);
    DRRSched *clone() const			{ return new DRRSched; }
  
    void notify_ninputs(int);
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
  
    Packet *pull(int port);

    // from Notifier
    SearchOp notifier_search_op();
    
  private:

    int _quantum;   // Number of bytes to send per round.

    Packet **_head; // First packet from each queue.
    unsigned *_deficit;  // Each queue's deficit.
    NotifierSignal *_signals;	// upstream signals
    int _next;      // Next input to consider.
  
};

CLICK_ENDDECLS
#endif
