/*
//
// SPDX-FileCopyrightText: 2024 Friedrich-Alexander University Erlangen-Nuernberg (FAU), Computer Science 7 - Computer Networks and Communication Systems
//
 * TcpCubic.h
 *
 *  Created on: Sep 28, 2023
 *      Author: martino
 */

#ifndef __INET_TCPCUBIC_H
#define __INET_TCPCUBIC_H

#include "TcpSegmentTransmitInfoList.h"
#include "inet/transportlayer/tcp/flavours/TcpTahoeRenoFamily.h"

#include "inet/transportlayer/tcp/Tcp.h"

namespace inet {
namespace tcp {



class INET_API TcpCubicStateVariables : public TcpBaseAlgStateVariables
{
  protected:
    // Add your member variables here...

  public:
     TcpCubicStateVariables();
    ~TcpCubicStateVariables();
    
    virtual std::string str() const override;
    virtual std::string detailedInfo() const override;
    TcpSegmentTransmitInfoList regions;


    double beta;
    bool found;   /* the exit point is found? */
//    bool hystart;   // to be defined elsewhere
    double c;
    double cube_factor;
    


    uint32_t beta_scale;
    uint32_t cube_rtt_scale;
//    int do_div;

    bool fast_convergence;
    bool tcp_friendliness;
    // Cubic parameters

    uint32_t hystartLowWindow;
    uint32_t hystartMinSamples;
    simtime_t hystartAckDelta;
    simtime_t hystartDelayMin;
    simtime_t hystartDelayMax;
    simtime_t cubicDelta;

        uint32_t ssthresh;        /* < slow start threshold */
	uint32_t cnt;				/* increase cwnd by 1 after ACKs */
	uint32_t last_max_cwnd;		/* last maximum snd_cwnd */
	uint32_t last_cwnd;			/* the last snd_cwnd */
	simtime_t last_time;			/* time when updated last_cwnd */
	uint32_t bic_origin_point;	/* origin point of bic function */
	double	bic_K;				/* time to origin point from the beginning of the current epoch */              
				  	 					
	simtime_t delay_min;			/* min delay (usec) */
	simtime_t epoch_start;		/* beginning of an epoch */                      
	uint32_t ack_cnt;			/* number of acks */
	uint32_t tcp_cwnd;			/* estimated tcp cwnd */

	uint32_t sample_cnt;			/* number of samples to decide curr_rtt */
	simtime_t round_start;		/* beginning of each round */
	uint32_t end_seq;			/* end_seq of the round */
	simtime_t last_ack;			/* last time when the ACK spacing is close */
	simtime_t curr_rtt;			/* the minimum rtt of current round */
	uint32_t sampleCnt;
	uint32_t cWndCnt;
	uint32_t endSeq;                    /*  end sequence of the round   */

	simtime_t K;
	simtime_t minRTT;
	simtime_t c_t;

	uint32 segmentsAcked;



	enum HybridSSDetectionMode {
        PACKET_TRAIN,
        DELAY,
        BOTH
    };

    HybridSSDetectionMode hystart_Detect;


  private:
};




/**
 * State variables for TcpCubic.
 **/


class INET_API TcpCubic : public TcpBaseAlg {    //TcpBaseAlg

protected:

    TcpCubicStateVariables *& state; // alias to TcpCubic algorithm's 'state'

    static simsignal_t WmaxSignal; // will record the estimated Wmax



    Tcp *tcpMain = nullptr;    // Tcp module



    /** Create and return a TcpFitStateVariables object. */
    virtual TcpStateVariables *createStateVariables() override {

        return new TcpCubicStateVariables();
    }

    /** Utility function to recalculate ssthresh */

    void recalculateSlowStartThreshold();   


public:
    /** Ctor */
    TcpCubic();

    double do_div(double cube_factor, int bic_scale);

    virtual void processRexmitTimer(TcpEventCode& event);          


    virtual void setSendQueueLimit(uint32 newLimit);


    /** Redefine what should happen when data got acked, to add congestion window management */
    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck() override;                                 
    virtual void dataSent(uint32_t fromseq) override;
    virtual void segmentRetransmitted(uint32_t fromseq, uint32_t toseq);

    uint32_t cubic_root(uint64_t a);
    void bictcp_update();     

    void tcpFriendlinessLogic();   

    void HystartReset();  
    void HystartUpdate(TcpCubicStateVariables *& state, simtime_t delay);
    simtime_t HystartDelayThresh(const simtime_t t);

    void IncreaseWindow();  
    virtual void initialize();
    void cubic_reset();



private:

    simtime_t currentTime;

};





} // namespace tcp
} // namespace inet




#endif // ifndef __INET_TCPCUBIC_H
