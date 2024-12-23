/*
//
// SPDX-FileCopyrightText: 2024 Friedrich-Alexander University Erlangen-Nuernberg (FAU), Computer Science 7 - Computer Networks and Communication Systems
//
 * TcpCubic.cc
 *
 *  Created on: Sep 28, 2023
 *      Author: martino
 */



#include <algorithm>    

#include "inet/common/INETMath.h"
#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/tcp/flavours/TcpNewReno.h"
#include "inet/transportlayer/tcp/flavours/TcpCubic.h"
#include <cmath>
#include <cstring> 
#include <cstddef>  
#include <cstdint>  

#define ACK_RATIO_SHIFT  4   

#define BICTCP_BETA_SCALE  1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ  10	/* BIC HZ 2^10 = 1024 */

#define HZ  1000       /* num of ticks (or clock interrupts)per second */

#define SIMTIME_PRECISION 1u  


/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	inet::math::clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)



static int BETA = 717;  /* = 717/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh;
static int bic_scale = 41;



using namespace inet;
using namespace tcp;


Register_Class(TcpCubic);

TcpCubicStateVariables::TcpCubicStateVariables() {
    
//    The fast convergence is designed for network environments with
//    multiple CUBIC flows.  In network environments with only a single
//    CUBIC flow and without any other traffic, the fast convergence SHOULD
//    be disabled.

      fast_convergence;   
      tcp_friendliness;
      beta = 0.7;
             
    hystartLowWindow = 16;    //segments
    hystartMinSamples = 8;
    hystartAckDelta = 0.002;   // 2ms
    hystartDelayMin= 0.004;    // 4ms
    hystartDelayMax = 1;       // 1000ms
    cubicDelta = 10; 
      c = 0.4;

        ssthresh = 0xFFFFFFFF;; // 0xffffffff; /* */  
        cnt = 0;                /* increase cwnd by 1 after ACKs */
        last_max_cwnd = 0;      /* last maximum snd_cwnd */
        last_cwnd = 0;          /* the last snd_cwnd */
        last_time = 0;          /* time when updated last_cwnd */
        bic_origin_point = 0;   /* origin point of bic function */
        bic_K = 0.0;              /* time to origin point from the beginning of the current epoch */
        delay_min;          /* min delay (usec) */
        epoch_start = 0;        /* beginning of an epoch */
        ack_cnt = 0;            /* number of acks */
        tcp_cwnd = 0;           /* estimated tcp cwnd  = snd_cwnd*/
        cWndCnt = 0;

        sample_cnt = 0;         /* number of samples to decide curr_rtt */
        last_ack = SIMTIME_ZERO;           /* last time when the ACK spacing is close */
        curr_rtt = SIMTIME_ZERO;           /* the minimum rtt of current round */
        round_start = SIMTIME_ZERO;
        endSeq = 0;

        found = false;              /* the exit point is found? */

        end_seq = 0;            /* end_seq of the round */

        sampleCnt = 0;
        minRTT = SIMTIME_ZERO;                 
        K = SIMTIME_ZERO;
        c_t = SIMTIME_ZERO;

        segmentsAcked =  0;
        /* Precompute a bunch of the scaling factors that are used per-packet
             * based on SRTT of 100ms
             */

           beta_scale = 8*(BICTCP_BETA_SCALE+ BETA) / 3
                / (BICTCP_BETA_SCALE - BETA);                   
           cube_rtt_scale = (bic_scale * 10);  /* 1024*c/rtt */

            /* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
             *  so K = cubic_root( (wmax-cwnd)*rtt/c )
             * the unit of K is bictcp_HZ=2^10, not HZ
             *
             *  c = bic_scale >> 10
             *  rtt = 100ms
             *
             * the following code has been designed and tested for
             * cwnd < 1 million packets
             * RTT < 100 seconds
             * HZ < 1,000,00  (corresponding to 10 nano-second)
             */

            /* 1/c * 2^2*bictcp_HZ * srtt */
            // Assuming cube_factor is a double or another numeric type
            cube_factor = pow(2.0, 10 + 3 * BICTCP_HZ);  

}

TcpCubicStateVariables::~TcpCubicStateVariables() {
}

simsignal_t TcpCubic::WmaxSignal = cComponent::registerSignal("Wmax"); 

void TcpCubic::initialize()
{
    TcpBaseAlg::initialize();
    cubic_reset();
    state->fast_convergence = true;
    state->tcp_friendliness = true;
    state->hystart_Detect == state->HybridSSDetectionMode::BOTH;


}



std::string TcpCubicStateVariables::str() const {
    std::stringstream out;
    out << TcpBaseAlgStateVariables::str();

    return out.str();
}

std::string TcpCubicStateVariables::detailedInfo() const {
    std::stringstream out;
    out << TcpBaseAlgStateVariables::detailedInfo();
    out << " ssthresh=" << ssthresh << "\n";
    return out.str();
}

void TcpCubic::setSendQueueLimit(uint32 newLimit){
    // The initial value of ssthresh SHOULD be set arbitrarily high (e.g.,
    // to the size of the largest possible advertised window) -> defined by sendQueueLimit
    state->sendQueueLimit = newLimit;
    state->ssthresh = state->sendQueueLimit;
}


/* Ctor */
TcpCubic::TcpCubic() :
        TcpBaseAlg(), state((TcpCubicStateVariables *&) TcpAlgorithm::state) {
}


double TcpCubic::do_div(double cube_factor, int bic_scale){

    double d = inet::math::div(cube_factor, bic_scale * 10);

    return d;
}




void TcpCubic::recalculateSlowStartThreshold()      
{
    EV_DEBUG << "recalculateSlowStartThreshold(), ssthresh=" << state->ssthresh
            << "\n";

    state->epoch_start = SIMTIME_ZERO;    /* end of epoch */

    uint32 seg_cwnd = state->snd_cwnd / state->snd_mss;    

    /* Wmax and fast convergence */                            
        if (state->snd_cwnd < state->last_max_cwnd && state->fast_convergence ){   
            state->last_max_cwnd = ((seg_cwnd * (1 + state->beta))/2) * state->snd_mss  ;   

        }

        else{
            state->last_max_cwnd = seg_cwnd * state->snd_mss;

        }


        state->ssthresh = std::max(static_cast<uint32_t>(seg_cwnd * state->beta), uint32(2)) * state->snd_mss;

        conn->emit(cwndSignal,state->snd_cwnd);
        conn->emit(WmaxSignal,state->last_max_cwnd);
        conn->emit(ssthreshSignal, state->ssthresh);

}




void TcpCubic::processRexmitTimer(TcpEventCode& event)
{
    TcpBaseAlg::processRexmitTimer(event);

    if (event == TCP_E_ABORT)
        return;


    state->recover = (state->snd_max - 1);
    EV_INFO << "recover=" << state->recover << "\n";
    state->lossRecovery = false;
    state->firstPartialACK = false;
    EV_INFO << "Loss Recovery terminated.\n";


    // begin Slow Start (RFC 2581)
    recalculateSlowStartThreshold();
    cubic_reset();
    HystartReset();

    state->snd_cwnd = state->snd_mss;


    conn->emit(cwndSignal, state->snd_cwnd);

    EV_INFO << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
            << ", ssthresh=" << state->ssthresh << "\n";
    state->afterRto = true;
   conn->retransmitOneSegment(true);
}



void TcpCubic::cubic_reset()
{
    state->last_max_cwnd = 0;
    state->epoch_start = SIMTIME_ZERO;
    state->bic_origin_point = 0;
    state->minRTT = SIMTIME_ZERO;
    state->tcp_cwnd = 0;
    state->ack_cnt = 0;
    state->K = 0;
    state->found = false;
}


void TcpCubic::HystartReset()
{

   state->round_start = state->last_ack = simTime();
   state->endSeq = state->snd_max;                             
    state->curr_rtt = SIMTIME_ZERO;
    state->sampleCnt = 0;
}


void TcpCubic::HystartUpdate(TcpCubicStateVariables *& state, const  simtime_t delay)
{

  if (!(state->found))
    {
      simtime_t now = simTime();

      /* first detection parameter - ack-train detection */
      if ((now - state->time_lastAck) <= state->hystartAckDelta)
        {
          state->time_lastAck = now;

          if ((now - state->round_start) > state->minRTT)
            {

              if (state->hystart_Detect == state->HybridSSDetectionMode::PACKET_TRAIN ||
                      state->hystart_Detect == state->HybridSSDetectionMode::BOTH)
              {
                  state->found = true;
              }
            }
          }

      /* obtain the minimum delay of more than sampling packets */
      if (state->sample_cnt < state->hystartMinSamples)
        {
          if (state->curr_rtt == SIMTIME_ZERO || state->curr_rtt > delay)
            {
              state->curr_rtt = delay;
            }

          state->sample_cnt++;
        }
      else if (state->curr_rtt > state->minRTT + HystartDelayThresh(state->minRTT))
        {
              state->found = true;
            }
      /*
       * Either one of two conditions are met,
       * we exit from slow start immediately.
       */
      if (state->found)
        {
          EV_INFO << "Exit from Slow Start, immediately :-)"<< "\n";

          state->ssthresh = state->snd_cwnd;

          conn->emit(ssthreshSignal, state->ssthresh);

        }
    }
}



simtime_t TcpCubic::HystartDelayThresh(const simtime_t t)
{

    simtime_t ret = t;

    if (t > state->hystartDelayMax)
    {
        ret = state->hystartDelayMax;
    }
    else if (t < state->hystartDelayMin)
    {
        ret = state->hystartDelayMin;
    }

    return ret;
}



void TcpCubic::IncreaseWindow()    
{

    if (state->snd_cwnd < state->ssthresh)
    {
        if (state->hystart && state->last_ack_sent > state->endSeq)
        {
            HystartReset();
        }
//

         state->snd_cwnd += state->snd_mss;


        // In Linux, the QUICKACK socket option enables the receiver to send
        // immediate acks initially (during slow start) and then transition
        // to delayed acks.  ns-3 does not implement QUICKACK, and if ack
        // counting instead of byte counting is used during slow start window
        // growth, when TcpSocket::DelAckCount==2, then the slow start will
        // not reach as large of an initial window as in Linux.  Therefore,
        // we can approximate the effect of QUICKACK by making this slow
        // start phase perform Appropriate Byte Counting (RFC 3465)



        conn->emit(cwndSignal, state->snd_cwnd);

        EV_INFO << "In SlowStart, updated to cwnd " << state->snd_cwnd << " ssthresh "
                                                     << state->ssthresh;

    }

   else {


        bictcp_update();    



        /* According to RFC 6356 even once the new cwnd is
         * calculated you must compare this to the number of ACKs received since
         * the last cwnd update. If not enough ACKs have been received then cwnd
         * cannot be updated.
         */
        if (state->cWndCnt >= state->cnt)
        {
            state->snd_cwnd += state->snd_mss;  

            conn->emit(cwndSignal, state->snd_cwnd);

            state->cWndCnt = 0;
            EV_INFO << "In CongAvoid, updated to cwnd " << state->snd_cwnd;
        }
        else
        {
           state->cWndCnt += 1;

            EV_INFO << "Not enough segments have been ACKed to increment cwnd."
                        "Until now "
                        << state->cWndCnt << " cnd " << state->cnt;
        }

    }
}


void TcpCubic::receivedDataAck(uint32_t firstSeqAcked)
{
    TcpBaseAlg::receivedDataAck(firstSeqAcked);

    const TcpSegmentTransmitInfoList::Item *found2 = state->regions.get(firstSeqAcked);

       if (found2 != nullptr) {
           simtime_t currentTime = simTime();

           simtime_t RTT = currentTime - (found2->getFirstSentTime());



       //Find the min rtt
       if(state->minRTT == SIMTIME_ZERO || state->minRTT > RTT)
       {
           state->minRTT = RTT;
       }

       /* hystart triggers when cwnd is larger than some threshold */
       if (state->hystart && state->snd_cwnd <= state->ssthresh && state->snd_cwnd >= state->hystartLowWindow * state->snd_mss)
       {
               HystartUpdate(state, RTT);
       }

    }


    // RFC 3782, page 5:
    // "5) When an ACK arrives that acknowledges new data, this ACK could be
    // the acknowledgment elicited by the retransmission from step 2, or
    // elicited by a later retransmission.
    //
    // Full acknowledgements:
    // If this ACK acknowledges all of the data up to and including
    // "recover", then the ACK acknowledges all the intermediate
    // segments sent between the original transmission of the lost
    // segment and the receipt of the third duplicate ACK.  Set cwnd to
    // either (1) min (ssthresh, FlightSize + SMSS) or (2) ssthresh,
    // where ssthresh is the value set in ssegmentsAckedtep 1; this is termed
    // "deflating" the window.  (We note that "FlightSize" in step 1
    // referred to the amount of data outstanding in step 1, when Fast
    // Recovery was entered, while "FlightSize" in step 5 refers to the
    // amount of data outstanding in step 5, when Fast Recovery is
    // exited.)  If the second option is selected, the implementation is
    // encouraged to take measures to avoid a possible burst of data, in
    // case the amount of data outstanding in the network is much less
    // than the new congestion window allows.  A simple mechanism is to
    // limit the number of data packets that can be sent in response to
    // a single acknowledgement; this is known as "maxburst_" in the NS
    // simulator.  Exit the Fast Recovery procedure."

    if (state->lossRecovery) {
        if (seqGE(state->snd_una - 1, state->recover)) {
            // Exit Fast Recovery: deflating cwnd
            //
            // option (1): set cwnd to min (ssthresh, FlightSize + SMSS)     


            uint32_t flight_size = state->snd_max - state->snd_una;


            state->snd_cwnd = state->ssthresh;             



            EV_INFO << "Fast Recovery - Full ACK received: Exit Fast Recovery, setting cwnd to " << state->snd_cwnd << "\n";

            // option (2): set cwnd to ssthresh
            // tcpEV << "Fast Recovery - Full ACK received: Exit Fast Recovery, setting cwnd to ssthresh=" << state->ssthresh << "\n";
            // TODO - If the second option (2) is selected, take measures to avoid a possible burst of data (maxburst)!
            conn->emit(cwndSignal, state->snd_cwnd);

            state->lossRecovery = false;
            state->firstPartialACK = false;
            EV_INFO << "Loss Recovery terminated.\n";
        }
        else {

            // RFC 3782, page 5:
            // "Partial acknowledgements:
            // If this ACK does *not* acknowledge all of the data up to and
            // including "recover", then this is a partial ACK.  In this case,
            // retransmit the first unacknowledged segment.  Deflate the
            // congestion window by the amount of new data acknowledged by the
            // cumulative acknowledgement field.  If the partial ACK
            // acknowledges at least one SMSS of new data, then add back SMSS
            // bytes to the congestion window.  As in Step 3, this artificially
            // inflates the congestion window in order to reflect the additional
            // segment that has left the network.  Send a new segment if
            // permitted by the new value of cwnd.  This "partial window
            // deflation" attempts to ensure that, when Fast Recovery eventually
            // ends, approximately ssthresh amount of data will be outstanding
            // in the network.  Do not exit the Fast Recovery procedure (i.e.,
            // if any duplicate ACKs subsequently arrive, execute Steps 3 and 4
            // above).
            //
            // For the first partial ACK that arrives during Fast Recovery, also
            // reset the retransmit timer.  Timer management is discussed in
            // more detail in Section 4."



   //(from RFC 8312)  restart epoch_start=0, record W_max, rcord epoch_start (new at loss event), deflate cwnd


            EV_INFO << "Fast Recovery - Partial ACK received: retransmitting the first unacknowledged segment\n";
            // retransmit first unacknowledged segment
            conn->retransmitOneSegment(false);

            // deflate cwnd by amount of new data acknowledged by cumulative acknowledgement field

            state->snd_cwnd -= state->snd_una - firstSeqAcked;     

            conn->emit(cwndSignal, state->snd_cwnd);

            EV_INFO << "Fast Recovery: deflating cwnd by amount of new data acknowledged, new cwnd=" << state->snd_cwnd << "\n";

            // if the partial ACK acknowledges at least one SMSS of new data, then add back SMSS bytes to the cwnd
            if (state->snd_una - firstSeqAcked >= state->snd_mss) {

                state->snd_cwnd += state->snd_mss;


                conn->emit(cwndSignal, state->snd_cwnd);

                EV_DETAIL << "Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";
            }

            // try to send a new segment if permitted by the new value of cwnd
            sendData(false);

            // reset REXMIT timer for the first partial ACK that arrives during Fast Recovery
            if (state->lossRecovery) {
                if (!state->firstPartialACK) {
                    state->firstPartialACK = true;
                    EV_DETAIL << "First partial ACK arrived during recovery, restarting REXMIT timer.\n";
                    restartRexmitTimer();

                }
            }
        }
    }
    else {
                // Perform slow start and congestion avoidance.

        IncreaseWindow();   


        state->recover = (state->snd_una - 2);
    }

    state->regions.clearTo(state->snd_una);

    sendData(false);

}



void TcpCubic::receivedDuplicateAck()
{
    TcpBaseAlg::receivedDuplicateAck();

    if (state->dupacks == DUPTHRESH) {    // DUPTHRESH = 3
        if (!state->lossRecovery) {
            // RFC 3782, page 4:
            // "1) Three duplicate ACKs:
            // When the third duplicate ACK is received and the sender is not
            // already in the Fast Recovery procedure, check to see if the
            // Cumulative Acknowledgement field covers more than "recover".  If
            // so, go to Step 1A.  Otherwise, go to Step 1B."
            //
            // RFC 3782, page 6:
            // "Step 1 specifies a check that the Cumulative Acknowledgement field
            // covers more than "recover".  Because the acknowledgement field
            // contains the sequence number that the sender next expects to receive,
            // the acknowledgement "ack_number" covers more than "recover" when:
            //      ack_number - 1 > recover;"
            if (state->snd_una - 1 > state->recover) {
                EV_INFO << "CUBIC on dupAcks == DUPTHRESH(=3): perform Fast Retransmit, and enter Fast Recovery:";

                // RFC 3782, page 4:
                // "1A) Invoking Fast Retransmit:
                // If so, then set ssthresh to no more than the value given in
                // equation 1 below.  (This is equation 3 from [RFC2581]).
                //      ssthresh = max (FlightSize / 2, 2*SMSS)           (1)
                // In addition, record the highest sequence number transmitted in
                // the variable "recover", and go to Step 2."


   // (from RFC 8312)  with these steps (CUBIC does not change Fast Recovery and Retransmit of standard TCP): restart epoch_start=0, record W_max, rcord epoch_start (new at loss event), deflate cwnd 

                recalculateSlowStartThreshold();           

                state->recover = (state->snd_max - 1);   
                state->firstPartialACK = false;
                state->lossRecovery = true;
                EV_INFO << " set recover=" << state->recover;


                // RFC 3782, page 4:
                // "2) Entering Fast Retransmit:
                // Retransmit the lost segment and set cwnd to ssthresh plus 3 * SMSS.
                // This artificially "inflates" the congestion window by the number
                // of segments (three) that have left the network and the receiver
                // has buffered."
                state->snd_cwnd = state->ssthresh + 3 * state->snd_mss;

                conn->emit(cwndSignal, state->snd_cwnd);

                EV_DETAIL << " , cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";
                conn->retransmitOneSegment(false);
               // RFC 3782, page 5:
                // "4) Fast Recovery, continued:
                // Transmit a segment, if allowed by the new value of cwnd and the
                // receiver's advertised window."
                sendData(false);
            }
            else {
                EV_INFO << "CUBIC on dupAcks == DUPTHRESH(=3): not invoking Fast Retransmit and Fast Recovery\n";

                // RFC 3782, page 4:
                // "1B) Not invoking Fast Retransmit:
                // Do not enter the Fast Retransmit and Fast Recovery procedure.  In
                // particular, do not change ssthresh, do not go to Step 2 to
                // retransmit the "lost" segment, and do not execute Step 3 upon
                // subsequent duplicate ACKs."
            }
        }
        EV_INFO << "CUBIC on dupAcks == DUPTHRESH(=3): TCP is already in Fast Recovery procedure\n";
    }
    else if (state->dupacks > DUPTHRESH) {    // DUPTHRESH = 3
        if (state->lossRecovery) {
            // RFC 3782, page 4:
            // "3) Fast Recovery:
            // For each additional duplicate ACK received while in Fast
            // Recovery, increment cwnd by SMSS.  This artificially inflates the
            // congestion window in order to reflect the additional segment that
            // has left the network."
            state->snd_cwnd += state->snd_mss;

            conn->emit(cwndSignal, state->snd_cwnd);

            EV_DETAIL << "CUBIC on dupAcks > DUPTHRESH(=3): Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

            // RFC 3782, page 5:
            // "4) Fast Recovery, continued:
            // Transmit a segment, if allowed by the new value of cwnd and the
            // receiver's advertised window."
            sendData(false);
        }
    }
}




void TcpCubic::dataSent(uint32_t fromseq) {
    TcpBaseAlg::dataSent(fromseq);

    // save the time the packet was sent
    // fromseq is the seq number of the 1st sent byte

    simtime_t sendtime = simTime();
    state->regions.clearTo(state->snd_una);
    state->regions.set(fromseq, state->snd_max, sendtime);
}


void TcpCubic::segmentRetransmitted(uint32_t fromseq, uint32_t toseq)
{
    TcpBaseAlg::segmentRetransmitted(fromseq, toseq);

    state->regions.set(fromseq, toseq, simTime());
}



uint32_t TcpCubic::cubic_root(uint64_t a){
    uint32_t x, b, shift;
    /*
     * cbrt(x) MSB values for x MSB values in [0..63].
     * Precomputed then refined by hand - Willy Tarreau
     *
     * For x in [0..63],
     *   v = cbrt(x << 18) - 1
     *   cbrt(x) = (v[x] + 10) >> 6
     */
    static const uint8_t v[] = {
        /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
        /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
        /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
        /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
        /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
        /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
        /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
        /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
    };


    b = static_cast<int>(std::log2(a & -a)) + 1;
    if (b < 7) {
        /* a in [0..63] */
        return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
    }

    b = ((b * 84) >> 8) - 1;
    shift = (a >> (b * 3));

    x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

    /*
     * Newton-Raphson iteration
     *                         2
     * x    = ( 2 * x  +  a / x  ) / 3
     *  k+1          k         k
     */
    x = (2 * x + static_cast<uint32_t>(inet::math::div(a, static_cast<uint64>(x) * static_cast<uint64>(x - 1))));
    x = ((x * 341) >> 10);
    return x;
}



void TcpCubic::tcpFriendlinessLogic() {   

    double const_cal = ((3.0 * 0.2)/(2.0 - 0.2));
    double mul = ((double)(state->ack_cnt * state->snd_mss))/((double)state->snd_cwnd);
    double resolt_mul = const_cal * mul;
    state->tcp_cwnd = state->tcp_cwnd + static_cast<uint32_t>(resolt_mul);
    state->ack_cnt = 0;
    if(state->tcp_cwnd > state->snd_cwnd)
    {
        uint32_t max_cnt = (state->snd_cwnd / (state->tcp_cwnd - state->snd_cwnd));         
        if( state->cnt > max_cnt)
        {
            state->cnt = max_cnt;
        }
    }
}


/*
 * Compute congestion window to use in Congestion Avoidance.        
 */     
void TcpCubic::bictcp_update()   
{
    uint32_t bic_target, max_cnt;

    double delta;
    simtime_t offs;
    simtime_t t;


    state->ack_cnt++;   /* count the number of ACKed packets */



    if (state->epoch_start == SIMTIME_ZERO) {    
        state->epoch_start = simTime();  

        if ((state->last_max_cwnd) < ( state->snd_cwnd)) {
            state->K = SIMTIME_ZERO; 
            state->bic_origin_point = state->snd_cwnd;
        } else {
 

            double dividend = static_cast<double>(state->last_max_cwnd - state->snd_cwnd);
            dividend = dividend/state->snd_mss; 
            double cubic_root = dividend / state->c;
            state->bic_K = std::cbrtl(cubic_root);
            state->K = SimTime(state->bic_K);
            state->bic_origin_point = state->last_max_cwnd;
        }

        state->ack_cnt = 1;
        state->tcp_cwnd = state->snd_cwnd;
    }

    /* cubic function - calc*/
    /* calculate c * time^3 / rtt,
     *  while considering overflow in calculation of time^3
     */

    t = (simTime() + state->minRTT - state->epoch_start);  

    state->c_t = t;


    /* change the unit from HZ to bictcp_HZ */

    if (t < state->K)
        offs = state->K - t;
    else
        offs = t - state->K;

    double d = SIMTIME_DBL(offs);;
      delta = std::pow(d , 3.0);

    uint32_t factor =  static_cast<uint32_t>(state->c * delta);



    if (t < state->K)
        bic_target = state->bic_origin_point/state->snd_mss - factor;
    else
        bic_target = state->bic_origin_point/state->snd_mss + factor;

    /* cubic function - calc bictcp_cnt*/

    if (bic_target > state->snd_cwnd/state->snd_mss)   
        state->cnt = state->snd_cwnd/state->snd_mss / (bic_target - state->snd_cwnd/state->snd_mss);
    else
        state->cnt = 100 * (state->snd_cwnd/state->snd_mss); 

    if (state->tcp_friendliness == true)

        tcpFriendlinessLogic();   

}
