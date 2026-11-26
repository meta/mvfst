/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! ACK cadence tests over the pair harness of [`crate::testing`]: how many ack-eliciting packets
//! make an ACK due, and when the ACK timer fires.

use std::ops::RangeInclusive;
use std::time::Duration;
use std::time::Instant;

use mvfstr_wire::Frame;
use mvfstr_wire::Frames;
use mvfstr_wire::VarInt;

use super::tests::Forge;
use super::tests::client_addr;
use super::tests::handshake;
use super::tests::limits;
use super::tests::open_own_one_rtt;
use crate::AckPolicy;
use crate::Ecn;
use crate::InlineSealer;
use crate::RxDatagram;
use crate::RxMeta;
use crate::TransportConfig;
use crate::recovery::Space;
use crate::testing::Pair;
use crate::testing::VecSink;
use crate::testing::fixtures::Setup;

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);

/// A server connection whose handshake and its acknowledgments are over, the time it is at, and
/// the next packet number of its peer. The pair does not run again: the tests hand the server
/// 1-RTT packets that the client never sent.
struct Receiver {
    pair: Pair,
    now: Instant,
    next_pn: u64,
}

impl Receiver {
    /// Returns the server of a pair whose server acknowledges by `policy`, over links that take
    /// `one_way` each way.
    fn new(policy: AckPolicy, one_way: Duration) -> Self {
        let setup = Setup {
            server_transport: TransportConfig::builder()
                .ack_policy(policy)
                .build()
                .expect("a transport config"),
            ..Setup::default()
        };
        let mut config = setup.pair();
        config.to_server.delay = one_way;
        config.to_client.delay = one_way;
        let (_, mut pair) = handshake(config);
        let settled = pair.now + Duration::from_secs(1);
        pair.run(settled);
        assert_eq!(
            (pair.to_server.next_arrival(), pair.to_client.next_arrival()),
            (None, None),
            "a datagram is still in flight"
        );
        let ack = &pair.server.conn().sources.ack[Space::Data.index()];
        assert_eq!(ack.deadline(), None, "an ACK still waits");
        let (largest, _) = ack
            .received()
            .largest()
            .expect("1-RTT packets from the client");
        Self {
            now: pair.now,
            next_pn: largest + 1,
            pair,
        }
    }

    /// Hands the server one PING packet numbered each of `pns`, in order and with nothing
    /// missing, in one receive batch at the current time.
    fn receive(&mut self, pns: RangeInclusive<u64>) {
        assert_eq!(
            *pns.start(),
            self.next_pn,
            "a packet number skipped or repeated"
        );
        self.next_pn = pns.end() + 1;
        let client = self.pair.client.conn();
        let mut packets: Vec<Vec<u8>> = pns
            .map(|pn| Forge::of(client, Space::Data, pn, &[Frame::Ping]).seal(client))
            .collect();
        let meta = RxMeta {
            src: client_addr(),
            dst_ip: None,
            ecn: Ecn::NotEct,
            stride: 0,
            rx_time: self.now,
        };
        let mut batch: Vec<RxDatagram<'_>> = packets
            .iter_mut()
            .map(|data| RxDatagram {
                meta: &meta,
                data: data.as_mut_slice(),
            })
            .collect();
        let summary = self.pair.server.conn_mut().recv_batch(self.now, &mut batch);
        assert_eq!(summary.packets as usize, batch.len(), "{summary:?}");
    }

    /// Returns when the server's delayed ACK of 1-RTT packets becomes due, if one waits.
    fn ack_deadline(&self) -> Option<Instant> {
        self.pair.server.conn().sources.ack[Space::Data.index()].deadline()
    }

    /// Returns whether the server sends an ACK at the current time. It sends nothing else, so
    /// that is one datagram holding one ACK frame of every packet received.
    fn acks_now(&mut self) -> bool {
        let now = self.now;
        let conn = self.pair.server.conn_mut();
        let mut sink = VecSink::new(1500);
        conn.poll_transmit(&limits(now), &mut sink, &mut InlineSealer);
        let sent = sink.take();
        let Some(datagram) = sent.first() else {
            return false;
        };
        assert_eq!(sent.len(), 1, "more than one datagram");
        let largest: Vec<VarInt> = open_own_one_rtt(conn, &datagram.data)
            .iter()
            .flat_map(|plaintext| {
                Frames::new(plaintext)
                    .filter_map(|frame| match frame.expect("a frame") {
                        Frame::Ack(ack) => Some(ack.largest()),
                        Frame::Padding { .. } => None,
                        other => panic!("a frame other than an ACK: {other:?}"),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(largest, [VarInt::from_u64(self.next_pn - 1).unwrap()]);
        true
    }

    /// Makes the server acknowledge every packet received: at once if an ACK is due, else when
    /// its ACK timer fires.
    fn acknowledge(&mut self) {
        if let Some(at) = self.ack_deadline() {
            self.now = at;
            self.pair.server.conn_mut().on_deadline(at);
        }
        assert!(self.acks_now(), "the server did not acknowledge");
    }
}

#[test]
fn ten_ack_eliciting_packets_make_an_ack_due_on_both_sides_of_the_init_threshold_by_default() {
    let mut rx = Receiver::new(AckPolicy::default(), 10 * MS);
    assert!(
        rx.next_pn <= 90,
        "the handshake took {} packet numbers",
        rx.next_pn
    );
    rx.receive(rx.next_pn..=90);
    rx.acknowledge();
    // Nine waiting packets leave the ACK to the timer, and the tenth, the init threshold of 100,
    // sends it.
    rx.receive(91..=99);
    assert!(!rx.acks_now(), "nine packets up to 99");
    rx.receive(100..=100);
    assert!(rx.acks_now(), "ten packets up to 100");
    // Above the init threshold, the threshold is ten as well.
    rx.receive(101..=109);
    assert!(!rx.acks_now(), "nine packets up to 109");
    rx.receive(110..=110);
    assert!(rx.acks_now(), "ten packets up to 110");
    // The threshold is checked once per receive batch, so one ACK answers 25 packets.
    rx.receive(111..=135);
    assert!(rx.acks_now(), "a batch of 25 packets");
    assert!(!rx.acks_now());
}

#[test]
fn the_configured_threshold_switches_once_the_largest_packet_number_passes_the_init_threshold() {
    let policy = AckPolicy {
        init_threshold: 40,
        before_init: 2,
        after_init: 5,
        ..AckPolicy::default()
    };
    let mut rx = Receiver::new(policy, 10 * MS);
    assert!(
        rx.next_pn <= 38,
        "the handshake took {} packet numbers",
        rx.next_pn
    );
    rx.receive(rx.next_pn..=38);
    rx.acknowledge();
    rx.receive(39..=39);
    assert!(!rx.acks_now(), "one packet up to 39");
    rx.receive(40..=40);
    assert!(rx.acks_now(), "two packets up to the init threshold");
    rx.receive(41..=44);
    assert!(!rx.acks_now(), "four packets above the init threshold");
    rx.receive(45..=45);
    assert!(rx.acks_now(), "five packets above the init threshold");
}

#[test]
fn the_ack_timer_is_a_quarter_of_the_smoothed_rtt_at_least_1_ms_and_below_max_ack_delay() {
    let short = AckPolicy {
        max_ack_delay: 4 * MS,
        ..AckPolicy::default()
    };
    let fixed = AckPolicy {
        rtt_timer: false,
        ..AckPolicy::default()
    };
    // The policy, the one-way delay of the links, the smoothed RTT they make and the ACK timer.
    // The timer fires up to one granularity late, so it stays that much below max_ack_delay.
    let cases = [
        // A quarter of 1 ms is below the 1 ms timer granularity.
        (AckPolicy::default(), 500 * US, MS, MS),
        (AckPolicy::default(), 10 * MS, 20 * MS, 5 * MS),
        // A quarter of 120 ms is past the default max_ack_delay of 25 ms.
        (AckPolicy::default(), 60 * MS, 120 * MS, 24 * MS),
        (short, 10 * MS, 20 * MS, 3 * MS),
        // Without the RTT timer, the timer runs to just below max_ack_delay whatever the RTT.
        (fixed, 500 * US, MS, 24 * MS),
        (fixed, 10 * MS, 20 * MS, 24 * MS),
    ];
    for (policy, one_way, srtt, timer) in cases {
        let mut rx = Receiver::new(policy, one_way);
        let smoothed = rx.pair.server.conn().recovery.rtt().smoothed();
        assert_eq!(smoothed, srtt, "links of {one_way:?} each way");
        let first = rx.now;
        rx.receive(rx.next_pn..=rx.next_pn);
        assert_eq!(
            rx.ack_deadline(),
            Some(first + timer),
            "{policy:?}, smoothed RTT {srtt:?}"
        );
    }
}

#[test]
fn a_max_ack_delay_below_two_granularities_makes_an_ack_due_at_once() {
    // The timer fires up to one granularity late, so it has no time left to wait, whatever the
    // RTT, and its 1 ms floor would take it past max_ack_delay.
    for max_ack_delay in [Duration::ZERO, MS] {
        for rtt_timer in [true, false] {
            let policy = AckPolicy {
                max_ack_delay,
                rtt_timer,
                ..AckPolicy::default()
            };
            let mut rx = Receiver::new(policy, 10 * MS);
            rx.receive(rx.next_pn..=rx.next_pn);
            assert!(rx.acks_now(), "{policy:?}");
        }
    }
}
