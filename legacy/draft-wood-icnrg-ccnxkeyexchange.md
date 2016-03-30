---
title: CCNx Key Exchange Protocol Version 1.0
abbrev: CCNxKE
docname: draft-wood-ccnxkeyexchange-00
category: std

<!-- ipr: pre5378Trust200902 -->
<!-- ipr: None -->
area: General
workgroup: icnrg
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+
author:
-
    ins: M. Mosko
    name: M. Mosko
    organization: PARC
    email: marc.mosko@parc.com
-
    ins: E. Uzun
    name: Ersin Uzun
    organization: PARC
    email: ersin.uzun@parc.com
-
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: PARC
    email: christopher.wood@parc.com

normative:
  <!-- RFC2104: --> <!-- HMAC --> -->
  RFC2119:
  <!-- RFC3447: --> <!--  Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1--> -->
  <!-- RFC5280: -->
  <!-- RFC5288: -->
  <!-- RFC5289: -->
  <!-- RFC6209: -->
  <!-- RFC6367: -->
  <!-- RFC6655: -->
  <!-- RFC7251: -->
  RFC4086:  <!-- randomness reqs -->
  RFC5869: <!-- hkdf -->
  RFC2631: <!-- DH key exchange -->
  RFC4987: <!-- syn flooding -->
  SALSA20:
  RFC6479:
  RFC4302:
  RFC6347:
  RFC4303:
  SALSA20:
    title: "Salsa20 specification"
    date: 2005-4
    author:
        ins: D. Bernstein
    seriesinfo: www.http://cr.yp.to/snuffle/spec.pdf
  QUIC:
          title: "QUIC: A UDP-Based Secure and Reliable Transport for HTTP/2"
          author:
            -
              ins: J. Iyengar
              org: Google
            -
              ins: I. Swett
              org: Google
          date: 2015-12-19
  TLS13:
     title: "The Transport Layer Security (TLS) Protocol Version 1.3"
     author:
       -
         ins: E. Rescorla
         org: RTFM, Inc.
     date: 2015-8-28
  GCM:
        title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
        date: 2007-11
        author:
            ins: M. Dworkin
        seriesinfo:
            NIST: Special Publication 800-38D
  DH:
        title: "New Directions in Cryptography"
        author:
          - ins: W. Diffie
          - ins: M. Hellman
        date: 1977-06
        seriesinfo: IEEE Transactions on Information Theory, V.IT-22 n.6
  RSA:
     title: "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems"
     author:
       -
         ins: R. Rivest
       -
         ins: A. Shamir
       -
         ins: L. M. Adleman
     date: 1978-02
     seriesinfo:
       Communications of the ACM: v. 21, n. 2, pp. 120-126.
  ECDSA:
    title: "Public Key Cryptography for the Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    author:
      org: American National Standards Institute
    date: 2005-11
    seriesinfo:
      ANSI: ANS X9.62-2005
  CCNxMessages:
    target: https://tools.ietf.org/html/draft-irtf-icnrg-ccnxmessages-00
    title: "CCNx Messages in TLV Format"
    author:
        -
            ins: M. Mosko
            org: PARC, Inc.
        -
            ins: I. Solis
            org: PARC, Inc.
    date: 2015-06

informative:
  RFC5077: <!-- Transport Layer Security (TLS) Session Resumption without Server-Side State -->
  HASHCHAIN:
      title: "Password Authentication with Insecure Communication"
      author:
        org: L. Lamport
      date: 1981-11
      seriesinfo:
        ANSI: Communications of the ACM 24.11, pp 770-772

--- abstract

This document specifies Version 1.0 of the CCNx Key Exchange (CCNxKE) protocol.
The CCNxKE protocol allows two peers to establish a shared, forward-secure key
for secure and confidential communication. The protocol is designed to prevent
eavesdropping, tampering, and message forgery between two peers. It is also
designed to minimize the number of rounds required to establish a shared key.
In the worst case, it requires two RTTs between a consumer and producer to establish
a shared key. In the best case, no RTTs are required (i.e., a consumer may start)
transmitting messages right away. This specification is only to derive keys. It
does not specify how those keys are used.

--- middle

#  Introduction

DISCLAIMER: This is a WIP draft of CCNxKE and has not yet seen significant security analysis.

Ephemeral sessions a la TLS 1.3 {{TLS13}} and QUIC {{QUIC}} are needed for some
CCN exchanges between consumers and producers. Currently, there does not exist
a standard way to establish these sessions. Thus, the primary goal of
the CCNxKE protocol is to provide privacy and data integrity between two CCN-enabled
peers (e.g., a consumer and producer engaged in session-based communication). It
is built on the CCNx 1.0 protocol and only relies
upon standard Interest and Content Objects as a vehicle for communication.
The CCNxKE protocol is used to bootstrap session-based communication, wherein
traffic is encapsulated and encrypted using symmetric-key cryptography for
transmission between two endpoints (i.e., a consumer and producer). The CCNxKE
protocol enables this form of communication by establishing shared state,
i.e., shared, ephemeral, and forward-secure symmetric keys.
This protocol has the following three main properties:

- The peer's identity can be authenticated using asymmetric, or
  public key, cryptography (e.g., RSA {{RSA}}, ECDSA {{ECDSA}}, etc.). This
  authentication can be made optional, but is generally required for
  at least one of the peers.

- The negotiation of a shared secret is secure from eavesdroppers
 and man-in-the-middle (MITM) attacks.

- The negotiation is reliable: no attacker can modify the
  negotiation communication without being detected by the parties to
  the communication.

- The state of a CCNx-KE session can be securely migrated between endpoints
using a "move token." This allows authentication and authorization to be
separated from encryption for a session, enabling different systems to perform
each of these steps.

Usage of CCNxKE is entirely independent of upper-layer application protocols.
Session-based communication via encapsulation and encryption enables secure,
confidential, and authenticated communication between two peers. One advantage
of this protocol is that it facilitates the creation and use of completely
ephemeral CCN Interest and Content Objects.

CCNxKE also introduces the use of reverse hash-chained nonces {{HASHCHAIN}}
in an Interest name to provide proof of a single continued message exchange. Prior
TCP-based protocols, such as TLS {{TLS13}}, use the TCP 3-way handshake for such proof.
Prior UDP-based protocols, such as QUIC {{QUIC}}, use a session address token that
must be presented by the client (consumer) to prove ownership of an address during
a key exchange procedure.

The main contribution of this work is adapting key exchange principles to
the CCNx communications model. CCNxKE achieves its goals by applying existing
key exchange techniques to the CCNx model of Named addresses and the Interest and
Content Object pull model. CCNxKE only assumes that a consumer knows a first name
that initiates the key exchange and understands the CCNxKE fields inside an Interest
and Content Object. The first Interest does not need to be a CCNxKE packet — the
producer can signal back to the consumer that it requires CCNxKE before progressing.

Finally, note that this specification does not subsume other ICN-compliant key exchange
protocols, nor does its existence imply that all encryption in an ICN must be based
on sessions. It was designed specifically to solve the problem of session-based
encryption in ICN.

##  Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

The following terms are used:

Consumer: The CCN consumer initiating the CCNxKE key exchange via a first Interest.

Producer: The CCN producer receiving or accepting the CCNxKE key exchange request request Interest.

Sender: An endpoint that originates a message.

Receiver: An endpoint that is receiving messages.

Peer: An endpoint. When discussing a particular endpoint, "peer" refers to the endpoint that is remote to the primary subject of discussion.

Connection: A network path of n >= 1 hops between the consumer and producer.

Endpoint: Either the consumer or producer of the connection.

Handshake: A series of message exchanges between two peers that is used to perform a
task (e.g., perform key exchange and derivation).

Session: An association between a consumer and a producer resulting from a
CCNxKE handshake.

DH: A Diffie Hellman key exchange procedure {{RFC2631}} {{DH}}.

DH Share: One half of the shared-secret provided by one peer performing a DH key exchange.

Forward-secure: The property that compromising any long-term secrets (e.g., cryptographic
keys) does not compromise any session keys derived from those long-term secrets.

CONFIG information: A data structure created by a producer which contains long-term
cryptographic material and associated information needed by a client to initiate a
key-exchange with the producer.

HELLO exchange: An exchange between a consumer and producer wherein the consumer
retrieves the CONFIG information from the producer.

Payload: The payload section of a CCNxMessage as defined in {{CCNxMessages}}.

KEPayload: A payload for information used in the CCNxKE protocol which is a generic
key-value store. The KEPayload is *not* the CCNxMessage payload.

CCNxName: A CCNxName as defined in {{CCNxMessages}}.

Semi-static: Short-term.

Short-term Secret (SS): A secret which is derived from the server's semi-static
DH share and the client's fresh DH share.

Forward-secure Secret (FSK): A secret which is derived from fresh (i.e., generated
on demand at random) DH shares from both the consumer and producer for the given
connection.

HKDF: Hash-based key-derivation function {{RFC5869}}.

#  Goals

The goals of the CCNxKE protocol, in order of priority, are as follows:

1. Cryptographic security: CCNxKE should be used to securely establish a session
and all related shared secrets between two peers. Cryptographic properties of interest
include: (a) forward-secure session key derivation and (b) (state and computational)
denial-of-service prevention at the producer (see {{RFC4987}}). For property (a),
different keys (and relevant algorithm parameters, such as IVs) are established for
each communication direction, i.e., from consumer to producer and producer to consumer.

2. Interoperability: Independent programmers should be able to develop
applications utilizing CCNxKE that can successfully exchange cryptographic
parameters without knowledge of one another's code.

3. Extensibility: CCNxKE seeks to provide a framework into which new public key
and symmetric key methods and algorithms can be incorporated without breaking
backwards compatability or requiring all clients to implement new functionality.
Moreover, the protocol should be able to support a variety of peer authentication
protocols, e.g., EAP-TLS, EAP-PWD, or a simple challenge-response protocol.

4. Relative efficiency: CCNxKE tries to create sessions with minimal computation,
bandwidth, and message complexity. In particular, it seeks to create sessions with
as few end-to-end round trips as possible, and also provide support for accelerated
session establishment and resumption when appropriate. At most 2 round-trip-times
(RTTs) should be used to establish a session key, with the possibility of 1 or 0 RTT
accelerated starts and resumption.

#  Scope

This document and the CCNxKE protocol are highly influenced by the TLS 1.3 {{TLS13}} and QUIC {{QUIC}}
protocols. The reader, however, does not need a detailed understanding of those
protocols to understand this document. Moreover, where appropriate, references
to related protocols are made for brevity and technical clarity. This document
is intended primarily for readers who will be implementing the protocol and for
those doing cryptographic analysis of it. The specification has been written with
this in mind, and it is intended to reflect the needs of those two groups.

Note that this document is not intended to supply any details of service definition or
of interface definition, although it does cover select areas of policy as they are
required for the maintenance of solid security.

#  Presentation Language

This document uses a presentation language of remote calls (i.e. packet messages)
similar to the format used by TLS {{TLS13}}.

# CCNxKE Overview

## Connection Establishment Latency

CCNxKE operates in three rounds, where each round requires a single RTT
to complete. The full execution of the protocol therefore requires 2 RTTs
before a session is fully established. The full version is used when consumers
have no a priori information about the producer. An accelerated two round
version is used when the consumer has valid configuration information about
the producer; this variant requires 1 RTT before a session is established.
Finally, the quickest execution of the protocol requires only a single round
to resume a previous session (similar to the goal of {{RFC5077}}). Indeed, if 0 RTT
latency is desired then the consumer must also include application data in this
initial round.

## Connection Migration and Resumption

CCN end hosts lack the notion of addresses. Thus, the producer endpoint
for a given execution of the CCNxKE protocol is one which can authoritatively
serve as the owner of a particular namespace. For example, a consumer may wish
to establish a session with a producer who owns the /company/foo namespace.
The specific end host which partakes in the protocol instance is not specified,
by virtue of the fact that all CCNxKE messages are based on well-defined names.
This enables the producer end-host which partakes in the protocol to change
based on the name of the CCNxKE messages. Consequently, to maintain
correctness, it is important that a single execution of the protocol operates
within the same trusted context; this does not mean that the same producer
end-host is required to participate in all three steps of the protocol.
Rather, it means that the end-host responding to a CCNxKE message must be
trusted by the consumer to complete the exchange. CCNxKE is designed to enable
this sort of producer migration.

For example, a consumer may use an initial name like ‘/parc/index.html’ that
works like an IP any cast address and could got to one of several systems.
CCNxKE allows the responding endpoint to include a localized name to ensure
that subsequent messages from the consumer come back to the same producer.
CCNxKE also allows the key exchange peer to securely hand-off the session to a
content producer peer via another name and session token once the client is
authenticated and keying material is exchanged.

## Re-Transmissions, Timeouts, and Replay Prevention

CCNxKE timeouts and retransmissions are handled using the approach in {{RFC6347}}.
One primary difference is that timer values may need to be adjusted (elongated)
due to prefix shifts and the need for a producer to transfer security information
between different machines.

Replay attack prevention is also an optional feature, and if used, MAY be done
using one of the following two approaches at the receiver (producer):

- IPSec AH {{RFC4302}} and ESP {{RFC4303}} style replay detection based on sliding
windows and monotonically increasing sequence numbers for windows. Note that the
sliding window inherently limits the performance of the protocol to the window size,
since only a finite number of messages may be received within a given window (based
on the window size).

- The optimized anti-replay algorithm of {{RFC6479}}.

# The CCNxKE Protocol

This section describes the CCNxKE protocol in detail at the message level. The
specific encoding of those messages is given later. CCNxKE could be adapted to
different wire format encodings, such as those used by the NDN protocol.

The following assumptions are made about peers participating in the CCNxKE protocol:

- Consumers know the namespace prefix of the producer for which they wish to
execute the CCNxKE protocol.

- The CCNxInterest carries a distinguished field that contains CCNxKE fields.

- The CCNxContentObject carries a distinguished field — separate from the Payload —
that contains the CCNxKE field. This is necessary for 0 RTT packets that carry
both keying material and application payload.

- CCNxKE does not require any special behavior of intermediate systems to forward packets.

- CCNxKE packets generally should not be cached for significant periods of time,
as use normal protocol methods to limit caching. Part of this is achieved through
the use of consumer-specific nonces in names.

## Round Overview

CCNxKE is composed of three rounds. The purpose of each round is described below.

* Round 1: Perform a bare HELLO exchange to obtain the public parameters and CONFIG
information (detailed later) provided by the producer. The CONFIG information is
relatively long-term cryptographic material generated by the producer and does not require
significant computation to produce. After this round the consumer is in possession
of the producer CONFIG information that is used to begin the real key exchange.

* Round 2: Perform the initial FULL-HELLO exchange to establish a forward-secure
key used for future communication, i.e., Interest and Content Object exchanges in
the context of the newly established session.

* Round 3: Send the first bit of application data and (optionally) transfer
resumption cookie(s) from the producer to the consumer.

Conceptually, there are two secrets that are established during a single execution
of CCNxKE:

* Short-term Secret (SS): A secret which is derived from the server's semi-static
    DH share and the client's fresh DH share. Keying material derived from SS is
    not forward secure.

* Forward-secure Secret (FSK): A secret which is derived from fresh DH shares
    from both the consumer and producer for the given connection. Keying material
    derived from FSK is intended to be forward secure.

All secrets are derived with the appropriate amount of randomness {{RFC4086}}.
An overview of the messages sent in each of the three rounds to
establish and use these secrets is shown in Figure {{ccnxke-high}} below.  This
diagram omits the optional session migration tokens and the quick
restart cookie.

~~~
    Consumer                                           Producer

    Payload:
    HELLO
                        I[/prefix/nonce1]
                            -------->
                                                        Payload:
                                                          Config
                                                          nonce2*
                                                            salt*
                        CO[/prefix/nonce1]
                            <---------
    Payload:
    ClientShare1
    {AlgorithmOptions}
    {NonceTarget}
    {ClientShare2}
                        I[/prefix/nonce2]
                            -------->
                                                        Payload:
                                                       SessionID
                                                           {ACK}
                                                  {ServerShare2}
                                                            [RC]
                        CO[/prefix/nonce2]
                            <---------
    Payload:
    [ConsumerData]

                        I[/prefix/SessionID/[...]]
                            -------->
                                                        Payload:
                                                  [ProducerData]
                        CO[/prefix/SessionID/[...]]
                            <--------

    (Repeat with data)      <-------->       (Repeat with data)

            *  Indicates optional or situation-dependent
               messages that are not always sent.

            {} Indicates messages protected using keys
               derived from the short-term secret (SS)

            [] Indicates messages protected using keys
               derived from the forward-secure secret (FSK).
~~~
{: #ccnxke-high title="High-level message flow for full CCNxKE protocol"}

In the following sections, we will describe the format of each round in this
protocol in more detail.

We do not specify the encoding of messages sent in Interest and Content Object
payloads. Any viable encoding will suffice, so long as both parties agree
upon the type. For example, the payload could be structured and encoded as
a JSON object whose, e.g.,

{
    "Config": CONFIG,
    "nonce2": nonce2*,
    "salt": salt*
}

For now, we assume some valid encoding mechanism is used to give structure
to message payloads.

## Round 1

Recall that the purpose of Round 1 is to acquire the CONFIG information used in
Round 2 of the protocol. To that end, the format of the Round 1 message is trivial.
First, the client issues an Interest with the following name

~~~
    /prefix/nonce1
~~~

and a HELLO KEPayload with the following information:

| HELLO Field | Description | Optional? |
| CCS | Compressed certificate set that the consumer possesses. This is used for generating
authenticators by the server. See {{QUIC}} for more details. | No |
| CCRT | Cached certificates in the consumer's possession | No |
| VER | Supported CCNxKE protocol version(s) | No |
| PROOF | Proof of demand (i.e., a sorted list of types of proof the consumer will expect) | No |
| NONCE1 | A 32-byte hash digest computed over a random input NONCE-TOKEN (used later) using SHA-256 | No |

Upon receipt of this interest, the producer responds with a HELLO-REJECT Content Object whose
KEPayload has the following fields:

| HELLO-REJECT Field | Description | Optional? |
| {REJ} | Rejection flag | No |
| {REASON} | Reason for rejection | No |
| CONFIG | The server CONFIG information | Yes |
| NONCE2 | An optional 32-byte nonce to use for the following message in the CCNxKE instance | Yes |
| PSALT1 | An optional 32-byte salt to use when deriving SS | Yes |
| PREFIX2 | An optional CCNxName prefix to use when continuing the session establishment protocol in Round 2 | Yes |

Recall that the CONFIG information is a semi-static catalog of information that consumers
can use to complete future key exchanges with the producer. The fields of the CONFIG
information are shown below.

<!-- table -->

| CONFIG Information Field | Description | Optional? |
| SCID | Server configuration ID | Yes |
| KEXS | Supported elliptic-curve key-exchange algorithms | No |
| AEAD | Supported AEAD algorithms | No |
| PUBS | List of public values (for key exchange algorithm) encoded appropriately for the given group | No |
| EXPRY | Expiration timestamp (i.e., longevity of the CONFIG structure) | No |
| VER | Version of the CONFIG structure | Yes |

The KEXS is a data structure that enumerates the elliptic curve key-exchange algorithms that
are supported by the producer (see {{QUIC}} for more details). Currently, only the following
curves are supported:

* Curve25519

* P-256

Selection criteria for these curves is given at http://safecurves.cr.yp.to/.

The AEAD structure enumerates the supported AEAD algorithms used for symmetric-key
authenticated encryption after the session has been established. Currently, the
only supported algorithms are:

* AES-GCM-(128,192,256) {{GCM}}: a 12-byte tag is used, where the first four bytes are taken
from the FSK key-derivation step and the last eight are taken from the initial consumer
nonce.

* Salsa20 {{SALSA20}} (stream cipher) with Poly1305 (MAC).

The key sizes and related parameters are provided with the AEAD tag in the CONFIG
structure.

((TODO: the exact structure of the AEAD needs to be spelled out here for completeness.))

The PUBS structure contains the public values for the initial key exchange. Both
Curve25519 and P-256 provide their own set of accepted parameters. Thus, the only
values provided here are the random curve elements used in the DH operation.

## Round 2

Recall that the purpose of Round 2 is to perform the initial FULL-HELLO exchange
to establish a forward-secure key used for future communication. It is assumed that
the consumer already has the CONFIG information that is provided from the producer
in Round 1. Moreover, assume that nonce2 is a ephemeral nonce provided by the
producer in Round 1. Then, the consumer issues an Interest with the following name:

~~~
    /prefix/nonce2
~~~

and a KEPayload with the following information:

| FULL-HELLO Field | Description | Optional? |
| CLIENT-SHARE1 | Client public share for the initial DH exchange | No |
| CSALT1 | Client salt for initial DH exchange and SS generation | Yes |
| PSALT1 | Echoed producer salt (not optional if the server provided one) | Yes |
| {PROOF} | Proof of demand (i.e., a sorted list of types of proof the consumer will expect) | No |
| {CCS} | Compressed certificate set that the consumer possesses | No |
| {CHALLENGE} | A random 32-byte challenge that is to be signed by the producer | No |
| {CHOICE} | Algorithm (KEXS and AEAD) options choice (a list of tags echoed from the server CONFIG) | No |
| {NONCE-TOKEN} | The preimage such that SHA-256(NONCE-TOKEN) = NONCE1 | No |
| {CLIENT-SHARE2} | Second share for generating the ephemeral key | No |
| {CSALT2} | Client salt for generating the FSK key | Yes |

Upon receipt of this interest, the producer performs the DH computation
to compute SS, decrypts all protected fields in the consumer's KEPayload, and validates the
algorithm choice selection (CHOICE). If any of these steps fail, the producer
replies with with a HELLO-REJECT Content Object whose KEPayload contains
a REJ flag and the reason of the error.
If the above steps complete without failure or error, then the producer responds
with a Content Object whose KEPayload has the following fields:

| HELLO-ACCEPT Field | Description | Optional? |
| SessionID | Cleartext session identifier | No |
| [RC] | Resumption cookie encrypted under a FSK-derived key | Yes |
| {ACK} | Positive ACK flag indicating success | No |
| {RESPONSE} | The signed output of the CHALLENGE according to the PROOF preferences and CCS certificates in possession of the consumer | No |
| {PSALT2} | 32-byte producer salt for the FSK key exchange | Yes |
| {SERVER-SHARE2} | Server’s public key share to use when generating MSK | No |
| {(Prefix3,MoveToken)} | Third CCNxName prefix and token to use when moving to session establishment | Yes |

((TODO: we need to spell out what type of flag ACK is (a bit? byte?)))

## Round 3

In Round 3, the consumer sends interests whose name and optional Payload are
encrypted using one of the forward-secure keys derived after Round 2. In normal operation,
the producer will respond with Content Objects whose Payloads are encrypted using
a different forward-secure key. That is, interests and Content Objects are encrypted
and authenticated using two separate keys. The producer may also optionally provide
a new resumption cookie (RC) with a Content Object response. This is used to keep
the consumer's resumption cookie fresh and to also support 0 RTT resumption. In this
case, the producer's Content Object response has the following fields:

* Payload: the actual Content Object payload data encrypted with the producer's
forward-secure key.

* RC': A new resumption cookie to be used for resuming this session in the future.

The producer is free to choose the frequency at which new resumption cookies are
issued to the consumer.

# Key Derivation

The goal of the CCNxKE protocol is to establish the following key material:

    consumer write key (FSK-C)
    producer write key (FSK-P)
    consumer write IV  (IV-C)
    producer write IV  (IV-P)

To get this material, first the SS must be derived. We use the HKDF {{RFC5869}} function
for all key derivation and expansion. Also, the DH operation produces a
32-byte value that used for the HKDF-Expand function.

~~~
  SS = HKDF(Salt, IKM)
Salt = CSALT1 || PSALT1 || “ss generation”
 IKM = DH(CLIENT-SHARE1, SERVER-SHARE1)
~~~
{: #ss-derive title="SS Derivation. SERVER-SHARE1 is the share corresponding to the consumer's CHOICE selection in Round 2."}

~~~
 FSK = HKDF(Salt, IKM)
Salt = CSALT2 || PSALT2 || “fsk generation”
 IKM = DH(CLIENT-SHARE2, SERVER-SHARE2)
~~~
{: #fsk-derive title="SS Derivation. SERVER-SHARE1 is the share corresponding to the consumer's CHOICE selection in Round 2."}

The keying material FSK-C/P and IV-C/P are then expanded from the FSK forward-secure
secret in the following order using the HKDF-Expand function.

    FSK-C
    FSK-P
    IV-C
    IV-P

# SessionID and Resumption Cookie Properties, Derivation, and Usage

The purpose of the session identifier SessionID is to uniquely
identify a single session for the producer and consumer. A Producer MAY use
a random bit string or MAY use the method described in this section or MAY
use another proprietary method to distinguish clients.

We provide a more secure creation of the SessionID since it is used
with the RC derivation (defined later). Specifically,
the SessionID is derived as the encryption of the hash digest of a server
secret, FSK, and an optional prefix (e.g., Prefix3). Encryption is done by the
using a long-term secret key owned by the server used for only this purpose, i.e.,
it is not used for consumer traffic encryption. Mechanically, this derivation is:

    SessionID = Enc(k1, H(secret || FSK || (Prefix3 | ""))),

where k1 is the long-term producer key, and "secret" is the producer's secret.

For the resumption cookie, we require that it must be able to be used to
recover the SS and FSK for a given session. Without SS and FSK, correct session
communication is not possible. We derive it as the encryption of the hash digest
of the server secret, SS, FSK, and the optional (Prefix3, MoveToken) tuple
(if created for the session). The producer must use a long-term secret key
for this encryption. Mechanically, this derivation is:

    RC = Enc(k2, SS || FSK || ((Prefix3 || MoveToken) | "")),

where k2 is again a long-term producer key. Note that it may be the case that
k1 = k2 (see above), though this is not required.

With this SessionID and RC, the consumer then resumes a session by providing
both the SessionID and RC to the producer. This is done to prove to the producer that
the consumer who knows the SessionID is also in possession of the correct RC.
The producer verifies this by computing

    (SS || FSK || ((Prefix3 || MoveToken)| "")) = Dec(k2, RC)

and checking the following equality

    SessionID = Enc(k1, H( secret || FSK || ( Prefix3 | "")))

If equality holds, the producer uses the SS and FSK recovered from RC to re-initialize
the previous session with the consumer.

# Client Authentication

Currently, only the producer is authenticated in the CCNxKE protocol using a standard
challenge-response protocol. This could be extended to enable mutual authentication
for the client by adding a challenge-response exchange from the producer to the consumer
in Rounds 2 and 3. That is, the producer could return a CHALLENGE in Round 2, to which
the consumer is expected to sign and return as a RESPONSE in Round 3 before the producer
accepts any application data.

Additional authentication mechanisms based on EAP may also be used, including:

- EAP-TLS: EAP based on a TLS-like exchange.
- EAP-PWD: EAP based on a password.
- EAP-PSK: EAP based on a pre-shared key.

(( TODO: should we add examples for each of the above variants? ))

# Security Considerations

For CCNxKE to be able to provide a secure connection, both the consumer and producer
systems, keys, and applications must be secure. In addition, the implementation
must be free of security errors.

The system is only as strong as the weakest key exchange and authentication
algorithm supported, and only trustworthy cryptographic functions should be
used. Short public keys and anonymous servers should be used with great
caution. Implementations and users must be careful when deciding which
certificates and certificate authorities are acceptable; a dishonest
certificate authority can do tremendous damage.
