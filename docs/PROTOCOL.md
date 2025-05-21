# Streaming Datagram Protocol

The Streaming Datagram Protocol is a simple protocol for streaming data between peers. It's designed primarily for use over UDP, but also supports TCP and WebRTC transports.

Two peers connect by first exchanging "connect" and "accept" packets. These packets authenticate the peers using long-lived "static" ED25519 public keys, which are analogous to SSH public keys. The peers also exchange ephemeral x25519 public keys which are used with Diffie-Helman to derive a shared secret.

After authenticating each other, peers establish a connection over which all further data is sent. Connection frames are encrypted using an AEAD cipher with a key derived from the shared secret.

When using WebRTC as a transport, the protocol disables encryption and instead relies on the security properties of WebRTC.

WebRTC Mode:
- Ephemeral public keys are not exchanged
- Stream frames headers are not masked
- Stream ciphertext is sent in the clear
- Stream frames do not have an auth tag

UDP and TCP transports employ the encryption protocol defined in [Encryption Protocol](#encryption-protocol).

## Frame Definition

```
sdp_frame ::=
    | handshake_frame
    | connection_frame
```

SDP frames are either handshake frames or connection frames. Handshake frames authenticate a peer and setup a new connection. Connection frames contain encrypted conntection data sent to a peer.

Multiple connections are multiplexed over a single SDP endpoint. Each connection is encrypted to a pair of public keys; one for the sender and receiver. Multiple streams are multiplexed over each connection.

The UDP transport sends SDP frames as individual datagrams. Multiple key exchange and stream frames (potentially for different streams) are packed into a single SDP frame.

The TCP and WebRTC transports are streaming transports, so they cannot rely on the implicit UDP length field to delimit a SDP frame. Instead, they always include the optional packet type field to delimit datagrams in the stream. Otherwise, the protocol is the same.

```
# UDP transport sends datagram frames. TCP and WebRTC transports send stream
# frames

handshake_frame ::=
    | handshake_datagram_frame
    | handshake_stream_frame

# MSB of the packet number being not set identifies this as a handshake frame

handshake_datagram_frame ::=
    !((1 << 7) & packet_number)
    key_exchange_frame+

handshake_stream_frame ::=
    packet_type
    length                      # 2 B
    key_exchange_frame+

# Multiple key exchange frames may be packed into a single handshake frame

key_exchange_frame ::=
    | connect_frame
    | accept_frame
    | declaration_frame
    | reject_frame

# Key exchange starts with with the SEND-side sending a connect frame. Both
# sides must agree on the protocol version and connection flags. Flags configure
# connection-ID-length, enables the public key fingerprint field, and other
# connection parameters.

# (flags | fingerprint_flag) -> The fingerprint field will contain the hash of
# the SEND-side public key and the RECV-side may use a cached public key to
# verify signatures

# !(flags | fingerprint_flag) -> The fingerprint field will be absent and a
# declaration frame must be sent

# Signatures cover the entire frame, except the signature field itself.
# Signatures must be verified after the frame is reassembled

connect_frame ::=
    packet_type                 # 1 B
    length                      # 2 B
    protocol_version            # 4 B
    connect_flags               # 1 B
    connection_id_length        # 1 B, =1-20
    src_connection_id           # min 2 B
    fingerprint?                # 0-32 B
    key_exchange
    signature

connect_flags ::=
    | (crypto_mode << 6)        # 2 bits

# The crypto mode determines selection of either classical, hybrid, or pq frame
# types for remainder of the handshake flow

crypto_mode ::=
    | classical_only            # 0b00
    | hybrid                    # 0b01
    | pq_only                   # 0b10

# RECV-side peer may respond to a connect frame by sending an accept frame. The
# protocol version must be the same or compatible with the SEND-side version.
# The connection flags may be disjoint from the SEND-side flags, and the
# SEND-side may reject them. The `dst_connection_id` identifies the connect
# frame this accept frame is in response to. SEND-side must send all future
# frames to `src_connection_id`. RECV-side must send all future frames to
# `dst_connection_id`

accept_frame ::=
    packet_type             # 1 B
    length                  # 2 B
    protocol_version        # 4 B
    connection_flags        # 1 B
    dst_connection_id       # min 2 B
    src_connection_id       # min 2 B
    fingerprint?            # 0-32 B
    key_exchange
    signature

# Key mode is determined by `connect_packet_type`

key_exchange ::=
    | key_exchange_classical
    | key_exchange_hybrid
    | key_exchange_pq

key_exchange_classical ::=
    x25519_public_key       # 32 B

key_exchange_hybrid ::=
    x25519_public_key       # 32 B
    mlkem768_ciphertext     # 1088 B

key_exchange_pq ::=
    mlkem768_ciphertext   # 1088 B

# Declaration frames must be sent if a fingerprint field is omitted from either
# the connect or accept frames. Otherwise, declaration frames may be sent in
# response to a `unknown_fingerprint` rejection

declaration_frame ::=
    packet_type             # 1 B
    length                  # 2 B
    declaration

declaration ::=
    | declaration_classical
    | declaration_pq

declaration_classical ::=
    ed25519_public_key      # 32 B

declaration_pq
    mlkem768_public_key     # 1184 B

# SEND or RECV sides may send reject frames if an error occurs during the
# handshake. The connection is immediately closed after a rejection and any
# connection IDs may be reused

reject_frame ::=
    packet_type             # 1 B
    length                  # 2 B
    reason_code             # 1 B
    signature

# protocol_version -> Incompatible protocol versions

# connection_id_length -> Incompatible connection ID lengths

# public_key_denied -> Authentication and/or authorization failed

# unknown_fingerprint -> Receiver no longer has the public key associated with a
# previously used fingerprint. Sender may send a declaration frame with their
# public key. Receiver will replay their previously sent frames using the
# refreshed public key

# unknown_error -> Any other error

reason_code ::=
    | protocol_version
    | connection_id_length
    | public_key_denied
    | unknown_fingerprint
    | unknown_error             # 0xff

# Signature mode is determined by `connect_packet_type`

signature ::=
    | ed25519_signature     # 64 B
    | mldsa65_signature   # 3309 B

# Hash of a peer's public key to leverage a remote peer's public key cache

fingerprint ::=
    | "ed25519_" || sha255_hash             # 32 B
    | "mldsa65_" || sha255_hash             # 32 B
```

---------

```
connection_frame ::=
    | 0x00 handshake_connect_payload
    | 0x01 handshake_accept_payload
    | 0x02 handshake_reject_payload
    | 0x03 stream_payload

handshake_connect_payload ::=
    protocol_version
    src_connection_id
    static_public_key
    ephemeral_public_key
    signature

handshake_accept_payload ::=
    protocol_version
    dst_connection_id
    src_connection_id
    static_public_key
    ephemeral_public_key
    signature

handshake_reject_payload ::=
    dst_connection_id
    reason_code
    static_public_key
    signature

stream_payload ::=
    dst_connection_id
    mask_header(stream_id, packet_number)
    stream_frame
    where
        stream_frame = decrypt(ciphertext, auth_tag)

stream_frame ::=
    | 0x00 stream_start stream_transmission?
    | stream_transmission

stream_start ::=
    stream_flags

stream_transmission ::=
    | 0x01 stream_data
    | 0x02 stream_datagram
    | 0x03 stream_message
    | 0x04 stream_final_message
    | stream_end

stream_data     ::= bytes
stream_datagram ::= bytes

stream_message ::=
    message_id
    offset
    bytes

stream_final_message ::= stream_message
stream_end           ::= 0x05
```

## Encryption Protocol

Peers first echange ephemeral x25519 public keys and derive a shared secret.

```
shared_secret ::= diffie_helman(
    our_ephemeral_secret,
    their_ephemeral_public_key
)
```

If the peers successfully authenticate each other, the shared secret is used to derive a connection secret that is unique for that pair of exchanged connection IDs.

```
connection_secret = hkdf_sha256(
    shared_secret,
    "sdp connection ({their_connection_id}, {our_connection_id}) secret {side}"
)
```

The connection secret is derived using HKDF-SHA256 with a label unique to current connection.

The stream packet header (stream ID and packet number) is masked by xoring the header bytes with an encrypted sample of the adjacent ciphertext. This sample is computed by deriving a ChaCha20 nonce from the first N ciphertext bytes, and then encrypting H 0-bytes, where H is the header length, using the nonce and the header secret as key. The resulting H bytes are then XORed with the header to mask it.

```
header_secret = hkdf_sha256(connection_secret, "sdp header secret {side}")

mask_header(header, ciphertext) =
    nonce = ciphertext[0..chacha20_nonce_len]
    mask = zeroes(len(header))
    chacha20_encrypt(header_secret, nonce, mask) ^ header
```

The stream packet payload is encrypted with ChaCha20-Poly1305.

```
stream_secret = hkdf_sha256(
    connection_secret,
    "sdp stream {stream_id} secret {side}"
)

static_iv = hkdf_sha256(stream_secret, "sdp static iv {side}")
aead_key  = hkdf_sha256(stream_secret, "sdp aead key {side})

encrypt_stream_payload(stream_id, packet_number, plaintext) =
    nonce = stream_nonce(static_iv, packet_number)
    associated_data = stream_id || packet_number
    ciphertext, tag = chacha20_poly1305_encrypt(
        aead_key,
        nonce,
        associated_data,
        plaintext
    )
    ciphertext || tag

stream_nonce(static_iv, packet_number) :=
    bytes = be_u64_bytes(packet_number)
    stativ_iv ^ left_pad_zero(len(static_iv) - len(bytes), bytes)
```

The packet number is incremented for every packet sent in a stream. Once it equals or exceeds 1 << 62 a new stream secret is derived using the previous stream secret as input, and the static IV and AEAD keys are also rederived.

```
stream_secret = hkdf_sha256(
    stream_secret,
    "sdp stream {stream_id} rekey {side}"
)
```

The peer that sent the initial connect packet is considered the "send side" and the accepting peer is the "recv side". In all HKDF key expansions "side" is substituted with either "send" or "recv" respectively for either encrypting data to send or decrypting recevied data.

So the send (sent connect) peer will use "send" for decryption data and "recv" for encryption, and the recv (sent accept) peer will use "recv" for decryption and "send" for encryption.

## Ordered and Unordered Streams

Streams packets may be either ordered or unordered.

Ordered streams deliver packets in sequentially increasing, non-repeating, packet number order.

Unordered streams deliver packets in any arbitrary order, but packet numbers are never repeated.
