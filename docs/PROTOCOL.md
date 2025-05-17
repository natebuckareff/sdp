# Streaming Datagram Protocol

The Streaming Datagram Protocol is a simple protocol for streaming data between peers. It's designed primarily for use with UDP as a transform, but can also be used with TCP and WebRTC.

Two peers connect by first exchanging "connect" and "accept" packets. These packets authenticate the peers using long-lived "static" ED25519 public keys, which are analogous to SSH public keys. The peers also exchange ephemeral x25519 public keys which are used with Diffie-Helman to derive a shared connection secret.

When using WebRTC as a transport, the protocol disables encryption and instead relies on the security properties of WebRTC.

WebRTC Mode:
- Ephemeral public keys are not exchanged
- Stream frames headers are not masked
- Stream ciphertext is sent in the clear
- Stream frames do not have an auth tag

UDP and TCP transports do employ an encryption protocol which is defined in [Encryption Protocol](#encryption-protocol).


## Frame Definition

```
frame ::=
    | connect_packet_type      connect_payload
    | accept_packet_type       accept_payload
    | reject_packet_type       reject_payload
    | start_stream_packet_type start_stream_payload
    | stream_data_packet_type  stream_data_payload

connect_packet_type      ::= 0x00
accept_packet_type       ::= 0x01
reject_packet_type       ::= 0x02
start_stream_packet_type ::= 0x03
stream_data_packet_type  ::= 0x04

connect_payload ::=
    protocol_version
    connection_id
    static_public_key
    ephemeral_public_key
    signature

accept_payload ::=
    protocol_version
    connection_id
    static_public_key
    ephemeral_public_key
    signature

reject_payload ::= connection_id error_code

start_stream_payload ::=
    connection_id
    mask_header(stream_id, stream_flags)

stream_flags ::=
    | ordered_stream_flag
    | unordered_stream_flag

ordered_stream_flag   ::= 0x00
unordered_stream_flag ::= 0x01

stream_data_payload ::=
    connection_id
    mask_header(stream_id, packet_number)
    ciphertext
    auth_tag
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
