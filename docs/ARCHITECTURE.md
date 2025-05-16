
Organized into four core modules:
- transport
- encode
- crypto
- protocol

The `transport` module contains implementions for  UDP, TCP, and WebRTC transports using `tokio`.

The `wire` module contains the implementation of the SDP wire format.

The `crypto` module contains implementations of core cryptographic primitives.

The `protocol` module contains the implementation of the SDP protocol state machine.

Transports:
- `GenericTransport`
- `UdpTransport`
- `TcpTransport`
- `WebRtcTransport`
