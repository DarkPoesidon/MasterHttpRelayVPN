# MasterHttpRelayVPN Android Port

This folder is an isolated Android port scaffold. It does not modify or depend on the Python desktop code at runtime.

## Structure

- `core/`: Go networking core intended for `gomobile bind`
- `app/`: Android Studio project scaffold in Kotlin

## Implemented Scope

- Local Go HTTP proxy listening on `127.0.0.1:8085`
- Google Apps Script HTTP relay over a domain-fronted TLS dialer
- Basic `CONNECT` tunneling support as a placeholder for HTTPS flows
- Android `VpnService` scaffold showing where the TUN interface and Go proxy integration meet
- A Go TUN bridge built on `gvisor/netstack` for Android/Linux targets
- A `gomobile` protector callback path so outbound sockets can be passed to `VpnService.protect(fd)` before connect

## Packet Flow

1. `LocalVpnService` creates the Android TUN interface and gets its file descriptor.
2. Kotlin registers a protector callback with the Go core through `GoBridge`.
3. Kotlin calls `StartVpn(configJson, tunFd)` in the Go binding.
4. The Go core starts the local proxy and attaches `gvisor/netstack` to the TUN FD.
5. TCP packets arriving from the TUN device are reconstructed into TCP streams by netstack.
6. Each reconstructed TCP stream is bridged into the local proxy by opening a loopback connection to `127.0.0.1:8085` and issuing a local `CONNECT` request for the original destination.
7. Any outbound host sockets created by the Go core run through a custom dialer that calls back into Kotlin so `VpnService.protect(fd)` can bypass the VPN and prevent routing loops.

## Current Limitation

The Go core relays plain HTTP through the Apps Script endpoint, and the new bridge now feeds TCP flows into the local proxy. `CONNECT` itself is still a direct TCP tunnel rather than a full Apps Script HTTPS relay. Full blocked-HTTPS support still requires one of these next options:

1. Local MITM plus relay reconstruction, similar to the Python desktop path.
2. A remote raw tunnel endpoint paired with a framed transport, such as WebSocket or HTTP/2 stream multiplexing.
3. DNS-aware host reconstruction and policy routing for domains that must be relayed rather than directly tunneled.

## Go Build Steps

1. Install Go 1.22+.
2. Install `gomobile`:

   ```bash
   go install golang.org/x/mobile/cmd/gomobile@latest
   gomobile init
   ```

3. Build the Android binding AAR from `Android/core`:

   ```bash
   cd Android/core
   go mod tidy
   gomobile bind -target=android -androidapi 24 -javapkg com.masterhttprelayvpn.core -o ../app/app/libs/mastervpn_core.aar .
   ```

   This command generates the binding package used by `GoBridge.kt`:
   - `com.masterhttprelayvpn.core.Mastervpncore`
   - `com.masterhttprelayvpn.core.Protector`

4. Open `Android/app` in Android Studio.

The Android Gradle scaffold already loads `.aar` files from `app/libs`, so once the binding is generated it can be consumed without changing the Kotlin source layout.

## Android Integration Notes

- `MainActivity.kt` asks Android for VPN permission and starts/stops `LocalVpnService`.
- `LocalVpnService.kt` establishes the TUN interface, passes the TUN FD to Go, and answers `protect(fd)` requests.
- `GoBridge.kt` now calls the generated `gomobile` bindings directly and registers the `Protector` callback implementation.
- `bridge.go` contains the Android/Linux-only netstack bridge implementation; `bridge_stub.go` keeps desktop validation working on non-Linux hosts.

## Suggested Next Phase

1. Extend CONNECT relay support to cover non-HTTP tunneled TLS payloads without degrading compatibility.
2. Add richer DNS policy support (DoH/DoT fallback, multi-resolver racing).
3. Move placeholder proxy config in `MainActivity.kt` into persisted UI settings.
4. Add runtime telemetry and debug tracing around bridge drops/timeouts.