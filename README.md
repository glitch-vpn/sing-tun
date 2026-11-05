# sing-tun

> **Glitch VPN fork.** This is `glitch-vpn/sing-tun`, MetaCubeX/sing-tun v0.4.28 with two changes. First: the gVisor stack closes the stop eventfd of its inbound dispatchers. `fdbased.New` in `github.com/metacubex/gvisor` creates one eventfd per dispatcher and never closes it, so every start and close of the stack leaked a file descriptor. `GVisor.Close` now detaches the endpoint, waits for the dispatchers and closes those descriptors once, reading them by reflection (`stack_gvisor_stop_linux.go`); if gVisor changes the shape the descriptors are left open and a warning is logged. Other platforms are unchanged. Second, every stack drops an ICMP echo request the handler declines (`PrepareConnection` returns no destination) or fails, instead of answering it locally; an echo addressed to the TUN's own address is still answered.

Simple transparent proxy library.

For Linux, Windows, macOS and iOS.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```