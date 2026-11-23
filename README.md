# sing-tun

> **Glitch VPN fork.** This is `glitch-vpn/sing-tun`: MetaCubeX/sing-tun v0.4.29 with the fork's own changes on the `glitch` branch, each a commit after v0.4.29. The gVisor stack closes the stop eventfd of its inbound dispatchers, which `fdbased.New` leaks (`stack_gvisor_stop_linux.go`). Every stack drops an ICMP echo request the handler declines or fails instead of answering it locally. On Windows: the Wintun adapter can be kept for the life of the process and reused by later sessions (`tun_kept_windows.go`), a session clears only the routes and addresses it set, a route that fails to add stops the rest, strict route can let local IPv6 pass (`StrictRouteLocalNetworksDirect`), and the adapter's steps and Wintun's own log are timed into the log. Upstream's newer fixes are merged in at each release of the fork. CI: `.github/workflows/glitch.yml`.

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