# Local map assets

`world.json` and `china.json` are bundled local GeoJSON map assets used by the Insights traffic map so the route does not depend on an external map tile API.

Source reference: `vam876/FastMonitor` (`frontend/public/maps/*`), Apache-2.0 licensed.

The bundled `china.json` has SHA-256
`688a774de6d93b24003ae48a1f8df7b1acfaa1ea7eb98a95fe50688b64be5719`,
which matches the current upstream file byte-for-byte. The bundled `world.json` has
SHA-256 `049b334579e5a42d5d16c72d014d380e048e39fc1504049f212acb589484d2fa`.

The frontend registers these files into the bundled ECharts runtime and overlays Dreaming OS GeoIP flow points/routes on top of them.
