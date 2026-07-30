# Local map assets

`world.json` and `china.json` are bundled local GeoJSON map assets used by the Insights traffic map so the route does not depend on an external map tile API.

Source reference: `vam876/FastMonitor` (`frontend/public/maps/*`), Apache-2.0 licensed.

The frontend registers these files into the bundled ECharts runtime and overlays Dreaming OS GeoIP flow points/routes on top of them.
