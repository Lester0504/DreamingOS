# Third-Party Notices

DreamingOS is a multi-license source tree. The license attached to each upstream
file or component remains authoritative. This document summarizes notable bundled
or derived components and does not replace their license text.

## OpenWrt

- Project: <https://github.com/openwrt/openwrt>
- Baseline: `25ee12629edcc38feffbd06255dd47840cd7af7e`
- License: GPL-2.0-only for the OpenWrt tree, with component-specific exceptions
  identified by SPDX headers and files under `LICENSES/`

## FanchmWrt

- Project: <https://github.com/fanchmwrt/fanchmwrt>
- Use: parts of the DreamingOS DPI and timed filtering components are derived from
  FanchmWrt code
- License: GPL-2.0-only at the referenced upstream tree
- Attribution: derived files retain the original `destan19` copyright notice

## Apache ECharts

- Project: <https://echarts.apache.org/>
- Bundled file: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/vendor/echarts.min.js`
- Version: 5.5.1; the bundled file matches the official npm artifact byte-for-byte
- License: Apache-2.0
- License and notice files: `echarts.LICENSE.txt`, `echarts.NOTICE.txt`, and the
  embedded d3.js `echarts.LICENSE-d3.txt` beside the bundled source

## FastMonitor map data

- Project: <https://github.com/vam876/FastMonitor>
- Bundled files: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/maps/world.json`
  and `china.json`
- Use: local GeoJSON assets for the Insights traffic map
- License: Apache-2.0
- Verification: `china.json` matches the current upstream file byte-for-byte;
  `world.json` matches the previously audited upstream map artifact

## qrcode-generator

- Project: <https://github.com/kazuhikoarase/qrcode-generator>
- Bundled file: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/vendor/qrcode-generator.min.js`
- Version: 1.4.4
- License: MIT
- License file: `qrcode-generator.LICENSE.txt` beside the bundled source

## Lucide

- Project: <https://lucide.dev/>
- Bundled file: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/ui-kit/lucide.min.js`
- Version: 1.25.0
- License: ISC
- License file: `lucide.LICENSE.txt` beside the bundled source

## Sampled Liquid Glass

- Upstream project: liquid-glass-react 1.1.1
- Upstream author: Max Rovensky
- Bundled adaptation: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/ui-kit/dwrt-sampled-liquid-glass.js`
  and its companion `dwrt-sampled-liquid-glass.css`
- Use: only the displacement-map algorithm is adapted; the surrounding component is
  DreamingOS code
- License: MIT, referenced in the source header and reproduced in full in
  `dwrt-sampled-liquid-glass.LICENSE.txt` beside the bundled source

## ISO 3166-1 country table

- Bundled file: `package/lester/jmxd/files/geoip/iso3166-1.csv`
- Content: ISO 3166-1 alpha-2 codes with English and Chinese names and continent
- Status: ISO 3166-1 alpha-2 codes and English short names are factual data published
  by the ISO 3166 Maintenance Agency and are not themselves copyrightable; the Chinese
  names, continent grouping and sort order in this file were compiled for DreamingOS
- License: the compiled table is released under the DreamingOS tree license

## MaxMind Test Database

- Project: <https://github.com/maxmind/MaxMind-DB>
- Bundled file: `package/lester/jmxd/tests/fixtures/GeoIP2-Country-Test.mmdb`
- Use: unit-test fixture only; it is not installed into firmware
- License: Creative Commons Attribution-ShareAlike 4.0 International
- Source and checksum: documented in the fixture directory's `README.md`

## Carrier marks

- Bundled files: `package/lester/dreamingwrt-web/files/www/dreamingwrt/static/images/logo/china-telecom.svg`,
  `china-unicom.svg`, `china-mobile.svg`, `china-cernet.svg`
- Use: displayed next to a WAN line when DreamingOS recognizes the carrier, so
  operators can tell their uplinks apart at a glance
- Status: these are the registered trademarks of the respective carriers. They are
  **not** licensed to this project. They are included solely as nominative
  identification of the network operator a WAN line is connected to, and imply no
  affiliation with, sponsorship by, or endorsement from those carriers.
- Redistribution note: anyone redistributing DreamingOS, and in particular anyone
  doing so commercially, should confirm that this use is acceptable in their
  jurisdiction. The frontend already prefers a backend-supplied logo and falls back
  to a generic icon when the carrier is unknown, so the bundled marks can be removed
  by deleting the four files and the `CARRIER_LOGOS` maps in `dashboard.js`,
  `menu-shell.js`, `global-config.js` and `network-interface-config.js`.

## Optional Downloads

Some build options can download external datasets such as GeoLite-compatible MMDB
files. They are disabled by default and are not part of this repository. Anyone
enabling those options is responsible for reviewing the selected data provider's
license and distribution terms.
