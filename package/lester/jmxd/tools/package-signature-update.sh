#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage:
  jmxd/tools/package-signature-update.sh --db PATH --logo DIR --out PATH [--conf PATH] [--version VERSION] [--format v1|v2]
  jmxd/tools/package-signature-update.sh --db PATH --logo DIR --out PATH --format v2 [--geoip PATH] [--reputation DIR] [--content DIR] [--fingerprint PATH] [--ips DIR] [--device-icons DIR]

Creates a DreamingWrt signature update .bin package.

v1 package layout:
  signature-update.conf
  dreamingwrt_signatures.db
  logo/

v2 package layout:
  signature-update.conf
  manifest.json
  dreamingwrt_signatures.db
  logo/
  geoip/        optional
  reputation/   optional
  content/      optional
  fingerprint/fingerprint.db  optional
  ips/          optional
  device_icon/  optional

The generated conf contains counts and build metadata for the frontend card and
future jmxd validation/apply flow.
EOF
}

db=""
logos=""
out=""
conf=""
version=""
format="v1"
geoip=""
reputation=""
content=""
fingerprint=""
ips=""
device_icons=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --db) db="${2:-}"; shift 2 ;;
    --logo) logos="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --conf) conf="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --format) format="${2:-}"; shift 2 ;;
    --geoip) geoip="${2:-}"; shift 2 ;;
    --reputation) reputation="${2:-}"; shift 2 ;;
    --content) content="${2:-}"; shift 2 ;;
    --fingerprint) fingerprint="${2:-}"; shift 2 ;;
    --ips) ips="${2:-}"; shift 2 ;;
    --device-icons|--device_icon|--device-icon) device_icons="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$db" ] || { echo "--db is required" >&2; exit 2; }
[ -n "$logos" ] || { echo "--logo is required" >&2; exit 2; }
[ -n "$out" ] || { echo "--out is required" >&2; exit 2; }
[ -f "$db" ] || { echo "DB not found: $db" >&2; exit 1; }
[ -d "$logos" ] || { echo "logo directory not found: $logos" >&2; exit 1; }
[ "$format" = "v1" ] || [ "$format" = "v2" ] || { echo "--format must be v1 or v2" >&2; exit 2; }
[ -z "$fingerprint" ] || [ "$format" = "v2" ] || { echo "--fingerprint requires --format v2" >&2; exit 2; }
command -v sqlite3 >/dev/null 2>&1 || { echo "sqlite3 is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  echo "shasum or sha256sum is required" >&2
  exit 1
fi

case "$db" in /*) ;; *) db="$(cd "$(dirname "$db")" && pwd)/$(basename "$db")" ;; esac
case "$logos" in /*) ;; *) logos="$(cd "$logos" && pwd)" ;; esac
case "$out" in
  /*) ;;
  *) out_dir="$(dirname "$out")"; out_base="$(basename "$out")";
     mkdir -p "$out_dir"; out="$(cd "$out_dir" && pwd)/$out_base" ;;
esac

if [ -n "$fingerprint" ]; then
  if [ -L "$fingerprint" ]; then
    echo "--fingerprint must not be a symlink" >&2
    exit 1
  fi
  if [ -d "$fingerprint" ]; then
    fingerprint_dir="$fingerprint"
    fingerprint_entries="$(find "$fingerprint_dir" -mindepth 1 -print | wc -l | tr -d ' ')"
    [ "$fingerprint_entries" = "1" ] || {
      echo "--fingerprint directory must contain only fingerprint.db" >&2
      exit 1
    }
    fingerprint="$fingerprint_dir/fingerprint.db"
  fi
  [ -f "$fingerprint" ] && [ ! -L "$fingerprint" ] || {
    echo "fingerprint DB not found or unsafe: $fingerprint" >&2
    exit 1
  }
  [ "$(basename "$fingerprint")" = "fingerprint.db" ] || {
    echo "--fingerprint file must be named fingerprint.db" >&2
    exit 1
  }
  case "$fingerprint" in
    /*) ;;
    *) fingerprint="$(cd "$(dirname "$fingerprint")" && pwd)/fingerprint.db" ;;
  esac
fi

pkg_version="${version:-$(date +%Y.%m.%d.%H%M%S)}"
build_epoch="$(date +%s)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/dwrt-signature-update.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

file_count() {
  if [ -d "$1" ]; then
    find "$1" -type f | wc -l | tr -d ' '
  elif [ -f "$1" ]; then
    printf '1'
  else
    printf '0'
  fi
}

byte_count() {
  if [ -d "$1" ]; then
    find "$1" -type f -exec wc -c {} + | awk '/ total$/ {t=$1} !/ total$/ {s+=$1} END {print t ? t : s+0}'
  elif [ -f "$1" ]; then
    wc -c < "$1" | tr -d ' '
  else
    printf '0'
  fi
}

tree_sha256() {
  if [ -d "$1" ]; then
    (cd "$1" && find . -type f | LC_ALL=C sort | while IFS= read -r f; do
      p="${f#./}"
      printf '%s  %s\n' "$(sha256_file "$p")" "$p"
    done) | sha256_stdin
  elif [ -f "$1" ]; then
    sha256_file "$1"
  else
    printf ''
  fi
}

copy_dataset() {
  src="$1"
  dst="$2"
  [ -n "$src" ] || return 0
  if [ -d "$src" ]; then
    mkdir -p "$dst"
    (cd "$src" && tar cf - .) | (cd "$dst" && tar xf -)
  elif [ -f "$src" ]; then
    mkdir -p "$dst"
    cp "$src" "$dst/$(basename "$src")"
  else
    echo "dataset path not found: $src" >&2
    exit 1
  fi
}

append_dataset_json() {
  manifest="$1"
  name="$2"
  path="$3"
  src="$4"
  comma="$5"
  files="$(file_count "$src")"
  bytes="$(byte_count "$src")"
  sha="$(tree_sha256 "$src")"
  esc_name="$(json_escape "$name")"
  esc_path="$(json_escape "$path")"
  esc_sha="$(json_escape "$sha")"
  if [ "$comma" = "1" ]; then
    printf ',\n' >> "$manifest"
  fi
  cat >> "$manifest" <<EOF
    {
      "name": "$esc_name",
      "path": "$esc_path",
      "sha256": "$esc_sha",
      "file_count": $files,
      "size_bytes": $bytes
    }
EOF
}

dataset_manifest_path() {
  base="$1"
  src="$2"
  if [ -d "$src" ]; then
    printf '%s/' "$base"
  else
    printf '%s/%s' "$base" "$(basename "$src")"
  fi
}

dataset_stage_path() {
  base="$1"
  src="$2"
  if [ -d "$src" ]; then
    printf '%s/%s' "$tmpdir" "$base"
  else
    printf '%s/%s/%s' "$tmpdir" "$base" "$(basename "$src")"
  fi
}

sql_scalar() {
  sqlite3 "$db" "$1" 2>/dev/null || printf '0\n'
}

validate_fingerprint_db() {
  [ -n "$fingerprint" ] || return 0
  fp_integrity="$(sqlite3 "$fingerprint" "PRAGMA integrity_check;" 2>/dev/null || true)"
  fp_application_id="$(sqlite3 "$fingerprint" "PRAGMA application_id;" 2>/dev/null || true)"
  fp_user_version="$(sqlite3 "$fingerprint" "PRAGMA user_version;" 2>/dev/null || true)"
  fp_tables="$(sqlite3 "$fingerprint" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('fingerprint_device','fingerprint_meta');" 2>/dev/null || true)"
  fp_expected="$(sqlite3 "$fingerprint" "SELECT CAST(value AS INTEGER) FROM fingerprint_meta WHERE key='device_count';" 2>/dev/null || true)"
  fp_actual="$(sqlite3 "$fingerprint" "SELECT COUNT(*) FROM fingerprint_device;" 2>/dev/null || true)"

  [ "$fp_integrity" = "ok" ] || { echo "fingerprint DB integrity check failed: $fp_integrity" >&2; exit 1; }
  [ "$fp_application_id" = "1146570320" ] || { echo "fingerprint DB application_id mismatch: $fp_application_id" >&2; exit 1; }
  [ "$fp_user_version" = "1" ] || { echo "fingerprint DB user_version mismatch: $fp_user_version" >&2; exit 1; }
  [ "$fp_tables" = "2" ] || { echo "fingerprint DB required tables are missing" >&2; exit 1; }
  [ -n "$fp_expected" ] && [ "$fp_expected" -gt 0 ] 2>/dev/null || { echo "fingerprint DB device_count is invalid" >&2; exit 1; }
  [ "$fp_actual" = "$fp_expected" ] || { echo "fingerprint DB device_count mismatch: expected=$fp_expected actual=$fp_actual" >&2; exit 1; }
}

validate_icon_assets() {
  list="$tmpdir/icon-assets.txt"
  missing="$tmpdir/icon-assets-missing.txt"
  invalid="$tmpdir/icon-assets-invalid.txt"
  checked=0

  sqlite3 "$db" \
    "SELECT icon_file FROM icon_asset WHERE COALESCE(icon_file,'')<>'' ORDER BY icon_file;" \
    > "$list"
  : > "$missing"
  : > "$invalid"
  while IFS= read -r icon_file; do
    [ -n "$icon_file" ] || continue
    runtime_name="$icon_file"
    case "$runtime_name" in icons/*) runtime_name="${runtime_name#icons/}" ;; esac
    [ "$runtime_name" = "tencent-docs.svg" ] && runtime_name="tencent.svg"
    case "$runtime_name" in
      ""|*..*|*/*)
        printf '%s\n' "$icon_file" >> "$invalid"
        continue
        ;;
    esac
    checked=$((checked + 1))
    if [ ! -f "$logos/$runtime_name" ] || [ -L "$logos/$runtime_name" ]; then
      printf '%s\n' "$icon_file" >> "$missing"
    fi
  done < "$list"

  if [ "$checked" -eq 0 ]; then
    echo "icon asset validation failed: no icon_asset rows with icon_file" >&2
    return 1
  fi
  if [ -s "$invalid" ] || [ -s "$missing" ]; then
    if [ -s "$invalid" ]; then
      echo "invalid icon_asset paths:" >&2
      sed 's/^/  - /' "$invalid" >&2
    fi
    if [ -s "$missing" ]; then
      echo "icon_asset files missing from --logo:" >&2
      sed 's/^/  - /' "$missing" >&2
    fi
    echo "signature package rejected: database and logo directory are not a complete artifact set" >&2
    return 1
  fi
}

integrity="$(sqlite3 "$db" "PRAGMA integrity_check;" 2>/dev/null || true)"
[ "$integrity" = "ok" ] || { echo "DB integrity check failed: $integrity" >&2; exit 1; }
validate_icon_assets
validate_fingerprint_db

apps="$(sql_scalar "SELECT COUNT(*) FROM app WHERE enabled=1;")"
dpi_rules="$(sql_scalar "SELECT COUNT(*) FROM dpi_rule WHERE enabled=1;")"
domain_groups="$(sql_scalar "SELECT COUNT(*) FROM domain_group;")"
domain_entries="$(sql_scalar "SELECT COUNT(*) FROM domain_entry;")"
device_vendors="$(sql_scalar "SELECT COUNT(*) FROM device_vendor;")"
device_types="$(sql_scalar "SELECT COUNT(*) FROM device_type;")"
device_fingerprint_rules="$(sql_scalar "SELECT COUNT(*) FROM device_fingerprint_rule WHERE enabled=1;")"
carrier_prefixes="$(sql_scalar "SELECT COUNT(*) FROM carrier_prefix WHERE enabled=1;")"
geoip_countries="$(sql_scalar "SELECT COUNT(*) FROM geoip_country WHERE enabled=1;")"
geoip_country_prefixes="$(sql_scalar "SELECT COUNT(*) FROM geoip_country_prefix WHERE enabled=1;")"
reputation_ip_entries="$(sql_scalar "SELECT COUNT(*) FROM reputation_ip_entry WHERE enabled=1;")"
reputation_domain_entries="$(sql_scalar "SELECT COUNT(*) FROM reputation_domain_entry WHERE enabled=1;")"
reputation_url_entries="$(sql_scalar "SELECT COUNT(*) FROM reputation_url_entry WHERE enabled=1;")"
content_categories="$(sql_scalar "SELECT COUNT(*) FROM content_category WHERE enabled=1;")"
content_domain_entries="$(sql_scalar "SELECT COUNT(*) FROM content_domain_entry WHERE enabled=1;")"
app_icon_mappings="$(sql_scalar "SELECT COUNT(*) FROM app_icon;")"
icon_assets="$(sql_scalar "SELECT COUNT(*) FROM icon_asset;")"
db_sha256="$(sha256_file "$db")"
logo_files="$(find "$logos" -type f | wc -l | tr -d ' ')"

cp "$db" "$tmpdir/dreamingwrt_signatures.db"
mkdir -p "$tmpdir/logo"
(cd "$logos" && tar cf - .) | (cd "$tmpdir/logo" && tar xf -)
copy_dataset "$geoip" "$tmpdir/geoip"
copy_dataset "$reputation" "$tmpdir/reputation"
copy_dataset "$content" "$tmpdir/content"
if [ -n "$fingerprint" ]; then
  mkdir -p "$tmpdir/fingerprint"
  cp "$fingerprint" "$tmpdir/fingerprint/fingerprint.db"
fi
copy_dataset "$ips" "$tmpdir/ips"
copy_dataset "$device_icons" "$tmpdir/device_icon"

dataset_count=2
[ -n "$geoip" ] && dataset_count=$((dataset_count + 1))
[ -n "$reputation" ] && dataset_count=$((dataset_count + 1))
[ -n "$content" ] && dataset_count=$((dataset_count + 1))
[ -n "$fingerprint" ] && dataset_count=$((dataset_count + 1))
[ -n "$ips" ] && dataset_count=$((dataset_count + 1))
[ -n "$device_icons" ] && dataset_count=$((dataset_count + 1))

conf_file="$tmpdir/signature-update.conf"
if [ -n "$conf" ]; then
  [ -f "$conf" ] || { echo "conf not found: $conf" >&2; exit 1; }
  cp "$conf" "$conf_file"
else
  if [ "$format" = "v2" ]; then
    cat > "$conf_file" <<EOF
format=signature-update-$format
version=$pkg_version
build_epoch=$build_epoch
build_date=$build_date
source_db=dreamingwrt_signatures.db
db_sha256=$db_sha256
manifest=manifest.json
datasets=$dataset_count
apps=$apps
dpi_rules=$dpi_rules
domain_groups=$domain_groups
domain_entries=$domain_entries
device_vendors=$device_vendors
device_types=$device_types
device_fingerprint_rules=$device_fingerprint_rules
carrier_prefixes=$carrier_prefixes
geoip_countries=$geoip_countries
geoip_country_prefixes=$geoip_country_prefixes
reputation_ip_entries=$reputation_ip_entries
reputation_domain_entries=$reputation_domain_entries
reputation_url_entries=$reputation_url_entries
content_categories=$content_categories
content_domain_entries=$content_domain_entries
app_icon_mappings=$app_icon_mappings
icon_assets=$icon_assets
logo_files=$logo_files
EOF
  else
    cat > "$conf_file" <<EOF
format=signature-update-v1
version=$pkg_version
build_epoch=$build_epoch
build_date=$build_date
source_db=dreamingwrt_signatures.db
db_sha256=$db_sha256
apps=$apps
dpi_rules=$dpi_rules
domain_groups=$domain_groups
domain_entries=$domain_entries
device_vendors=$device_vendors
device_types=$device_types
device_fingerprint_rules=$device_fingerprint_rules
carrier_prefixes=$carrier_prefixes
geoip_countries=$geoip_countries
geoip_country_prefixes=$geoip_country_prefixes
reputation_ip_entries=$reputation_ip_entries
reputation_domain_entries=$reputation_domain_entries
reputation_url_entries=$reputation_url_entries
content_categories=$content_categories
content_domain_entries=$content_domain_entries
app_icon_mappings=$app_icon_mappings
icon_assets=$icon_assets
logo_files=$logo_files
EOF
  fi
fi

if [ "$format" = "v2" ]; then
  manifest="$tmpdir/manifest.json"
  cat > "$manifest" <<EOF
{
  "format": "signature-update-v2",
  "version": "$(json_escape "$pkg_version")",
  "build_epoch": $build_epoch,
  "build_date": "$(json_escape "$build_date")",
  "datasets": [
EOF
  append_dataset_json "$manifest" "signature_db" "dreamingwrt_signatures.db" "$db" 0
  append_dataset_json "$manifest" "logo" "logo/" "$tmpdir/logo" 1
  [ -n "$geoip" ] && append_dataset_json "$manifest" "geoip" "$(dataset_manifest_path geoip "$geoip")" "$(dataset_stage_path geoip "$geoip")" 1
  [ -n "$reputation" ] && append_dataset_json "$manifest" "reputation" "$(dataset_manifest_path reputation "$reputation")" "$(dataset_stage_path reputation "$reputation")" 1
  [ -n "$content" ] && append_dataset_json "$manifest" "content" "$(dataset_manifest_path content "$content")" "$(dataset_stage_path content "$content")" 1
  [ -n "$fingerprint" ] && append_dataset_json "$manifest" "fingerprint" "fingerprint/fingerprint.db" "$tmpdir/fingerprint/fingerprint.db" 1
  [ -n "$ips" ] && append_dataset_json "$manifest" "ips" "$(dataset_manifest_path ips "$ips")" "$(dataset_stage_path ips "$ips")" 1
  [ -n "$device_icons" ] && append_dataset_json "$manifest" "device_icon" "$(dataset_manifest_path device_icon "$device_icons")" "$(dataset_stage_path device_icon "$device_icons")" 1
  cat >> "$manifest" <<EOF

  ],
  "counts": {
    "apps": $apps,
    "dpi_rules": $dpi_rules,
    "domain_groups": $domain_groups,
    "domain_entries": $domain_entries,
    "device_vendors": $device_vendors,
    "device_types": $device_types,
    "device_fingerprint_rules": $device_fingerprint_rules,
    "carrier_prefixes": $carrier_prefixes,
    "geoip_countries": $geoip_countries,
    "geoip_country_prefixes": $geoip_country_prefixes,
    "reputation_ip_entries": $reputation_ip_entries,
    "reputation_domain_entries": $reputation_domain_entries,
    "reputation_url_entries": $reputation_url_entries,
    "content_categories": $content_categories,
    "content_domain_entries": $content_domain_entries,
    "app_icon_mappings": $app_icon_mappings,
    "icon_assets": $icon_assets,
    "logo_files": $logo_files
  },
  "reload_plan": [
    "dreamingwrt-core.signature.reload",
    "dreamingwrt-flowd.signature.reload",
    "dreamingwrt-routed.sets.reload"
  ]
}
EOF
fi

mkdir -p "$(dirname "$out")"
if [ "$format" = "v2" ]; then
  entries="signature-update.conf manifest.json dreamingwrt_signatures.db logo"
  [ -e "$tmpdir/geoip" ] && entries="$entries geoip"
  [ -e "$tmpdir/reputation" ] && entries="$entries reputation"
  [ -e "$tmpdir/content" ] && entries="$entries content"
  [ -e "$tmpdir/fingerprint" ] && entries="$entries fingerprint"
  [ -e "$tmpdir/ips" ] && entries="$entries ips"
  [ -e "$tmpdir/device_icon" ] && entries="$entries device_icon"
  # shellcheck disable=SC2086
  (cd "$tmpdir" && tar czf "$out" $entries)
else
  (cd "$tmpdir" && tar czf "$out" signature-update.conf dreamingwrt_signatures.db logo)
fi

printf 'Created %s\n' "$out"
printf 'format=%s datasets=%s apps=%s dpi_rules=%s domain_entries=%s app_icon_mappings=%s icon_assets=%s logo_files=%s\n' "$format" "$dataset_count" "$apps" "$dpi_rules" "$domain_entries" "$app_icon_mappings" "$icon_assets" "$logo_files"
