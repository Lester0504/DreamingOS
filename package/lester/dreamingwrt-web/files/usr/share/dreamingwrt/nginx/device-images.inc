# Fingerprint images are fetched on demand and cached on DATA by webd.
# Keep the exact prefix ahead of LuCI's static/extension locations.
location ^~ /luci-static/dreamingwrt/fingerprint/images/ {
	include restrict_locally;
	proxy_http_version 1.1;
	proxy_set_header Host $http_host;
	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	proxy_set_header X-Forwarded-Proto $scheme;
	proxy_intercept_errors off;
	proxy_pass http://127.0.0.1:12518;
}
