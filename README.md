# ota-https-esp32

This is a modified ESP-IDF 'component' version of the ESP32 Secure over-the-air update demo located at https://github.com/classycodeoss/esp32-ota-https

More information on the original code is available on the blog: https://blog.classycode.com/secure-over-the-air-updates-for-esp32-ec25ae00db43

## Changes

* Renamed wifi_tls module to ota_tls
* Renamed https_client to ota_https_client
* Added md5sum to compare download vs meta data info
* Use (git-)version string instead of version number
* Implemented a more generic way of handling and copying certificates (i.e. don't rely on them being strings).
  This allows loading them via ESP-IDF's (ascii/binary) file inclusion mechanism.
* Increased fwup_wifi_task stack size to 8192 to handle RSA 4096 bit certs
* Implemented wifi event handling via callback to be better suitable as a component
