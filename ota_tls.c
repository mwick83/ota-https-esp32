//
//  ota_tls.c
//  esp32-ota-https
//
//  Updating the firmware over the air.
//
//  This module provides TLS connections with certificate pinning and
//  callback-based request/response functionality.
//
//  Created by Andreas Schweizer on 11.01.2017.
//  Copyright © 2017 Classy Code GmbH
//
//  Copyright (c) 2018 Manuel Wick
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this 
// software and associated documentation files (the "Software"), to deal in the Software 
// without restriction, including without limitation the rights to use, copy, modify, 
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
// permit persons to whom the Software is furnished to do so, subject to the following 
// conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies 
// or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_event_loop.h"
#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/esp_debug.h"

#include "ota_tls.h"


#define TAG "ota_tls"


// Internal state for a single TLS context (single connection).
typedef struct ota_tls_context_ {
    
    // We transparently clean up the context in case of errors.
    // This flag indicates if the context is ready to use.
    bool is_valid;
    
    char *server_host_name;
    char *server_root_ca_public_key_pem;
    char *peer_public_key_pem;
    int server_port;
    
    // mbedTLS SSL context.
    mbedtls_ssl_context ssl;

    // mbedTLS SSL configuration.
    mbedtls_ssl_config ssl_conf;
    
    // Counter mode deterministic random byte generator.
    mbedtls_ctr_drbg_context ctr_drbg;
    
    // Context for the generic entropy collector.
    mbedtls_entropy_context entropy;
    
    // Container for the X.509 Root CA certificate.
    mbedtls_x509_crt root_ca_cert;
    
    // Container for the X.509 Peer certificate.
    mbedtls_x509_crt peer_cert;
    
    // Server file descriptor.
    mbedtls_net_context server_fd;

} ota_tls_context_t;


static int ota_tls_init_context(ota_tls_context_t *ctx);
static int ota_tls_reset_context(ota_tls_context_t *ctx);
static int ota_tls_handshake(ota_tls_context_t *ctx);
static int ota_tls_cert_pinning(ota_tls_context_t *ctx);
static void ota_tls_print_mbedtls_error(char *message, int code);
static void ota_tls_dump_hex_buffer(char *buf, int len);


ota_tls_context_t *ota_tls_create_context(ota_tls_init_struct_t *params)
{
    // Validate the input parameters.
    
    if (!params->server_port || !params->server_host_name
        || !params->server_root_ca_public_key_pem
        || !params->peer_public_key_pem)
    {
        ESP_LOGE(TAG, "ota_tls_create_context: parameter missing");
        return NULL;
    }

    int server_port = atoi(params->server_port);
    if (server_port < 1 || server_port > 65535) {
        ESP_LOGE(TAG, "ota_tls_create_context: invalid server port");
        return NULL;
    }

    // Allocate the context structure.

    ota_tls_context_t *ctx = malloc(sizeof(ota_tls_context_t));
    if (!ctx) {
        ESP_LOGE(TAG, "ota_tls_create_context: out of memory");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(ota_tls_context_t));
    
    // Configure the context structure.
    
    ctx->server_host_name = malloc(strlen(params->server_host_name) + 1);
    if (!ctx->server_host_name) {
        ESP_LOGE(TAG, "ota_tls_create_context: out of memory");
        free(ctx);
        return NULL;
    }
    strcpy(ctx->server_host_name, params->server_host_name);
    
    ctx->server_root_ca_public_key_pem = malloc(params->server_root_ca_public_key_pem_len + 1);
    if (!ctx->server_root_ca_public_key_pem) {
        ESP_LOGE(TAG, "ota_tls_create_context: out of memory");
        free(ctx->server_host_name);
        free(ctx);
        return NULL;
    }
    memcpy(ctx->server_root_ca_public_key_pem, params->server_root_ca_public_key_pem, params->server_root_ca_public_key_pem_len);
    ctx->server_root_ca_public_key_pem[params->server_root_ca_public_key_pem_len] = '\0';

    ctx->peer_public_key_pem = malloc(params->peer_public_key_pem_len + 1);
    if (!ctx->peer_public_key_pem) {
        ESP_LOGE(TAG, "ota_tls_create_context: out of memory");
        free(ctx->server_root_ca_public_key_pem);
        free(ctx->server_host_name);
        free(ctx);
        return NULL;
    }
    memcpy(ctx->peer_public_key_pem, params->peer_public_key_pem, params->peer_public_key_pem_len);
    ctx->peer_public_key_pem[params->peer_public_key_pem_len] = '\0';

    ctx->is_valid = false;
    ctx->server_port = server_port;

    ESP_LOGD(TAG, "ota_tls_create_context: context created for server: %s", ctx->server_host_name);
    return ctx;
}

void ota_tls_free_context(ota_tls_context_t *ctx)
{
    free(ctx->peer_public_key_pem);
    free(ctx->server_root_ca_public_key_pem);
    free(ctx->server_host_name);
    memset(ctx, 0, sizeof(ota_tls_context_t));
    
    free(ctx);
}

int ota_tls_connect(ota_tls_context_t *ctx)
{
    // Make sure the context is valid.
    int init_context_result = ota_tls_init_context(ctx);
    if (init_context_result) {
        ESP_LOGE(TAG, "ota_tls_connect: failed to initialise the module context");
        return init_context_result;
    }
    
    
    // Connect to the server
    
    mbedtls_net_init(&ctx->server_fd);
    
    char portBuf[16];
    sprintf(portBuf, "%d", ctx->server_port);
    
    int net_connect_result = mbedtls_net_connect(&ctx->server_fd, ctx->server_host_name, portBuf, MBEDTLS_NET_PROTO_TCP);
    if (net_connect_result != 0) {
        ota_tls_print_mbedtls_error("ota_tls_connect: failed to connect to server", net_connect_result);
        ota_tls_reset_context(ctx);
        return -1;
    }
    
    ESP_LOGD(TAG, "ota_tls_connect: connected to server '%s', fd = %d", ctx->server_host_name, ctx->server_fd.fd);

    // WORKAROUND
    // http://www.esp32.com/viewtopic.php?f=14&t=1007
    vTaskDelay(200 / portTICK_PERIOD_MS);


    // Define input and output functions for sending and receiving network data.

    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    
    // Perform SSL/TLS handshake.
    
    ESP_LOGD(TAG, "ota_tls_connect: starting handshake");
    int handshakeResult = ota_tls_handshake(ctx);
    if (handshakeResult != 0) {
        ESP_LOGE(TAG, "ota_tls_connect: handshake failed");
        ota_tls_disconnect(ctx);
        return -1;
    }
    
    // Verify Root CA Certificate
    
    ESP_LOGD(TAG, "ota_tls_connect: verifying root CA certificate");
    uint32_t caCertVerificationResult = mbedtls_ssl_get_verify_result(&ctx->ssl);
    if (caCertVerificationResult != 0) {
        ota_tls_print_mbedtls_error("ota_tls_connect: mbedtls_ssl_get_verify_result", caCertVerificationResult);

        static char caCertInfoBuf[512];
        bzero(caCertInfoBuf, sizeof(caCertInfoBuf));
        mbedtls_x509_crt_verify_info(caCertInfoBuf, sizeof(caCertInfoBuf), "verification info: ", caCertVerificationResult);
        ESP_LOGE(TAG, "ota_tls_connect: %s", caCertInfoBuf);

        ota_tls_disconnect(ctx);
        return -1;
    }
    
    // Verify Peer Certificate (Certificate Pinning)
    
    ESP_LOGD(TAG, "ota_tls_connect: certificate pinning");
    int pinningResult = ota_tls_cert_pinning(ctx);
    if (pinningResult != 0) {
        ESP_LOGE(TAG, "ota_tls_connect: certificate pinning failed");
        ota_tls_disconnect(ctx);
        return -1;
    }
    
    ESP_LOGI(TAG, "Started valid TLS/SSL session with server '%s'.", ctx->server_host_name);
    ESP_LOGD(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ctx->ssl));
    return 0;
}

void ota_tls_disconnect(ota_tls_context_t *ctx)
{
    mbedtls_net_free(&ctx->server_fd);
    ESP_LOGI(TAG, "Ended TLS/SSL session with server '%s'.", ctx->server_host_name);

    ota_tls_reset_context(ctx);
}

int ota_tls_send_request(ota_tls_context_t *ctx, ota_tls_request_t *request)
{
    size_t lenRemaining = request->request_len;
    char *p = request->request_buffer;
    
    ESP_LOGD(TAG, "ota_tls_send_request: '%s'", request->request_buffer);
    
    while (lenRemaining > 0) {
        int ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char *)p, lenRemaining);
        if (ret > 0) {
            lenRemaining -= ret;
            p += ret;
            ESP_LOGD(TAG, "ota_tls_send_request: partial write: %d bytes written, %d bytes remaining", ret, lenRemaining);
            continue;
        }
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGD(TAG, "ota_tls_send_request: write: MBEDTLS_ERR_SSL_WANT_READ");
            continue;
        }
        
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGD(TAG, "ota_tls_send_request: write: MBEDTLS_ERR_SSL_WANT_WRITE");
            continue;
        }
        
        // Context is invalid, need to disconnect.
        ota_tls_print_mbedtls_error("ota_tls_send_request: write: error, disconnecting, context is invalid", ret);
        ota_tls_disconnect(ctx);
        return -1;
    }
    
    // INV: Request successfully written.
    // Read the response.

    int callbackIndex = 0;
    while (1) {
        int ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char *)request->response_buffer, request->response_buffer_size);
        
        if (ret == 0) {
            ESP_LOGD(TAG, "ota_tls_send_request: EOF");
            // EOF
            ota_tls_disconnect(ctx);
            return 0;
        }
        
        if (ret > 0) {
            // Partial read
            ESP_LOGD(TAG, "ota_tls_send_request: partial read: %d bytes read", ret);
            int continueReading = request->response_callback(ctx, request, callbackIndex, ret);
            if (!continueReading) {
                ota_tls_disconnect(ctx);
                return 0;
            }
            callbackIndex++;
            continue;
        }
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGD(TAG, "ota_tls_send_request: read: MBEDTLS_ERR_SSL_WANT_READ");
            continue;
        }
        
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGD(TAG, "ota_tls_send_request: read: MBEDTLS_ERR_SSL_WANT_WRITE");
            continue;
        }
        
        // Context is invalid, need to disconnect.
        ota_tls_print_mbedtls_error("ota_tls_send_request: read: error, disconnecting, context is invalid", ret);
        ota_tls_disconnect(ctx);
        return -1;
    }
    
    return 0;
}


static int ota_tls_init_context(ota_tls_context_t *ctx)
{
    if (ctx->is_valid) {
        return 0;
    }
    
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_x509_crt_init(&ctx->root_ca_cert);
    mbedtls_x509_crt_init(&ctx->peer_cert);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_ssl_config_init(&ctx->ssl_conf);
    mbedtls_entropy_init(&ctx->entropy);
    
    
    // Random number generator.
    int drbg_seed_result = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy, NULL, 0);
    if (drbg_seed_result != 0) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_ctr_drbg_seed failed", drbg_seed_result);
        ota_tls_reset_context(ctx);
        return -1;
    }
    
    // Root CA certificate.
    size_t buf_len = strlen(ctx->server_root_ca_public_key_pem) + 1; // needs to include the trailing 0x00!
    int cert_parse_result = mbedtls_x509_crt_parse(&ctx->root_ca_cert, (const unsigned char *)ctx->server_root_ca_public_key_pem, buf_len);
    if (cert_parse_result != 0) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_x509_crt_parse failed for Root CA Cert", cert_parse_result);
        ota_tls_reset_context(ctx);
        return -1;
    }
    
    // Peer certificate (for certificate pinning).
    buf_len = strlen(ctx->peer_public_key_pem) + 1; // needs to include the trailing 0x00!
    cert_parse_result = mbedtls_x509_crt_parse(&ctx->peer_cert, (const unsigned char *)ctx->peer_public_key_pem, buf_len);
    if (cert_parse_result != 0) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_x509_crt_parse failed for Peer Cert", cert_parse_result);
        ota_tls_reset_context(ctx);
        return -1;
    }

    int ssl_set_hostname_result = mbedtls_ssl_set_hostname(&ctx->ssl, ctx->server_host_name);
    if(ssl_set_hostname_result) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_ssl_set_hostname failed", ssl_set_hostname_result);
        ota_tls_reset_context(ctx);
        return -1;
    }

    // SSL configuration shared between SSL context structures.
    int ssl_config_defaults_result =
        mbedtls_ssl_config_defaults(&ctx->ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if(ssl_config_defaults_result) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_ssl_config_defaults failed", ssl_config_defaults_result);
        ota_tls_reset_context(ctx);
        return -1;
    }

    mbedtls_ssl_conf_authmode(&ctx->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ctx->ssl_conf, &ctx->root_ca_cert, NULL);
    mbedtls_ssl_conf_rng(&ctx->ssl_conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);

    #ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&ctx->ssl_conf, 4);
    #endif

    // SSL Context
    int ssl_setup_result = mbedtls_ssl_setup(&ctx->ssl, &ctx->ssl_conf);
    if (ssl_setup_result) {
        ota_tls_print_mbedtls_error("ota_tls_init_context: mbedtls_ssl_setup failed", ssl_setup_result);
        ota_tls_reset_context(ctx);
        return -1;
    }
    
    ESP_LOGD(TAG, "ota_tls_init_context: context initialised for server: %s", ctx->server_host_name);
    ctx->is_valid = true;

    return 0;
}

static int ota_tls_reset_context(ota_tls_context_t *ctx)
{
    ctx->is_valid = false;
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ssl_config_free(&ctx->ssl_conf);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_x509_crt_free(&ctx->root_ca_cert);
    mbedtls_x509_crt_free(&ctx->peer_cert);
    mbedtls_ssl_free(&ctx->ssl);
    
    ESP_LOGD(TAG, "ota_tls_reset_context: context reset for server: %s", ctx->server_host_name);
    return 0;
}

static int ota_tls_handshake(ota_tls_context_t *ctx)
{
    while (1) {
        ESP_LOGD(TAG, "ota_tls_handshake: mbedtls_ssl_handshake");
        int handshakeResult = mbedtls_ssl_handshake(&ctx->ssl);
        ESP_LOGD(TAG, "ota_tls_handshake: mbedtls_ssl_handshake: %d", handshakeResult);
        if (handshakeResult == 0) {
            // Handshake completed.
            ESP_LOGD(TAG, "ota_tls_handshake: handshake completed successfully");
            break;
        }
        
        if (handshakeResult == MBEDTLS_ERR_SSL_WANT_READ
            || handshakeResult == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGD(TAG, "ota_tls_handshake: handshake continuing (%d)", handshakeResult);
            continue;
        }
        
        ota_tls_print_mbedtls_error("ota_tls_handshake: handshake failed", handshakeResult);
        return -1;
    }
    
    return 0;
}

// returns 0 on success, -1 on error
static int ota_tls_cert_pinning(ota_tls_context_t *ctx)
{
    // Get the peer certificate from the connection.
    
    const mbedtls_x509_crt *cert = mbedtls_ssl_get_peer_cert(&ctx->ssl);
    if (!cert) {
        ESP_LOGE(TAG, "ota_tls_cert_pinning: failed to get peer certificate");
        return -1;
    }
    
    
    // Allocate memory to store the actual and the expected public keys.
    
    //int bufSize = 512; // in practice, the length was 294 bytes
    int bufSize = 1024; // in practice, the length was 294 bytes
    uint8_t *certExpectedPubKey = calloc(bufSize, 1);
    uint8_t *certActualPubKey = calloc(bufSize, 1);
    if (!certExpectedPubKey || !certActualPubKey) {
        ESP_LOGE(TAG, "ota_tls_cert_pinning: failed to allocate memory for the public key");
        if (certExpectedPubKey) {
            free(certExpectedPubKey);
        }
        if (certActualPubKey) {
            free(certActualPubKey);
        }
        return -1;
    }
    
    
    // Extract the public keys from the certificates.
    
    // mbedTLS writes the data at the *end* of the buffer...!
    int lenExpected = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *) &(ctx->peer_cert.pk), certExpectedPubKey, bufSize);
    int lenActual = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *) &(cert->pk), certActualPubKey, bufSize);
    
    
    // Compare the expected to the actual public key.
    
    int result = -1; // assume failure
    if (lenExpected == lenActual) {
        if (!memcmp(certExpectedPubKey, certActualPubKey, lenActual)) {
            result = 0; // length and content matches
        }
    }

    // In case of a mismatch, we print the two public keys to simplify debugging.
    if (result) {
        ESP_LOGE(TAG, "ota_tls_cert_pinning: actual public key different from expected public key!\n");
        
        ESP_LOGE(TAG, "EXPECTED public key (%d bytes):", lenExpected);
        ota_tls_dump_hex_buffer((char*)&certExpectedPubKey[bufSize - lenExpected], lenExpected);
        
        ESP_LOGE(TAG, "ACTUAL   public key (%d bytes):", lenActual);
        ota_tls_dump_hex_buffer((char*)&certActualPubKey[bufSize - lenActual], lenActual);
    }
    
    free(certExpectedPubKey);
    free(certActualPubKey);
    
    return result;
}

static void ota_tls_print_mbedtls_error(char *message, int code)
{
    char errorDescBuf[256];
    mbedtls_strerror(code, errorDescBuf, sizeof(errorDescBuf) / sizeof(char));
    ESP_LOGE(TAG, "%s: %d %s", message, code, errorDescBuf);
}

static void ota_tls_dump_hex_buffer(char *buf, int len)
{
    char bufAscii[17];
    bufAscii[16] = 0x00;
    
    for (int i = 0; i < len; i++) {
        uint8_t c = buf[i];
        bufAscii[i % 16] = (c >= 32 && c < 127) ? (char)c : '.';
        printf("%02x ", (char)c);
        if ((i + 1) == len) {
            for (int j = 0; j < (15 - (i % 16)); j++) {
                printf("   ");
            }
        }
        if (i % 16 == 15 || (i + 1) == len) {
            printf("  %s\n", bufAscii);
            for (int j = 0; j < 16; j++) {
                bufAscii[j] = ' ';
            }
        }
    }
    printf("\n");
}

