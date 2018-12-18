//
//  ota_https_client.c
//  esp32-ota-https
//
//  Updating the firmware over the air.
//
//  This module provides functions to execute HTTPS requests on an
//  existing TLS TCP connection.
//
//  Created by Andreas Schweizer on 19.01.2017.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"

#include "ota_tls.h"
#include "ota_https_client.h"


#define TAG "ota_https_cli"


// This object lives on the heap and is passed around in callbacks etc.
// It contains the state for a single HTTP request.
typedef struct ota_http_request_context_ {
    
    uint32_t request_id;
    
    ota_http_request_t *request;
    
    // Number of bytes used in the buffer.
    size_t response_buffer_count;
    
    // Total number of message body bytes that have been received.
    size_t response_body_total_count;
    
    size_t content_length;
    int is_processing_headers;
    
    char *tls_request_buffer;
    size_t tls_request_buffer_size;
    
    char *tls_response_buffer;
    size_t tls_response_buffer_size;
    
} ota_http_request_context_t;


static const char *ota_http_get_request_format_string = "GET %s HTTP/1.1\r\nHost: %s\r\n\
User-Agent: ota-https-esp32/1.0\r\n\r\n";
static uint32_t request_nr;


static int ota_https_tls_callback(struct ota_tls_context_ *context, struct ota_tls_request_ *request, int index, size_t len);

static ota_http_err_t ota_https_validate_request(ota_http_request_t *httpRequest);
static ota_http_err_t ota_https_create_context_for_request(ota_http_request_context_t **httpContext, ota_http_request_t *httpRequest);
static void ota_https_destroy_context(ota_http_request_context_t *httpContext);


// Send the specified HTTP request on the (connected and verified) tlsContext.
ota_http_err_t ota_https_send_request(struct ota_tls_context_ *tlsContext, ota_http_request_t *httpRequest)
{
    // Validate the input.
    
    if (!tlsContext) {
        ESP_LOGE(TAG, "ota_https_send_request: tlsContext missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    ota_http_err_t result = ota_https_validate_request(httpRequest);
    if (result != OTA_HTTP_SUCCESS) {
        return result;
    }


    // Create the HTTP context.

    // This object lives on the heap and is passed around in callbacks etc.
    // It contains the state for a single HTTP request.

    ota_http_request_context_t *httpContext;
    result = ota_https_create_context_for_request(&httpContext, httpRequest);
    if (result != OTA_HTTP_SUCCESS) {
        return result;
    }


    // Create the TLS context.
    
    ota_tls_request_t tlsRequest;
    
    tlsRequest.custom_data = httpContext;

    tlsRequest.request_len = httpContext->tls_request_buffer_size;
    tlsRequest.request_buffer = httpContext->tls_request_buffer;
    
    tlsRequest.response_buffer_size = httpContext->tls_response_buffer_size;
    tlsRequest.response_buffer = httpContext->tls_response_buffer;
    
    tlsRequest.response_callback = &ota_https_tls_callback;

    
    // Submit the TLS request.
    
    int tlsResult = ota_tls_send_request(tlsContext, &tlsRequest);


    // Cleanup.

    if (tlsResult == 0) {
        ESP_LOGD(TAG, "ota_https_send_request: successfully completed HTTP request %d to the server: %s",
                 httpContext->request_id, tlsRequest.request_buffer);

        ota_https_destroy_context(httpContext);
        return OTA_HTTP_SUCCESS;
    }
    
    ESP_LOGE(TAG, "ota_https_send_request: failed to complete HTTP request %d (ota_tls_send_request returned %d)",
             httpContext->request_id, tlsResult);

    ota_https_destroy_context(httpContext);
    return OTA_HTTP_ERR_SEND_FAILED;
}

static int ota_https_tls_callback(struct ota_tls_context_ *context, struct ota_tls_request_ *request, int index, size_t len)
{
    ota_http_request_context_t *httpContext = (ota_http_request_context_t*)request->custom_data;
    ESP_LOGD(TAG, "ota_https_tls_callback: request_id = %d", httpContext->request_id);

    ota_http_request_t *httpRequest = httpContext->request;

    // First packet resets the state
    if (index == 0) {
        httpContext->response_buffer_count = 0;
        httpContext->response_body_total_count = 0;
        httpContext->content_length = 0;
        httpContext->is_processing_headers = 1;
        bzero(httpRequest->response_buffer, httpRequest->response_buffer_len);
    }
    
    // If the received data would overflow our buffer, we simply stop processing the packet and drop it.
    if (httpContext->response_buffer_count + len > httpRequest->response_buffer_len) {
        ESP_LOGE(TAG, "ota_https_tls_callback: packet buffer overflow (%d bytes), dropping the packet.", httpRequest->response_buffer_len + len);
        httpRequest->error_callback(httpRequest, OTA_HTTP_ERR_BUFFER_TOO_SMALL, 0);
        return 0; // Stop processing the packet.
    }
    
    // Accumulate the received data from the TLS buffer in the HTTP buffer.
    memcpy(&httpRequest->response_buffer[httpContext->response_buffer_count], request->response_buffer, len);
    httpContext->response_buffer_count += len;
    httpContext->response_body_total_count += len;
    //httpRequest->response_buffer[httpContext->response_buffer_count] = 0x00;
    ESP_LOGD(TAG, "ota_https_tls_callback: packet index=%d length=%d inHeaders=%d",
             index, httpContext->response_buffer_count, httpContext->is_processing_headers);
    
    // ---------- Headers processing ----------
    
    if (httpContext->is_processing_headers) {
        
        // Wait with processing until all headers have been completely received.
        char *endOfHeader = strstr(httpRequest->response_buffer, "\r\n\r\n");
        if (!endOfHeader) {
            ESP_LOGD(TAG, "ota_https_tls_callback: headers not yet complete, waiting for remaining header data.");
            return 1;
        }
        
        // --- All headers received. ---
        
        // TODO: use the headers callback!!!! handle missing Content-Length!!!
        
        // The last received packet may contain data that belongs to the message body.
        // Make sure we don't process the message body data as part of the headers processing.
        uint32_t nofHeaderBytes = endOfHeader - &httpRequest->response_buffer[0] + 4;
        *endOfHeader = 0x00;
        
        ESP_LOGD(TAG, "ota_https_tls_callback: HTTP headers (%d bytes) successfully received. %d bytes of message body data received.",
                 nofHeaderBytes, httpContext->response_buffer_count - nofHeaderBytes);
        
        // Check the HTTP status line.
        int httpVersionMajor = 0;
        int httpVersionMinor = 0;
        int httpStatusCode = 0;
        if (3 != sscanf(httpRequest->response_buffer, "HTTP/%d.%d %d ", &httpVersionMajor, &httpVersionMinor, &httpStatusCode)) {
            ESP_LOGE(TAG, "ota_https_tls_callback: invalid HTTP status line, dropping packet. '%s'", httpRequest->response_buffer);
            httpRequest->error_callback(httpRequest, OTA_HTTP_ERR_INVALID_STATUS_LINE, 0);
            return 0;
        }
        ESP_LOGD(TAG, "ota_https_tls_callback: HTTP status line: version = %d.%d, status code = %d", httpVersionMajor, httpVersionMinor, httpStatusCode);
        if (httpVersionMajor != 1) {
            ESP_LOGE(TAG, "ota_https_tls_callback: HTTP version not supported, dropping packet. '%s'", httpRequest->response_buffer);
            httpRequest->error_callback(httpRequest, OTA_HTTP_ERR_VERSION_NOT_SUPPORTED, 0);
            return 0;
        }
        if (httpStatusCode != 200) {
            ESP_LOGE(TAG, "ota_https_tls_callback: non-200 HTTP status code received, dropping packet. '%s'", httpRequest->response_buffer);
            httpRequest->error_callback(httpRequest, OTA_HTTP_ERR_NON_200_STATUS_CODE, httpStatusCode);
            return 0;
        }
        
        // We're mainly interested in the content length.
        // The server should either send the Content-Length header or should close the connection at the end.
        int contentLength = 0;
        if (!ota_http_parse_key_value_int(httpRequest->response_buffer, "Content-Length:", &contentLength)) {
            ESP_LOGD(TAG, "Content-Length: %d", contentLength);
            httpContext->content_length = contentLength;
        } else {
            ESP_LOGW(TAG, "Content length header missing, dropping the packet. '%s'", httpRequest->response_buffer);
            // TODO error callback??
            return 0;
        }
        
        // -----------------------------------------
        
        // If the last received packet also contains message body data, we copy it to the beginning of the buffer.
        httpContext->response_buffer_count -= nofHeaderBytes;
        httpContext->response_body_total_count = httpContext->response_buffer_count; // Start counting bytes in the message body.
        if (httpContext->response_buffer_count > 0) {
            ESP_LOGD(TAG, "ota_https_tls_callback: last packet contains data of the message body; copying to the beginning, new length = %d", httpContext->response_buffer_count);
            memcpy(httpRequest->response_buffer, &request->response_buffer[nofHeaderBytes], httpContext->response_buffer_count);
        }
        httpRequest->response_buffer[httpContext->response_buffer_count] = 0x00;
        
        // Continue with message body processing.
        httpContext->is_processing_headers = 0;
    }
    
    if (httpContext->is_processing_headers) {
        return 1;
    }
    
    // ---------- Message body processing ----------
    
    if (httpRequest->response_mode == OTA_HTTP_WAIT_FOR_COMPLETE_BODY) {
    
        // Wait with processing until the message body has been completely received.
        if (httpContext->response_buffer_count < httpContext->content_length) {
            ESP_LOGD(TAG, "ota_https_tls_callback: message body is not yet complete, waiting for remaining data (total = %d, received = %d).",
                     httpContext->content_length, httpContext->response_buffer_count);
            return 1;
        }
    
        ESP_LOGD(TAG, "ota_https_tls_callback: message body has been completely received, starting processing");
        httpRequest->body_callback(httpRequest, httpContext->response_buffer_count);

        return 0;
    }
    
    // Provide partial message body fragments to the callback function.
    
    if (httpContext->response_buffer_count > 0) {
        ESP_LOGD(TAG, "ota_https_tls_callback: message body fragment received (%d bytes, total %d of %d bytes), forwarding to callback",
                 httpContext->response_buffer_count, httpContext->response_body_total_count, httpContext->content_length);
        
        ota_http_continue_receiving_t cr = httpRequest->body_callback(httpRequest, httpContext->response_buffer_count);
    
        // The callback handler doesn't want to receive more packets.
        if (cr != OTA_HTTP_CONTINUE_RECEIVING) {
            return 0;
        }
        
        // Don't read after the end.
        if (httpContext->response_body_total_count >= httpContext->content_length) {
            // Invoke the callback with length 0 to indicate that all data has been received.
            httpRequest->body_callback(httpRequest, 0);
            return 0;
        }
    
        // The next fragment should start at the beginning of the packet.
        httpContext->response_buffer_count = 0;
    }
    
    return 1;
}

int ota_http_parse_key_value_int(const char *buffer, const char *key, int *value)
{
    const char *locKey = strstr(buffer, key);
    
    if (!locKey) {
        return -1;
    }
    
    *value = atoi(&locKey[strlen(key)]);
    return 0;
}

int ota_http_parse_key_value_string(const char *buffer, const char *key, char *str, int strLen)
{
    const char *locKey = strstr(buffer, key);
    
    if (!locKey) {
        return -1;
    }
    
    // Copy max. strLen characters up to end-of-string or newline.
    
    const char *src = &locKey[strlen(key)];
    for (int i = 0; i < strLen - 1; i++) {
        if (*src == 0x00 || *src == '\r' || *src == '\n') {
            break;
        }
        *str++ = *src++;
    }
    *str++ = 0x00;
    
    return 0;
}

// Converts a single hex character (0-9,A-F) to an integer (0-15)
static int ota_http_hex_char_to_int(char charVal, uint8_t* pInt)
{
    int result = 1;

    if ( ( '0' <= charVal ) && ( charVal <= '9' ) ) {
        *pInt = charVal - '0';
    } else if ( ( 'A' <= charVal ) && ( charVal <= 'F' ) ) {
        *pInt = 10u + charVal - 'A';
    } else if( ( 'a' <= charVal ) && ( charVal <= 'f' ) ) {
        *pInt = 10u + charVal - 'a';
    } else if( ( '\r' == charVal ) || ( '\n' == charVal ) || ( '\0' == charVal) ) {
        result = 0;
    } else {
        result = -1;
    }

    return result;
}

int ota_http_parse_key_value_hex_byte_array(const char *buffer, const char *key, uint8_t *byteArray, int arrayLen)
{
    int ret = 0;
    uint8_t val, tempVal;

    const char *locKey = strstr(buffer, key);
    
    if (!locKey) {
        return -1;
    }

    const char *src = &locKey[strlen(key)];

    if(arrayLen > 2*strlen(src)) {
        // not enough chars, more is okay
        return -1;
    }

    val = 0; // make the compiler happy about val being used uninitialized
    for(int nibbleCnt=0; nibbleCnt < (arrayLen*2); nibbleCnt++) {
        int byteCnt = nibbleCnt / 2;

        ret = ota_http_hex_char_to_int(src[nibbleCnt], &tempVal);
        //ESP_LOGD(TAG, "ret = %d, tempVal = %d", ret, tempVal);

        if(ret == -1) break;
        if(ret == 0) {
            // end reached before enough chars read
            ret = -1;
            break;
        }

        if(ret == 1) {
            if(0 == (nibbleCnt % 2)) {
                val = tempVal;
            } else {
                val = val << 4;
                val += tempVal;
                byteArray[byteCnt] = val;
            }
        } else {
            // unknown return code
            ret = -1;
            break;
        }

        ret = 0;
    }

    return ret;
}

static ota_http_err_t ota_https_validate_request(ota_http_request_t *httpRequest)
{
    if (!httpRequest) {
        ESP_LOGE(TAG, "ota_https_validate_request: httpRequest missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    if (!httpRequest->host) {
        ESP_LOGE(TAG, "ota_https_validate_request: host name missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    if (!httpRequest->path || !httpRequest->path[0]) {
        ESP_LOGE(TAG, "ota_https_send_request: resource path missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    if (!httpRequest->response_buffer) {
        ESP_LOGE(TAG, "ota_https_send_request: no response buffer provided");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    if (!httpRequest->error_callback) {
        ESP_LOGE(TAG, "ota_https_send_request: error callback missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    if (!httpRequest->body_callback) {
        ESP_LOGE(TAG, "ota_https_send_request: body callback missing");
        return OTA_HTTP_ERR_INVALID_ARGS;
    }
    
    // (This is only a partial implementation so far ;-)
    
    if (httpRequest->verb != OTA_HTTP_GET) {
        ESP_LOGE(TAG, "ota_https_send_request: only GET is currently supported");
        return OTA_HTTP_ERR_NOT_IMPLEMENTED;
    }
    
    return OTA_HTTP_SUCCESS;
}

static ota_http_err_t ota_https_create_context_for_request(ota_http_request_context_t **httpContext, ota_http_request_t *httpRequest)
{
    // Create the HTTP context object.
    
    ota_http_request_context_t *ctx = malloc(sizeof(ota_http_request_context_t));
    *httpContext = ctx;
    
    ctx->request_id = ++request_nr;
    
    ESP_LOGD(TAG, "ota_https_create_context_for_request: request_id = %d", ctx->request_id);

    if (!ctx) {
        ESP_LOGE(TAG, "ota_https_create_context_for_request: failed to allocate HTTP context object");
        return OTA_HTTP_ERR_OUT_OF_MEMORY;
    }
    
    bzero(ctx, sizeof(ota_http_request_context_t));
    
    // Link the context to the HTTP request for which we create it.
    
    ctx->request = httpRequest;
    
    // Create the TLS request string.
    
    size_t requestLen = strlen(ota_http_get_request_format_string) - 4 // strlen("%s%s") = 4
        + strlen(httpRequest->host) + strlen(httpRequest->path);
    
    ctx->tls_request_buffer_size = requestLen;
    ctx->tls_request_buffer = malloc((ctx->tls_request_buffer_size + 1) * sizeof(char));

    if (!ctx->tls_request_buffer) {
        ESP_LOGE(TAG, "ota_https_create_context_for_request: failed to allocate TLS request buffer");
        ota_https_destroy_context(ctx);
        *httpContext = NULL;
        return OTA_HTTP_ERR_OUT_OF_MEMORY;
    }
    
    sprintf(ctx->tls_request_buffer, ota_http_get_request_format_string, httpRequest->path, httpRequest->host);
    ESP_LOGD(TAG, "ota_https_create_context_for_request: request string = '%s'", ctx->tls_request_buffer);
    
    // Create a buffer for TLS responses.
    
    ctx->tls_response_buffer_size = 4096;
    ctx->tls_response_buffer = malloc(ctx->tls_response_buffer_size * sizeof(char));
    if (!ctx->tls_response_buffer) {
        ESP_LOGE(TAG, "ota_https_create_context_for_request: failed to allocate TLS response buffer");
        ota_https_destroy_context(ctx);
        *httpContext = NULL;
        return OTA_HTTP_ERR_OUT_OF_MEMORY;
    }
    
    return OTA_HTTP_SUCCESS;
}

static void ota_https_destroy_context(ota_http_request_context_t *httpContext)
{
    if (!httpContext) {
        return;
    }
    
    ESP_LOGD(TAG, "ota_https_destroy_context: request_id = %d", httpContext->request_id);
    
    free(httpContext->tls_request_buffer);
    free(httpContext->tls_response_buffer);
    free(httpContext);
}

