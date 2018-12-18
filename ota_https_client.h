//
//  ota_ota_https_client.h
//  esp32-ota-https
//
//  Updating the firmware over the air.
//
//  This module provides functions to execute HTTPS requests on an
//  existing TLS TCP connection.
//
//  Created by Andreas Schweizer on 11.01.2017.
//  Copyright © 2017 Classy Code GmbH
//
//  Changes by Manuel Wick, 2018.
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

#ifndef __OTA_HTTPS_CLIENT__
#define __OTA_HTTPS_CLIENT__ 1


// This module depends on the ota_tls module.
// Forward declaration of the ota_tls context structure.
struct ota_tls_context_;


typedef int32_t ota_http_err_t;

#define OTA_HTTP_SUCCESS 0
#define OTA_HTTP_ERR_INVALID_ARGS           0x101
#define OTA_HTTP_ERR_OUT_OF_MEMORY          0x102
#define OTA_HTTP_ERR_NOT_IMPLEMENTED        0x103
#define OTA_HTTP_ERR_BUFFER_TOO_SMALL       0x104
#define OTA_HTTP_ERR_SEND_FAILED            0x105
#define OTA_HTTP_ERR_INVALID_STATUS_LINE    0x106
#define OTA_HTTP_ERR_VERSION_NOT_SUPPORTED  0x107
#define OTA_HTTP_ERR_NON_200_STATUS_CODE    0x108 // additional info = status code

// HTTP methods to use in the requests.
// TODO Right now, this is only a partial implementation.
typedef enum {
    OTA_HTTP_GET = 0,
    // OTA_HTTP_POST, ...
} ota_http_request_verb_t;

// Callback behaviour of a single request.
// If you can provide a response buffer that you know is big enough,
// you can let this module collect all data in the buffer before it
// invokes your callback. Otherwise, for large downloads which don't
// fit in the buffer, use OTA_HTTP_STREAM_BODY which causes the callback
// to be invoked multiple times.
typedef enum {
    OTA_HTTP_WAIT_FOR_COMPLETE_BODY,
    OTA_HTTP_STREAM_BODY,
} ota_http_response_mode_t;

// Callback return values.
// Specify OTA_HTTP_CONTINUE_RECEIVING if you're interested to receive
// more data. The size of the content provided by the web server
// in the Content-Length header overrides this value, i.e. if there's
// no more content to be received, you can use OTA_HTTP_CONTINUE_RECEIVING
// but won't get any more callbacks for the corresponding request.
typedef enum {
    OTA_HTTP_CONTINUE_RECEIVING = 0,
    OTA_HTTP_STOP_RECEIVING
} ota_http_continue_receiving_t;


struct ota_http_request_;

typedef ota_http_continue_receiving_t (*ota_http_request_headers_callback_t)(struct ota_http_request_ *request, int statusCode, int contentLength);
typedef ota_http_continue_receiving_t (*ota_http_request_body_callback_t)(struct ota_http_request_ *request, size_t bytesReceived);
typedef void (*ota_http_request_error_callback_t)(struct ota_http_request_ *request, ota_http_err_t error, int additionalInfo);

typedef struct ota_http_request_ {
    
    // GET, POST, ...
    ota_http_request_verb_t verb;
    
    // www.classycode.io
    const char *host;
    
    // /esp32/ota.txt
    const char *path;
    
    // Buffer to store the response.
    char *response_buffer;
    
    // Size of the response buffer.
    // Needs to be large enough to hold all HTTP headers!
    size_t response_buffer_len;
    
    // Invoked if something goes wrong.
    ota_http_request_error_callback_t error_callback;
    
    // (Optional) callback handler invoked after all headers have been received.
    // Lets the application handle re-direction, authentication requests etc.
    ota_http_request_headers_callback_t headers_callback;
    
    // Define if the body callback should be invoked once after the entire message body
    // has been received (response_buffer needs to be large enough to hold the entire body),
    // or if it should be invoked periodically after parts of the message body have been
    // stored in response_buffer.
    ota_http_response_mode_t response_mode;
    
    // Callback handler to process the message body.
    // Invoked once after receiving the whole message body (OTA_HTTP_WAIT_FOR_COMPLETE_BODY)
    // or periodically after receiving more body data (OTA_HTTP_STREAM_BODY). In the latter case,
    // a callback with length 0 indicates the end of the body.
    ota_http_request_body_callback_t body_callback;
    
} ota_http_request_t;


// Send the specified HTTP request on the (connected and verified) tlsContext.
// The httpRequest object needs to be kept in memory until the request has been completed.
ota_http_err_t ota_https_send_request(struct ota_tls_context_ *tlsContext, ota_http_request_t *httpRequest);


// Search the buffer for the specified key and try to parse an integer value right after the key.
// Returns 0 on success.
int ota_http_parse_key_value_int(const char *buffer, const char *key, int *value);

// Search the buffer for the specified key. If it exists, copy the string after the key up to
// but without newline into the str buffer which has a size of strLen.
// Returns 0 on success.
int ota_http_parse_key_value_string(const char *buffer, const char *key, char *str, int strLen);

// Search the buffer for the specified key. If it exists, convert the hex string after the key up to
// but without newline into the byte buffer which has a size of arrayLen.
// Returns 0 on success.
int ota_http_parse_key_value_hex_byte_array(const char *buffer, const char *key, uint8_t *byteArray, int arrayLen);

#endif // __OTA_HTTPS_CLIENT__
