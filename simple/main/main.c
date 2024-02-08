/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include "cJSON.h"
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"
// #include "esp_tls_crypto.h"
#include "esp_tls.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <psa/crypto_builtin_primitives.h>
#include <mbedtls/ecdh.h>
#include <esp_http_server.h>

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "example";

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct
{
    char *username;
    char *password;
} basic_auth_info_t;

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    int out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    asprintf(&user_info, "%s:%s", username, password);
    if (!user_info)
    {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
     */
    digest = calloc(1, 6 + n + 1);
    if (digest)
    {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1)
    {
        buf = calloc(1, buf_len);
        if (!buf)
        {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        }
        else
        {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials)
        {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len))
        {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        }
        else
        {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (!basic_auth_resp)
            {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    }
    else
    {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri = "/basic_auth",
    .method = HTTP_GET,
    .handler = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info)
    {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char *buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1)
    {
        buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[32];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK)
            {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char *resp_str = (const char *)req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0)
    {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

static const httpd_uri_t hello = {
    .uri = "/hello",
    .method = HTTP_GET,
    .handler = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = "Hello World!"};

/* An HTTP POST handler */
static esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                                  MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = {
    .uri = "/echo",
    .method = HTTP_POST,
    .handler = echo_post_handler,
    .user_ctx = NULL};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    else if (strcmp("/echo", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0)
    {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0')
    {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/echo");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else
    {
        ESP_LOGI(TAG, "Registering /hello and /echo URIs");
        httpd_register_uri_handler(req->handle, &hello);
        httpd_register_uri_handler(req->handle, &echo);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/*static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};
*/
void evaluar(psa_status_t estado)
{
    if (estado == PSA_SUCCESS)
    {
        printf("PSA_SUCCESS1\n");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE \n");
    }

    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED \n");
    }

    else if (estado == PSA_ERROR_ALREADY_EXISTS)
    {
        printf("PSA_ERROR_ALREADY_EXISTS \n");
    }

    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED \n");
    }
    // export key
    else if (estado == PSA_SUCCESS)
    {
        printf("GENERAdo \n");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("Iniciar \n");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("llave no valida \n");
    }
    else if (estado == PSA_ERROR_BUFFER_TOO_SMALL)
    {
        printf("buffer pequeño \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("no clave par \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("no soportado  \n");
    }
    // Acuerdo de secreto
    else if (estado == PSA_SUCCESS)
    {
        printf("GENERACION HECHA");
    }
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("iniciar  \n");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("no valido \n");
    }
    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED  \n");
    }
    else if (estado == PSA_ERROR_BUFFER_TOO_SMALL)
    {
        printf("PSA_ERROR_BUFFER_TOO_SMALL  \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT  \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED  \n");
    }
    // SETUP DERIVATION
    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE \n");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT \n");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("PSA_ERROR_NOT_SUPPORTED \n");
    }
    // DERIVADA

    else if (estado == PSA_ERROR_BAD_STATE)
    {
        printf("PSA_ERROR_BAD_STATE");
    }
    else if (estado == PSA_ERROR_INVALID_HANDLE)
    {
        printf("PSA_ERROR_INVALID_HANDLE");
    }
    else if (estado == PSA_ERROR_NOT_PERMITTED)
    {
        printf("PSA_ERROR_NOT_PERMITTED");
    }
    else if (estado == PSA_ERROR_INVALID_ARGUMENT)
    {
        printf("PSA_ERROR_INVALID_ARGUMENT");
    }
    else if (estado == PSA_ERROR_NOT_SUPPORTED)
    {
        printf("=PSA_ERROR_NOT_SUPPORTED");
    }
    else if (estado == PSA_ERROR_DATA_INVALID)
    {
        printf("PSA_ERROR_DATA_INVALID");
    }
    else if (estado == PSA_ERROR_INSUFFICIENT_MEMORY)
    {
        printf("PSA_ERROR_DATA_INVALID");
    }
}
uint8_t hex_to_decimal(char hex_char) {
  if (hex_char >= '0' && hex_char <= '9') {
    return hex_char - '0';
  } else if (hex_char >= 'A' && hex_char <= 'F') {
    return hex_char - 'A' + 10;
  } else if (hex_char >= 'a' && hex_char <= 'f') {
    return hex_char - 'a' + 10;
  } else {
    return 0;
  }
}
char ascii_to_text(uint8_t ascii_char) {
  if (ascii_char >= ' ' && ascii_char <= '~') {
    return ascii_char;
  } else {
    return '\\';
  }
}

uint64_t hex_to_decimal_32(char *hex_string) {
  uint32_t decimal_value = 0;
  for (int i = 0; i < 8; i++) {
    decimal_value = (decimal_value << 4) | hex_to_decimal(hex_string[i]);
  }
  return decimal_value;
}

char *hex_to_text_32(char *hex_string, char *text_buffer, int text_buffer_size) {
  uint64_t decimal_value = hex_to_decimal_32(hex_string);

  // Ajusta la cantidad de bytes a escribir según el tamaño del buffer
  int bytes_to_write = text_buffer_size - 1; // Restando 1 para el caracter nulo
  if (bytes_to_write > 64) {
    bytes_to_write = 64; // Limita a 64 bytes si el buffer es mayor
  }

  // Variable para acumular el mensaje de texto
  char accumulated_text[bytes_to_write + 1];
  accumulated_text[0] = '\0'; // Inicializa el string acumulado

  // Convierte y acumula caracteres uno a uno
  for (int i = 0; i < bytes_to_write; i++) {
    char current_char = ascii_to_text((decimal_value >> (8 * (3 - i))) & 0xFF);
    // Concatena el caracter actual al texto acumulado
    strcat(accumulated_text, &current_char);
  }

  // Copia el texto acumulado al buffer principal
  strcpy(text_buffer, accumulated_text);

  return text_buffer;
}
int hex_to_text(const char *hex_str, char *text_buffer, int text_buffer_size) {
  int i, j;
  char c;

  // Recorrer la cadena hexadecimal.
  for (i = 0, j = 0; i < strlen(hex_str) && j < text_buffer_size - 1; i += 2, j++) {
    // Convertir el par de caracteres hexadecimales a un valor decimal.
    c = (hex_str[i] >= 'A' ? hex_str[i] - 'A' + 10 : hex_str[i] - '0') << 4;
    c |= (hex_str[i + 1] >= 'A' ? hex_str[i + 1] - 'A' + 10 : hex_str[i + 1] - '0');

    // Almacenar el caracter en el buffer de texto.
    text_buffer[j] = c;
  }

  // Agregar el caracter nulo al final del texto.
  text_buffer[j] = '\0';

  // Devolver la longitud del texto convertido.
  return j;
}
int hex_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    } else if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1; // Carácter no válido
}
void intToBytes(int num, unsigned char *bytes)
{
    bytes[0] = (num >> 24) & 0xFF; // Obtén el byte más significativo
    bytes[1] = (num >> 16) & 0xFF; // Obtén el segundo byte más significativo
    bytes[2] = (num >> 8) & 0xFF;  // Obtén el tercer byte más significativo
    bytes[3] = num & 0xFF;         // Obtén el byte menos significativo
}

struct ServerData
{
    char server_id[100];
    char messages[10][150];
    char public_key_alice[10][150];
    char compartidaB[100];
    char derivadaB[100];
    int num_messages;
    psa_key_handle_t dev;
};

size_t olenB;
uint8_t llave_alice[65];
uint8_t llave_publica_bob[65];
uint8_t compartidaB[32];
uint8_t derivadaB[32];
psa_key_handle_t llave_privada_bob, llave_derivada;
uint8_t llave_derivadaB[32];
psa_key_handle_t comp,comp2,comp3;
uint32_t output_lenB;
;
struct ServerData server_data;

esp_err_t iniciar_handler(httpd_req_t *req)
{
    char *server_id = NULL;
    size_t buf_len = httpd_req_get_hdr_value_len(req, "X-Server-ID") + 1;
    if (buf_len > 1)
    {
        server_id = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id, buf_len) == ESP_OK)
        {
            strncpy(server_data.server_id, server_id, sizeof(server_data.server_id));
            printf("X-Server-ID guardado en server_data: %s\n", server_data.server_id);
            free(server_id);

            httpd_resp_send(req, "Servidor iniciado\n", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }
    }

    if (server_id != NULL)
    {
        free(server_id);
    }

    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Error: no se encontró el encabezado X-Server-ID");
    return ESP_FAIL;
}
httpd_uri_t iniciar = {
    .uri = "/iniciar",
    .method = HTTP_GET,
    .handler = iniciar_handler};
void evo(esp_err_t error)
{
    switch (error)
    {
    case ESP_ERR_NOT_FOUND:
        printf("ESP_ERR_NOT_FOUND\n");
        break;
    case ESP_ERR_INVALID_ARG:
        printf("ESP_ERR_INVALID_ARG\n ");
        break;

    case ESP_ERR_HTTPD_INVALID_REQ:
        printf("ESP_ERR_HTTPD_INVALID_REQ\n");
        break;

    case ESP_ERR_HTTPD_RESULT_TRUNC:
        printf("ESP_ERR_HTTPD_RESULT_TRUNC\n");
        break;
    default:
        printf("ESP_OK\n");
        break;
    }
}
esp_err_t enviar_msg_handler(httpd_req_t *req)
{
    char server_id[50];
    char message[150];
    esp_err_t err;
    size_t tamano;
    req->content_len = 200;
    size_t server_id_len = httpd_req_get_hdr_value_len(req, "X-Server-ID");
    size_t message_len = httpd_req_get_hdr_value_len(req, "Content-Type");
    if (server_id_len >= sizeof(server_id) || message_len >= sizeof(message))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid header length");
        return ESP_FAIL;
    }

    err = httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id, server_id_len + 1);
    evo(err);
    err = httpd_req_get_hdr_value_str(req, "Content-Type", message, message_len + 1);
    evo(err);
    
    char *buffer = malloc(150);
    /*err = httpd_req_get_url_query_str(req, buffer, message_len + 1);
    evo(err);*/
    if (httpd_req_recv(req, buffer, 149) <= 0)
    {
        free(buffer);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
        return ESP_FAIL;
    }
    // printf("%d\n",httpd_req_recv(req, buffer,   120));
    printf("%d\n", req->content_len);
    

    /*if (httpd_req_get_url_query_str(req, buffer, message_len+1) != ESP_OK) {
        free(buffer);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid messagevacio");
        return ESP_FAIL;
    }*/
    
    // buffer[message_len] = '\0';
    cJSON *jsonObject = cJSON_Parse(buffer);
    free(buffer);

    if (jsonObject == NULL)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message PARSE");
        return ESP_FAIL;
    }
    cJSON *jsonMessage = cJSON_GetObjectItem(jsonObject, "message");
    if (!cJSON_IsString(jsonMessage))
    {
        cJSON_Delete(jsonObject);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message IS STRING");
        return ESP_FAIL;
    }
    if (cJSON_IsString(jsonMessage))
    {
        const char *clavep = cJSON_GetStringValue(jsonMessage);
        
    }

    strcpy(message, jsonMessage->valuestring);
    cJSON_Delete(jsonObject);
    
    if (strcmp(server_id, server_data.server_id) == 0)
    {
        if (server_data.num_messages >= 10)
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Maximum message limit reached");
            return ESP_FAIL;
        }
        strcpy(server_data.messages[0], message);
        
        server_data.num_messages++;
        ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
        ESP_LOGI(TAG,"CLAVE PUBLICA CLIENTE: %s",message);
        //printf("Mensaje recibido: %s\n", message);
        httpd_resp_send(req, "Mensaje recibido", HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        printf("Error: el servidor %s no se encuentra en el archivo\n", server_id);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Servidor no encontrado");
    }

    ESP_LOGE(TAG, "------------------------------------------------------------------------");
    psa_status_t estado = psa_crypto_init();

    psa_key_attributes_t attributes = psa_key_attributes_init();

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    estado = psa_generate_key(&attributes, &llave_privada_bob);
    evaluar(estado);
    estado = psa_export_public_key(llave_privada_bob, llave_publica_bob, sizeof(llave_publica_bob), &olenB);
    evaluar(estado);
    char clave_publica_hex[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
    char post_data[256];
    for (int i = 0; i < sizeof(llave_publica_bob); i++)
    {
        snprintf(clave_publica_hex + (2 * i), sizeof(clave_publica_hex) - (2 * i), "%02x", llave_publica_bob[i]);
    }
    /*for (int i = 0; i < sizeof(llave_publica_bob); i++)
    {
        printf("%02x", llave_publica_bob[i]);
    }*/
    printf("\n");
    strcpy(server_data.public_key_alice[0], clave_publica_hex);
    //ESP_LOGI(TAG, "%s", server_data.public_key_alice[0]);
    ESP_LOGE(TAG, "------------------------------------------------------------------------");
    return ESP_OK;
}
httpd_uri_t enviar_msg = {
    .uri = "/enviarMSG",
    .method = HTTP_POST,
    .handler = enviar_msg_handler};

esp_err_t mensajes_handler(httpd_req_t *req)
{
    char *server_id = NULL;
    req->content_len = 200;
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
    ESP_LOGI(TAG, " CLAVE PUBLICA SERVER: %s ", server_data.public_key_alice[0]);
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");

    /*cJSON *public_key_alice_dict=cJSON_CreateString(server_data.public_key_alice[0]);
    cJSON *esp1 = cJSON_CreateObject();
            cJSON_AddItemToObject(esp1, "messages", cJSON_CreateArray());
            cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(esp1, "messages"), messages);
            cJSON_AddItemToObject(esp1, "public_key_alice", cJSON_CreateArray());
            cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(esp1, "public_key_alice"), public_key_alice_dict);
    char *response = cJSON_Print(esp1);*/
    // cJSON_Delete(esp1);
    cJSON *jsonObject = cJSON_CreateObject();
    cJSON_AddStringToObject(jsonObject, "public_key_alice", server_data.public_key_alice[0]);
    char *jsonData = cJSON_PrintUnformatted(jsonObject);

    //printf("%s", jsonData);
    size_t buf_len = httpd_req_get_hdr_value_len(req, "X-Server-ID") + 1;
    if (buf_len > 1)
    {
        server_id = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id, buf_len) == ESP_OK)
        {
            if (strcmp(server_id, server_data.server_id) == 0)
            {
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, jsonData, strlen(jsonData));
                free(jsonData);
            }

            free(server_id);

            return ESP_OK;
        }
    }

    return ESP_OK;
}
httpd_uri_t mensajes = {
    .uri = "/mensajes",
    .method = HTTP_GET,
    .handler = mensajes_handler};

esp_err_t compartida_handler(httpd_req_t *req)
{
    char server_id[50];
    char message[150];
    esp_err_t err;
    size_t tamano;

    size_t server_id_len = httpd_req_get_hdr_value_len(req, "X-Server-ID");
    size_t message_len = httpd_req_get_hdr_value_len(req, "Content-Type");
    if (server_id_len >= sizeof(server_id) || message_len >= sizeof(message))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid header length");
        return ESP_FAIL;
    }

    err = httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id, server_id_len + 1);
    evo(err);
    err = httpd_req_get_hdr_value_str(req, "Content-Type", message, message_len + 1);
    evo(err);
    //ESP_LOGE(TAG, "%s", message);
    char *buffer = malloc(150);
    if (httpd_req_recv(req, buffer, 149) <= 0)
    {
        free(buffer);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
        return ESP_FAIL;
    }

    //printf("%d\n", req->content_len);
    //printf("%s\n", buffer);
    //ESP_LOGE(TAG, "%s", buffer);
    // buffer[message_len] = '\0';
    cJSON *jsonObject = cJSON_Parse(buffer);
    free(buffer);

    if (jsonObject == NULL)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message PARSE");
        return ESP_FAIL;
    }
    cJSON *jcompartida = cJSON_GetObjectItem(jsonObject, "compartidaB");
    if (!cJSON_IsString(jcompartida))
    {
        cJSON_Delete(jsonObject);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message IS STRING");
        return ESP_FAIL;
    }
    if (cJSON_IsString(jcompartida))
    {
        const char *clavep = cJSON_GetStringValue(jcompartida);
        //ESP_LOGE(TAG, "%s", clavep);
    }
    strcpy(message, jcompartida->valuestring);
    cJSON_Delete(jsonObject);
    //ESP_LOGE(TAG, "%s", message);
    if (strcmp(server_id, server_data.server_id) == 0)
    {
        if (server_data.num_messages >= 10)
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Maximum message limit reached");
            return ESP_FAIL;
        }
        strcpy(server_data.derivadaB, message);
        //ESP_LOGE(TAG, "Esto es en el server:%s", server_data.compartidaB);
        ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
        ESP_LOGI(TAG,"CLAVE COMPARTIDA RECIBIDA %s", message);
        ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
       // printf("Mensaje recibido: %s\n", message);
        httpd_resp_send(req, "Mensaje recibido", HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        printf("Error: el servidor %s no se encuentra en el archivo\n", server_id);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Servidor no encontrado");
    }

    return ESP_OK;
}
httpd_uri_t compartida = {
    .uri = "/compartida",
    .method = HTTP_POST,
    .handler = compartida_handler};

void hexToBytes(const char *hex, unsigned char *bytes, size_t num_bytes)
{
    size_t hex_len = strlen(hex);
    size_t copy_len = (hex_len < (2 * num_bytes)) ? hex_len : (2 * num_bytes);

    for (size_t i = 0; i < copy_len; i += 2)
    {
        sscanf(hex + i, "%2hhx", &bytes[i / 2]);
    }
}

esp_err_t verificacion_handler(httpd_req_t *req)
{
    char server_id[50];
    req->content_len = 200;
    size_t hex_len = strlen(server_data.messages[0]);

    size_t byte_len = hex_len / 2;
    hexToBytes(server_data.messages[0], llave_alice, byte_len);
    /*for (int i = 0; i < sizeof(llave_alice); i++)
    {
        printf("%02X ", llave_alice[i]); // Imprimir cada byte en hexadecimal
    }*/
    psa_status_t estado2 = psa_crypto_init();
    estado2 = psa_raw_key_agreement(PSA_ALG_ECDH, llave_privada_bob, llave_alice, sizeof(llave_alice), compartidaB, sizeof(compartidaB), &output_lenB);
    printf("\n");
    evaluar(estado2);

    printf("\n");
    /*printf("Bytes Compartida ESP: ");
    for (int i = 0; i < sizeof(compartidaB); i++)
    {
        printf("%02x ", compartidaB[i]);
        // Imprimir cada byte en hexadecimal
    }*/
    char clave_publica_hex2[150]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

    for (int i = 0; i < sizeof(compartidaB); i++)
    {
        snprintf(clave_publica_hex2 + (2 * i), sizeof(clave_publica_hex2) - (2 * i), "%02x", compartidaB[i]);
    }
    ESP_LOGI(TAG,"CLAVE COMPARTIDA SERVIDOR: %s",clave_publica_hex2);
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
    strcpy(server_data.compartidaB, clave_publica_hex2);
    if (strcmp(clave_publica_hex2, server_data.compartidaB) == 0)
    {
        int valor = 0;
        cJSON *jsonObject2 = cJSON_CreateObject();
        cJSON_AddNumberToObject(jsonObject2, "valor", valor);
        char *jsonData2 = cJSON_PrintUnformatted(jsonObject2);
        //printf("%s", jsonData2);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, jsonData2, strlen(jsonData2));
        free(jsonData2);
    }
    return ESP_OK;
}
httpd_uri_t verificacion = {
    .uri = "/verificacion",
    .method = HTTP_GET,
    .handler = verificacion_handler};

esp_err_t derivada_handler(httpd_req_t *req)
{

    char server_id3[500];
    char message3[500];
    esp_err_t err;
    size_t tamano;
    req->content_len = 200;

    err = httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id3, 51);
    evo(err);
    err = httpd_req_get_hdr_value_str(req, "Content-Type", message3, 151);
    evo(err);
    //ESP_LOGE(TAG, "%s", message3);
    char buffer[199];
    if (httpd_req_recv(req, buffer, 199) <= 0)
    {
        free(buffer);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
        return ESP_FAIL;
    }

    //printf("%d\n", req->content_len);
    //printf("%s\n", buffer);
    //ESP_LOGE(TAG, "%s", buffer);
    // buffer[message_len] = '\0';
    cJSON *bufferjson = cJSON_Parse(buffer);
    if (bufferjson == NULL)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message PARSE");
        return ESP_FAIL;
    }
    cJSON *derivada = cJSON_GetObjectItem(bufferjson, "derivadaB");
    if (!cJSON_IsString(derivada))
    {
        cJSON_Delete(bufferjson);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message IS STRING");
        return ESP_FAIL;
    }
    if (cJSON_IsString(derivada))
    {
        const char *clavep2 = cJSON_GetStringValue(derivada);
       // ESP_LOGE(TAG, "%s", clavep2);
    }
    strcpy(message3, derivada->valuestring);
    cJSON_Delete(bufferjson);
    //ESP_LOGE(TAG, "%s", message3);
    if (strcmp(server_id3, server_data.server_id) == 0)
    {
        if (server_data.num_messages >= 10)
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Maximum message limit reached");
            return ESP_FAIL;
        }
        strcpy(server_data.derivadaB, message3);
        //ESP_LOGE(TAG, "Esto es en el server:%s", server_data.derivadaB);
        ESP_LOGI(TAG,"CALVE DERIVADA CLIENTE: %s",message3);
        ESP_LOGE(TAG, "------------------------------------------------------------------------\n");
       // printf("Mensaje recibido: %s\n", message3);
        httpd_resp_send(req, "Mensaje recibido", HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        printf("Error: el servidor %s no se encuentra en el archivo\n", server_id3);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Servidor no encontrado");
    }
    /*




    free(server_id3);
*/
    return ESP_OK;
}
httpd_uri_t Derivada = {
    .uri = "/Derivada",
    .method = HTTP_POST,
    .handler = derivada_handler};

esp_err_t verificacion2_handler(httpd_req_t *req)
{
    char server_id[50];
    req->content_len = 200;
    size_t hex_len = strlen(server_data.derivadaB);
    //ESP_LOGE(TAG, "------------------------------------------------------------------------\n");    
    size_t byte_len = hex_len / 2;
    hexToBytes(server_data.derivadaB, derivadaB, byte_len);
    /*for (int i = 0; i < sizeof(derivadaB); i++)
    {
        printf("%02X ", derivadaB[i]); // Imprimir cada byte en hexadecimal
    }*/
    psa_status_t estado3 = psa_crypto_init();

    psa_key_derivation_operation_t operacion;
    operacion = psa_key_derivation_operation_init();
    uint8_t vuelta = 0;
    char * lol="aaaa";
    uint8_t* bytes=(uint8_t*)lol;
    const char* cadena = "isma_crypto_send";
    int len =strlen(cadena);
    int len2=strlen(lol);
    //printf("%d",len);
    //printf("\n");
    //len=len*2;
    //printf("%d",len);
    uint8_t bufff[len];
    uint8_t bufff2[len2];
    //printf("%d",sizeof(bufff));
    //printf("\n");
    for (size_t i = 0; i < len; i++)
    {
        bufff[i]=(uint8_t)cadena[i];
        printf("%02x",bufff[i]);
    }
    printf("\n");  
    for (size_t i = 0; i < len2; i++)
    {
        bufff2[i]=(uint8_t)lol[i];
        printf("%02x",bufff2[i]);
    } 

    psa_key_attributes_t atributo3 = psa_key_attributes_init();
    psa_set_key_usage_flags(&atributo3, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT| PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&atributo3, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&atributo3, PSA_ALG_CTR);
    psa_set_key_type(&atributo3, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&atributo3, 256);

    estado3 = psa_import_key(&atributo3, compartidaB, sizeof(compartidaB), &comp);
    evaluar(estado3);
    estado3 = psa_key_derivation_setup(&operacion,  PSA_ALG_HKDF(PSA_ALG_SHA_256));

    evaluar(estado3);
    estado3 = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_SALT, bufff2, sizeof(bufff2));
    
    evaluar(estado3);
   
    estado3=psa_key_derivation_input_bytes(&operacion,PSA_KEY_DERIVATION_INPUT_SECRET,compartidaB,sizeof(compartidaB));
    evaluar(estado3);
    
    estado3 = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_INFO, bufff, sizeof(bufff));
    evaluar(estado3);

    
    estado3 = psa_key_derivation_output_key(&atributo3, &operacion, &llave_derivada);
    evaluar(estado3);
    estado3 = psa_key_derivation_output_bytes(&operacion, &llave_derivadaB, sizeof(llave_derivadaB));
    evaluar(estado3);
    estado3 = psa_key_derivation_abort(&operacion);
    
    
    
    /*estado3 = psa_key_derivation_setup(&operacion,  PSA_ALG_HKDF(PSA_ALG_SHA_256));
    evaluar(estado3);

    estado3 = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_SALT, bytes, sizeof(bytes));
    evaluar(estado3);
    
    estado=psa_key_derivation_input_bytes(&operacion,PSA_KEY_DERIVATION_INPUT_SECRET,compartidaB,sizeof(compartidaB));
    //estado3 = psa_key_derivation_key_agreement(&operacion, PSA_KEY_DERIVATION_INPUT_SECRET, llave_privada_bob, &llave_alice, sizeof(llave_alice));
    evaluar(estado3);

    evaluar(estado3);
    // vuelta++;

    // estado=psa_key_derivation_set_capacity(&operacion,256);
    // evaluar(estado);
    estado3 = psa_key_derivation_input_bytes(&operacion, PSA_KEY_DERIVATION_INPUT_INFO, compartidaB, sizeof(compartidaB));
    evaluar(estado3);

    printf("break \n");
    estado3 = psa_key_derivation_output_key(&atributo3, &operacion, &llave_derivada);
    evaluar(estado3);
    estado3 = psa_key_derivation_output_bytes(&operacion, &llave_derivadaB, sizeof(llave_derivadaB));
    evaluar(estado3);*/
    psa_cipher_operation_t cifrado,cifrado2;
        


    char clave_publica_hex3[150]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo

    for (int i = 0; i < sizeof(derivadaB); i++)
    {
        snprintf(clave_publica_hex3 + (2 * i), sizeof(clave_publica_hex3) - (2 * i), "%02x", llave_derivadaB[i]);
    }
    printf("\n");
    ESP_LOGI(TAG,"CLAVE DERIVADA SERVIDOR: %s",clave_publica_hex3);
    ESP_LOGE(TAG, "------------------------------------------------------------------------\n");

    if (strcmp(clave_publica_hex3, server_data.derivadaB) == 0)
    {
        int valor = 0;
        cJSON *jsonObject2 = cJSON_CreateObject();
        cJSON_AddNumberToObject(jsonObject2, "valor2", valor);
        char *jsonData2 = cJSON_PrintUnformatted(jsonObject2);
        //printf("%s", jsonData2);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, jsonData2, strlen(jsonData2));
    }

    return ESP_OK;
}
httpd_uri_t verificacion2 = {
    .uri = "/verificacion2",
    .method = HTTP_GET,
    .handler = verificacion2_handler};


esp_err_t cifrado_handler(httpd_req_t *req)
{
    char server_id3[50];
    char message3[500];
        char message4[500];
    psa_key_attributes_t atributo4;
    atributo4 = psa_key_attributes_init();
    psa_set_key_usage_flags(&atributo4, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT| PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&atributo4, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&atributo4, PSA_ALG_CTR);
    psa_set_key_type(&atributo4, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&atributo4, 256);
    esp_err_t err;
    size_t tamano;
    req->content_len = 350;

    err = httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id3, 51);
    evo(err);
    err = httpd_req_get_hdr_value_str(req, "Content-Type", message3, 151);
    evo(err);
   // ESP_LOGE(TAG, "%s", message3);
    char buffer[199];
    if (httpd_req_recv(req, buffer, 349) <= 0)
    {
        free(buffer);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
        return ESP_FAIL;
    }

    //printf("%d\n", req->content_len);
    //printf("%s\n", buffer);
    //ESP_LOGE(TAG, "%s", buffer);
    // buffer[message_len] = '\0';
    cJSON *cifradojson = cJSON_Parse(buffer);
    if (cifradojson == NULL)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message PARSE");
        return ESP_FAIL;
    }
    cJSON *cifrado = cJSON_GetObjectItem(cifradojson, "msg");
    if (!cJSON_IsString(cifrado))
    {
        cJSON_Delete(cifradojson);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid message IS STRING");
        return ESP_FAIL;
    }
    
    if (cJSON_IsString(cifrado))
    {
        const char *clavep2 = cJSON_GetStringValue(cifrado);
       // ESP_LOGE(TAG, "%s", clavep2);
    }
    
    strcpy(message3, cifrado->valuestring);
    
    cJSON_Delete(cifradojson);
   // ESP_LOGE(TAG, "%s", message3);
    if (strcmp(server_id3, server_data.server_id) == 0)
    {
        if (server_data.num_messages >= 10)
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Maximum message limit reached");
            return ESP_FAIL;
        }

        psa_cipher_operation_t cifrado,cifrado2;
        cifrado = psa_cipher_operation_init();
        cifrado2 = psa_cipher_operation_init();
        psa_status_t estado = psa_crypto_init();
        uint8_t ivs[33];
        // uint8_t mensaje[] = {54, 45};
        size_t olenC, olenD;
        psa_key_handle_t llave_aes;
        char llave[33];
        uint8_t guardado[33];
        uint8_t derivada[32];
        uint8_t iv_s[ PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR)];
        memset(iv_s, 0, sizeof(iv_s));
        strcpy(llave, server_data.derivadaB);
        hexToBytes(llave,derivada,sizeof(derivada));
        size_t hexLength = strlen(message3);
        size_t byteLength = hexLength / 2;
        
        uint8_t llave_aesB[33];
        
        hexToBytes(message3,llave_aesB,byteLength);
        
        /*for (size_t i = 0; i < byteLength; i++)
                    {
                        printf("%02x ", llave_aesB[i]);
                    }*/
        printf("\nSeparador*************************************\n");
        
       /* estado=psa_cipher_decrypt(&llave_derivada,PSA_ALG_CTR,&llave_aesB, sizeof(llave_aesB), &guardado, sizeof(guardado), &olenD);
        evaluar(estado);*/
        /*estado=psa_cipher_decrypt(llave_derivada,PSA_ALG_CTR,llave_aesB,sizeof(llave_aesB),guardado,sizeof(guardado),&olenC);
        evaluar(estado);*/
        estado = psa_import_key(&atributo4,llave_derivadaB,sizeof(llave_derivadaB),&comp2);
        evaluar(estado);
        estado = psa_cipher_decrypt_setup(&cifrado, comp2, PSA_ALG_CTR);
        evaluar(estado);
        estado = psa_cipher_decrypt_setup(&cifrado2, comp2, PSA_ALG_CTR);
        evaluar(estado);
        estado=psa_cipher_set_iv(&cifrado,&iv_s, 16);
        evaluar(estado);
        /*estado = psa_cipher_generate_iv(&cifrado, iv_s,  PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR), &olenC);
        evaluar(estado);*/
        estado = psa_cipher_update(&cifrado, llave_aesB, sizeof(llave_aesB), guardado, sizeof(guardado), &olenD);
        evaluar(estado);
        estado=psa_cipher_finish(&cifrado,guardado,sizeof(guardado),&olenD);
            evaluar(estado);
            char clave_publica_hex4[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
                char post_data3[256];
                for (int i = 0; i < sizeof(guardado); i++)
                {
                    snprintf(clave_publica_hex4 + (2 * i), sizeof(clave_publica_hex4) - (2 * i), "%02x", guardado[i]);
                }
                for (int i = 0; i < sizeof(guardado); i++)
                {
                   // printf("%d", guardado[i]);
                }
        printf("\n");
        ESP_LOGE(TAG,"MENSAJE CIFRADO POR PARTE DEL CLIENTE: %s",message3);
        ESP_LOGI(TAG,"MENSAJE DESCIFRADO EN EL SERVIDOR HEX: %s",clave_publica_hex4);
        int length = strlen(clave_publica_hex4);
    char mensaje_en_claro[length / 2 + 1]; // Espacio suficiente para el mensaje en claro
    int i, j = 0;

    for (i = 0; i < length; i += 2) {
        char c1 = clave_publica_hex4[i];
        char c2 = clave_publica_hex4[i + 1];

        int valor_ascii = (hex_to_int(c1) << 4) | hex_to_int(c2);
        mensaje_en_claro[j++] = valor_ascii;
    }
    mensaje_en_claro[j] = '\0'; // Agrega el carácter nulo al final

    //printf("Mensaje en claro: %s\n", mensaje_en_claro);
    ESP_LOGI(TAG,"MENSAJE DESCIFRADO EN EL SERVIDOR: %s",mensaje_en_claro);
        //printf("\nAqui :%s\n", clave_publica_hex4);
        //printf("Mensaje recibido: %s\n", message3);
        httpd_resp_send(req, "Mensaje recibido", HTTPD_RESP_USE_STRLEN);

    }
    else
    {
        printf("Error: el servidor %s no se encuentra en el archivo\n", server_id3);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Servidor no encontrado");
    }
    /*




    free(server_id3);
*/

    return ESP_OK;
}
httpd_uri_t cifrado = {
    .uri = "/cifrado",
    .method = HTTP_POST,
    .handler = cifrado_handler

};

esp_err_t descifrado_handler(httpd_req_t *req){
            
            
            char server_id3[50];
            psa_key_attributes_t atributo4 ;
            atributo4= psa_key_attributes_init();
    psa_set_key_usage_flags(&atributo4, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT| PSA_KEY_USAGE_DERIVE);
    psa_set_key_lifetime(&atributo4, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&atributo4, PSA_ALG_CTR);
    psa_set_key_type(&atributo4, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&atributo4, 256);
            psa_cipher_operation_t cifrado,cifrado2;
            cifrado=psa_cipher_operation_init();
            cifrado2=psa_cipher_operation_init();
            uint8_t iv_s[ PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR)];
            memset(iv_s, 0, sizeof(iv_s));
            uint8_t mensaje[32];
            uint8_t descifrado[33];
            srand(time(NULL));
            char cadena5[] = "Hola esp1 soy el servidor";
            // mensaje[sizeof(cadena5)];

            strcpy((char *)mensaje, cadena5);

             for (size_t i = 0; i < sizeof(mensaje); i++) {
                 printf("%u ", mensaje[i]);
             }
             printf("Mensaje:\n");
    for (size_t i = 0; i < sizeof(mensaje); i++) {
    printf("%c", mensaje[i]);
    }
    /*
            for (size_t i = 0; i < sizeof(mensaje); i++) {
        mensaje[i] = (uint8_t)rand();
    }
    printf("Números aleatorios:\n");
    for (size_t i = 0; i < sizeof(mensaje); i++) {
        printf("%u ", mensaje[i]);
    }*/
    printf("\n");
            size_t olenC, olenD;
            psa_key_handle_t llave_aes;
            uint8_t llave_aesB[33];
            uint32_t output_lenD;
            psa_status_t estado=psa_crypto_init();
            estado = psa_import_key(&atributo4,llave_derivadaB,sizeof(llave_derivadaB),&comp3);
            evaluar(estado);
            estado = psa_cipher_encrypt_setup(&cifrado, comp3, PSA_ALG_CTR);
            evaluar(estado);
            estado=psa_cipher_decrypt_setup(&cifrado2, comp3, PSA_ALG_CTR);
            evaluar(estado);
            //estado=psa_cipher_set_iv(&cifrado,&iv_s,output_lenC);
            /*estado = psa_cipher_generate_iv(&cifrado, &iv_s, PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR), &output_lenC);
            evaluar(estado);*/
            estado=psa_cipher_set_iv(&cifrado,&iv_s, 16);
            evaluar(estado);
            estado=psa_cipher_set_iv(&cifrado2,&iv_s, 16);
            evaluar(estado);

            estado=psa_cipher_update(&cifrado,mensaje,sizeof(mensaje),&llave_aesB,sizeof(llave_aesB),&olenD);
            
            estado=psa_cipher_finish(&cifrado,&llave_aesB,sizeof(llave_aesB),&olenD);
            evaluar(estado);

            estado=psa_cipher_update(&cifrado2,llave_aesB,sizeof(llave_aesB),&descifrado,sizeof(descifrado),&output_lenD);
            evaluar(estado);
            estado=psa_cipher_finish(&cifrado2,&descifrado,sizeof(descifrado),&output_lenD);
            evaluar(estado);
              char clave_publica_hex4[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
                
                for (int i = 0; i < sizeof(llave_aesB); i++)
                {
                    snprintf(clave_publica_hex4 + (2 * i), sizeof(clave_publica_hex4) - (2 * i), "%02x", llave_aesB[i]);
                }
                for (int i = 0; i < sizeof(llave_aesB); i++)
                {
                    //printf("%d", llave_aesB[i]);
                }
                printf("\n");
                ESP_LOGE(TAG,"MENSAJE CIFRADO EN EL SERVIDOR: %s",clave_publica_hex4);
                //printf("\nCIfrado:%s", clave_publica_hex4);

                char clave_publica_hex5[135]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
                
                for (int i = 0; i < sizeof(descifrado); i++)
                {
                    snprintf(clave_publica_hex5 + (2 * i), sizeof(clave_publica_hex5) - (2 * i), "%02x", descifrado[i]);
                }
                for (int i = 0; i < sizeof(descifrado); i++)
                {
                    //printf("%d", descifrado[i]);
                }
                /*char clave_publica_hex6[PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR)]; // 65 bytes (2 caracteres hexadecimales por byte) + 1 byte nulo
                
                for (int i = 0; i < PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES,PSA_ALG_CTR); i++)
                {
                    snprintf(clave_publica_hex6 + (2 * i), sizeof(clave_publica_hex6) - (2 * i), "%02x", iv_s[i]);
                }
                for (int i = 0; i < sizeof(iv_s); i++)
                {
                    printf("%d", descifrado[i]);
                }*/
               // printf("\n");
                /*for (int i = 0; i < sizeof(iv_s); i++)
                {
                    printf( "%02x", iv_s[i]);
                }
                printf("\n");
                printf("\nIV:%s", clave_publica_hex6);*/

                //printf("\n");
                ESP_LOGI(TAG,"MENSAJE DESCIFRADO EN EL SERVIDOR HEX: %s",clave_publica_hex5);
                int length = strlen(clave_publica_hex5);
    char mensaje_en_claro[length / 2 + 1]; // Espacio suficiente para el mensaje en claro
    int i, j = 0;

    for (i = 0; i < length; i += 2) {
        char c1 = clave_publica_hex5[i];
        char c2 = clave_publica_hex5[i + 1];

        int valor_ascii = (hex_to_int(c1) << 4) | hex_to_int(c2);
        mensaje_en_claro[j++] = valor_ascii;
    }
    mensaje_en_claro[j] = '\0'; // Agrega el carácter nulo al final

ESP_LOGI(TAG,"MENSAJE DESCIFRADO EN EL SERVIDOR : %s",mensaje_en_claro);

                //printf("\nDescifrado:%s", clave_publica_hex5);
                cJSON *jsonObject4 = cJSON_CreateObject();
                cJSON_AddStringToObject(jsonObject4, "cifrado", clave_publica_hex4);
                char *jsonData4 = cJSON_PrintUnformatted(jsonObject4);
                //printf("%s", jsonData4);
                estado = httpd_req_get_hdr_value_str(req, "X-Server-ID", server_id3, 51);
                evo(estado);
                if (strcmp(server_id3,server_data.server_id)==0)
                {
                    httpd_resp_set_type(req, "application/json");
                    httpd_resp_send(req, jsonData4, strlen(jsonData4));
                }
                
                

return ESP_OK;
}
httpd_uri_t descifrado = {
    .uri = "/descifrado",
    .method = HTTP_GET,
    .handler = descifrado_handler

};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers=500;
    config.stack_size=16384;
    config.server_port=80;
    config.recv_wait_timeout=30;
    config.send_wait_timeout=30;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        // httpd_register_uri_handler(server, &hello);
        // httpd_register_uri_handler(server, &echo);
        // httpd_register_uri_handler(server, &ctrl);
        httpd_register_uri_handler(server, &iniciar);
        httpd_register_uri_handler(server, &enviar_msg);
        httpd_register_uri_handler(server, &mensajes);
        httpd_register_uri_handler(server, &compartida);
        httpd_register_uri_handler(server, &verificacion);
        httpd_register_uri_handler(server, &Derivada);
        httpd_register_uri_handler(server, &verificacion2);
        httpd_register_uri_handler(server, &cifrado);
        httpd_register_uri_handler(server, &descifrado);
#if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void *arg, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET

    /* Start the server for the first time */
    server = start_webserver();
}
