#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <pthread.h>

#define MAX_FILENAME            256
#define MAX_URL_LENGTH          2048
#define MAX_LINKS               1000
#define BUFFER_SIZE             4096
#define MAX_VISITED_URLS        10000
#define MAX_DEPTH               2
#define MAX_RETRIES             3
#define NUM_THREADS             3
#define MAX_REDIRECTS           10

#define SUCCESS                 0
#define ERROR_BASE              0
#define ERR_HTTP_STATUS         ERROR_BASE - 1
#define ERR_NORMALIZE_URL       ERROR_BASE - 2
#define ERR_GETADDRINFO_FAIL    ERROR_BASE - 3
#define ERR_FAIL_CONNECT        ERROR_BASE - 4
#define ERR_SEND_REQST_FAIL     ERROR_BASE - 5
#define ERR_BODY_NOT_FOUND      ERROR_BASE - 6
#define ERR_WRON_BODY_TAG       ERROR_BASE - 7
#define ERR_FILE_OPEN_FAIL      ERROR_BASE - 8

typedef struct {
    char scheme[8];
    char host[256];
    char path[1024];
    int port;
} URL;

typedef struct {
    char *data;
    size_t length;
    char content_type[256];
} Content;

SSL_CTX *create_ssl_context();
SSL *setup_ssl_connection(int sockfd, SSL_CTX **ctx);
Content* fetch_url(const char *url, int redirect_count, char *final_url, size_t final_url_size);
void parse_url(const char *url, URL *parsed_url);
int connect_to_host(const char *hostname, int port);
int send_request(SSL *ssl, int sockfd, const URL *parsed_url);
Content* handle_response(SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size);
int normalize_url(const char *base_url, const char *rel_url, char *result, size_t result_size);
int extract_links(const char *html_content, const char *base_url, char **links, int *link_count);
void create_filename(const char *url, const char *content_type, char *filename, size_t filename_size);
int save_content(const char *url,  Content *content, const char *output_dir); 
int is_url_visited(const char *url, char **visited_urls, int visited_count);
void crawl_level(const char *base_url, const char *output_dir, int current_depth, char **visited_urls, int *visited_count);

void parse_url(const char *url, URL *parsed_url) 
{
    const char *scheme_end = strstr(url, "://");
    if (scheme_end) 
    {
        strncpy(parsed_url->scheme, url, scheme_end - url);
        parsed_url->scheme[scheme_end - url] = '\0';
        url = scheme_end + 3;
    } 
    else 
    {
        strcpy(parsed_url->scheme, "http");
    }

    const char *path_start = strchr(url, '/');
    if (path_start) 
    {
        strncpy(parsed_url->host, url, path_start - url);
        parsed_url->host[path_start - url] = '\0';
        strcpy(parsed_url->path, path_start);
    } 
    else 
    {
        strcpy(parsed_url->host, url);
        strcpy(parsed_url->path, "/");
    }

    parsed_url->port = strcmp(parsed_url->scheme, "https") == 0 ? 443 : 80;
}

int connect_to_host(const char *hostname, int port)
{
    struct addrinfo hints, *res, *p;
    int sockfd;
    char port_str[6];
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", port);

    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) 
    {
        printf("getaddrinfo error\n");
        return ERR_GETADDRINFO_FAIL;
    }

    for(p = res; p != NULL; p = p->ai_next) 
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }

        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        int connect_result = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (connect_result == 0) 
        {
            fcntl(sockfd, F_SETFL, flags);
            break;
        } 
        else if (errno != EINPROGRESS) 
        {
            close(sockfd);
            continue;
        }

        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        int select_result = select(sockfd + 1, NULL, &fdset, NULL, &tv);
        if (select_result > 0) 
        {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) 
            {
                fcntl(sockfd, F_SETFL, flags);
                break;
            }
        }

        close(sockfd);
    }

    freeaddrinfo(res);

    if (p == NULL) 
    {
        printf("Failed to connect to %s:%d\n", hostname, port);
        return ERR_FAIL_CONNECT;
    }

    return sockfd;
}

SSL_CTX* create_ssl_context() 
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Unable to create SSL context\n");
        return NULL;
    }
    return ctx;
}

SSL *setup_ssl_connection(int sockfd, SSL_CTX **ctx) 
{
    *ctx = create_ssl_context();
    if (!*ctx) {
        return NULL;
    }
    SSL *ssl = SSL_new(*ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(*ctx);
        return NULL;
    }
    return ssl;
}

int send_request(SSL *ssl, int sockfd, const URL *parsed_url) 
{
    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: SimpleWebCrawler/1.0\r\n"
             "Connection: close\r\n\r\n",
             parsed_url->path, parsed_url->host);

    int bytes_sent;
    if (ssl) 
    {
        bytes_sent = SSL_write(ssl, request, strlen(request));
    } 
    else 
    {
        bytes_sent = send(sockfd, request, strlen(request), 0);
    }
    return bytes_sent > 0 ? SUCCESS : ERR_SEND_REQST_FAIL;
}

Content* handle_response(SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size) 
{
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int status_code = 0;
    int is_chunked = 0;
    Content *content = malloc(sizeof(Content));
    if (!content) return NULL;
    content->data = NULL;
    content->length = 0;
    content->content_type[0] = '\0';

    size_t response_size = 0;
    int headers_done = 0;
    char *body_start = NULL;
    
    // 用於處理chunked傳輸
    char *chunk_start = NULL;
    size_t chunk_size = 0;
    int reading_chunk_size = 0;
    char chunk_size_str[20] = {0};
    int chunk_size_str_pos = 0;

    while (1) 
    {
        if (ssl) 
        {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        } 
        else 
        {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        }

        if (bytes_received <= 0) 
        {
            break;
        }

        buffer[bytes_received] = '\0';

        if (!headers_done) 
        {
            char *header_end = strstr(buffer, "\r\n\r\n");
            if (header_end) 
            {
                headers_done = 1;
                body_start = header_end + 4;
                
                sscanf(buffer, "HTTP/1.1 %d", &status_code);
                printf("HTTP Status Code: %d\n", status_code);

                if (status_code >= 300 && status_code < 400) 
                {
                    char new_location[MAX_URL_LENGTH] = {0};
                    char *location = strstr(buffer, "Location: ");
                    if (location) 
                    {
                        sscanf(location, "Location: %s", new_location);
                        char full_url[MAX_URL_LENGTH];
                        if (normalize_url(url, new_location, full_url, MAX_URL_LENGTH) == SUCCESS) 
                        {
                            printf("Redirecting to: %s\n", full_url);
                            free(content->data);
                            free(content);
                            return fetch_url(full_url, redirect_count + 1, final_url, final_url_size);
                        }
                    }
                }
                else if (status_code == 200)
                {
                    strncpy(final_url, url, final_url_size);
                    final_url[final_url_size - 1] = '\0';
                }
                else if (status_code >= 400) 
                {
                    fprintf(stderr, "Error response: %d for URL %s\n", status_code, url);
                    free(content->data);
                    free(content);
                    return NULL;
                }

                char *content_type = strstr(buffer, "Content-Type: ");
                if (content_type) 
                {
                    sscanf(content_type, "Content-Type: %255[^\r\n]", content->content_type);
                }

                if (strstr(buffer, "Transfer-Encoding: chunked") != NULL) 
                {
                    is_chunked = 1;
                    printf("Detected chunked transfer encoding\n");
                }

                bytes_received -= (body_start - buffer);
                chunk_start = body_start;
            }
        }

        if (is_chunked && headers_done) 
        {
            char *current = chunk_start;
            while (current < buffer + bytes_received) 
            {
                if (chunk_size == 0) 
                {
                    // 讀取chunk大小
                    while (*current != '\r' && current < buffer + bytes_received) 
                    {
                        if (chunk_size_str_pos < sizeof(chunk_size_str) - 1) 
                        {
                            chunk_size_str[chunk_size_str_pos++] = *current;
                        }
                        current++;
                    }
                    
                    if (*current == '\r') 
                    {
                        chunk_size_str[chunk_size_str_pos] = '\0';
                        sscanf(chunk_size_str, "%zx", &chunk_size);
                        chunk_size_str_pos = 0;
                        current += 2; // 跳過 \r\n
                        
                        if (chunk_size == 0) 
                        {
                            // 最後一個chunk
                            break;
                        }
                    } 
                    else 
                    {
                        // chunk大小不完整,等待更多數據
                        break;
                    }
                }

                // 讀取chunk數據
                size_t remaining = buffer + bytes_received - current;
                size_t to_copy = (chunk_size < remaining) ? chunk_size : remaining;
                
                char *new_data = realloc(content->data, response_size + to_copy);
                if (!new_data) 
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(content->data);
                    free(content);
                    return NULL;
                }
                content->data = new_data;
                
                memcpy(content->data + response_size, current, to_copy);
                response_size += to_copy;
                current += to_copy;
                chunk_size -= to_copy;

                if (chunk_size == 0) 
                {
                    current += 2; // 跳過每個chunk後的 \r\n
                }

                chunk_start = current;
            }
        } 
        else if (headers_done) 
        {
            // 非chunked數據的處理
            char *new_data = realloc(content->data, response_size + bytes_received);
            if (!new_data) 
            {
                fprintf(stderr, "Memory allocation failed\n");
                free(content->data);
                free(content);
                return NULL;
            }
            content->data = new_data;
            memcpy(content->data + response_size, body_start, bytes_received);
            response_size += bytes_received;
            body_start = buffer;
        }
    }

    if (!content->data) 
    {
        fprintf(stderr, "Failed to receive any data from %s\n", url);
        free(content);
        return NULL;
    }

    content->length = response_size;

    printf("Successfully fetched URL: %s\n", url);
    printf("Final base URL after redirects: %s\n", final_url);
    printf("Content-Type: %s\n", content->content_type);
    printf("Total content length: %zu bytes\n", content->length);

    return content;
}

Content* fetch_url(const char *url, int redirect_count, char *final_url, size_t final_url_size)
{
    if(redirect_count >= MAX_REDIRECTS)
    {
        printf("Max redirects reached for URL: %s\n", url);
        return NULL;
    }

    URL parsed_url;
    parse_url(url, &parsed_url);

    int retries = 0;
    int sockfd = -1;
    while (retries < MAX_RETRIES && sockfd == -1)
    {
        sockfd = connect_to_host(parsed_url.host, parsed_url.port);
        if (sockfd == -1)
        {
            retries++;
            printf("Connection failed, retry %d for URL: %s\n", retries, url);
        }
    }

    if (sockfd == -1) 
    {
        printf("Failed to connect after %d attempts: %s\n", MAX_RETRIES, url);
        return NULL;
    }

    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    if (strcmp(parsed_url.scheme, "https") == 0) 
    {
        ctx = create_ssl_context();
        if (!ctx) 
        {
            close(sockfd);
            return NULL;
        }
        ssl = setup_ssl_connection(sockfd, &ctx);
    }
   
    int bytes_sent = send_request(ssl, sockfd, &parsed_url);

    if (bytes_sent < 0) 
    {
        perror("Failed to send request");
        if (ssl) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        close(sockfd);
        return NULL;
    }

    Content* content = handle_response(ssl, sockfd, url, redirect_count, final_url, final_url_size);
    if (ssl) 
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);

    return content;
}

int normalize_url(const char *base_url, const char *rel_url, char *result, size_t result_size) 
{
    URL base_parsed;
    parse_url(base_url, &base_parsed);

    if (strncmp(rel_url, "http://", 7) == 0 || strncmp(rel_url, "https://", 8) == 0) 
    {
        strncpy(result, rel_url, result_size);
        result[result_size - 1] = '\0';
        return SUCCESS;
    } 
    else if (rel_url[0] == '/') 
    {
        snprintf(result, result_size, "%s://%s%s", base_parsed.scheme, base_parsed.host, rel_url);
        return SUCCESS;
    } 
    else 
    {
        const char *path_end = strrchr(base_parsed.path, '/');
        if (path_end)
        {
            size_t base_path_len = path_end - base_parsed.path + 1;
            snprintf(result, result_size, "%s://%s%.*s%s", 
                     base_parsed.scheme, base_parsed.host, (int)base_path_len, base_parsed.path, rel_url);
        } 
        else
        {
            snprintf(result, result_size, "%s://%s/%s", 
                     base_parsed.scheme, base_parsed.host, rel_url);
        }
        return SUCCESS;
    }
    return ERR_NORMALIZE_URL;
}

int extract_links(const char *html_content, const char *base_url, char **links, int *link_count) 
{
    const char *body_start = strstr(html_content, "<body");
    const char *body_end = strstr(html_content, "</body>");

    if (!body_start || !body_end || body_end <= body_start) 
    {
        fprintf(stderr, "No valid body content found\n");
        *link_count = 0;
        return ERR_BODY_NOT_FOUND;
    }

    body_start = strchr(body_start, '>');
    if (!body_start) 
    {
        fprintf(stderr, "Malformed body tag\n");
        *link_count = 0;
        return ERR_WRON_BODY_TAG;
    }
    body_start++;

    const char *ptr = body_start;
    *link_count = 0;

    while (ptr < body_end && (ptr = strstr(ptr, "<a ")) != NULL) 
    {
        ptr += 2; // move after "<a"
        const char *href = strstr(ptr, "href=");
        if (!href || href >= body_end) continue;

        href += 5; // move after href=
        char quote = *href; // get " or '
        const char *end;

        if (quote != '"' && quote != '\'') 
        {
            end = strpbrk(href, " >");
        } 
        else 
        {
            href++;
            end = strchr(href, quote);
        }

        if (!end || end > body_end) continue;

        int len = end - href;
        if (len == 0) continue;

        char *link = malloc(len + 1);
        if (!link) {
            fprintf(stderr, "Memory allocation failed\n");
            continue;
        }
        strncpy(link, href, len);
        link[len] = '\0';

        char full_url[MAX_URL_LENGTH];
        normalize_url(base_url, link, full_url, sizeof(full_url));

        if (*link_count < MAX_LINKS) 
        {
            links[*link_count] = strdup(full_url);
            (*link_count)++;
        }

        free(link);
        ptr = (quote != '"' && quote != '\'') ? end : end + 1;
    }

    printf("Extracted %d links from body\n", *link_count);
    return SUCCESS;
}

void create_filename(const char *url, const char *content_type, char *filename, size_t filename_size) 
{
    const char *start = strstr(url, "://");
    start = start ? start + 3 : url;
    size_t i = 0;
    while (*start && i < filename_size - 5)
    { 
        if (*start == '/' || *start == '?' || *start == '&' || *start == '=') 
        {
            filename[i++] = '_';
        } 
        else if (*start != ':') 
        {
            filename[i++] = *start;
        }
        start++;
    }
    
    const char *extension = ".bin";
    if (strstr(content_type, "text/html")) 
    {
        extension = ".html";
    } 
    else if (strstr(content_type, "application/pdf")) 
    {
        extension = ".pdf";
    } 
    else if (strstr(content_type, "image/jpeg")) 
    {
        extension = ".jpg";
    } 
    else if (strstr(content_type, "application/msword")) 
    {
        extension = ".doc";
    }
    
    strncpy(filename + i, extension, filename_size - i);
    filename[filename_size - 1] = '\0';
}

int save_content(const char *url,  Content *content, const char *output_dir) 
{
    char filename[MAX_FILENAME];
    create_filename(url, content->content_type, filename, sizeof(filename));
    
    char full_path[MAX_FILENAME * 2];
    snprintf(full_path, sizeof(full_path), "%s/%s", output_dir, filename);
    char *begin = content->data;
    
    FILE *fp = fopen(full_path, "wb");
    if (fp) 
    {
        fwrite(content->data, 1, content->length-(content->data-begin), fp);
        fclose(fp);
        printf("Content saved to: %s\n", full_path);
        return SUCCESS;
    } 
    else 
    {
        printf("Failed to open file: %s\n", full_path);
        return ERR_FILE_OPEN_FAIL;
    }
}

int is_url_visited(const char *url, char **visited_urls, int visited_count) 
{
    for (int i = 0; i < visited_count; i++) 
    {
        if (strcmp(url, visited_urls[i]) == 0) 
        {
            return 1;
        }
    }
    return 0;
}

void crawl_level(const char *start_url, const char *output_dir, int current_depth, char **visited_urls, int *visited_count)  
{
    if (current_depth > MAX_DEPTH || *visited_count >= MAX_VISITED_URLS) {
        return;
    }

    char base_url[MAX_URL_LENGTH];
    strncpy(base_url, start_url, MAX_URL_LENGTH);
    base_url[MAX_URL_LENGTH - 1] = '\0';

    if (is_url_visited(start_url, visited_urls, *visited_count)) {
        printf("URL already visited: %s\n", start_url);
        return;
    }

    visited_urls[*visited_count] = strdup(start_url);
    (*visited_count)++;

    Content *content = fetch_url(start_url, 0, base_url, MAX_URL_LENGTH);
    if (!content) 
    {
        printf("Failed to fetch: %s\n", start_url);
        return;
    }

    printf("Successfully fetched URL: %s\n", base_url);
    printf("Content-Type: %s\n", content->content_type);
    
    save_content(base_url, content, output_dir);

    if (strstr(content->content_type, "text/html")) 
    {
        char *links[MAX_LINKS];
        int link_count = 0;
        extract_links(content->data, base_url, links, &link_count);

        printf("Found %d links in %s\n", link_count, base_url);

        for (int i = 0; i < link_count; i++) 
        {
            char full_url[MAX_URL_LENGTH];
            if (normalize_url(base_url, links[i], full_url, MAX_URL_LENGTH) == SUCCESS)
            {
                crawl_level(full_url, output_dir, current_depth + 1, visited_urls, visited_count);
            }
            free(links[i]);
        }
    }

    free(content->data);
    free(content);

    printf("Finished crawling: %s (Depth: %d)\n", start_url, current_depth);
}

int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        fprintf(stderr, "Usage: %s [Start URL] [Output Directory]\n", argv[0]);
        return 1;
    }

    const char *start_url = argv[1];
    const char *output_dir = argv[2];

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    struct stat st = {0};
    if (stat(output_dir, &st) == -1) 
    {
        mkdir(output_dir, 0700);
    }
    char* visited_url[MAX_VISITED_URLS] = {0};
    int visited_count = 0;

    crawl_level(start_url, output_dir, 1, visited_url, &visited_count);

    EVP_cleanup();
    ERR_free_strings();

    for (int i = 0; i < visited_count; i++) {
        free(visited_url[i]);
    }

    return 0;
}