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
#define OVERLAP_SIZE            100  

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
    size_t length;
    char content_type[256];
    char filename[MAX_FILENAME];
} Content;

typedef struct {
    char urls[MAX_LINKS][MAX_URL_LENGTH];
    int visited[MAX_LINKS];  // 0 havent visit，1 visited
    int count;
} Link_storage;

SSL_CTX *create_ssl_context();
void parse_url(const char *url, URL *parsed_url);
int connect_to_host(const char *hostname, int port);
SSL *setup_ssl_connection(int sockfd, SSL_CTX **ctx);
int is_url_visited(const char *url, Link_storage *pool) ;
int send_request(SSL *ssl, int sockfd, const URL *parsed_url);
int normalize_url(const char *base_url, const char *rel_url, char *result, size_t result_size);
void create_filename(const char *url, const char *content_type, char *filename, size_t filename_size);
void crawl_level(const char *start_url, const char *output_dir, int current_depth, Link_storage *pool);
Content* fetch_url(const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir, Link_storage *links);
void extract_links(const char *html_content, size_t content_length, const char *base_url, Link_storage *pool, char *overlap_buffer, size_t *overlap_size);
Content* handle_response(SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir, Link_storage *links);

void parse_url(const char *url, URL *parsed_url) 
{
    const char *scheme_end = strstr(url, "://");
    if (scheme_end) 
    {
        strncpy(parsed_url->scheme, url, scheme_end - url);
        parsed_url->scheme[scheme_end - url] = '\0';
        url = scheme_end + 3;
    } 
    else strcpy(parsed_url->scheme, "http");
    

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
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) continue;
        
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        int connect_result = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if (connect_result == 0) 
        {
            fcntl(sockfd, F_SETFL, flags);
            break;
        } 
        else if (errno != EINPROGRESS)// trying to connect 
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
    if (!ctx) 
    {
        printf("Unable to create SSL context\n");
        return NULL;
    }
    return ctx;
}

SSL *setup_ssl_connection(int sockfd, SSL_CTX **ctx) 
{
    *ctx = create_ssl_context();
    if (!*ctx)  return NULL;

    SSL *ssl = SSL_new(*ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) 
    {
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

    if (ssl)  bytes_sent = SSL_write(ssl, request, strlen(request));
    else      bytes_sent = send(sockfd, request, strlen(request), 0);
    
    return bytes_sent > 0 ? SUCCESS : ERR_SEND_REQST_FAIL;
}

Content* handle_response(SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir, Link_storage *pool) 
{
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int status_code = 0;
    Content *content = malloc(sizeof(Content));
    if (!content) return NULL;
    content->length = 0;
    content->content_type[0] = '\0';

    FILE *fp = NULL;
    char filename[MAX_FILENAME];
    int headers_done = 0;
    char *body_start = NULL;
    int is_chunked = 0;

    char overlap_buffer[OVERLAP_SIZE] = {0};
    size_t overlap_size = 0;

    // chunck state define
    enum ChunkState { CHUNK_SIZE, CHUNK_DATA, CHUNK_END } chunk_state = CHUNK_SIZE;
    size_t current_chunk_size = 0;
    size_t remaining_chunk_size = 0;
    char chunk_size_buffer[20] = {0};
    int chunk_size_index = 0;

    while (1) 
    {
        if (ssl) bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        else     bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) break;

        buffer[bytes_received] = '\0';
        char *current_pos = buffer;
        size_t remaining_bytes = bytes_received;

        if (!headers_done) 
        {
            char *header_end = strstr(current_pos, "\r\n\r\n");
            if (header_end) 
            {
                headers_done = 1;
                body_start = header_end + 4;
                remaining_bytes -= (body_start - current_pos);
                current_pos = body_start;

                sscanf(buffer, "HTTP/1.1 %d", &status_code);
                printf("HTTP Status Code: %d\n", status_code);

                if (status_code >= 300 && status_code < 400) 
                {
                    // handle redirect
                    char new_location[MAX_URL_LENGTH] = {0};
                    char *location = strstr(buffer, "Location: ");
                    if (location && sscanf(location, "Location: %s", new_location) == 1) 
                    {
                        char full_url[MAX_URL_LENGTH];
                        if (normalize_url(url, new_location, full_url, MAX_URL_LENGTH) == SUCCESS) 
                        {
                            printf("Redirecting to: %s\n", full_url);
                            free(content);
                            return fetch_url(full_url, redirect_count + 1, final_url, final_url_size, output_dir, pool);
                        }
                    }
                }
                else if (status_code == 200)
                {
                    strncpy(final_url, url, final_url_size - 1);
                    final_url[final_url_size - 1] = '\0';
                }
                else if (status_code >= 400) 
                {
                    fprintf(stderr, "Error response: %d for URL %s\n", status_code, url);
                    free(content);
                    return NULL;
                }

                char *content_type = strstr(buffer, "Content-Type: ");
                if (content_type) 
                {
                    sscanf(content_type, "Content-Type: %255[^\r\n]", content->content_type);
                    create_filename(url, content->content_type, filename, sizeof(filename));
                    char full_path[MAX_FILENAME * 2];
                    snprintf(full_path, sizeof(full_path), "%s/%s", output_dir, filename);
                    fp = fopen(full_path, "wb");
                    if (!fp) 
                    {
                        fprintf(stderr, "Failed to open file for writing: %s\n", full_path);
                        free(content);
                        return NULL;
                    }
                }
                is_chunked = (strstr(buffer, "Transfer-Encoding: chunked") != NULL);
            }
        }

        if (fp)
        {
            if (is_chunked) 
            {
                while (remaining_bytes > 0)
                {
                    switch (chunk_state)
                    {
                        case CHUNK_SIZE:
                            while (remaining_bytes > 0 && chunk_size_index < 19 && *current_pos != '\r' && *current_pos != '\n')
                            {
                                chunk_size_buffer[chunk_size_index++] = *current_pos++;
                                remaining_bytes--;
                            }
                            if (remaining_bytes > 0 && (*current_pos == '\r' || *current_pos == '\n'))
                            {
                                chunk_size_buffer[chunk_size_index] = '\0';
                                current_chunk_size = strtol(chunk_size_buffer, NULL, 16);
                                remaining_chunk_size = current_chunk_size;
                                chunk_size_index = 0;
                                chunk_state = CHUNK_DATA;
                                while (remaining_bytes > 0 && (*current_pos == '\r' || *current_pos == '\n'))
                                {
                                    current_pos++;
                                    remaining_bytes--;
                                }
                            }
                            break;

                        case CHUNK_DATA:
                            {
                                size_t write_size = (remaining_chunk_size < remaining_bytes) ? remaining_chunk_size : remaining_bytes;
                                fwrite(current_pos, 1, write_size, fp);
                                content->length += write_size;
                                if (strstr(content->content_type, "text/html"))
                                {
                                    extract_links(current_pos, write_size, url, pool, overlap_buffer, &overlap_size);
                                }
                                current_pos += write_size;
                                remaining_bytes -= write_size;
                                remaining_chunk_size -= write_size;

                                if (remaining_chunk_size == 0)
                                {
                                    chunk_state = CHUNK_END;
                                }
                            }
                            break;

                        case CHUNK_END:
                            while (remaining_bytes > 0 && (*current_pos == '\r' || *current_pos == '\n'))
                            {
                                current_pos++;
                                remaining_bytes--;
                            }
                            chunk_state = CHUNK_SIZE;

                            if (current_chunk_size == 0)  goto end_of_response; // Last chunk
                            break;
                    }
                }
            } 
            else 
            {
                fwrite(current_pos, 1, remaining_bytes, fp);
                content->length += remaining_bytes;
                if (strstr(content->content_type, "text/html"))
                {
                    extract_links(current_pos, remaining_bytes, url, pool, overlap_buffer, &overlap_size);
                }
            }
        }
    }

    end_of_response:
    
    if (fp) fclose(fp);
    if (content->length == 0) 
    {
        fprintf(stderr, "Failed to receive any data from %s\n", url);
        free(content);
        return NULL;
    }

    printf("Successfully fetched URL: %s\n", url);
    printf("Final base URL after redirects: %s\n", final_url);
    printf("Content-Type: %s\n", content->content_type);
    printf("Total content length: %zu bytes\n", content->length);

    return content;
}

Content* fetch_url(const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir, Link_storage *pool)
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
        if (ssl) 
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        close(sockfd);
        return NULL;
    }

    Content* content = handle_response(ssl, sockfd, url, redirect_count, final_url, final_url_size, output_dir, pool );
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

void extract_links(const char *html_content, size_t content_length, const char *base_url, Link_storage *pool, char *overlap_buffer, size_t *overlap_size) 
{
    // deal with overlap
    char *combined = malloc(OVERLAP_SIZE + content_length + 1);
    if (!combined) 
    {
        fprintf(stderr, "Memory allocation failed in extract_links\n");
        return;
    }
    memcpy(combined, overlap_buffer, *overlap_size);
    memcpy(combined + *overlap_size, html_content, content_length);
    combined[*overlap_size + content_length] = '\0';
    size_t total_length = *overlap_size + content_length;

    const char *ptr = combined;
    const char *end = combined + total_length;

    while ((ptr = strstr(ptr, "<a ")) != NULL && ptr < end) 
    {
        const char *href = strstr(ptr, "href");
        if (!href || href >= end) break;

        href += 4; // move after href
        while (href < end && (*href == ' ' || *href == '\t' || *href == '\n' || *href == '\r')) href++; // move after space
        
        if (href >= end || *href != '=') continue;

        href++; // move after '='
        while (href < end && (*href == ' ' || *href == '\t' || *href == '\n' || *href == '\r')) href++;// move after space

        if (href >= end) break;

        char quote = 0;
        if (*href == '"' || *href == '\'') 
        {
            quote = *href;
            href++;
        }

        const char *link_end = href;
        if (quote)  link_end = strchr(href, quote);
        else 
        {
            while (link_end < end && *link_end != ' ' && *link_end != '>' && *link_end != '\n' && *link_end != '\r') link_end++;
        }

        if (!link_end || link_end >= end) break;

        size_t link_length = link_end - href;
        if (link_length > 0 && link_length < MAX_URL_LENGTH) 
        {
            char link[MAX_URL_LENGTH];
            strncpy(link, href, link_length);
            link[link_length] = '\0';

            char full_url[MAX_URL_LENGTH];
            if (normalize_url(base_url, link, full_url, sizeof(full_url)) == SUCCESS) 
            {
                if (pool->count < MAX_LINKS && !is_url_visited(full_url, pool)) 
                {
                    strncpy(pool->urls[pool->count], full_url, MAX_URL_LENGTH - 1);
                    pool->urls[pool->count][MAX_URL_LENGTH - 1] = '\0';
                    pool->visited[pool->count] = 0;
                    pool->count++;
                    printf("Added to pool: %s\n", full_url);  
                }
            }
        }
        ptr = link_end + 1;
    }

    // update buffer for overlap
    *overlap_size = (total_length > OVERLAP_SIZE) ? OVERLAP_SIZE : total_length;
    memcpy(overlap_buffer, combined + total_length - *overlap_size, *overlap_size);

    free(combined);
}

void create_filename(const char *url, const char *content_type, char *filename, size_t filename_size) 
{
    const char *start = strstr(url, "://");
    start = start ? start + 3 : url;
    size_t i = 0;

    while (*start && i < filename_size - 5)
    { 
        if (*start == '/' || *start == '?' || *start == '&' || *start == '=') filename[i++] = '_';
        else if (*start != ':') filename[i++] = *start;

        start++;
    }
    
    const char *extension = ".bin";

    if (strstr(content_type, "text/html"))               extension = ".html";
    else if (strstr(content_type, "application/pdf"))    extension = ".pdf";
    else if (strstr(content_type, "image/jpeg"))         extension = ".jpg";
    else if (strstr(content_type, "application/msword")) extension = ".doc";
    
    strncpy(filename + i, extension, filename_size - i);
    filename[filename_size - 1] = '\0';
}

int is_url_visited(const char *url, Link_storage *pool) 
{
    for (int i = 0; i < pool->count; i++) 
    {
        if (strcmp(url, pool->urls[i]) == 0) return (pool->visited[i] == 1) ? 1 : 0;
    }

    return 0;
}

void crawl_level(const char *start_url, const char *output_dir, int current_depth, Link_storage *pool)  
{
    if (current_depth > MAX_DEPTH || pool->count >= MAX_VISITED_URLS) return;

    char final_url[MAX_URL_LENGTH];
    strncpy(final_url, start_url, MAX_URL_LENGTH);
    final_url[MAX_URL_LENGTH - 1] = '\0';

    if (is_url_visited(final_url, pool)) 
    {
        printf("URL already visited: %s\n", final_url);
        return;
    }

    strncpy(pool->urls[pool->count], final_url, MAX_URL_LENGTH - 1);
    pool->urls[pool->count][MAX_URL_LENGTH - 1] = '\0';
    pool->visited[pool->count] = 1; 
    pool->count++;

    Content *content = fetch_url(start_url, 0, final_url, MAX_URL_LENGTH, output_dir, pool);
    if (!content) 
    {
        printf("Failed to fetch: %s\n", start_url);
        return;
    }
    
    printf("Successfully fetched URL: %s\n", final_url);
    printf("Content-Type: %s\n", content->content_type);
    
    for (int i = 0; i < pool->count; i++) 
    {
        if (!pool->visited[i])
        {
            crawl_level(pool->urls[i], output_dir, current_depth + 1, pool);
        }
    }
    
    free(content);

    printf("Finished crawling: %s (Depth: %d)\n", final_url, current_depth);
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

    struct stat st = {0}; //for file state
    if (stat(output_dir, &st) == -1) mkdir(output_dir, 0700); //to get file state
    
    Link_storage pool;
    for (int i = 0; i < MAX_LINKS; i++) 
    {
        pool.urls[i][0] = '\0';
        pool.visited[i] = 0;
    }
    pool.count = 0;

    crawl_level(start_url, output_dir, 1, &pool);

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}