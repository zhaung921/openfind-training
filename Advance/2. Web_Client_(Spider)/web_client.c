#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_FILENAME 256
#define MAX_URL_LENGTH 2048
#define MAX_LINKS 1000
#define BUFFER_SIZE 4096
#define MAX_VISITED_URLS 10000
#define MAX_DEPTH 2

typedef struct {
char scheme[8];
char host[256];
char path[1024];
int port;
} URL;

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
    int sockfd = -1;
    char port_str[6];
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP 

    snprintf(port_str, sizeof(port_str), "%d", port);

    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) 
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    
    for(p = res; p != NULL; p = p->ai_next) 
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)//creat new socket 
        {
            perror("socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)//connect 
        {
            close(sockfd);
            perror("connect");
            continue;
        }

        break; 
    }

    if (p == NULL) 
    {
        fprintf(stderr, "Failed to connect\n");
        return -1;
    }
    freeaddrinfo(res); 

    return sockfd;
}

SSL_CTX* create_ssl_context() 
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

char *fetch_url(const char *url) 
{
    URL parsed_url;
    parse_url(url, &parsed_url);

    int sockfd = connect_to_host(parsed_url.host, parsed_url.port);
    if (sockfd == -1) 
    {
        return NULL;
    }

    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    if (strcmp(parsed_url.scheme, "https") == 0) 
    {
        ctx = create_ssl_context();
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) 
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return NULL;
        }
    }

    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: SimpleWebCrawler/1.0\r\n"
                "Connection: close\r\n\r\n",
                parsed_url.path, parsed_url.host);

    if (ssl) 
    {
        SSL_write(ssl, request, strlen(request));
    } 
    else 
    {
        send(sockfd, request, strlen(request), 0);
    }

    char *response = NULL;
    size_t response_size = 0;
    char buffer[BUFFER_SIZE];
    int bytes_received;

    while (1) //store into respons
    {
        if (ssl) 
        {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        } 
        else 
        {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        }

        if (bytes_received <= 0) break;

        buffer[bytes_received] = '\0';
        response = realloc(response, response_size + bytes_received + 1);
        memcpy(response + response_size, buffer, bytes_received);
        response_size += bytes_received;
    }

    if (response) 
    {
        response[response_size] = '\0';
    }

    if (ssl) 
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);
    return response;
}

void normalize_url(const char *base_url, const char *rel_url, char *result, size_t result_size) 
{
    if (strncmp(rel_url, "http://", 7) == 0 || strncmp(rel_url, "https://", 8) == 0) 
    {
        // 绝对 URL
        strncpy(result, rel_url, result_size);
        result[result_size - 1] = '\0';
    } 
    else if (rel_url[0] == '/') 
    {
        // 相对于根的 URL
        const char *scheme_end = strstr(base_url, "://");
        if (scheme_end) 
        {
            const char *domain_end = strchr(scheme_end + 3, '/');
            if (domain_end) 
            {
                size_t base_len = domain_end - base_url;
                strncpy(result, base_url, base_len);
                result[base_len] = '\0';
                strncat(result, rel_url, result_size - base_len - 1);
            } 
            else 
            {
                snprintf(result, result_size, "%s%s", base_url, rel_url);
            }
        }
    } 
    else 
    {
        // 相对 URL
        const char *last_slash = strrchr(base_url, '/');
        if (last_slash) 
        {
            size_t base_len = last_slash - base_url + 1;
            strncpy(result, base_url, base_len);
            result[base_len] = '\0';
            strncat(result, rel_url, result_size - base_len - 1);
        } 
        else 
        {
            snprintf(result, result_size, "%s/%s", base_url, rel_url);
        }
    }
}

void extract_links(const char *html_content, const char *base_url, char **links, int *link_count) 
{
    const char *body_start = strstr(html_content, "<body");
    const char *body_end = strstr(html_content, "</body>");

    if (!body_start || !body_end || body_end <= body_start) 
    {
        fprintf(stderr, "No valid body content found\n");
        *link_count = 0;
        return;
    }

    body_start = strchr(body_start, '>');
    if (!body_start) 
    {
        fprintf(stderr, "Malformed body tag\n");
        *link_count = 0;
        return;
    }
    body_start++;

    const char *ptr = body_start;
    *link_count = 0;

    while (ptr < body_end && (ptr = strstr(ptr, "<a ")) != NULL) 
    {
        ptr += 2; // 移動到 'a' 之後
        const char *href = strstr(ptr, "href=");
        if (!href || href >= body_end) continue;

        href += 5; // 移動到 href= 之後
        char quote = *href; // 獲取引號類型 (' 或 ")
        if (quote != '"' && quote != '\'') 
        {
            // 如果沒有引號，直接查找空格或 '>'
            const char *end = strpbrk(href, " >");
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

            // 規範化 URL
            char full_url[MAX_URL_LENGTH];
            normalize_url(base_url, link, full_url, sizeof(full_url));

            if (*link_count < MAX_LINKS) 
            {
                links[*link_count] = strdup(full_url);
                if (!links[*link_count]) 
                {
                    fprintf(stderr, "Memory allocation failed for link\n");
                    free(link);
                    continue;
                }
                (*link_count)++;
            }

            free(link);
            ptr = end;
        } 
        else 
        {
            href++; // 移動到 URL 開始
            const char *end = strchr(href, quote);
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

            // 規範化 URL
            char full_url[MAX_URL_LENGTH];
            normalize_url(base_url, link, full_url, sizeof(full_url));

            if (*link_count < MAX_LINKS) 
            {
                links[*link_count] = strdup(full_url);
                if (!links[*link_count]) 
                {
                    fprintf(stderr, "Memory allocation failed for link\n");
                    free(link);
                    continue;
                }
                (*link_count)++;
            }

            free(link);
            ptr = end + 1;
        }
    }

    printf("Extracted %d links from body\n", *link_count);
}

void create_filename(const char *url, char *filename, size_t filename_size) 
{
    const char *start = strstr(url, "://");
    start = start ? start + 3 : url;
    size_t i = 0;
    while (*start && i < filename_size - 5)// -5 for ".html" and null terminator
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
    strcpy(filename + i, ".html");
}

void save_body_content(const char *url, const char *content, const char *output_dir) 
{
    const char *body_start = strstr(content, "<body");
    const char *body_end = strstr(content, "</body>");

    if (body_start && body_end && body_end > body_start) 
    {
        body_start = strchr(body_start, '>');
        if (body_start) 
        {
            body_start++; // 移動到 body 標籤之後

            char filename[MAX_FILENAME];
            create_filename(url, filename, sizeof(filename));
            char full_path[MAX_FILENAME * 2];
            snprintf(full_path, sizeof(full_path), "%s/%s", output_dir, filename);
        
            FILE *fp = fopen(full_path, "w");
            if (fp) 
            {
                fwrite(body_start, 1, body_end - body_start, fp);
                fclose(fp);
                printf("Body content saved to: %s\n", full_path);
            } 
            else 
            {
                fprintf(stderr, "Failed to open file: %s\n", full_path);
            }
        }
    } 
    else 
    {
        fprintf(stderr, "No body content found in response from %s\n", url);
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

void crawl_recursive(const char *url, const char *output_dir, char **visited_urls, int *visited_count, int depth) 
{
    if (depth > 5 || *visited_count >= MAX_VISITED_URLS) 
    {  
        return;
    }

    if (is_url_visited(url, visited_urls, *visited_count)) 
    {
        return;
    }

    printf("Crawling (depth %d): %s\n", depth, url);

    // store visited url
    visited_urls[*visited_count] = strdup(url);
    (*visited_count)++;

    char *response = fetch_url(url);
    if (!response) 
    {
        printf("Failed to fetch: %s\n", url);
        return;
    }

    save_body_content(url, response, output_dir);

    char *links[MAX_LINKS];
    int link_count = 0;
    extract_links(response, url, links, &link_count);

    for (int i = 0; i < link_count; i++) 
    {
        crawl_recursive(links[i], output_dir, visited_urls, visited_count, depth + 1);
        free(links[i]);
    }

    free(response);
}

void crawl_level(const char *base_url, const char *output_dir, int current_depth) 
{
    if (current_depth > MAX_DEPTH) 
    {
        return;
    }

    char *response = fetch_url(base_url);
    if (!response) 
    {
        printf("Failed to fetch: %s\n", base_url);
        return;
    }

    
    save_body_content(base_url, response, output_dir);

    char *links[MAX_LINKS];
    int link_count = 0;
    extract_links(response, base_url, links, &link_count);

    printf("Level %d: Found %d links in %s\n", current_depth, link_count, base_url);

    for (int i = 0; i < link_count; i++) 
    {
        char *next_response = fetch_url(links[i]);
        if (next_response) 
        {
            save_body_content(links[i], next_response, output_dir);
            free(next_response);
        }
    }

    if (current_depth < MAX_DEPTH) 
    {
        for (int i = 0; i < link_count; i++) 
        {
            crawl_level(links[i], output_dir, current_depth + 1);
        }
    }

    for (int i = 0; i < link_count; i++) 
    {
        free(links[i]);
    }
    free(response);
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

    // init OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    struct stat st = {0};
    if (stat(output_dir, &st) == -1) 
    {
        mkdir(output_dir, 0700);
    }

    crawl_level(start_url, output_dir, 1);

    // clear OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}