#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define BUFFER_SIZE 4096
#define MAX_LINKS 1000

typedef struct {
    char url[1024];
    char host[256];
    char path[1024];
    int port;
    int is_https;
} URL;

void parse_url(const char *url, URL *parsed_url) {
    char *protocol = strstr(url, "://");
    const char *host_start = protocol ? protocol + 3 : url;
    
    parsed_url->is_https = (strncmp(url, "https", 5) == 0);
    parsed_url->port = parsed_url->is_https ? 443 : 80;

    const char *path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(parsed_url->host, host_start, path_start - host_start);
        parsed_url->host[path_start - host_start] = '\0';
        strcpy(parsed_url->path, path_start);
    } else {
        strcpy(parsed_url->host, host_start);
        strcpy(parsed_url->path, "/");
    }

    strcpy(parsed_url->url, url);
}

int create_socket(const char *host, int port) {
    struct addrinfo hints, *res, *p;
    int sockfd;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1) {
            break;
        }

        close(sockfd);
    }

    freeaddrinfo(res);
    return (p == NULL) ? -1 : sockfd;
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

int send_request(SSL *ssl, int sockfd, const URL *url) {
    char request[BUFFER_SIZE];
    int bytes_sent;

    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
             "Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
             "Connection: close\r\n\r\n",
             url->path, url->host);

    if (url->is_https) {
        bytes_sent = SSL_write(ssl, request, strlen(request));
    } else {
        bytes_sent = send(sockfd, request, strlen(request), 0);
    }

    return bytes_sent;
}

int receive_response(SSL *ssl, int sockfd, const char *output_dir, const URL *url, char **links, int *link_count) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    FILE *file = NULL;
    int chunked = 0;
    int content_length = -1;
    int body_started = 0;
    int status_code = 0;
    char filename[1024];
    char *file_basename = strrchr(url->path, '/');
    if (file_basename == NULL || *(file_basename + 1) == '\0') {
        file_basename = "index.html";
    } else {
        file_basename++; // 跳過 '/'
    }
    snprintf(filename, sizeof(filename), "%s/%s", output_dir, file_basename);

    // 創建輸出目錄（如果不存在）
    char mkdir_command[1024];
    snprintf(mkdir_command, sizeof(mkdir_command), "mkdir -p %s", output_dir);
    system(mkdir_command);

    file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open output file");
        fprintf(stderr, "Attempted to open file: %s\n", filename);
        return -1;
    }

    while (1) {
        if (url->is_https) {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        } else {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        }

        if (bytes_received <= 0) break;

        buffer[bytes_received] = '\0';

        if (!body_started) {
            char *body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                body_started = 1;
                body_start += 4;

                // Parse headers
                char *status_line = strstr(buffer, "HTTP/1.1");
                if (status_line) {
                    sscanf(status_line, "HTTP/1.1 %d", &status_code);
                }

                char *transfer_encoding = strcasestr(buffer, "Transfer-Encoding: chunked");
                if (transfer_encoding) {
                    chunked = 1;
                }

                char *content_length_header = strcasestr(buffer, "Content-Length:");
                if (content_length_header) {
                    sscanf(content_length_header, "Content-Length: %d", &content_length);
                }

                // Write body part to file
                fwrite(body_start, 1, bytes_received - (body_start - buffer), file);
            } else {
                continue;  // Still in headers, skip
            }
        } else {
            // Process body
            fwrite(buffer, 1, bytes_received, file);
        }

        // Parse HTML for links
        char *link_start = buffer;
        while ((link_start = strstr(link_start, "href=\"")) != NULL) {
            link_start += 6;  // Move past href="
            char *link_end = strchr(link_start, '"');
            if (link_end && *link_count < MAX_LINKS) {
                int link_length = link_end - link_start;
                links[*link_count] = malloc(link_length + 1);
                strncpy(links[*link_count], link_start, link_length);
                links[*link_count][link_length] = '\0';
                (*link_count)++;
            }
            link_start = link_end;
        }
    }

    fclose(file);
    printf("Status Code: %d\n", status_code);
    printf("Content saved to: %s\n", filename);
    return status_code;
}

int crawl_url(const char *url, const char *output_dir) {
    URL parsed_url;
    parse_url(url, &parsed_url);

    int sockfd = create_socket(parsed_url.host, parsed_url.port);
    if (sockfd == -1) {
        perror("Failed to create socket");
        return -1;
    }

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (parsed_url.is_https) {
        ctx = create_ssl_context();
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return -1;
        }
    }

    if (send_request(ssl, sockfd, &parsed_url) < 0) {
        perror("Failed to send request");
        if (parsed_url.is_https) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
        close(sockfd);
        return -1;
    }

    char *links[MAX_LINKS];
    int link_count = 0;
    int status_code = receive_response(ssl, sockfd, output_dir, &parsed_url, links, &link_count);

    printf("Found %d links:\n", link_count);
    for (int i = 0; i < link_count; i++) {
        printf("%s\n", links[i]);
        free(links[i]);
    }

    if (parsed_url.is_https) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    close(sockfd);

    return status_code;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s [Start URL] [Output Directory]\n", argv[0]);
        return 1;
    }

    const char *start_url = argv[1];
    const char *output_dir = argv[2];

    init_openssl();
    int status = crawl_url(start_url, output_dir);
    cleanup_openssl();

    return (status >= 200 && status < 300) ? 0 : 1;
}