#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <bits/waitflags.h>
#include <sys/wait.h> 

#define MAX_FILENAME            256
#define MAX_URL_LENGTH          2048
#define MAX_LINKS               1000
#define BUFFER_SIZE             4096
#define MAX_VISITED_URLS        10000
#define MAX_DEPTH               1
#define MAX_RETRIES             3
#define NUM_CHILD               3
#define MAX_REDIRECTS           10
#define OVERLAP_SIZE            10
#define MAX_SCHEME_SIZE         8
#define MAX_HOST_SIZE           256
#define MAX_PATH_SIZE           104
#define MAX_CONTENT_TYPE_SIZE   256
#define MAX_WAIT_COUNT          100

#define NOT_FOUND               0
#define FOUND                   1

#define HAVEN_VISITED           0
#define DELIVERING              1
#define VISITING                2
#define VISITED                 3
#define VISITED_FAIL            4

#define SHM_NAME "/web_crawler_shm"
#define SEM_NAME "/web_crawler_sem"

#define SUCCESS                 0
#define ERROR_BASE              0
#define ERR_NORMALIZE_URL       ERROR_BASE - 1
#define ERR_GETADDRINFO_FAIL    ERROR_BASE - 2
#define ERR_FAIL_CONNECT        ERROR_BASE - 3
#define ERR_SEND_REQST_FAIL     ERROR_BASE - 4
#define ERR_DUPLICATE_URL       ERROR_BASE - 5
#define ERR_FETCH_CONTENT       ERROR_BASE - 6
#define ERR_FAIL_CRAWL_LEVEL    ERROR_BASE - 7
#define ERR_FAIL_MALLOC         ERROR_BASE - 9
#define ERR_OUT_OF_RANGE        ERROR_BASE - 10
#define ERR_ARGUMENTS           ERROR_BASE - 11
#define ERR_FORK_FAIL           ERROR_BASE - 12
#define ERR_SHM_OPEN_FAIL       ERROR_BASE - 13
#define ERR_SEM_OPEN_FAIL       ERROR_BASE - 14
#define ERR_MAP_FAIL            ERROR_BASE - 15
#define ERR_CREAT_CHILD         ERROR_BASE - 16
#define ERR_INIT_SHM            ERROR_BASE - 17

typedef struct {
    char scheme[MAX_SCHEME_SIZE];
    char host[MAX_HOST_SIZE];
    char path[MAX_PATH_SIZE];
    int port;
} URL;

typedef struct {
    size_t length;
    char content_type[MAX_CONTENT_TYPE_SIZE];
    char filename[MAX_FILENAME];
} Content;

typedef struct {
    char urls[MAX_LINKS][MAX_URL_LENGTH];
    int state[MAX_LINKS];  // 0 havent visit, 1 delivering, 2 visiting, 3 visited, 4 fail
    int depth[MAX_LINKS];
    int count;
    char mutex_name[256];
    int ready;
    int waiting_child;
} link_storage;

sem_t *mutex;
link_storage *shared_pool;
int init_shared_resources() ;
SSL_CTX *create_ssl_context();

int has_unprocessed_urls();
void parent_process(const char *start_url);
int create_child_processes(const char *output_dir);
void parse_url(const char *url, URL *parsed_url);
void child_process(int child_id, const char *output_dir);
int connect_to_host(const char *hostname, int port);
SSL *setup_ssl_connection(int sockfd, SSL_CTX **ctx);
int is_url_visited(const char *url) ;
int send_request(SSL *ssl, int sockfd, const URL *parsed_url);
int normalize_url(const char *base_url, const char *rel_url, char *result, size_t result_size);
void create_filename(const char *url, const char *content_type, char *filename, size_t filename_size);
int crawl_level(const char *start_url, const char *output_dir, int current_depth);
Content* fetch_url(int current_depth, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir);
int extract_links(int current_depth, const char *html_content, size_t content_length, const char *base_url, char *overlap_buffer, size_t *overlap_size);
Content* handle_response(int current_depth, SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir);

int init_shared_resources() 
{
    // creat share memory
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) 
    {
        perror("Error shm_open failed\n");
        return ERR_SHM_OPEN_FAIL;
    }
    
    ftruncate(shm_fd, sizeof(link_storage));
    
    shared_pool = mmap(0, sizeof(link_storage), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shared_pool == MAP_FAILED) 
    {
        printf("Error mmap failed\n");
        return ERR_MAP_FAIL;
    }
    // initial link_storage
    memset(shared_pool, 0, sizeof(link_storage));   
    strcpy(shared_pool->mutex_name, SEM_NAME);
    shared_pool->ready = 0;
    shared_pool->waiting_child = 0;
    // creat posix semaphore
    mutex = sem_open(SEM_NAME, O_CREAT, 0666, 1);
    if (mutex == SEM_FAILED) 
    {
        perror("Error sem_open failed\n");
        return ERR_SEM_OPEN_FAIL;
    }
    
    return SUCCESS;
}

int create_child_processes(const char *output_dir) 
{
    for (int i = 0; i < NUM_CHILD; i++) 
    {
        pid_t pid = fork();
        if (pid == -1) 
        {
            perror("fork failed");
            return ERR_FORK_FAIL;
        } 
        else if (pid == 0) 
        {
            // wait for ready
            while (1) 
            {
                sem_wait(mutex);
                if (shared_pool->ready)
                {
                    sem_post(mutex);
                    break;
                }
                sem_post(mutex);
                usleep(1000); 
            }
            child_process(i, output_dir);
        }
    }
    return SUCCESS;
}

void parent_process(const char *start_url) 
{
    int active_children = NUM_CHILD;
    int urls_to_process = 1; 

    while (active_children > 0) 
    {
        sem_wait(mutex);    // search url and set to deliver
        for (int i = 0; i < shared_pool->count && i < MAX_LINKS; i++) 
        {
            if (shared_pool->state[i] == HAVEN_VISITED) 
            {
                shared_pool->state[i] = DELIVERING;  
                urls_to_process++;
                printf("Parent set URL %s (index: %d) to DELIVERING\n", shared_pool->urls[i], i);
                if(shared_pool->ready == 0) shared_pool->ready = 1;
            }
        }
        sem_post(mutex);

        // check finish child
        int status;
        int sem_status;
        pid_t finished_pid = waitpid(-1, &status, WNOHANG);
        if (finished_pid > 0) 
        {
            active_children--;
            usleep(100000);
            sem_getvalue(mutex,&sem_status);
            if(__sync_fetch_and_add(&shared_pool->waiting_child, 0) >= active_children && sem_status == 0 )
            {
                printf("Child process %d could be crash and locked, reset mutex\n", finished_pid);
                sem_post(mutex);
            }
            else printf("Child process %d has finished.\n", finished_pid);
        }
    }
    printf("All URLs have been processed.\n");
}

void child_process(int child_id, const char *output_dir) 
{
    printf("Child %d started\n", child_id);
    int wait_count = 0;
    while (1) 
    {
        char url[MAX_URL_LENGTH];
        int url_index = -1;
        int current_depth = -1;
       __sync_fetch_and_add(&shared_pool->waiting_child, 1);

        sem_wait(mutex);
         __sync_fetch_and_sub(&shared_pool->waiting_child, 1);
        for (int i = 0; i < shared_pool->count && i < MAX_LINKS; i++) 
        {
            if (shared_pool->state[i] == DELIVERING && shared_pool->depth[i] <= MAX_DEPTH) 
            {  
                url_index = i;
                current_depth = shared_pool->depth[i];
                strncpy(url, shared_pool->urls[i], MAX_URL_LENGTH - 1);
                url[MAX_URL_LENGTH - 1] = '\0';
                shared_pool->state[i] = VISITING;  
                printf("Child %d picked URL: %s (index: %d)\n", child_id, url, i);
                break;
            } 
        }
        sem_post(mutex);

        if (url_index == -1) 
        {
            printf("Child %d found no more URLs to process\n", child_id);
            usleep(100000);
            wait_count ++;
            if(wait_count>MAX_WAIT_COUNT||has_unprocessed_urls() == NOT_FOUND ) exit(0); 
            continue;  
        }

        printf("Child %d processing URL: %s\n", child_id, url);
        int result = crawl_level(url, output_dir, current_depth);

        __sync_fetch_and_add(&shared_pool->waiting_child, 1);
        sem_wait(mutex);
        __sync_fetch_and_sub(&shared_pool->waiting_child, 1);
        if (result == SUCCESS) 
        {
            shared_pool->state[url_index] = VISITED;
            printf("Child %d successfully processed URL: %s\n", child_id, url);
        } 
        else 
        {
            shared_pool->state[url_index] = VISITED_FAIL;  
            printf("Child %d failed to fetch URL: %s\n", child_id, url);
        }
        sem_post(mutex);

        printf("Child %d finished processing URL: %s\n", child_id, url);
    }
}

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

Content* handle_response(int current_depth, SSL *ssl, int sockfd, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir) 
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
                            return fetch_url(current_depth, full_url, redirect_count + 1, final_url, final_url_size, output_dir);
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
                    printf("Error response: %d for URL %s\n", status_code, url);
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
                    fp = fopen(full_path, "ab");
                    if (!fp) 
                    {
                        printf("Failed to open file for writing: %s\n", full_path);
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
                                if (strstr(content->content_type, "text/html") && current_depth + 1 <= MAX_DEPTH)
                                {
                                    extract_links(current_depth, current_pos, write_size, url, overlap_buffer, &overlap_size);
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
                if (strstr(content->content_type, "text/html") && current_depth + 1 <= MAX_DEPTH)
                {
                    extract_links(current_depth, current_pos, remaining_bytes, url, overlap_buffer, &overlap_size);
                }
            }
        }
    }

    end_of_response:
    if (fp) fclose(fp);
    if (content->length == 0) 
    {
        printf("Failed to receive any data from %s\n", url);
        free(content);
        return NULL;
    }

    printf("Successfully fetched URL: %s\n", url);
    printf("Final base URL after redirects: %s\n", final_url);
    printf("Content-Type: %s\n", content->content_type);
    printf("Total content length: %zu bytes\n", content->length);

    return content;
}

Content* fetch_url(int current_depth, const char *url, int redirect_count, char *final_url, size_t final_url_size, const char *output_dir)
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
    Content* content = handle_response(current_depth, ssl, sockfd, url, redirect_count, final_url, final_url_size, output_dir);
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

int extract_links(int current_depth, const char *html_content, size_t content_length, const char *base_url, char *overlap_buffer, size_t *overlap_size) 
{
    // deal with overlap
    char *combined = malloc(OVERLAP_SIZE + content_length + 1);
    if (!combined) 
    {
        printf("Memory allocation failed in extract_links\n");
        return ERR_FAIL_MALLOC;
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
                __sync_fetch_and_add(&shared_pool->waiting_child, 1);
                sem_wait(mutex);
                __sync_fetch_and_sub(&shared_pool->waiting_child, 1);
                if (shared_pool->count < MAX_LINKS && !is_url_visited(full_url)) 
                {
                    strncpy(shared_pool->urls[shared_pool->count], full_url, MAX_URL_LENGTH - 1);
                    shared_pool->urls[shared_pool->count][MAX_URL_LENGTH - 1] = '\0';
                    shared_pool->state[shared_pool->count] = HAVEN_VISITED;
                    shared_pool->depth[shared_pool->count] = current_depth + 1;
                    shared_pool->count++;
                    printf("Added to pool: %s\n", full_url);  
                }
                sem_post(mutex);
            }
        }
        ptr = link_end + 1;
    }
    // update buffer for overlap
    *overlap_size = (total_length > OVERLAP_SIZE) ? OVERLAP_SIZE : total_length;
    memcpy(overlap_buffer, combined + total_length - *overlap_size, *overlap_size);

    free(combined);
    return SUCCESS;
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

int has_unprocessed_urls()
{
    for(int i = 0; i<shared_pool->count; i++)
    {
        if(shared_pool->state[i] != VISITED && shared_pool->state[i] != VISITED_FAIL) return FOUND;
    }
    return NOT_FOUND;
}

int is_url_visited(const char *url) 
{
    int reval = 0 ;
    for (int i = 0; i < shared_pool->count; i++) 
    {
        if (strcmp(url, shared_pool->urls[i]) == 0) 
        {
            printf("URL %s is %s (status: %d)\n", url, 
                   (shared_pool->state[i] != HAVEN_VISITED) ? "visited" : "not visited", 
                   shared_pool->state[i]);
            reval =  (shared_pool->state[i] != HAVEN_VISITED) ? FOUND : NOT_FOUND;
        }
    }
    printf("URL %s is not in the pool\n", url);
    return reval;
}

int crawl_level(const char *start_url, const char *output_dir, int current_depth) 
{
    if (shared_pool->count >= MAX_VISITED_URLS) return ERR_OUT_OF_RANGE;

    char final_url[MAX_URL_LENGTH];
    strncpy(final_url, start_url, MAX_URL_LENGTH - 1);
    final_url[MAX_URL_LENGTH - 1] = '\0';

    Content *content = fetch_url(current_depth, start_url, 0, final_url, MAX_URL_LENGTH, output_dir);
    if (!content) 
    {
        printf("Failed to fetch: %s\n", start_url);
        return ERR_FETCH_CONTENT;
    }
    
    printf("Successfully fetched URL: %s\n", final_url);
    printf("Content-Type: %s\n", content->content_type);
    
    free(content);

    printf("Finished crawling: %s (Depth: %d)\n", final_url, current_depth);
    return SUCCESS;
}

int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        printf("Usage: %s [Start URL] [Output Directory]\n", argv[0]);
        return ERR_ARGUMENTS;
    }
    sem_unlink(SEM_NAME);
    shm_unlink(SHM_NAME);
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

    if (init_shared_resources() != SUCCESS) 
    {
        printf("Failed to initialize shared resources\n");
        return ERR_INIT_SHM;
    }
    //set start url and posh to share memory
    sem_wait(mutex);
    strncpy(shared_pool->urls[0], start_url, MAX_URL_LENGTH - 1);
    shared_pool->urls[0][MAX_URL_LENGTH - 1] = '\0';
    shared_pool->state[0] = HAVEN_VISITED;
    shared_pool->depth[0] = 0;
    shared_pool->count = 1;
    sem_post(mutex);

    if (create_child_processes(output_dir) != SUCCESS) 
    {
        printf("Failed to create child processes\n");
        return ERR_CREAT_CHILD;
    }
    parent_process(start_url);

    sem_close(mutex);
    sem_unlink(SEM_NAME);
    munmap(shared_pool, sizeof(link_storage));
    shm_unlink(SHM_NAME);
    EVP_cleanup();
    ERR_free_strings();

    return SUCCESS;
}