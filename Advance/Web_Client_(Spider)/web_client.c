#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define MAX_FILENAME 256
#define MAX_URL_LENGTH 2048
#define MAX_LINKS 1000

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

void normalize_url(const char *base_url, const char *relative_url, char *result, size_t result_size) {
    CURLU *url = curl_url();
    curl_url_set(url, CURLUPART_URL, base_url, 0);
    curl_url_set(url, CURLUPART_URL, relative_url, 0);
    char *normalized;
    curl_url_get(url, CURLUPART_URL, &normalized, 0);
    strncpy(result, normalized, result_size);
    result[result_size - 1] = '\0';
    curl_free(normalized);
    curl_url_cleanup(url);
}

void extract_links(const char *html_content, const char *base_url, char **links, int *link_count) {
    const char *ptr = html_content;
    while ((ptr = strstr(ptr, "href=\"")) != NULL) {
        ptr += 6; // 跳過 "href=""
        const char *end = strchr(ptr, '"');
        if (end && *link_count < MAX_LINKS) {
            int len = end - ptr;
            char *link = malloc(len + 1);
            strncpy(link, ptr, len);
            link[len] = '\0';
            
            char normalized_url[MAX_URL_LENGTH];
            normalize_url(base_url, link, normalized_url, sizeof(normalized_url));
            links[*link_count] = strdup(normalized_url);
            (*link_count)++;
            
            free(link);
        }
        ptr = end + 1;
    }
}

int crawl_url(const char *url, const char *output_dir, int is_original) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    char filename[MAX_FILENAME];
    FILE *fp;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_handle = curl_easy_init();

    if(curl_handle) {
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(curl_handle);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            long response_code;
            curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);
            printf("Crawling: %s (Response: %ld)\n", url, response_code);

            char *content_type;
            curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE, &content_type);

            if (content_type && strstr(content_type, "text/html")) {
                char *body_start = strstr(chunk.memory, "\r\n\r\n");
                if (body_start) {
                    body_start += 4; // 跳過 "\r\n\r\n"

                    snprintf(filename, MAX_FILENAME, "%s/%p.html", output_dir, (void*)url);
                    fp = fopen(filename, "wb");
                    if(fp) {
                        fwrite(body_start, 1, strlen(body_start), fp);
                        fclose(fp);
                        printf("Body content saved to: %s\n", filename);
                    }

                    if (is_original) {
                        char *links[MAX_LINKS];
                        int link_count = 0;
                        extract_links(body_start, url, links, &link_count);

                        for (int i = 0; i < link_count; i++) {
                            crawl_url(links[i], output_dir, 0);
                            free(links[i]);
                        }
                    }
                }
            } else {
                printf("Skipping non-HTML content: %s\n", url);
            }
        }

        curl_easy_cleanup(curl_handle);
    }

    free(chunk.memory);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s [Start URL] [Output Directory]\n", argv[0]);
        return 1;
    }

    const char *start_url = argv[1];
    const char *output_dir = argv[2];

    curl_global_init(CURL_GLOBAL_ALL);
    int result = crawl_url(start_url, output_dir, 1);
    curl_global_cleanup();

    return result;
}