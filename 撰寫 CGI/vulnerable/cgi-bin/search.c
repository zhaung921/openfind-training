#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


void url_decode(char *dest, const char *src) {
    char a, b;
    while (*src) 
    {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) 
        {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dest++ = 16*a + b;
            src+=3;
        } 
        else if (*src == '+') 
        {
            *dest++ = ' ';
            src++;
        } 
        else 
        {
            *dest++ = *src++;
        }
    }
    *dest++ = '\0';
}

void xssPrevent(char *dest, const char *src, size_t size) {
    size_t i, j = 0;
    for (i = 0; i < size && src[i] != '\0'; i++) {
        switch (src[i]) {
            case '&':
                j += snprintf(dest + j, size - j, "&amp;");
                break;
            case '<':
                j += snprintf(dest + j, size - j, "&lt;");
                break;
            case '>':
                j += snprintf(dest + j, size - j, "&gt;");
                break;
            case '"':
                j += snprintf(dest + j, size - j, "&quot;");
                break;
            case '\'':
                j += snprintf(dest + j, size - j, "&#x27;");
                break;
            case '/':
                j += snprintf(dest + j, size - j, "&#x2F;");
                break;
            default:
                if (j < size - 1) {
                    dest[j++] = src[i];
                }
                break;
        }
    }
    dest[j] = '\0';
}

int main(int argc, char *argv[]) {
    
    char *queryString = getenv("QUERY_STRING");
    char *q = NULL;

    if (queryString != NULL) {
        q = strstr(queryString, "q=");
        if (q != NULL) {
            q += 2;
        }
    }

    printf("Content-type: text/html\r\n\r\n");
    printf("<html><head><title>Search</title></head><body>");
    printf("<h1>Search Results</h1>");
    if (q != NULL) 
    {
        char decodedQuery[1024];
        char safeQuery[1024];
        url_decode(decodedQuery, q);
        xssPrevent(safeQuery,decodedQuery,sizeof(safeQuery));
        printf("<p>Your search query: %s</p>", safeQuery);
    } 
    else 
    {
        printf("<p>No search query provided.</p>");
    }
    printf("</body></html>");

    return 0;
}

