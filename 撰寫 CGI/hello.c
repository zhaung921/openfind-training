#include <stdio.h>

int main(void) {
    printf("Content-type: text/html\n\n");
    printf("<html>\n");
    printf("  <head>\n");
    printf("    <title>CGI Response</title>\n");
    printf("  </head>\n");
    printf("  <body>\n");
    printf("    Hello World\n");
    printf("  </body>\n");
    printf("</html>\n");

    return 0;
}
