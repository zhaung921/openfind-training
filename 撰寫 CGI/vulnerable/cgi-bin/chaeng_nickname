#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <hiredis.h>
#include <sqlite3.h>

#define SUCCESS                 0
#define ERROR_BASE              0
#define ERR_OPEN_DB_FAIL    ERROR_BASE-1

                
void generateCSRFToken(char *csrfToken, char *username, int tokenSize)
{
    char charset[] = "0123456789"
                    "abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int randomStrSize=tokenSize-sizeof(username);
    strncpy(csrfToken,username,strlen(username));
    for(int i=strlen(username);i<tokenSize;i++)
    {
        int key = rand() % (int) (sizeof(charset) - 1);
        csrfToken[i] = charset[key];
    }
    csrfToken[tokenSize-1]='\0';
}

void hash_password(const char* input, char* output) 
{
    if (crypto_pwhash_str(output, input, strlen(input), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }
}

void createSession(char *userSessionID, char *username) 
{
    redisContext *c = redisConnect("127.0.0.1", 6379);
    if (c == NULL || c->err) {
        if (c) {
            printf("Redis error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Redis allocation error\n");
        }
        exit(1);
    }
    redisReply *reply = redisCommand(c, "SET session:%s %s", userSessionID, username);
    if (reply) freeReplyObject(reply);
    redisFree(c);
}

void createCsrfSession(char *userSessionID, char *csrfToken)
{
    redisContext *c = redisConnect("127.0.0.1", 6379);
    if (c == NULL || c->err) {
        if (c) {
            fprintf(stderr, "Redis error: %s\n", c->errstr);
            redisFree(c);
        } else {
            fprintf(stderr, "Redis allocation error\n");
        }
        exit(1);
    }
    redisReply *reply = redisCommand(c, "SET csrf:%s %s", userSessionID, csrfToken);
    if (reply) freeReplyObject(reply);
    redisFree(c);
}

char* getCSRFTokenFromRedis(char *userSessionID) 
{
    redisContext *c = redisConnect("127.0.0.1", 6379);
    if (c == NULL || c->err) {
        if (c) {
            fprintf(stderr, "Redis error: %s\n", c->errstr);
            redisFree(c);
        } else {
            fprintf(stderr, "Redis allocation error\n");
        }
        exit(1);
    }
    redisReply *reply = redisCommand(c, "GET csrf:%s", userSessionID);
    char *csrfToken = NULL;
    if (reply->type == REDIS_REPLY_STRING) {
        csrfToken = strdup(reply->str);
    }
    if (reply) freeReplyObject(reply);
    redisFree(c);
    return csrfToken;
}

void changeUserID(char *csrfToken ) 
{
    printf("<form action=\"/cgi-bin/change_nickname.cgi\" method=\"POST\">");
    printf("<label for=\"newUserID\">New UserID:</label>");
    printf("<input type=\"text\" id=\"newUserID\" name=\"newUserID\"><br><br>");
    printf("<input type=\"hidden\" name=\"action\" value=\"updateUserID\">");
    printf("<input type=\"hidden\" name=\"csrfToken\" value=\"%s\">", csrfToken);
    printf("<input type=\"submit\" value=\"Update UserID\">");
    printf("</form>");
}

int main(int argc, char *argv[]) {
    

    // Process environment variables and standard input to get CGI variables.
    char *contentLengthStr = getenv("CONTENT_LENGTH");
    long contentLength = contentLengthStr != NULL ? atol(contentLengthStr) : 0;
    
    if (contentLength > 0) 
    {
        char *inputData = malloc(contentLength + 1);
        // Read the data from standard input (stdin).
        fread(inputData, 1, contentLength, stdin);
        inputData[contentLength] = '\0';

        char *action = NULL;
        char *username = NULL;
        char *password = NULL;
        char *newUserID = NULL;
        char *currentUserID = NULL;
        char *csrfToken = NULL;

        char *token = strtok(inputData, "&");
        while (token != NULL) {
           if (strncmp(token, "action=", 7) == 0) 
            {
                action = token + 7;
            } 
            else if (strncmp(token, "username=", 9) == 0) 
            {
                username = token + 9;
            } 
            else if (strncmp(token, "password=", 9) == 0) 
            {
                password = token + 9;
            } 
            else if (strncmp(token, "newUserID=", 10) == 0) 
            {
                newUserID = token + 10;
            } 
            else if (strncmp(token, "currentUserID=", 14) == 0) 
            {
                currentUserID = token + 14;
            }
            else if (strncmp(token, "csrfToken=", 10) == 0) 
            {
                csrfToken = token + 10;
            }
            token = strtok(NULL, "&");
        }

        sqlite3 *db;
        char *err_msg = 0;
        int rc = sqlite3_open("test.db", &db);
        if (rc) 
        {
            fprintf(stderr, "Fail to open db\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return ERR_OPEN_DB_FAIL;
        }

        if (action != NULL && strcmp(action, "updateUserID") == 0  && newUserID != NULL) 
        {
            char *userSessionID = getenv("HTTP_COOKIE"); 
            if (userSessionID == NULL || strncmp(userSessionID, "sessionID=", 10) != 0) {
                printf("Content-type: text/html\r\n\r\n");
                printf("<p>Invalid session</p>");
                return 1;
            }
            userSessionID += 10;
            char username2[8]; 
            char *serverCSRFToken = getCSRFTokenFromRedis(userSessionID);
            char *p=NULL;
            p = strchr(userSessionID, '-'); 
            size_t len = p - userSessionID;
            strncpy(username2, userSessionID, len); 
            username2[len] = '\0'; 
            printf("Content-type: text/html\r\n\r\n");
            printf("%s",username2);
            
            //prevent CSRF
            if (csrfToken == NULL || serverCSRFToken == NULL || strcmp(csrfToken, serverCSRFToken) != 0) {
                printf("Content-type: text/html\r\n\r\n");
                printf("<p>Invalid CSRF token</p>");
                printf("%s",userSessionID);
                return 1;
            }

            // Update userID
            const char *update_sql = "UPDATE log_in_table SET userID = ? WHERE user = ?";
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, newUserID, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username2, -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) 
            {
                fprintf(stderr, "Update failed: %s\n", sqlite3_errmsg(db));
                printf("Content-type: text/html\r\n\r\n");
                printf("<p>Update failed: %s</p>", sqlite3_errmsg(db));
            } 
            else 
            {
                printf("Content-type: text/html\r\n\r\n");
                printf("<p>UserID updated to: %s</p>", newUserID);
            }
            sqlite3_finalize(stmt);
            free(serverCSRFToken);
        } 
        else if (username && password) 
        {
            // Original login logic
            const char *sql = "INSERT INTO log_in_table (user, password, userID) VALUES (?, ?, ?);";
            sqlite3_stmt *stmt;
            char *admin_Password = "admin";
            char admin_hash_password[256];
            hash_password(admin_Password, admin_hash_password);
            sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, admin_hash_password, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, "admin123", -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) 
            {
                printf("insert fail 1: %s\n", sqlite3_errmsg(db));
            }

            sqlite3_reset(stmt);
            char *webmail_Password = "webmail";
            char webmail_hash_password[256];
            hash_password(webmail_Password, webmail_hash_password);
            sqlite3_bind_text(stmt, 1, "webmail", -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, webmail_hash_password, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, "webmail321", -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) 
            {
                printf("insert fail 2: %s\n", sqlite3_errmsg(db));
            }

            const char *query_sql = "SELECT userID FROM log_in_table WHERE user = ?";
            sqlite3_reset(stmt);
            sqlite3_prepare_v2(db, query_sql, -1, &stmt, NULL);
            if (username && password && strcmp(username, "admin") == 0 && crypto_pwhash_str_verify(admin_hash_password, password, strlen(password)) == 0) 
            {
                
                char *userSessionID = "admin-6523cbac-bdc8-4ccf-a824-899a91b0f89f";
                createSession(userSessionID, username);
                printf("Set-Cookie: sessionID=%s; Path=/; HttpOnly\r\n",userSessionID);
                printf("Content-type: text/html\n\n");
                printf("<p>Hello admin</p>");

                char csrfToken[33];
                generateCSRFToken(csrfToken, username, sizeof(csrfToken));
                createCsrfSession(userSessionID,csrfToken);
            
                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const unsigned char *userID = sqlite3_column_text(stmt, 0);
                    printf("<html><body>UserID: %s</body></html>", userID);
                    changeUserID(csrfToken);
                } else {
                    printf("<html><body>userID:none </body></html>");
                }

            } 
            else if (username && password && strcmp(username, "webmail") == 0 && crypto_pwhash_str_verify(webmail_hash_password, password, strlen(password)) == 0) 
            {
                char *userSessionID = "webmail-da95a1fd-7028-4e8f-801d-0b18a6b33f2a";
                createSession(userSessionID, username);
                printf("Set-Cookie: sessionID=%s; Path=/; HttpOnly\r\n",userSessionID);
                printf("Content-type: text/html\n\n");
                printf("<html><head><title>CGI Response</title></head><body>");
                printf("<p>Hello webmail</p>");

                char csrfToken[33];
                generateCSRFToken(csrfToken, username, sizeof(csrfToken));
                createCsrfSession(userSessionID,csrfToken);

                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) 
                {
                    const unsigned char *userID = sqlite3_column_text(stmt, 0);
                    printf("<html><body>UserID: %s</body></html>", userID);
                    changeUserID(csrfToken);
                } 
                else 
                {
                    printf("<html><body>userID:none </body></html>");
                }

            } else {
                printf("Content-type: text/html\r\n\r\n");
                printf("<p>Invalid username or password</p>");
            }

            sqlite3_finalize(stmt);
        }

        free(inputData);
        sqlite3_close(db);
    }

    printf("</body></html>");

    return 0;
}
