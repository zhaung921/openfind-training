#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <hiredis.h>
#include <sqlite3.h>

#define SUCCESS                 0
#define ERROR_BASE              0
#define ERR_OPEN_DB_FAIL    ERROR_BASE-1

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

void changeUserID(char *currentUserID) 
{
    printf("<form action=\"/cgi-bin/log_in.cgi\" method=\"POST\">");
    printf("<label for=\"newUserID\">New UserID:</label>");
    printf("<input type=\"text\" id=\"newUserID\" name=\"newUserID\"><br><br>");
    printf("<input type=\"hidden\" name=\"action\" value=\"updateUserID\">");
    printf("<input type=\"hidden\" name=\"currentUserID\" value=\"%s\">", currentUserID);
    printf("<input type=\"submit\" value=\"Update UserID\">");
    printf("</form>");
}

int main(int argc, char *argv[]) {
    printf("Content-type: text/html\n\n");
    printf("<html><head><title>CGI Response</title></head><body>");

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

        if (action != NULL && strcmp(action, "updateUserID") == 0 && currentUserID != NULL && newUserID != NULL) 
        {
            // Update userID
            const char *update_sql = "UPDATE log_in_table SET userID = ? WHERE userID = ?";
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, newUserID, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, currentUserID, -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) 
            {
                printf("<p>Update failed: %s</p>", sqlite3_errmsg(db));
            } 
            else 
            {
                printf("<p>UserID updated to: %s</p>", newUserID);
            }
            sqlite3_finalize(stmt);

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
                printf("<p>Hello admin</p>");

                char *userSessionID = "123";
                createSession(userSessionID, username);

                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const unsigned char *userID = sqlite3_column_text(stmt, 0);
                    printf("<html><body>UserID: %s</body></html>", userID);
                    changeUserID((char *)userID);
                } else {
                    printf("<html><body>userID:none </body></html>");
                }

            } 
            else if (username && password && strcmp(username, "webmail") == 0 && crypto_pwhash_str_verify(webmail_hash_password, password, strlen(password)) == 0) 
            {
                printf("<p>Hello webmail</p>");

                char *userSessionID = "321";
                createSession(userSessionID, username);

                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                if (sqlite3_step(stmt) == SQLITE_ROW) 
                {
                    const unsigned char *userID = sqlite3_column_text(stmt, 0);
                    printf("<html><body>UserID: %s</body></html>", userID);
                    changeUserID((char *)userID);
                } 
                else 
                {
                    printf("<html><body>userID:none </body></html>");
                }

            } else {
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
