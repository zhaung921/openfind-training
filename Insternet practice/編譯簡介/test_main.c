#include<stdio.h>
#include<sqlite3.h>

#define SUCCESS             0
#define ERR_BASE            0
#define ERR_OPEN_DB_FAIL ERR_BASE-1
#define ERR_EXEC_DB_FAIL ERR_BASE-2

int main()
{   
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open("test.db", &db);
    if(rc!=SQLITE_OK)
    {
        fprintf(stderr,"Fail to open db %s\n ",sqlite3_errmsg(db));
        sqlite3_close(db);
        return ERR_OPEN_DB_FAIL;
    }

    char *sql = "INSERT INTO my_table (content) VALUES ('This is a test content');";
    rc=sqlite3_exec(db,sql,0,0,&err_msg);
    if(rc!=SQLITE_OK)
    {
        fprintf(stderr, "Open db fail: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return ERR_EXEC_DB_FAIL;
    }
    fprintf(stdout, "Insert success.\n");
    sqlite3_close(db);

    return SUCCESS;
}
