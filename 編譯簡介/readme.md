# 編譯簡介

1. 用 sqlite3 指令新增一個 DB  
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_fc44cd2262a6cf8282f5e641e5997843.png)
   
2. 開出一個 TABLE，包含一個 id 欄位以及一個 content   
    
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_cdf655baef0fc585636ab61e2100b328.png)
3. 下載 `sqlite-amalgamation`接著在解壓縮  
    ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_c6af59a88257285956c97f9b4d903b94.png)

4. 編譯出 `libsqlite3.a`
    
    由於.a檔靜態庫是由.o檔組成，因此可以用ar指令將文件打包成.a靜態庫      
    
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_eafd25e021c34ba109304322eeb6852e.png)
    
5. 用 C 寫一個程式使用 `libsqlite3.a`   
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_bf424dbd61225b7dadb0456006d15002.png)

   先寫一個基本的開db測試，然後寫一個makfile嘗試讓他自動編譯    
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_801baed2d6f0c69f6263f64987c303b9.png)

    
6. C 寫的程式往 db 內插入資料 `INSERT INTO my_table (content) VALUES ('This is a test content');`  
   ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_1fe8504e20f7043372234b1c261ba48c.png)

    
7. 展示資料已經被插入 DB 內 (在 sqlite3 指令中操作)  
    輸入指令 `sqlite3 test.db` 進到資料庫內  
    再輸入`SELECT * FROM my_table;` 就可看到剛剛insert進去的資料  
    ![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_33644dba4b319e8e9f4f5a23cd18e62d.png)
