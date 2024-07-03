# Disk Hash
## 題目:
情境：
搜尋引擎系統會先將資料建成索引檔，以便於後續搜尋能夠快速找到。往往會採用 Hash 方式來進行實作，而這個 hash 資料會保存在 disk 裡面，並不會因系統意外關機後，而需要再來重新建立索引。


請設計一個Disk Hash Library 供其他程式呼叫使用，同時該 Hash Table 要能夠滿足下列條件：
-	Key: 字串 (長度 1 ~ 255 Bytes )
-	Value: 不固定型態與大小(可能是字串、整數、Binary Data，不超過 4KB)
-	Hash Table 至少要能夠處理 10,000,000 筆資料以上。
-	當該程式結束 (含正常、意外、系統關機等所有情況) 後，已經成功加入該 Disk Hash Table 的內容仍可提供給其他程式來繼續使用。

Binary Data: 可理解為一個含有任意字元的資料，舉例：執行檔案內容就是 binary 資料。

需要 (至少) 提供下列的 Library Function
1.	新增/更新
輸入Key, Value
若該筆資料 (Key) 不存在，則新增此筆資料
若該筆資料 (Key) 已存在，則更新其Value
2.	刪除
輸入Key
若該筆資料不存在，則回傳錯誤
若該筆資料已存在，刪除此筆資料後，回傳成功
3.	查詢
輸入Key
若該筆資料不存在，則回傳 NOT FOUND
若該筆資料已存在，則回傳該Value

請設計 Library Function Interface，以及相關的資料結構、演算法和 pseudo code (包含 Library Function 呼叫範例)

 
驗證方式：  
1. 提供一個測試程式 (prog_test)
prog_test “mode” 
2. mode: add [filename]  
將參數檔案內 Key, Value 加入於 Disk Hash，檔案格式：  
Key1 \t Value1 \n  
Key2 \t Value2 \n  
…  
  結束後請顯示 “OK” 及成功加入的筆數，例如：“OK 3”  
3. mode: query [key]  
查詢所指定 key 的資料，如果有找到則是顯示其 value，如果找不到則是顯示 “NOT FOUND”。  
4. mode: del [key]  
刪除指定的 “Key” 資料，如果成功則是顯示 “SUCCESS”，失敗則是顯示 “FAILURE”。  
5. mode: import [filename]  
將所指定檔案名稱的內容加入 Disk Hash，Key 則是檔案名稱 (不含路徑)，成功後請顯示 “OK”、檔案名稱和檔案大小 (bytes)，例如：”OK test.doc 12345”， 錯誤則是顯示 “FAILUER”。  
6. mode: export [key] [save filename]  
將所指定 key 的資料保存在指定檔案裏面，成功後請顯示  
“OK”、檔案名稱和保存檔案大小 (bytes)，例如：”OK test.doc 12345”。  
資料找不到則是顯示 “NOT FOUND”，或者其他錯誤則是顯示 “FAILUER”。  

## 執行方式:  
一開始可先執行Makefile，他會新增Hash_Table.txt以及Table_index.txt兩個文件，並且產生出mode執行檔  
```./make```  
若要刪除Hash_Table.txt以及Table_index.txt兩個資料，可執行  
```./make clean```

### 要新增資料進hash table可執行指令:
```
./mode add [filename] 
```  

### 需要import可執行指令:
filetype有binary與str兩個選項
```
./mode import [filename] [filetype] 
```
  

### 要刪除可執行指令:  
(此時並不會真正刪除資料只會先被標記為刪除，若要真正刪除需手動執行reset)  
``` 
./mode del [keyname]
 ```  

### 要查詢值可執行指令:
``` 
./mode query [keyname]
```  

### 要將某key對應的值輸出到檔案可執行:
``` 
./mode export [keyname] [filename]
```  

### 清理hash table  
當執行了一些del以及新增更新需須執行:  
(釋放不需要的資料)
```
./mode reset
```
