# Disk Hash

## 執行方式:
使用前須新增Hash_Table.txt以及Table_index.txt兩個文件  

### 要新增資料進hash table可執行指令:
```
./mode add [filename] 
```  

### 需要import可執行指令:
```
./mode import [filename] [filetype] 
```
filetype有binary與str兩個選項  

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
