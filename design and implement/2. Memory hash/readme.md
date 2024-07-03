# memory hash
## 題目:
請設計一個 Hash Table，資料結構是標準的 hash table，有 header，後面用 linked-list 串起來，採用 linked-list 來解決 collision 的問題。  
      ![image](https://github.com/zhaung921/openfind-training/assets/94048436/e3b35aac-3294-4b97-b85e-836ef660e5fb)  
請使用上述設計的 Hash Table 來實作下列相關 Memory Hash Library。  
每一筆資料包含 Key 以及 Value，其中條件如下：
Key : 字串 (長度 1 ~ 255 Bytes )
Value : 不固定型態，大小為 4 MB 以內 (可能是字串、整數、Binary Data)

需要提供下列的 Library Function (請自行設計其 interface)：
1.	新增/更新
輸入：Key, Value
函數回傳：
若該筆資料 (Key) 不存在，則新增此筆資料
若該筆資料 (Key) 已存在，則更新其 Value

2.	刪除
輸入：Key
函數回傳：
若該筆資料不存在，則回傳 NOT FOUND
若該筆資料已存在，則進行刪除動作

3.	查詢
輸入：Key
函數回傳：
若該筆資料不存在，則回傳 NOT FOUND
若該筆資料已存在，則是可取得該資料的 Value

上述程式碼請撰寫於 memhash.c 以及 memhash.h 檔案中，並且提供一個 example 程式 (test.c) 作為使用此 memhash library function 參考。
設計該程式時，請確保記憶體使用狀況是合理的。
