# 題目:  
Web Client (Spider)  
請撰寫一個程式來複製指定網站內所有網頁資料  

條件如下：  
1.	指定要抓取的網站 URL以及輸出檔案的目錄，會將該網站內網頁內容保存在該目錄。  
2.	至少可支援 <a href=”xxxx”  > 連結所指到網頁  
3.	支援 HTTPS 資料抓取  
4.	若該網頁已經拜訪過，則不會重複拜訪  
5.	同時可執行 3 個 spider 程式已加快資料抓取速度  

程式呼叫方式：  
```
./web_client  [Start URL]  [Output Directory]  
```
舉例： 
```
./web_client  https://www.openfind.com/  webpage/  
```
設計順序：  
1.	完成 Http(s) 連線，並且成功發送 HTTP Request 以及得到 Response 結果  
1.1	連線至 www.openfin.com (port: 80 or port: 443)  
1.2	發送 HTTP(s) Request 來取得 首頁 ( GET / ) 的內容  
2.	處理 HTTP Response  
2.1	HTTP Status Code (200, 3xx)  
2.2	HTTP Response Chunking Transfer Encoding  
2.3	Save Response Body to a File  
2.4	Parse Html Content to retrieve HREF links  
3.	Multi-Process Spiders  
3.1	設計 Main Process 和 3 Child Process 互動方式  
3.1.1	要抓取哪一個連結、抓到網頁要怎麼處理、避免重複抓取  
3.2	Implement  


![image](https://github.com/user-attachments/assets/891423bd-d17e-438a-995f-ce3413a85ee7)




