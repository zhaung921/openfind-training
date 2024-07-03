# 題目  
## Sorting Performance

### 撰寫一個程式，從指定的檔案中讀取資料，檔案內容為每行代表一個字串以及分數，請依照分數高低來將所有字串重新排序 (由高到低)，輸出到另外一個檔案。


#### Program Usage:

```./mysort [input filename] [output filename]```

#### input file format:  
```
string1\t12345\n  
string2\t12346\n  
string3\t12344\n  
```
#### output file format:  
```
string1\t12345\n  
string2\t12346\n  
string3\t12344\n  
```
 Ex:
```./mysort test_rand.txt test_out.txt```

限制：
1.	分數範圍 1 ~ 100,000,000
2.	檔案中最多只包含 1,000,000 個字串
3.	字串的長度最長為 127 bytes

基本要求:
1.	符合 “開發標準”

 
特殊要求：
1.	速度夠快


驗證方式:
test_rand.txt 資料 1,000,000 筆，檔案大小為 18M.
```
andric@ANDRICYEH-PC:~$ time ./mysort test_rand.txt  test_out.txt

real    0m0.290s
user    0m0.188s
sys     0m0.094s
```
挑戰目標：
	0 m 0.4 s



