# Trace code 練習 - RFC 3875

## 1. 測試 測試用 CGI (Httpd 內建的)

先檢查cgi的路徑並在路徑中建立test_cgi.cgi的文件，在將此內容放進去

```jsx
#!/bin/bash

# To permit this cgi, replace # on the first line above with the
# appropriate #!/path/to/sh shebang, and set this script executable
# with chmod 755.
#
# ***** !!! WARNING !!! *****
# This script echoes the server environment variables and therefore
# leaks information - so NEVER use it in a live server environment!
# It is provided only for testing purpose.
# Also note that it is subject to cross site scripting attacks on
# MS IE and any other browser which fails to honor RFC2616.

# disable filename globbing
set -f

echo "Content-type: text/plain; charset=iso-8859-1"
echo

echo CGI/1.0 test script report:
echo

echo argc is $#. argv is "$*".
echo

echo SERVER_SOFTWARE = $SERVER_SOFTWARE
echo SERVER_NAME = $SERVER_NAME
echo GATEWAY_INTERFACE = $GATEWAY_INTERFACE
echo SERVER_PROTOCOL = $SERVER_PROTOCOL
echo SERVER_PORT = $SERVER_PORT
echo REQUEST_METHOD = $REQUEST_METHOD
echo HTTP_ACCEPT = "$HTTP_ACCEPT"
echo PATH_INFO = "$PATH_INFO"
echo PATH_TRANSLATED = "$PATH_TRANSLATED"
echo SCRIPT_NAME = "$SCRIPT_NAME"
echo QUERY_STRING = "$QUERY_STRING"
echo REMOTE_HOST = $REMOTE_HOST
echo REMOTE_ADDR = $REMOTE_ADDR
echo REMOTE_USER = $REMOTE_USER
echo AUTH_TYPE = $AUTH_TYPE
echo CONTENT_TYPE = $CONTENT_TYPE
echo CONTENT_LENGTH = $CONTENT_LENGTH
```

接著檢查/etc/httpd/config中針對cgi資料夾的路徑是否有匹配。

檢查完後輸入
```clike
curl http://172.16.222.101/cgi-bin/test_cgi.cgi
```

得到的輸出結果:

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_ba4519a35c1d0c00dc13cfc1ecf7814b.png)


## 2. Trace code

我主要是從mian().c的檔案開始，先看看整個server大概是怎麼運作的。

一開始mian()主要是新定義好一些配置例如


**`show_mpm_settings`**：顯示mpm的配置資料
**`show_compile_settings`**：顯示compile的一些設定以及版本?

**`destroy_and_exit_process`**：清理分配的資源然後讓程式可正常退出

**`init_process`**：初始化process，包含pool的配置等等

**`usage`**：不是太理解，大概是有錯誤時會顯示可用的選項?

**`mian:`**
1. 一開始會先初始化數值例如pool,log file等等
2. 接著會去引用一些模塊(可能為連線時會使用到的mod)
3. 開始配置資源，然後檢查是否配置成功等等
4. 接著啟動mpm，進行mutiprocessor的任務

### 嘗試修正

後續發追蹤發現系統會先到指定資料夾load進config檔中有指定的cgi，因此要先確認cgi檔案是否有被取消註解。也就是確認`/usr/local/apache2/conf/httpd.conf`
後續開始trace `mod_cgid.c`，接著就是檢查QUERY STRING他是如何被修改。
發現到`cgid_server`應該會是最主要的部份，當中有個
`argv = (const char * const *)create_argv(r->pool, NULL, NULL, NULL, argv0, r->args);`
這應該會是要修改的目標，因此進入到`create_argv`()去查看  
![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_b869baa5e9c269fe67d72d364b8e45d0.png)  
發現到應該會是這個迴圈當中會去依照+號分開取值存到w
並將w利用url去解碼，最後則是將他轉譯，並儲存在下一個位置，而透過修改這部分應該就可達到我們要的需求。

### 最後驗證

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_f85bbe862fbfd4224bbd60eb3e0f3e52.png)

## 額外實驗 Nginx + FCGI Wrap
`execl(filename, filename, (void *)NULL);`
這裡透過execl()去呼叫cgi，`filename`部分則是透過`static char *get_cgi_filename(void)`取得
而最後一個參數通常是傳遞args但這裡他使用`(void *)NULL`則不會傳參數進去，因此就不會與阿帕契遇到同樣的問題。
