# **SAML (Security Assertion Markup Language)**
## **實作SP(service provider):**

用之前實作cgi作業的經驗作一個saml的登入網頁內容主要就是一個按鈕，按下會進行saml驗證

登入介面:[`http://saml.example.com/saml_login.html`](http://saml.example.com/saml_login.html) 

成功登入介面:[`http://saml.example.com/saml_login_success.html`](http://saml.example.com/saml_login_success.html) 

介面由簡單的html組成:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <h2>Login</h2>
    <form>
        <input type="submit" value="SAML-Login">
    </form>
</body>
</html>
```

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_e22cd11b63089cbc9c80983ef25d30e1.png)


## 建立docker環境:

首先建立compose文件

```yaml
version: '3.7'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0.4
    command:
      - start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    volumes:
      - ./data:/opt/keycloak/data
    ports:
      - "8080:8080"
```

過中注意volumes路徑的權限問題，否則啟動一下就會自動跳掉(透過log發現)

設定完成後就可透過[`http://172.16.222.101:8080/`](http://172.16.222.101:8080/) 進入Keycloak

## 登入:

在登入介面輸入admin/admin就可登入

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_847f9b6c01e3d9b0de6e70f06537d974.png)


## Create realm+創造使用者:

創建一個新的realm叫test，用處是可以隔離不同用戶的設定，接著在test內創建使用者名稱先叫`user001` 

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_79c76de0134b2003199db60d45cd80ee.png)


## 創造 Client並設定網址:

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_2fede20f385e96109c0cdfb34b940969.png)


之後獲取導向介面:[`http://localhost:8080/realms/test/protocol/saml/clients/saml`](http://localhost:8080/realms/test/protocol/saml/clients/saml) 

## 設定user密碼:

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_3151d43743687d21d2260608a5bbba3f.png)


## 修改html:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <h2>Login</h2>
    <form action="http://localhost:8080/realms/test/protocol/saml/clients/saml" method="get">
        <input type="submit" value="SAML-Login">
    </form>
</body>
</html>

```

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_e22cd11b63089cbc9c80983ef25d30e1.png)

之後按下登入鍵就會轉跳到keycloak

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_836497af9ae559bd1d385ac4cba5604c.png)


帳號密碼輸入成功後會轉跳到成功頁面

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_94b9f7e9bb0a0bcdb5cb7bc5911d7f86.png)
