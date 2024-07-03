## **準備docker環境:**

準備docker compose(原本教學網站的compose文件在啟動openldap時會失敗，後來測試很久，把要把`openldap:1.2.2`換成`openldap:latest` 才能正常啟動。

```c
version: '2'

services:
  openldap:
    container_name: openldap
    image: osixia/openldap:latest
    ports:
      - "389:389"
      - "636:636"
    command: [--copy-service,  --loglevel, debug]

  phpldapadmin:
    container_name: phpldapadmin
    image: osixia/phpldapadmin:0.7.2
    ports:
      - "80:80"
    environment:
      - PHPLDAPADMIN_HTTPS="false"
      - PHPLDAPADMIN_LDAP_HOSTS=openldap
    links:
      - openldap
    depends_on:
      - openldap
```

之後執行:`docker compose up -d`

之後再瀏覽器輸入`http://172.16.222.101:80` 導向phpLDAPadmin介面

## phpLDAPadmin操作:

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_48c319812e6984594a75084fda9d945b.png)


輸入帳密`cn=admin,dc=example,dc=org` / `admin` 就可以成功登入

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_149605a0c2febdedb36394e00d2897be.png)


接著新增兩個ou一個叫user一個叫group

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_5be250a4fcbf8ce4321477f44a31c0f8.png)


接著在group中新增entry叫做all，也在users下新增一位使用者`foo 001`，並把這位使用者加入到group的all當中

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_6bdb006931bd3d89a0367b5e6f1d5a51.png)


## 作業一：加入更多使用者與群組

名字要會撞到，例如一個叫做 `foo` 的群組，就跟 `foo` 使用者衝突

也加上不同層級相同名稱使用者，例如 `cn=foo,ou=rd,ou=users,dc=example,dc=org`

1. 在 `ou=users` 下創建 `ou=rd`,`ou=pm`。
2. 添加名稱會衝突的群組和使用者：在 `ou=groups` 下創建群組 `foo`，在 `ou=users` 下創建`foo`。
3. 添加不同層級相同名稱的使用者：在 `ou=rd,ou=users` 以及`ou=pm,ou=users`下創建使用者 `cn=foo`

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_04735bd13c9649f6d7df0ba1dc7e9ce4.png)


## 作業二：用 `ldapsearch` 找出全部的 User

因為大家都叫foo所以需要知道使用者的`objectClass` 為何。透過觀察，發現使用者的`objectClass`都為`inetOrgPerson` 。因此可透過`ldapsearch -x -H ldap://localhost -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" -w admin "(objectClass=inetOrgPerson)”` 找到所有user

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_deef1407d782b26eb59d7e19374635da.png)


可看到查找成功，總共3個entries。

## 作業三：用 `ldapsearch` 找出全部的 Group

依樣透過觀察到group都為posixGroup屬性，因此透過

`ldapsearch -x -H ldap://localhost -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" -w admin" (objectClass=posixGroup)”` 

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_ff375c66de5abe9a1d7028298195651f.png)


就可以查找所有group也可看到group中有哪些人

## 作業四：用 `ldapsearch` 找某個 Group 的所有成員

要印出成員memberUid的部分，要先指定好群組路徑，這裡我要印出ou=rd,cn=foo的群組
`ldapsearch -x -H ldap://localhost -b "ou=rd,ou=users,dc=example,dc=org" -D "cn=admin,dc=example,dc=org" -w admin "(cn=foo)" memberUid` 

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_22a89084ee581c7bda0b32f6dd2ced2d.png)


## 作業五：用 `ldapsearch` 找出全部 Entry 的 DN

透過指令，並加上dn把它作為查找對象

`ldapsearch -x -H ldap://localhost -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" -w admin -s sub "(objectClass=*)" dn`

![](https://s3-ap-northeast-1.amazonaws.com/g0v-hackmd-images/uploads/upload_4af7e9725226fbc1ead75f45a5676ab1.png)


## **作業六：名詞解釋**

| 名詞 | 解釋 |
| --- | --- |
| Bind DN | 指在LDAP目錄服務中用於身分驗證，以確保只有授權用戶才能訪問或修改目錄數據。 |
| Base DN | 是 LDAP 查詢的起始點。當執行 LDAP 查詢時，Base DN 指定了查詢應該從哪個條目開始。這個條目及其子條目將成為查詢的範圍。用於限制查詢範圍，以增加效率。 |
| LDAPS | 是指在 SSL/TLS 加密通道上運行的 LDAP 協議。這提供了 LDAP 通訊的安全性，防止數據在傳輸過程中被攔截或篡改。LDAPS 通常使用端口 636，而非加密的 LDAP 使用端口 389。 |
| Schema | 定義了 LDAP 目錄中可以存儲的數據類型和格式。包括Object Classes、Attributes和它們之間的關係。LDAP 架構確保目錄中的數據結構一致且符合預定義的規範。例如inetOrgPerson 是一個常見的對象類，它定義了用戶應該包含哪些屬性（如 cn、sn、mail 等）。 |
| DIT (Directory Information Tree) | Directory Information Tree是 LDAP 目錄的層次結構表示。DIT 將目錄數據組織成一棵樹，每個節點代表一個條目。根節點是目錄的起始點，其他條目按層次結構排列在根節點之下，用於組織和管理目錄數據，使其易於查詢和導航。 |
