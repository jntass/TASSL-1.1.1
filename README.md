1、当前版本基于开源openssl1.1.1s修改。相较于之前的tassl 1.1.1k版本，修复了以下漏洞: CVE-2021-3711 CVE-2021-3712 CVE-2022-0778 CVE-2022-1292 CVE-2022-2068 CVE-2022-2097

2、支持国密SSL协议(GM/T 0024-2014)。使用原生接口加载加密证书/密钥，对于使用openssl的程序有更好的兼容性，降低应用进行国密SSL迁移的开发成本。

3、支持TLCP(GB/T 38636-2020)。增加对GCM套件的支持。

4、支持RFC 8998  ShangMi (SM) Cipher Suites for TLS 1.3。基于TLS1.3实现了两个国密套件TLS_SM4_GCM_SM3/TLS_SM4_CCM_SM3。放宽了双证的需求，使用SM2单证书；取消了在使用ECDHE算法时必须有客户端证书的限制。

5、支持原生nginx。tassl可与原生nginx实现国密SSL的web server/反向代理；同时支持使用江南天安硬件产品(密码机/密码卡)存储SSL长期密钥，以保证密钥安全性。(零代码改造，只需修改配置)

6、支持原生apache。tassl可与原生apache实现国密SSL的web server/反向代理；同时支持使用江南天安硬件产品(密码机/密码卡)存储SSL长期密钥，以保证密钥安全性。(零代码改造，只需修改配置)

7、支持ukey。tassl支持客户端使用ukey(客户端私钥/证书存储于ukey)完成与服务端的SSL握手。(参考tassl安装目录下tassl_demo/ukey/)

使用请参考《软算法支持SSL卸载使用指南.pdf》
