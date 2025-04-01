### …或在命令行上创建一个新的仓库



```
echo "# ctf-" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/milkcandyxx/ctf-.git
git push -u origin main
```

### …或从命令行中推送现有的仓库



```
git remote add origin https://github.com/milkcandyxx/ctf-.git
git branch -M main
git push -u origin main
```