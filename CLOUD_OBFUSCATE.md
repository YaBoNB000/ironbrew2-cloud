# 云端混淆使用说明(GitHub Actions 免费方案)

不打开电脑、手机也能用 IronBrew2 混淆。原理:混淆器源码放在 GitHub 云端,通过 GitHub Actions 免费机器执行混淆,产物下载回来。

## 免费额度

| 仓库类型 | 免费分钟 | 说明 |
|---|---|---|
| 公共仓库 | 无限 | 源码公开(注意别放敏感脚本) |
| 私有仓库 | 2000 分钟/月 | 一次混淆 1~3 分钟,够用几百次 |

> GitHub 免费账号即可,不用绑卡。

## 一次性准备(电脑上做一次)

1. 在 GitHub 新建仓库(推荐**私有**),例如 `ironbrew2-cloud`
2. 把本目录(`ironbrew-2-master`)内容推上去(**保持目录结构**):

```bash
cd ironbrew-2-master
git init
git add .
git commit -m "混淆器云端版"
git branch -M main
git remote add origin https://github.com/你的用户名/ironbrew2-cloud.git
git push -u origin main
```

> `.gitignore` 已排除测试垃圾、临时产物和你的脚本文件;**确认 `IronBrew2 CLI/bin/Release/net8.0/` 与 `Lua/`(含 lua.exe/luac.exe/Minifier)都被推送**。

## 日常使用(手机即可)

1. **上传源码**:手机浏览器打开 GitHub 仓库 → `Add file` → `Upload files` → 把你的 `.lua` 源码拖进去(建议放 `src/` 文件夹)
2. **触发混淆**:仓库页 → **Actions** 选项卡 → 左侧 **云端混淆** → **Run workflow**
   - `source_file`:填源码路径,如 `src/Main.lua`
   - 所有任务使用同一套稳定配置，不再选择强度
   - 点绿色 **Run workflow**
3. **等 1~3 分钟**:Actions 页面看进度,出现绿色 ✓ 即完成
4. **下载产物**:点进该次运行 → 底部 **Artifacts** → 下载 `obfuscated-xxx`(zip,里面就是 `out.lua` 混淆产物)

## 手机 App 操作(更顺手)

装 GitHub 官方 App:
- 上传文件:仓库页右上 `+` → Upload
- 跑 Actions:Actions 标签 → 云端混淆 → 右上 Run
- 下载产物:运行详情页 → Artifacts → 下载

## 常见问题

**Q:报错 "找不到源码文件"?**
A:路径写错了。先在仓库确认文件在哪个目录,`src/Main.lua` 是"仓库根/src/Main.lua"。

**Q:报错 "缺少 IronBrew2 CLI.dll"?**
A:推送时漏了 `IronBrew2 CLI/bin/Release/net8.0/`(被 .gitignore 或没 add)。检查仓库里该文件是否存在,存在再重跑。

**Q:报错 "缺少 Lua\luac.exe"?**
A:确认 `Lua/lua.exe`、`Lua/luac.exe`、`Lua/Minifier/` 都在仓库里。

**Q:产物下载是 zip?**
A:GitHub 会把单个文件打包成 zip,解压即得 `out.lua`。

**Q:私有仓库 2000 分钟用完了?**
A:一个月后自动恢复;或把仓库改公共(无限,但源码公开)。

**Q:混淆产物能否在纯 Lua 5.1 测试?**
A:可以。固定配置不启用执行器专用 AntiDump 或环境锁，并由自动差分测试验证 Lua 5.1 兼容性。

## 其他免费备选(不想用 GitHub 时)

- **已有云服务器**:装好 .NET 8 + Lua 5.1 后,手机 SSH(Termux/JuiceSSH)登录执行:
  `dotnet "IronBrew2 CLI\bin\Release\net8.0\IronBrew2 CLI.dll" 源码.lua`
  产物 `out.lua` 同目录,手机文件管理器/下载。
- **免费 VPS**:甲骨文云(Oracle Cloud)永久免费实例,装环境后同上。
