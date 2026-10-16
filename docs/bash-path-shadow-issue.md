# atomcode issue #1640 原文记录：[Bug][Windows] bash 工具下 find/sort 被 System32 同名程序抢占

> 用途：记录我在 atomcode 已提交的 issue **#1640** 的全文、讨论与处置。
> 姊妹篇：`mcp-tool-schema-issue.md`（#1664，MCP 工具 schema 延迟加载）。
> **结论：已修复并随 v5.2.3 发布**（修复提交 `2098100a1`，分支 `release/v5.2.3`）。

## 元数据

| 字段 | 值 |
|---|---|
| 编号 | **#1640** |
| 状态 | closed（已修复） |
| 标题 | [Bug][Windows] bash 工具下 find/sort 被 System32 同名程序抢占，GNU 语义失效且报中文错误 |
| 标签 | `bug` / `fixed` / `passed` |
| 里程碑 | v5.2.3 |
| 作者 | qq_43660926（hj01857655） |
| 指派 | saulcy（TheoCui） |
| 创建 | 2026-10-11 16:24:53 +08:00 |
| 关闭 | 2026-10-14 00:45:44 +08:00 |
| 评论 | 4 条 |
| 修复提交 | `2098100a1`（release/v5.2.3） |
| 链接 | https://atomgit.com/atomgit_atomcode/atomcode/issues/1640 |

## 正文原文

````markdown
## 环境

- Windows 10/11 + Git for Windows（Git Bash 已安装）
- AtomCode v5.x，`bash` 工具走 `bash -c` 分支（非 cmd.exe 回退）
- PATH 共 90 段，其中 `C:\Windows\system32` 位于**第 15 段**，而 Git Bash 自带的 `/usr/bin` 位于**第 89 段**

## 现象

`bash` 工具里，`find` / `sort` 被 Windows 原生同名程序抢占，GNU 语义全部失效，且报错是**中文 Windows 报错**，模型完全无法据此自我纠正：

```
$ sort -rn data.txt
输入文件指定了两次。
(exit=1)

$ find . -maxdepth 1 -name 'x.txt' -exec echo FOUND {} \;
FIND: 参数格式不正确
(exit=1)
```

## 根因

`crates/atomcode-capabilities/src/tools/bash.rs:1111` `build_command()`：

```rust
fn build_command(command: &str) -> Result<tokio::process::Command, String> {
    if let Some(bash) = detect_windows_bash() {
        let command = rewrite_nul_redirect(command);
        let mut cmd = tokio::process::Command::new(bash);
        cmd.arg("-c").arg(command.as_ref());
        return Ok(cmd);          // ← PATH 原样继承，未做任何处理
    }
    ...
```

检测到 Git Bash 后走 `bash -c`，但**从不调整 PATH**。MSYS2 启动时把 `/usr/bin` 追加到 Windows PATH 的**末尾**，而 `C:\Windows\system32` 靠前，于是同名命令解析到 Windows 版本。

Git Bash 自带的版本就在磁盘上，只是被遮蔽：

```
$ for c in find sort grep wc cut uniq tr sed awk head tail; do
    printf "%-5s -> %s\n" "$c" "$(command -v $c)"; done
find  -> /c/WINDOWS/system32/find      ← 抢占
sort  -> /c/WINDOWS/system32/sort      ← 抢占
grep  -> /usr/bin/grep
wc    -> /usr/bin/wc
cut   -> /usr/bin/cut
uniq  -> /usr/bin/uniq
...

$ ls -l /usr/bin/find.exe /usr/bin/sort.exe     ← GNU 版本存在却用不上
-rwxr-xr-x ... /usr/bin/find.exe
-rwxr-xr-x ... /usr/bin/sort.exe
```

规律：**只有 System32 里存在同名 exe 的命令才会被抢占**。所以 `grep`/`wc`/`cut` 正常，`find`/`sort` 异常——这类"部分命令好使、部分不好使"的间歇性表现让排查成本很高。

已确认被抢占的：`find`、`sort`、`where`、`tasklist`、`xcopy`、`attrib`。

## 为什么这个 bug 比看上去严重

工具描述（`bash.rs:466` `bash_suffix!`）明确告诉模型"这是一个 POSIX bash，`$(...)`、`|`、heredocs 等**和 Linux 上一样可用**"。于是模型放心地生成 GNU 语义的 `sort -rn` / `find -exec`，然后收到一条**中文 Windows 报错**。

模型看到 `输入文件指定了两次。` 无法推断出"其实是 System32 的 sort.exe 被调用了"，于是：换参数重试 → 再失败 → 再重试，白白消耗 turn 和 API 配额。这一路径在 `bash.rs:656` 的注释里已被承认过（"the model retries blindly, wasting turns + API quota"），但当时只解决了 cmd.exe 语法污染，没覆盖 PATH 抢占。

## 建议修复方向

在 `build_command()` 的 bash 分支里，为子进程设置一个前置的 MSYS2 PATH，使 Git Bash 自带工具优先：

```rust
let mut cmd = tokio::process::Command::new(bash);
cmd.arg("-c").arg(command.as_ref());
// 让 Git Bash 自带工具优先于 System32 同名程序
if let Some(p) = std::env::var_os("PATH") {
    let mut paths = vec![std::path::PathBuf::from("/usr/bin")];
    paths.extend(std::env::split_paths(&p));
    cmd.env("PATH", std::env::join_paths(paths)?);
}
```

（Windows 上 `/usr/bin` 对 MSYS2 子进程即可解析。）

另外建议在 `bash_suffix!` 描述里补一句提示，或做一次启动期探测：若 `find`/`sort` 解析到的不是 `/usr/bin`，就在描述中显式警告模型改用 `/usr/bin/find` 等全路径。

## 补充：此问题与 #1339 不同

#1339 说的是路径里的**反斜杠被当转义符**（`C:\Windows` → 建议用正斜杠），本 issue 是 **PATH 顺序导致同名程序被抢占**，两者根因不同，建议分开处理。
````

## 讨论与处置（4 条，按时间顺序）

### 1. `@atomgit-bot` — 回执

````
[193196071] 你好，谢谢反馈。我们已收到这条 Issue，会由维护者继续处理。代码相关结论需要读仓库核实后再说；若方便可补充版本号与最小复现。
````

### 2. `@saulcy`（维护者）— 修复说明

````
[193197899] 该问题已修复并推送到 release/v5.2.3，将随 v5.2.3 发布。

Windows 下使用 Git Bash/MSYS2 时，现在会在执行命令前将 /usr/bin:/bin 前置到 PATH，确保 GNU find/sort 优先于 System32 同名程序。原 PATH 保留，Windows 原生工具仍可访问；如需调用 Windows 同名版本，可使用明确路径。

修复同时覆盖 bash 和 bash_start，工具描述也已同步更新。相关自动化测试和编译检查通过，已添加 Windows 专用回归测试，尚待 Windows 实机验证。

修复提交：2098100a1。感谢提供详细的复现信息。
````

### 3. `@qq_43660926`（报告者本人）— Windows 实机验证

````
[193199363] ## Windows 实机验证（v5.2.3 / commit 2098100a1）

环境：Windows 10.0.26100，`MSYS_NT-10.0-26100`，Git for Windows。已读 `2098100a1` 完整 diff：Windows `bash -c` 分支现经 `windows_bash_script()` 前置 PATH，`bash` 工具描述已同步更新。以下按证据强度分节标注。

### 一、故障复现（实测，当前二进制未含修复）

```
find -> /c/WINDOWS/system32/find      sort -> /c/WINDOWS/system32/sort
grep -> /usr/bin/grep      wc -> /usr/bin/wc      cut -> /usr/bin/cut

PATH 段序：第 15 段 = /c/WINDOWS/system32
           第 89 段 = /usr/bin        （MSYS2 追加于末尾）

sort -rn data.txt                    → 输入文件指定了两次。
find . -maxdepth 1 -name x          → FIND: 参数格式不正确
find . -maxdepth 1 -name x -exec …  → FIND: 参数格式不正确
```

机制明确：System32 段位远高于 `/usr/bin`，同名时 Windows 版先被找到。

### 二、修复机制有效性（实测）

在**同一故障环境内**直接套用 `export PATH="/usr/bin:/bin${PATH:+:$PATH}"`：

```
find -> /usr/bin/find    sort -> /usr/bin/sort
sort -rn data.txt  → c b a                              exit=0
find -maxdepth 1 -name x     → ./x.txt
find -maxdepth 1 -exec echo FOUND {} \;  → FOUND ./x.txt
```

### 三、无回归（实测 + 文件系统核验）

前置后逐个 `command -v`：`where`→`system32\where`、`reg`→`system32\reg`、`tasklist`→`system32\tasklist`、`sc`→`system32\sc`。并已直接核验 Git 的 `usr/bin` 目录，其中确实**不存在** `where.exe` / `reg.exe` / `tasklist.exe` / `sc.exe`，故前置操作不可能抢占这四个名称。描述中"需调用 Windows 版本请用明确路径"的补充是准确的。

### 四、`bash_start` 双覆盖（读码追踪，非运行时观测）

```
BashStartTool::new → Arc::new(LocalShell)     background.rs:391
  → world.spawn(command, options)               background.rs:172
  → LocalShell::spawn                           bash.rs:2798
  → build_command(&effective_command)           bash.rs:2819
  → windows_bash_script(command)                bash.rs:1091
```

与 `bash` 汇入同一函数，无独立 spawn 旁路。`bash.rs:3485` 的 `Command::new("bash")` 位于 `#[cfg(all(test, unix))]` 内，属测试代码。

需要说明：此节为调用链追踪，我**未实际启动 `bash_start` 作业**观察其内部 PATH。

### 五、碰撞面与本修复的实际作用范围（实测）

同一环境下实测被 System32 抢占的还有：`timeout`、`where`、`ping`、`attrib`、`cipher`、`choice`、`curl`。

但需区分两类，这对评估本修复的收益与风险都很关键。经核验 Git `usr/bin` 目录内容：

| 命令 | Git `usr/bin` 中是否存在 | 本修复是否改变其解析结果 |
|---|---|---|
| `find` / `sort` / `timeout` | 存在 | **是** → 切换到 GNU 版 |
| `where` / `ping` / `attrib` / `cipher` / `choice` / `curl` | 不存在 | **否** → 仍为 Windows 版 |

即：本修复的实际作用面仅限 `find`、`sort`、`timeout` 这三个"两侧同名"的命令；其余命令虽然当前也解析到 System32 版本，但因 Git Bash 未提供对应程序，前置 PATH 对它们不产生任何影响。

其中 `timeout` 影响面较大，因为它常用且失败方式隐蔽：

```
故障环境  timeout 0.3 sleep 5  → rc=1，100ms 退出，被保护的 sleep 未执行，中文报错
修复后                          rc=124，进程按语义被杀
```

即 `timeout <秒> <命令>` 这种 GNU 写法在修复前**完全不可用**。补充一点方法论：测量退出码时不能用 `cmd | head`，`$?` 会变成末段命令的退出码，须重定向到文件后单独读取。

我实测到的碰撞均属"响亮拒绝"型（立即非零退出 + 报错）。**是否存在"接受语法但语义不同"的静默型碰撞，我没有逐命令验证，不作断言。**

### 六、一处未能判定的潜在行为变化

`curl` 当前解析到 `system32\curl`（Windows 自带版，schannel 证书）。本机 Git `usr/bin` 下无 `curl.exe`，故此修复在本机**不会**改变其行为。但若某台机器的 Git for Windows 在 `/usr/bin` 下带了 curl，`curl` 将从 Windows 版切换为 GNU 版（OpenSSL），对依赖系统证书 store 或系统代理的脚本属行为变化。是否需要提示、或对 `curl` 显式保留 Windows 优先，交由维护者判断。

---

**结论**：修复定位准确、实现最小；`bash` / `bash_start` 双覆盖与工具描述更新三项描述属实；机制经实机验证有效，实际修复 `find` / `sort` / `timeout` 三者的 GNU 语义。

**边界**：以上非装机验证——我无法替换正在运行的二进制，第二节是在真实故障环境内直接套用该 `export` 语句实测所得。v5.2.3 正式版仍待装机确认。
````

### 4. `@jiulongSQ` — 第三方 Windows 实机回归

````
[193475333] ## Windows 实机验证补充（release/v5.2.3，含修复提交 2098100a1）

在维护者上方两条评论的基础上，补上此前缺失的 Windows 实机回归测试结果。

**验证基线**：分支 `release/v5.2.3`（`45cdfa1f0`），修复提交 `2098100a1` 已在祖先链上；Windows 10 + Git Bash 本机实测；`cargo test -p atomcode-capabilities --lib`。

| 验证项 | 证据 | 结果 |
|---|---|---|
| PATH 前置实现 | `windows_bash_script()`（bash.rs:1073）在命令前插入 `export PATH="/usr/bin:/bin${PATH:+:$PATH}"`；`build_command()` 的 bash 分支（:1091）接入该脚本 | ✅ 代码核对 |
| 工具描述同步 | bash.rs:431 新增「GNU tools in /usr/bin and /bin take priority … To run a Windows version, use its explicit path (e.g. C:/Windows/System32/find.exe)」 | ✅ 代码核对 |
| Windows 真机回归测试 | `git_bash_prefers_gnu_find_and_sort_over_system32`：把子进程 PATH 设为**仅 System32**（复刻本 issue 的故障环境），走生产函数 `build_command()` 执行 `sort -rn data.txt && find . -maxdepth 1 -name x.txt -exec echo FOUND {} \;`，断言输出为 GNU 语义的 `10\n2\n1\nFOUND ./x.txt` | ✅ **1 passed / 0 failed** |

**结论**：这条 `#[cfg(windows)]` 测试直接在本机补上了「尚待 Windows 实机验证」的缺口——它在真实 Git Bash + 仅 System32 PATH 的环境下验证了修复后 GNU `find`/`sort` 生效。结合上方报告者已实测的机制验证（前置 PATH 后 `find`/`sort`/`timeout` 三者恢复 GNU 语义、`where`/`reg`/`tasklist`/`sc` 等不受影响），本修复可随 v5.2.3 发布。

**未验证范围**：`#[cfg(unix)]` 的继承工具测试（`windows_bash_setup_prefers_posix_tools_and_keeps_inherited_tools`）在 Windows 本机不可运行；报告者提到的静默型碰撞（「接受语法但语义不同」）未逐命令验证，维持报告者「不作断言」的结论。
````

## 处置结果

- **状态**：closed，标签 `bug` / `fixed` / `passed`，里程碑 **v5.2.3**。
- **修复**：`windows_bash_script()`（`bash.rs:1073`）在命令前插入 `export PATH="/usr/bin:/bin${PATH:+:$PATH}"`，`build_command()` 的 bash 分支（`:1091`）接入；`bash` 与 `bash_start` 双覆盖；工具描述（`bash.rs:431`）同步更新。修复提交 `2098100a1`。
- **回归**：新增 `#[cfg(windows)]` 测试 `git_bash_prefers_gnu_find_and_sort_over_system32`（1 passed / 0 failed），在仅 System32 的 PATH 下验证 GNU `find`/`sort` 生效。
- **实际作用面**：仅 `find` / `sort` / `timeout` 三个"两侧同名"的命令；`where`/`ping`/`attrib` 等因 Git Bash 未提供对应程序而不受影响。