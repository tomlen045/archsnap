# archsnap — 二进制架构画像与升级前后比对

`archsnap` 把目录里的每一个文件扫成一份机器可读的「架构画像」（ELF / Mach-O / PE / 脚本），再对两份画像做 diff，把「换过的文件」和「特征变了的老朋友」分开拎出来。

一句话：**cfgdrift 盯文本配置的漂移，archsnap 盯二进制特征的漂移。**

## 为什么需要它

- 供应商升级包 / 中间件补丁替换二进制后，PIE 被摘除、动态依赖悄悄多了一个库、interp 换了加载器——哈希变了你看得出「换过」，但**换出了什么没人告诉你**。
- 包管理器全靠 symlink 布局（brew / apt / yum 皆然）：升级包把软链改个指向 = 换了二进制，`ls` 看不出任何变化。
- 合规与应急：ARM 化迁移、信创适配、灰度发布前后，你需要一份「这套目录里的二进制长什么样」的底账。

## 特性

- **零依赖单文件**：Python 3 标准库实现，`python3 archsnap.py` 即跑，离线可用。
- **四格式解析**：ELF(32/64、大小端、PIE、PT_INTERP、DT_NEEDED)、Mach-O(cpu 类型/文件类型/MH_PIE)、PE(机器类型/子系统)、脚本(shebang)。
- **symlink 语义**：软链解析到真实目标取特征，同时把 target 记入档案——改指向 = 特征级变化(CRIT)，不是普通文件替换。
- **三级 diff**：`FEAT/CRIT`（特征级变化：PIE 摘除、依赖增减、架构变化、symlink 改向）＞ `CHANGED/WARN`（内容变了特征没变）＞ `ADD|DEL/INFO`。
- **退出码即结论**：`0` 干净、`1` 有变化、`2` 参数/IO 错误、`3` 自测未过——cron 与 CI 直接用。
- **偏态免疫**：4 万文件里 2 个特征变化也全部登顶 CRIT，不被海量普通替换淹没（内置演习验证）。
- **自测 14 项全绿**：`selftest` 子命令内置全部不变量，含合成 ELF fixture 与 400 文件偏态演习。

## 快速开始

```bash
# 升级前拍基线
python3 archsnap.py scan /opt/app -o baseline.json

# 供应商升级包落地后
python3 archsnap.py scan /opt/app -o after.json --baseline baseline.json

# 只对两份画像做比对(--fail-on feat: 仅特征级变化才返回 1)
python3 archsnap.py diff baseline.json after.json --fail-on feat --report diff.txt

# 内置自测
python3 archsnap.py selftest
```

输出示例（真实运行）：

```
[scan] files=44274 binaries=44274 -> cellar.json
  formats: {"RAW": 42407, "Mach-O": 1510, "SCRIPT": 347, "PE": 10}
  pie: {"yes": 560, "no": 0}
```

```
==============================================================
archsnap diff  CRIT=1  CHANGED=0  ADD/DEL=2
==============================================================
[CRIT][FEAT] svc.so
        pie: True -> False
[INFO][DEL] gone.txt
[INFO][ADD] new.txt
--------------------------------------------------------------
结论: 1 个文件特征级变化 —— 升级包不只是换了文件, 行为特征也变了
```

## diff 分级语义

| 级别 | 判定 | 含义 |
|---|---|---|
| `CRIT / FEAT` | PIE 位、格式、架构、interp、DT_NEEDED 集合、symlink target 任一变化 | 行为特征变了，不只是换了文件 |
| `WARN / CHANGED` | sha256 不同但特征全同 | 普通重编译/补丁，特征未变 |
| `INFO / ADD·DEL` | 文件出现/消失 | 名录变化 |

## 边界（一句大实话）

- 特征解析基于头部与动态段，**不是完整的逆向**：它回答「特征变没变」，不回答「新增了什么恶意代码」。
- 加壳/混淆的二进制可能解析为 `RAW`——仍会做哈希级 diff，只是没有特征级判定。
- 悬空软链（指向不存在的目标）不入档：换了指向但目标缺失属于部署事故，交给包管理器报错。
- 超大文件（>512MB）读入截断，哈希仅覆盖前部——这类文件通常是数据不是程序。

## 哨兵套件

| 环节 | 工具 | 盯什么 |
|---|---|---|
| 1 | cronguard | 定时任务死活 |
| 2 | authguard | 登录面 |
| 3 | cfgdrift | 文本配置漂移 |
| 4 | suidhunt | 特权文件 |
| 5 | callhome | 外联信标 |
| **6** | **archsnap** | **二进制特征漂移（本工具）** |

## 自测

```bash
$ python3 archsnap.py selftest
  elf: etype=3 识别为 PIE                                 PASS
  elf: DT_NEEDED 2 条全解出                                PASS
  elf: PT_INTERP 读出                                    PASS
  elf: etype=2 识别为非 PIE(EXEC)                          PASS
  pe: machine 0x8664 -> x64                            PASS
  macho: cputype -> ARM64                              PASS
  script: shebang 读出                                   PASS
  diff: DEL 检出                                         PASS
  diff: ADD 检出                                         PASS
  diff: PIE 摘除升级为 FEAT(CRIT)                           PASS
  diff: 未变文件零误报                                        PASS
  diff: FEAT 详情含 pie 字段                                PASS
  偏态演习: 2/400 特征变化全部拎出(CRIT=2)                         PASS
  退出码约定: 0干净/1变化/2参数/3自测失败(文档)                         PASS
==============================================================
SELFTEST PASS 14/14
```

## License

MIT
