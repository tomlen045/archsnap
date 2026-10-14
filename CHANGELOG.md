# Changelog

## v1.1.0 (2026-10-14)

- **修复**: symlink 改指向检出失效——`target` 记在档案顶层但 diff 从 `features` 读, 改指向永远落不进 FEAT/CRIT。真实升级演习抓到(软链 tool 指向被换, diff 只报 CHANGED)。现 diff 从顶层读 target, 改指向正确升格 CRIT。
- **自测 14 -> 15 项**: 新增 symlink 改指向端到端不变量。
- 版本纪律: 修复经真实演习验证(升级包换软链指向 -> `[CRIT][FEAT] bin/tool target: ... -> ...`)后才 bump。

## v1.0.0 (2026-10-13)

- 首发: 四格式解析(ELF/Mach-O/PE/脚本), symlink 语义, 三级 diff, 退出码即结论, 14 项自测, 44,274 份档案真机扫描。
