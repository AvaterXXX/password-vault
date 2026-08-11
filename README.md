# 密码保险柜

<p align="center">
  <img src="assets/app_icon.png" width="120" alt="密码保险柜图标" />
</p>

<p align="center">
  <b>本地 · 国密加密 · 账户 / 密码 / 二次验证管理</b>
</p>

<p align="center">
  白色简洁界面 · 一键复制 · 常用网站侧栏 · 可打包成 Windows 程序
</p>

---

## 能做什么

| 功能 | 说明 |
|------|------|
| **账户管理** | 新增 / 编辑 / 删除账户，分类筛选与搜索 |
| **字段分离** | 标题、账号、密码、二次验证密钥、网站地址、备注各自独立 |
| **二次验证** | 粘贴 TOTP 密钥后自动生成当前验证码，支持一键复制 |
| **常用网站** | 右侧快捷入口，左键打开，右键删除 |
| **国密加密** | SM3 派生主密钥 + SM4-CBC 加密敏感字段 |
| **主密码** | 主密码不落盘；无主密码无法解密本地数据 |

适合记录 ChatGPT 等 AI 账号、邮箱、开发平台等各类登录信息。

---

## 界面预览

```
┌──────────────┬────────────────────────────┬────────────┐
│  账户列表    │  账户详情                  │ 常用网站   │
│  分类筛选    │  账号 / 密码 / 二次验证    │ 一键打开   │
│  搜索        │  网站地址 / 备注           │ 右键删除   │
│              │  实时验证码 + 倒计时       │            │
└──────────────┴────────────────────────────┴────────────┘
```

- 左侧：账户列表（账号优先展示）
- 中间：详情编辑区
- 右侧：常用网站快捷栏

---

## 快速开始

### 环境要求

- Windows / macOS / Linux
- Python 3.10+

### 安装依赖

```bash
```bash
git clone https://github.com/AvaterXXX/password-vault.git
cd password-vault
pip install -r requirements.txt
```

### 运行

```bash
python main.py
```

仓库地址：<https://github.com/AvaterXXX/password-vault>

首次启动会要求设置 **主密码**（至少 6 位）。请牢记，丢失后本地密文无法恢复。

---

## 打包成 exe（Windows）

```bash
pip install -r requirements.txt
python build_exe.py
```

生成文件：

```text
dist/密码保险柜.exe
```

双击即可使用，无需安装 Python。

---

## 安全说明

本工具是 **密码管理器**，需要在你输入主密码后解密并回填密码，因此采用 **可逆的国密 SM4 加密**，而不是单向哈希。

| 项目 | 实现 |
|------|------|
| 密钥派生 | 国密 **SM3** 多轮派生 |
| 字段加密 | 国密 **SM4-CBC** |
| 保护字段 | 密码、二次验证密钥、备注 |
| 主密码 | 仅存随机盐 + 校验值，**主密码本身不写入磁盘** |

**建议：**

1. 使用足够长、复杂的主密码  
2. 不要把 `%APPDATA%\AccountVault\` 下的数据库/密钥文件分享给他人  
3. 导出明文（如有）后请妥善保管或及时删除  

> 说明：没有主密码时，攻击者难以在合理时间内解开密文；安全性很大程度上取决于你的主密码强度。

---

## 数据存放位置

| 系统 | 路径 |
|------|------|
| Windows | `%APPDATA%\AccountVault\` |
| 其他 | `~/.account_vault/AccountVault/` |

主要文件：

- `vault.db` — 本地数据库（敏感字段已加密）
- 元数据中的盐与校验信息（用于解锁，不可还原主密码）

---

## 项目结构

```text
password-vault/
├── main.py            # 界面与交互
├── storage.py         # 本地存储与解锁逻辑
├── crypto_gm.py       # 国密 SM3 / SM4
├── build_exe.py       # PyInstaller 打包脚本
├── requirements.txt
├── assets/
│   ├── app.ico        # Windows 图标
│   └── app_icon.png   # README 图标
└── README.md
```

---

## 依赖

```text
customtkinter   # 现代化界面
pyotp           # TOTP 验证码
gmssl           # 国密算法
cryptography    # 兼容旧数据迁移（可选）
pyinstaller     # 打包（可选）
```

---

## 常见问题

**Q：主密码忘了怎么办？**  
A：无法找回。国密设计下没有主密码就不能解密，只能重新建库。

**Q：二次验证填什么？**  
A：填认证器里的 **密钥（Secret）**，不是已经显示的 6 位动态码。支持带空格密钥或 `otpauth://` 链接。

**Q：可以只记录普通网站账号吗？**  
A：可以。分类、网站地址、备注都支持，不限于 AI 账号。

---

## 许可证

MIT License — 可自由使用与修改。欢迎 Star / Issue / PR。

---

<p align="center">
  用主密码守护你的数字钥匙 🔑
</p>
