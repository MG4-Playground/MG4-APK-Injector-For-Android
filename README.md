# MG4 车机应用商店 · 第三方 APK 注入（安卓版）

> **使用边界**：仅限本人拥有的设备与车辆。所用中间证书已被全球根库移除并吊销，
> 有效性只针对未更新信任库的旧车机。请勿用于他人设备。

## 一、原理（一句话）

安卓 APP（**需 root**）装在被劫持的**手机**上；手机开「移动热点」做网关，车机连该热点。
APP 用 root + iptables 把车机的 `udp/53 → 本机 15353`、`tcp/443 → 本机 18443` 重定向；
本机 DNS 把商店域名解析到热点 IP，HTTPS 服务用同一套证书改写详情 JSON + 直投 APK。

```
车机 (Android)
  │ 连手机热点, DNS 查询商店域名
  ▼
手机 (Android, root)
  ① NetInfo 探测真实热点 IP / 接口名
  ② iptables REDIRECT: 车机 53→15353, 443→18443
  ③ DnsServer 把商店域名解析到热点 IP
  ④ HttpsService 改写 JSON / 下发 APK
```

三层原理：

| 层 | 做什么 | 关键点 |
|---|---|---|
| **DNS 定向** | 把商店域名解析到本机 | 车机连的是**热点 IP**，不是 VPN 地址 |
| **TLS 冒充** | 用中间证书冒充商店 | 单张多 SAN 证书，**不按 SNI 切换** |
| **内容替换** | patch 改 JSON 字段 / serve 直投 APK | 回源要解 chunked + 内容压缩 |

## 二、前置条件与 root 必要性

- **手机已 root**（Magisk / KernelSU）。原因见下。
- 手机已开启「移动热点」；车机连上该热点。

### 为什么必须 root（Android 硬约束）

**约束一：特权端口。** Android 内核 `net.ipv4.ip_unprivileged_port_start = 1024`，
只有 root 或持有 `CAP_NET_BIND_SERVICE` 的进程才能绑定 1024 以下端口。声明 `INTERNET`
权限**绕不过**这个内核级检查。而车机侧写死：`https://…` → **443**，`DNS` → **53**。
所以 Android 上必须用 iptables 把车机的 53/443 重定向到高位端口（15353 / 18443）。

**约束二：热点客户端流量不进 VpnService。** Android 的 tethering（热点）走**内核转发**，
`VpnService` 只按**本机 UID** 做分流。官方文档与实测均确认：热点连接的设备，
其流量**不经过 VpnService 的 TUN 设备**。因此「靠 VPN 隧道拦截车机」在 Android 上不成立
——即使 VpnService 工作正常，车机的包也不会进隧道。结论：安卓版**必须有 root**。

> 无 root 时 App 仍可启动，但会在日志里明确说明无法劫持。

## 三、APK 构建步骤（详细）

### 3.1 环境要求

| 组件 | 版本 / 说明 |
|---|---|
| JDK | **17**（如 Eclipse Adoptium Temurin 17） |
| Android SDK | platform **34**，build-tools **34+**（建议 34 或 36） |
| Gradle | 项目自带 `gradlew` wrapper（Gradle 8.5），无需单独安装 |
| 设备 | 已 root 的 Android 手机 + 车机；ADB 可连手机 |
| Python | 仅离线回归测试需要（可选） |

### 3.2 配置 SDK 路径

在 `android-app/` 目录下创建 `local.properties`，写入 SDK 绝对路径
（**必须用正斜杠**，反斜杠会报"文件名、目录名或卷标语法不正确"）：

```properties
sdk.dir=C:/Users/<你的用户名>/AppData/Local/Android/Sdk
```

### 3.3 构建 Debug APK

```bash
cd MG4-Android/android-app

# 方式 A：用项目自带的 Gradle Wrapper（推荐，免装 Gradle）
./gradlew assembleDebug
# Windows PowerShell 若禁止脚本执行，可改用：
./gradlew.bat assembleDebug

# 方式 B：若已单独安装 Gradle 8.5
gradle assembleDebug
```

构建过程会：解析依赖 → 编译 `com.mg4.carstore` 下 12 个类 → 打包资源 → 产出 APK。
看到 `BUILD SUCCESSFUL` 即成功。

### 3.4 产物位置

```
MG4-Android/android-app/app/build/outputs/apk/debug/app-debug.apk
```

### 3.5 安装到手机

```bash
# 通过 ADB 安装（手机已连电脑并开启 USB 调试 + 已授权 root）
adb install -r MG4-Android/android-app/app/build/outputs/apk/debug/app-debug.apk

# 或：把 app-debug.apk 拷到手机，在文件管理器里手动安装
```

> `-r` 表示覆盖安装（保留数据）。首次安装需在系统设置里允许「未知来源」。

### 3.6 离线回归测试（可选，无真机时守回归）

```bash
cd MG4-Android/android-app/app/src/test
python run_all.py
```

覆盖：DNS 应答字节级对照、VPN 地址选取、iptables 规则序列、源码空安全静态检查。

### 3.7 常见构建问题

| 现象 | 原因 | 解决 |
|---|---|---|
| `SDK location not found` | 没配 `local.properties` | 按 3.2 创建并写对 `sdk.dir`（正斜杠） |
| `failed to find Build Tools` / AAPT 报错 | build-tools 未装或版本过低 | SDK Manager 安装 build-tools 34+ |
| `Could not determine java version` | JDK 不是 17 | 安装 JDK 17 并让 `JAVA_HOME` 指向它 |
| `Manifest merger failed` | 权限/SDK 配置冲突 | 检查 `targetSdk` 与 `compileSdk = 34` 一致 |
| 装到手机后打不开 | 未 root / 未授权 root | Magisk 中授权本 App 为 root |

## 四、使用步骤

1. **打开手机「移动热点」**（必须先开！未开热点 App 会提示「请先打开移动热点，再点启动劫持」
   并安全返回，不会闪退）
2. 车机连接该热点
3. 打开本 App → 确认顶部「热点地址 / VPN 地址」探测正确
   - 若探测不准，可在输入框手动改，点「重探测」
4. 选择要安装的 APK（App 自动读出真实包名 / 应用名 / 字节数并回填规则）
5. 点「启动劫持」→ 授予 VPN 权限
6. 车机上打开应用商店 → 进详情页 → 应显示你填的名字/体积 → 点安装

## 五、日志与排障

App 界面有实时日志。关键行：

```
[vpn] 网络探测结果: 热点开关=已开启 热点地址=192.168.43.1 接口=wlan1 | VPN=10.7.7.1
[root] iptables 重定向已安装 (wlan1): udp/53->15353, tcp/443->18443
[dns] 劫持 prod-r-platform.z-onesoft.com -> 192.168.43.1
[patch] 改写成功 4 个字段: ...
[serve] 投递完成 157605849 bytes == APK 大小 157605849 OK
```

| 现象 | 看哪行 | 怎么修 |
|---|---|---|
| 启动报「移动热点未开启」 | `热点开关=未开启` | 先开手机热点再点启动 |
| `未检测到 root` | `[root] 未检测到 root` | Magisk 授权本 App |
| iptables 规则安装失败 | `[root] iptables 规则安装失败` | 部分 ROM 的 iptables 路径不同，看日志调整 `RootTools.execSu` |
| 详情页名称没变、无 `[dns] 劫持` | — | 确认 root 生效 + 车机连本机热点；必要时车机 Wi-Fi 手动填 DNS=热点 IP |
| 详情页变了但装的是官方 app | 无 `[serve] 规则命中` | 把下载路径加进 `store_rules.json` 的 serve 规则 |

**关于「车机 DNS 没走到本机」**：Android 各 ROM 对 tethering DNS 处理不同，
有的把热点客户端 DNS 交给 VPN，有的用 DHCP 下发的 DNS（=热点 IP，靠 iptables 把
`udp/53` 重定向到 15353 兜底）。两条路都铺了，多数情况无需额外操作；若日志始终没有
`[dns] 劫持`，请在车机 Wi-Fi 设置里把 DNS 手动指定为本机热点 IP。

## 六、源码结构

路径以本仓库 `MG4-Android/android-app/` 为基准：

```
android-app/
├── app/src/main/java/com/mg4/carstore/
│   ├── MainActivity.java         UI: 探测显示 / 手动覆盖 / 选 APK / 启停
│   ├── CarStoreVpnService.java    服务编排: 探测 → 建隧道 → 起服务 → 装 iptables
│   ├── CarStoreApplication.java   全局 UncaughtExceptionHandler (crash.log + Toast)
│   ├── NetInfo.java               ★ 动态网络探测 (热点 IP / 接口名 / VPN 地址)
│   ├── RootTools.java             ★ root 检测 + iptables 规则管理
│   ├── DnsServer.java             DNS 劫持 (监听 15353, 占用时自动顺延)
│   ├── HttpsService.java          HTTPS 处理 (监听 18443, serve/patch/透传)
│   ├── SslFactory.java            从 assets PEM 构建 SSLContext (按 OID 选 KeyFactory)
│   ├── MiniDns.java               最小 DNS 客户端 (回源用, 不走系统解析器)
│   ├── RuleStore.java             规则引擎 (点路径 get/set)
│   ├── RuleEngine.java            单例: 规则 + 目标 APK
│   └── LogBus.java                日志总线
├── app/src/main/res/layout/activity_main.xml
├── app/src/test/
│   ├── run_all.py                 ★ 全部离线测试入口
│   ├── logic_check.py             ★ DNS 应答字节级对照 + VPN 地址选取
│   ├── iptables_check.py          ★ iptables 规则序列检查
│   └── nullsafety_check.py        ★ 源码空安全静态检查 (防 NPE 回归)
└── app/src/main/assets/
    ├── chain.pem                  叶子 + 3 张中间件 (覆盖 3 个信任库)
    ├── leaf.key.pem               叶子私钥
    └── store_rules.json           规则 (serve / patch)
```

**关键实现要点（踩坑沉淀）：**
- 监听端口 15353（DNS）/ 18443（HTTPS），均**支持自动顺延**（最多 20 个），
  且 DNS 只绑 `0.0.0.0`（天然覆盖所有本地地址，端口必然一致）。
- 叶子证书密钥 = **RSA-2048**（老车机兼容性最好），中间证书 = **P-384**；
  `SslFactory` 按 PKCS8 的 AlgorithmIdentifier OID 选 KeyFactory（rsa → RSA，ec → EC）。
- 证书链 4 张（`chain.pem`）：leaf + 两张 `EM OV TLS CA - G3C`（分别 issuer 为
  AAA Certificate Services 与 emSign Root TLS CA - G3）+ 交叉签名根，覆盖多信任库。
- 动态网络探测（`NetInfo`）：热点 IP 绝不写死（各机型网段不同），按
  `SoftApConfiguration` 热点地址(+400) > DHCP server(+200) > 接口名特征(+30)
  > 私网(+40) 打分，并排除上行接口(−80) 与 VPN 接口(−100)。

## 七、版本变更与已知限制

### 崩溃与稳定性修复（v5 → v7.4 累积）
- **v7.1**：`MainActivity.registerReceiver(..., RECEIVER_NOT_EXPORTED)`，修复 Android 13+
  启动即崩（`SecurityException`）。
- **v7.2**：`CarStoreVpnService.onStartCommand` 先同步调用 `startForeground` 满足前台服务
  ~5s 时限，重活丢后台线程，修复 `ForegroundServiceDidNotStartInTimeException` 导致进程被杀。
- **v7.1 起**：`CarStoreApplication` 注册全局 `UncaughtExceptionHandler`，未捕获异常写
  `crash.log` 并弹 Toast —— 实现「报错而非闪退」。
- **v7.3 起**：`crash.log` 外部（`getExternalFilesDir`）+ 内部（`getFilesDir`）双写兜底。
- **v5 起**：`stopEverything()` 改为后台线程执行 `execSu`，加 4s 看门狗与 `tornDown` 去重，
  修复「点停止劫持卡死闪退」。

### v7.4 关键改动（回退 v7.3 的劫持破坏）
v7.3 在 iptables 的 443 重定向上加了 `-d <热点IP>` 目的地址限制，意图只劫持被 DNS 定向到
热点 IP 的商店域名。但商店类 App 普遍走 **HTTPDNS**：详情/下载接口直接解析成真实 IP，
从而**绕过我们的 DNS 劫持**。v7.2 是「按端口 443 全量重定向」（不管目的 IP，只要车机发
443 就被 MITM 拦下改写），所以即便 HTTPDNS 解析到真实 IP 也能劫持成功；v7.3 加了 `-d 热点IP`
后，真实 IP 不匹配该目的地址、从 NAT 直放、MITM 看不到请求 → 标题/体积不再被篡改。

**v7.4 回退该 `-d` 限制**，恢复按端口 443 全量重定向
（`iptables -t nat -A CARSTORE -p tcp --dport 443 -j REDIRECT --to-ports <httpsPort>`，
不限目的地址），即恢复 v7.2 的劫持能力，同时保留上述全部崩溃修复。

### 已知限制
全量 443 MITM 会使非商店域名（speech / baidu / httpdns 等）的 TLS 握手失败，
这可能正是「安装第三方 APK 失败」的原因。若需在不破坏详情页劫持的前提下让安装也成功，
后续可在 `HttpsService` 做 **SNI 选择性隧道**：解析 ClientHello 的 SNI，命中商店域名才
MITM，否则原样 TCP 隧道到真实服务器。该改动风险较高，需单独迭代。

**与 Windows 版的关系**：证书（`chain.pem` / `leaf.key.pem`）、规则（`store_rules.json` 的
serve/patch 语义）、目标 APK 三样与 Windows 版**完全共用**，仅传输层实现不同
（Windows 用 hosts 劫持 + `proxy_server.py`；安卓用 iptables + 本机 DNS/HTTPS 服务）。

## 八、安全边界

- 本方案仅用于**本人车辆 + 本人设备**验证。
- 涉及的中间证书已被 Chrome / Firefox / Apple / Microsoft 从信任库移除，
  现代系统无法被此链欺骗；有效性只对**未更新信任库的旧车机**成立。
- root 后的 iptables 规则在**停止服务时会被清理**（`RootTools.removeRedirect()`）。
- 所有操作仅在你自己手机上执行，不涉及他人设备。
