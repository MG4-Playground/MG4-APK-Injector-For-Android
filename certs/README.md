# 证书重签 / 新增劫持域名

本目录是 APK 注入所需的 **MITM 证书重签工具**，随本安卓仓库一起维护，便于：
- 证书到期后续签；
- 应用商店再次更换下载/详情域名时，把新域名加进证书 SAN。

> 安全：本目录含中间证书私钥（`keys/*.key.pem`）与还原记录（`keys/_secrets.json`、
> `_recovery.json`），属敏感材料，**请勿外泄**，也不要提交到公开仓库。

## 原理

我们的叶子证书由 eMudhra 的弱密钥中间证书（`EM OV TLS CA - G3C`）签发；该 CA 的私钥
已通过公开披露的弱密钥缺陷（KGC 缺陷，无需任何秘密）还原，保存在 `keys/`。
车机信任的是 eMudhra 的公共根，因此由这些中间证书签发的叶子证书在旧车机上能通过校验。

## 重签步骤

```bash
cd MG4-APK-Injector-For-Android/certs
pip install cryptography        # 仅首次需要
python sign_leaf.py
```

脚本会：还原校验中间证书私钥 → 生成新的 RSA-2048 叶子 → 追加 3 张链证书 →
**直接写回** `android-app/app/src/main/assets/{chain.pem,leaf.key.pem}`。

随后回到工程目录重新构建 APK 即可（见仓库根 README 第三节）。

## 新增 / 修改劫持域名

1. 编辑本目录 `sign_leaf.py` 的 `DOMAINS` 列表（当前已含详情域名、通配 `*.z-onesoft.com`、
   旧 OSS 下载域名）。
2. 重新 `python sign_leaf.py` 重签。
3. 同时把新域名加进 `android-app/app/src/main/assets/store_rules.json` 的 `serve`（下载域名）
   或 `patch`（详情域名），否则证书放行了但本机不会投递/改写对应请求。

> 提示：`*.z-onesoft.com` 通配已覆盖 `z-onesoft.com` 下的**所有**子域（详情 + 当前及今后
> 可能出现的下载 CDN 子域）。因此 store 在该域下再换下载域名时，**一般只需**在
> `store_rules.json` 加一条 serve 规则，无需重签证书。
> 仅当域名落到其它一级域（如再次改回 aliyuncs 以外的 CDN）时才需要改 `DOMAINS` 并重签。

## 私钥丢失怎么办

若 `keys/*.key.pem` 不慎丢失，可先从公开的中间证书公钥把弱密钥中间证书私钥还原：

```bash
python recover_keys.py          # 还原 8 张中间证书私钥 -> keys/
python sign_leaf.py            # 随后照常重签
```
