# Zibll OAuth

Zibll OAuth 是一个运行在 WordPress 上的 OAuth2 / OpenID 风格授权服务端插件（面向 Zibll 主题站点），对外提供统一的授权、换取 Token、获取用户信息能力。

## 运行环境

- WordPress（需支持 WP-JSON）
- 推荐使用 Zibll 主题（插件的用户中心 UI/拟态框/人机验证/站内信能力会复用主题能力）

## 功能

> 本插件依赖 WP-JSON
- `/authorize` 授权页（Zibll 风格，支持同意/拒绝；同意需人机验证并通过 `admin-ajax` 提交，回调时直接返回 `openid` 与原样 `state`）
- `/token` 使用 `appid + appkey + openid + sign` 换取短期 `access_token`（可重复调用获取新 token）
- `/userinfo` 使用 `access_token` 获取用户信息（默认返回 **openid**，appid 维度，可在已完成财务授权时返回余额 `balance`）
- `/unionid` OpenID 转 UnionID（跨应用标识；默认 `unionid=WordPress 用户ID`）
- `/authorize_finance` 财务权限（免密支付）二次签约页
- `/finance/deduct` 扣除授权用户余额（类型在服务端固定为"三方扣款"，接入方只需传入商品名称、金额与订单号），支持异步校验
- `/finance/verify` 异步校验扣款结果（支持通过 `trade_no` 或接入方自定义的 `order_no` 查询）

### TG Bot 积分互通（2026-03 新增）

> 供 TG Bot（小芽精灵）通过 `appid + openid + sign` 服务端鉴权调用

| 端点 | 方法 | 说明 |
|------|------|------|
| `/points/add` | POST | 给用户充值站点积分（TG 积分兑换） |
| `/points/balance` | GET | 查询用户站点积分余额 |
| `/user/profile` | GET | 查询用户站点个人信息（昵称、推荐人数） |

签名规则：
- `points/add`：`sign = md5(appid + openid + amount + appkey)`
- `points/balance` / `user/profile`：`sign = md5(appid + openid + appkey)`

## SDK支持

本项目提供多种语言的SDK，方便开发者快速接入：

- [Go SDK](sdk/golang/) - Go语言实现的客户端SDK
- PHP插件 - 内置的WordPress插件实现

### Go SDK特点

- 类型安全的API调用
- 完善的错误处理
- 统一的返回格式（成功/失败都返回结构化数据）
- 财务接口支持（FinanceDeduct、FinanceVerify）
- 自定义日志支持
- 选项模式配置

### PHP插件特点

- WordPress原生集成
- 统一的成功/失败返回格式
- 支持财务扣款和验证
- 安全的回调处理
- 与Zibll主题无缝集成

## 文档

- 对接文档：`docs/开发文档.md`
- Go SDK文档：`sdk/golang/README.md`

## 前台（用户中心）能力

入口：用户中心侧边栏 `OAuth设置`。

- `应用管理`
  - 创建/编辑应用（redirect_uri、scope、图标上传）
  - 提交审核（需要人机验证）
  - 删除应用（高风险操作，**仅密码验证**，并可能需要人机验证）
  - 轮转 AppKey（高风险操作，**仅密码验证**，并可能需要人机验证）
    - 轮转成功后 **新 AppKey 不在页面回显**，仅通过：站内信 + 邮件发送
- `授权记录`
  - 查看历史授权过的应用与授权时间
  - 支持在"授权记录"中主动**取消授权**（包含财务权限），取消后应用将无法继续通过 `/userinfo` `/unionid` 等接口获取该用户任何信息（并通过回调通知接入方）
- `开发文档`
  - 指向对接文档

## 使用说明（新流程）

- 管理员在后台 `Zibll OAuth -> 基础设置` 配置 **开发者白名单**
- 开发者在前台用户中心 `OAuth设置`：创建应用、修改配置、提交审核（提交需人机验证）
- 管理员在后台 `Zibll OAuth -> 应用审核`：仅支持 **查/审**（不允许创建）
- 应用只有在后台将"审核状态"设置为 `已通过（上线）` 后才可授权
  - 未上线/被驳回将拒绝授权，并返回：`应用暂未上线，请联系应用管理员`

审核结果通知：

- 站内信 + 邮件通知开发者
- 通知内容包含 `AppID`

应用数据表：`wp_zibll_oauth_app`

## 授权记录

- 用户每次点击"同意授权"会写入一条授权记录
- 数据表：`wp_zibll_oauth_grant`
- 前台用户中心 `OAuth设置 -> 授权记录` 可查看历史授权过的应用与授权时间

## 文档

- 对接文档：`docs/开发文档.md`

## 安装与升级

### 安装

1. 将插件目录上传到 WordPress：`wp-content/plugins/zibll-oauth/`
2. 后台启用插件
3. 后台 `Zibll OAuth -> 基础设置` 配置开发者白名单

### 升级

- 直接覆盖插件文件后，重新启用/刷新后台即可
- 如涉及数据表结构升级，插件会在激活/初始化时自动执行升级逻辑

## 测试用例

- 示例与测试页面：`examples/`
- 手工验证步骤：见 `docs/开发文档.md` 的"测试用例"章节

## 目录结构

- `includes/` 插件核心实现
- `examples/` 示例与测试页面
- `docs/` 文档
- `zibll-oauth.php` 插件入口

## 打包发布（建议）

项目中可能包含主题目录（如 `zibll/`）仅用于开发联调，发布插件时应排除：

```bash
zip -r zibll-oauth-package.zip . -x 'zibll/*' -x '.git/*' -x '*.zip'
```

## 官网

- **辽宁天云港云计算有限责任公司**
- **www.yungnet.cn**

## 许可（非常重要）

本项目使用 **PolyForm Noncommercial License 1.0.0**（非商业许可）。

- 允许在**非商业用途**下使用、复制、修改与分发
- **禁止任何商业用途/商业分发/商业交付**（包括但不限于：售卖、付费部署、为第三方客户有偿实施、作为商业产品/服务的一部分等）
- 如需商业授权/商业合作，请联系官网：**www.yungnet.cn**

详见：`LICENSE`。
