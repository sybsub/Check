# 🌐 CF-Workers-CheckProxyIP
![CF-Workers-CheckProxyIP](./demo.png)
> 基于 Cloudflare Workers 的高性能 ProxyIP 验证服务

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange?style=flat-square&logo=cloudflare)](https://workers.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/cmliu/CF-Workers-CheckProxyIP?style=flat-square)](https://github.com/cmliu/CF-Workers-CheckProxyIP)

## 📖 项目简介

CF-Workers-CheckProxyIP 是一个部署在 Cloudflare Workers 上的轻量级 ProxyIP 验证工具。它能够快速、准确地检测代理IP的可用性，帮助用户筛选出有效的代理服务器。

### ✨ 主要特性

- 🚀 **高性能**：基于 Cloudflare Workers 边缘计算，全球低延迟
- 🔍 **智能检测**：自动识别IPv4/IPv6地址和域名
- 🌍 **全球部署**：利用 Cloudflare 全球网络，就近检测
- 📱 **响应式界面**：支持桌面和移动设备访问
- ⚡ **实时结果**：秒级响应，即时获取检测结果
- 🔒 **安全可靠**：无需存储用户数据，保护隐私安全

## 🚀 部署方式

- **Workers** 部署：复制 [_worker.js](https://github.com/cmliu/CF-Workers-CheckProxyIP/blob/main/_worker.js) 代码，保存并部署即可
- **Pages** 部署：`Fork` 后 `连接GitHub` 一键部署即可

## 📝 使用方法

### 网页界面

直接访问你的 Worker 地址，使用友好的网页界面进行检测：

```
https://check.proxyip.cmliussss.net
```

### API 接口

#### 🔗 检查单个 ProxyIP
- `proxyip` 参数支持 IPv4、IPv6 地址和域名，端口号可选，不填默认为 443。
```bash
# 检查带端口的 IP
curl "https://check.proxyip.cmliussss.net/check?proxyip=1.2.3.4:443"

# 检查不带端口的 IP（默认使用443端口）
curl "https://check.proxyip.cmliussss.net/check?proxyip=1.2.3.4"

# 检查 IPv6 地址
curl "https://check.proxyip.cmliussss.net/check?proxyip=[2001:db8::1]:443"

# 检查域名
curl "https://check.proxyip.cmliussss.net/check?proxyip=example.com:443"
```

- 设置 `TOKEN` 变量后，需要在路径中添加 `token=your-secret-token` 才能使用接口。

```bash
curl "https://check.proxyip.cmliussss.net/check?proxyip=1.2.3.4:443&token=your-secret-token"
```

#### 📄 响应格式

```json
{
  "success": true,
  "proxyIP": "1.2.3.4",
  "portRemote": 443,
  "statusCode": 400,
  "responseSize": 1234,
  "timestamp": "2025-01-20T10:30:00.000Z"
}
```

#### 🔧 参数说明

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `proxyip` | string | ✅ | 要检测的代理IP地址，支持IPv4、IPv6和域名 |
| `token` | string | ❌ | 设置 `TOKEN` 变量后，需要在路径中添加 `token=your-secret-token` 才能使用接口。 |

#### 📊 响应字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 代理IP是否可用 |
| `proxyIP` | string | 检测的IP地址（失败时为 -1） |
| `portRemote` | number | 使用的端口号（失败时为 -1） |
| `statusCode` | number | HTTP状态码 |
| `responseSize` | number | 响应数据大小（字节） |
| `timestamp` | string | 检测时间戳 |

## 🔧 环境变量配置

| 变量名 | 说明 | 示例 | 必需 |
|--------|------|------|------|
| `TOKEN` | API 访问令牌，用于保护接口（设置`TOKEN`之后，首页会变成**nginx**，避免变成公共服务） | `your-secret-token` | 否 |
| `URL302` | 302跳转伪装首页 | `https://example.com` | 否 |
| `URL` | 反向代理伪装首页 | `https://example.com` | 否 |
| `ICO` | 网站图标 URL | `https://example.com/favicon.ico` | 否 |

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🙏 致谢

- [Cloudflare Workers](https://workers.cloudflare.com/) - 提供强大的边缘计算平台
- 所有贡献者和使用者的支持
