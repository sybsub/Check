import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;

    // 不区分大小写检查路径
    if (path.toLowerCase() === '/check') {
      if (!url.searchParams.has('proxyip')) return new Response('Missing proxyip parameter', { status: 400 });
      if (url.searchParams.get('proxyip') === '') return new Response('Invalid proxyip parameter', { status: 400 });
      if (!url.searchParams.get('proxyip').includes('.') && !(url.searchParams.get('proxyip').includes('[') && url.searchParams.get('proxyip').includes(']'))) return new Response('Invalid proxyip format', { status: 400 });
      // 获取参数中的IP或使用默认IP
      const proxyIP = url.searchParams.get('proxyip').toLowerCase();

      // 调用CheckProxyIP函数
      const result = await CheckProxyIP(proxyIP);

      // 返回JSON响应，根据检查结果设置不同的状态码
      return new Response(JSON.stringify(result, null, 2), {
        status: result.success ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } else if (path.toLowerCase() === '/resolve') {
      if (!url.searchParams.has('domain')) return new Response('Missing domain parameter', { status: 400 });
      const domain = url.searchParams.get('domain');

      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        });
      }
    } else if (path.toLowerCase() === '/ip-info') {
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(JSON.stringify({ 
          status: "error",
          message: "IP参数未提供",
          code: "MISSING_PARAMETER",
          timestamp: new Date().toISOString()
        }, null, 4), {
          status: 400,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }

      if (ip.includes('[')) {
        ip = ip.replace('[', '').replace(']', '');
      }

      try {
        // 使用Worker代理请求HTTP的IP API
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();
        
        // 添加时间戳到成功的响应数据中
        data.timestamp = new Date().toISOString();

        // 返回数据给客户端，并添加CORS头
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });

      } catch (error) {
        console.error("IP查询失败:", error);
        return new Response(JSON.stringify({
          status: "error",
          message: `IP查询失败: ${error.message}`,
          code: "API_REQUEST_FAILED",
          query: ip,
          timestamp: new Date().toISOString(),
          details: {
            errorType: error.name,
            stack: error.stack ? error.stack.split('\n')[0] : null
          }
        }, null, 4), {
          status: 500,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
    } else {
      return await HTML(hostname);
    }
  }
};

// 新增域名解析函数
async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  try {
    // 并发请求IPv4和IPv6记录
    const [ipv4Response, ipv6Response] = await Promise.all([
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
        headers: { 'Accept': 'application/dns-json' }
      }),
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=AAAA`, {
        headers: { 'Accept': 'application/dns-json' }
      })
    ]);

    const [ipv4Data, ipv6Data] = await Promise.all([
      ipv4Response.json(),
      ipv6Response.json()
    ]);

    const ips = [];

    // 添加IPv4地址
    if (ipv4Data.Answer) {
      const ipv4Addresses = ipv4Data.Answer
        .filter(record => record.type === 1) // A记录
        .map(record => record.data);
      ips.push(...ipv4Addresses);
    }

    // 添加IPv6地址
    if (ipv6Data.Answer) {
      const ipv6Addresses = ipv6Data.Answer
        .filter(record => record.type === 28) // AAAA记录
        .map(record => `[${record.data}]`); // IPv6地址用方括号包围
      ips.push(...ipv6Addresses);
    }

    if (ips.length === 0) {
      throw new Error('No A or AAAA records found');
    }

    return ips;
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }
}

async function CheckProxyIP(proxyIP) {
  //const portRemote = proxyIP.includes('.tp') ? parseInt(proxyIP.split('.tp')[1].split('.')[0]) || 443 : 443;
  let portRemote = 443;
  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    proxyIP = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':')) {
    portRemote = parseInt(proxyIP.split(':')[1]);
    proxyIP = proxyIP.split(':')[0];
  }

  const tcpSocket = connect({
    hostname: proxyIP,
    port: portRemote,
  });

  try {
    // 构建HTTP GET请求
    const httpRequest =
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      "Host: speed.cloudflare.com\r\n" +
      "User-Agent: CheckProxyIP/cmliu\r\n" +
      "Connection: close\r\n\r\n";

    // 发送HTTP请求
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    // 读取HTTP响应
    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    let receivedData = false;

    // 读取所有可用数据
    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000)) // 5秒超时
      ]);

      if (done) break;
      if (value) {
        receivedData = true;
        // 合并数据
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;

        // 检查是否接收到完整响应
        const responseText = new TextDecoder().decode(responseData);
        if (responseText.includes("\r\n\r\n") &&
          (responseText.includes("Connection: close") || responseText.includes("content-length"))) {
          break;
        }
      }
    }
    reader.releaseLock();

    // 解析HTTP响应
    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;

    // 判断是否成功
    function isValidProxyResponse(responseText, responseData) {
      const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
      const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
      const looksLikeCloudflare = responseText.includes("cloudflare");
      const isExpectedError = responseText.includes("plain HTTP request") || responseText.includes("400 Bad Request");
      const hasBody = responseData.length > 100;

      return statusCode !== null && looksLikeCloudflare && isExpectedError && hasBody;
    }
    const isSuccessful = isValidProxyResponse(responseText, responseData);

    // 构建JSON响应
    const jsonResponse = {
      success: isSuccessful,
      proxyIP: isSuccessful ? proxyIP : -1,
      portRemote: isSuccessful ? portRemote : -1,
      statusCode: statusCode || null,
      responseSize: responseData.length,
      responseData: responseText,
      timestamp: new Date().toISOString(),
    };

    // 关闭连接
    await tcpSocket.close();

    return jsonResponse;
  } catch (error) {
    // 连接失败，返回失败的JSON
    return {
      success: false,
      proxyIP: -1,
      portRemote: -1,
      timestamp: new Date().toISOString(),
      error: error.message || error.toString()
    };
  }
}

async function HTML(hostname) {
  // 首页 HTML
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Check ProxyIP</title>
  <link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/19kSkLSfWtDcspvQI5pit4/c5630cf25d589a0de91978ca29486259/performance-acceleration-bolt.svg" type="image/x-icon">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      max-width: 900px;
      margin: 0 auto;
      padding: 20px;
      color: #333;
      background-color: rgba(248, 249, 250, 0.8);
      background-image: url('https://cf-assets.www.cloudflare.com/slt3lc6tev37/6VGwVJTzNdd2Jhij9A94so/49da00693309690c84183b645394bb18/Cloudflare_Network_275__Cities_in_100__Countries.png');
      background-size: cover;
      background-position: center;
      background-attachment: fixed;
      position: relative;
    }
    
    body::before {
      content: "";
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(255, 255, 255, 0.85);
      z-index: -1;
    }
    
    h1, h2, h3 {
      color: #2c3e50;
    }
    h1 {
      text-align: center;
      margin-bottom: 30px;
      font-size: 2.5em;
      background: linear-gradient(45deg, #3498db, #1abc9c);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .container {
      background-color: white;
      border-radius: 10px;
      padding: 25px;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
      margin-bottom: 30px;
    }
    .form-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 20px;
    }
    .form-label {
      flex: 0 0 100%;
      margin-bottom: 10px;
      font-weight: bold;
      font-size: 1.1em;
    }
    .input-wrapper {
      flex: 1;
      margin-right: 15px;
    }
    input[type="text"] {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e0e0e0;
      border-radius: 6px;
      box-sizing: border-box;
      font-size: 16px;
      transition: border-color 0.3s, box-shadow 0.3s;
    }
    input[type="text"]:focus {
      border-color: #3498db;
      box-shadow: 0 0 8px rgba(52, 152, 219, 0.5);
      outline: none;
    }
    .btn-check {
      background-color: #3498db;
      color: white;
      border: none;
      padding: 12px 25px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 16px;
      font-weight: 600;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
      min-width: 80px;
    }
    .btn-check:hover {
      background-color: #2980b9;
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .btn-check:active {
      transform: translateY(0);
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .btn-check:disabled {
      background-color: #95a5a6;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .btn-check.loading {
      background-color: #95a5a6;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    #result {
      margin-top: 20px;
      padding: 20px;
      border-radius: 6px;
      display: none;
    }
    .success {
      background-color: #e8f8f5;
      color: #16a085;
      border-left: 5px solid #16a085;
    }
    .error {
      background-color: #fdedeb;
      color: #c0392b;
      border-left: 5px solid #c0392b;
    }
    .loader {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #3498db;
      border-radius: 50%;
      width: 24px;
      height: 24px;
      animation: spin 1s linear infinite;
      display: none;
      margin: 0 auto;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .copy-value {
      display: inline-block;
      padding: 5px 12px;
      background-color: #f5f7fa;
      border: 1px solid #e6e9ed;
      border-radius: 4px;
      cursor: pointer;
      margin: 3px 0;
      transition: all 0.2s;
      position: relative;
      font-weight: 500;
      color: #3498db;
    }
    .copy-value:hover {
      background-color: #edf2f7;
      border-color: #cbd5e0;
    }
    .copy-value::after {
      content: "已复制!";
      position: absolute;
      left: calc(100% + 10px);
      top: 50%;
      transform: translateY(-50%);
      background-color: #333;
      color: white;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      opacity: 0;
      transition: opacity 0.3s;
      pointer-events: none;
      white-space: nowrap;
      z-index: 100;
    }
    .copy-value.copied::after {
      opacity: 1;
    }
    .api-docs {
      margin-top: 30px;
    }
    .code-block {
      background-color: #f5f5f5;
      padding: 15px;
      border-radius: 6px;
      overflow-x: auto;
      font-family: 'Courier New', Courier, monospace;
      font-size: 14px;
      border-left: 4px solid #3498db;
    }
    .footer {
      text-align: center;
      margin-top: 30px;
      color: #7f8c8d;
      font-size: 14px;
      padding: 10px 0;
      border-top: 1px solid #eee;
    }
    .section-title {
      color: #2c3e50;
      margin-top: 30px;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 1px solid #eee;
    }
    .highlight-red {
        color: red;
        font-weight: bold;
    }
    .github-corner svg {
      fill: rgb(45,175,179);
      color: rgb(254,254,254);
      position: fixed;
      top: 0;
      right: 0;
      border: 0;
      width: 80px;
      height: 80px;
    }

    .github-corner:hover .octo-arm {
      animation: octocat-wave 560ms ease-in-out;
    }

    /* 添加章鱼猫挥手动画关键帧 */
    @keyframes octocat-wave {
      0%, 100% { transform: rotate(0); }
      20%, 60% { transform: rotate(-25deg); }
      40%, 80% { transform: rotate(10deg); }
    }
    @media (max-width: 600px) {
      .form-row {
        flex-direction: column;
      }
      .input-wrapper {
        margin-right: 0;
        margin-bottom: 15px;
        width: 100%;
      }
      .btn-check {
        width: 100%;
      }
      .github-corner:hover .octo-arm {
        animation: none;
      }

      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
    }
    .ip-result {
      margin: 8px 0;
      padding: 10px;
      border-radius: 5px;
      border: 1px solid #ddd;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .ip-valid {
      background-color: #e8f8e8;
      border-color: #4caf50;
    }
    .ip-invalid {
      background-color: #fee;
      border-color: #f44336;
    }
    .ip-checking {
      background-color: #f0f8ff;
      border-color: #2196f3;
    }
    .status-icon {
      font-size: 18px;
      font-weight: bold;
      margin-left: 10px;
    }
    .status-valid {
      color: #4caf50;
    }
    .status-invalid {
      color: #f44336;
    }
    .status-checking {
      color: #2196f3;
    }
    .result-all-valid {
      background-color: #e8f8f5 !important;
      border-color: #16a085 !important;
      color: #16a085 !important;
    }
    .result-all-invalid {
      background-color: #fdedeb !important;
      border-color: #c0392b !important;
      color: #c0392b !important;
    }
    .result-partial {
      background-color: #fff8e1 !important;
      border-color: #ff9800 !important;
    }
  </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-CheckProxyIP" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <h1>Check ProxyIP</h1>

  <div class="container">
    <div class="form-row">
      <label for="proxyip" class="form-label">请输入 ProxyIP 地址:</label>
      <div class="input-wrapper">
        <input type="text" id="proxyip" name="proxyip" placeholder="例如: 1.2.3.4 或 example.com:443">
      </div>
      <button id="checkBtn" class="btn-check" onclick="checkProxyIP()">检查</button>
    </div>
    <div id="result"></div>
  </div>
  
  <div class="container api-docs">
    <h2 class="section-title">API 文档</h2>
    <p>您可以通过以下 API 直接检查代理 IP 是否有效:</p>
    <h3>请求格式</h3>
    <div class="code-block">
      <strong>GET</strong> /check?proxyip=<span style="color: red;">YOUR_PROXY_IP</span>
    </div>
    <h3>参数说明</h3>
    <ul>
      <li><strong>proxyip</strong>: 待检查的 ProxyIP 地址 (必填，不带端口默认443)</li>
    </ul>
    <h3>响应Json格式</h3>
    <div class="code-block">
{<br>
  &nbsp;&nbsp;"success": true|false,     // 代理 IP 是否有效<br>
  &nbsp;&nbsp;"proxyIP": "1.2.3.4",      // 如果有效,返回代理 IP,否则为 -1<br>
  &nbsp;&nbsp;"portRemote": 443,         // 如果有效,返回端口,否则为 -1<br>
  &nbsp;&nbsp;"timestamp": "2025-05-10T14:44:30.597Z"  // 检查时间<br>
}<br>
    </div>
    <h3>示例</h3>
    <div class="code-block">
curl "https://${hostname}/check?proxyip=1.2.3.4:443"
    </div>
  </div>

  <div class="footer">
    &copy; 2025 Check ProxyIP - 基于 Cloudflare Workers 构建的高性能 ProxyIP 验证服务 | by cmliu
  </div>

  <script>
    async function checkProxyIP() {
      const proxyipInput = document.getElementById('proxyip');
      const resultDiv = document.getElementById('result');
      const checkBtn = document.getElementById('checkBtn');
      
      const proxyip = proxyipInput.value.trim();
      if (!proxyip) {
        resultDiv.className = 'error';
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = '请输入代理IP地址';
        return;
      }
      
      // 显示加载状态
      checkBtn.disabled = true;
      checkBtn.classList.add('loading');
      resultDiv.style.display = 'none';
      
      try {
        // 检查输入是否为IP地址
        if (isIPAddress(proxyip)) {
          // 直接检查IP
          await checkSingleIP(proxyip, resultDiv);
        } else {
          // 解析域名并检查所有IP
          await checkDomain(proxyip, resultDiv);
        }
      } catch (err) {
        resultDiv.className = 'error';
        resultDiv.innerHTML = \`检查过程中发生错误: \${err.message}\`;
        resultDiv.style.display = 'block';
      } finally {
        checkBtn.disabled = false;
        checkBtn.classList.remove('loading');
      }
    }
    
    function isIPAddress(input) {
      // IPv4正则表达式
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      // IPv6正则表达式（支持带端口的格式 [ipv6]:port）
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      // IPv6带端口格式 [ipv6]:port
      const ipv6WithPortRegex = /^\\[[0-9a-fA-F:]+\\]:\\d+$/;
      // 普通IPv4带端口格式
      const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\\d+$/;
      
      return ipv4Regex.test(input) || ipv6Regex.test(input) || ipv6WithPortRegex.test(input) || ipv4WithPortRegex.test(input);
    }
    
    async function checkSingleIP(proxyip, resultDiv) {
      const response = await fetch(\`./check?proxyip=\${encodeURIComponent(proxyip)}\`);
      const data = await response.json();
      
      if (data.success) {
        resultDiv.className = 'success';
        resultDiv.innerHTML = \`
          <b>ProxyIP 有效!</b>
          <br><br>
          <b>IP:</b> <span class="copy-value" onclick="copyToClipboard(this)">\${data.proxyIP}</span>
          <br>
          <b>端口:</b> <span class="copy-value" onclick="copyToClipboard(this)">\${data.portRemote}</span>
          <br>
          <b>检测时间:</b> \${new Date(data.timestamp).toLocaleString()}
        \`;
      } else {
        resultDiv.className = 'error';
        resultDiv.innerHTML = \`
          <b>ProxyIP 失效!</b>
          <br><br>
          \${data.error ? \`<b>错误信息:</b> \${data.error}<br>\` : ''}
          <b>检测时间:</b> \${new Date(data.timestamp).toLocaleString()}
        \`;
      }
      resultDiv.style.display = 'block';
    }
    
    async function checkDomain(domain, resultDiv) {
      // 提取端口信息和清理域名
      let portRemote = 443;
      let cleanDomain = domain;
      
      if (domain.includes('.tp')) {
        portRemote = domain.split('.tp')[1].split('.')[0] || 443;
      } else if (domain.includes('[') && domain.includes(']:')) {
        portRemote = parseInt(domain.split(']:')[1]) || 443;
        cleanDomain = domain.split(']:')[0] + ']';
      } else if (domain.includes(':')) {
        portRemote = parseInt(domain.split(':')[1]) || 443;
        cleanDomain = domain.split(':')[0];
      }
      
      // 解析域名（使用清理后的域名）
      const resolveResponse = await fetch(\`./resolve?domain=\${encodeURIComponent(cleanDomain)}\`);
      const resolveData = await resolveResponse.json();
      
      if (!resolveData.success) {
        throw new Error(resolveData.error || '域名解析失败');
      }
      
      const ips = resolveData.ips;
      if (!ips || ips.length === 0) {
        throw new Error('未找到域名对应的IP地址');
      }

      // 显示初始结果
      resultDiv.innerHTML = \`
        <b>域名解析结果</b>
        <br><br>
        <b>域名:</b> <span class="copy-value" onclick="copyToClipboard(this)">\${cleanDomain}</span>
        <br>
        <b>端口:</b> <span class="copy-value" onclick="copyToClipboard(this)">\${portRemote}</span>
        <br>
        <b>解析到的IP地址 (\${ips.length}个):</b>
        <div id="ip-results">
          \${ips.map(ip => \`
            <div class="ip-result ip-checking" id="ip-\${ip.replace(/[\\[\\]:]/g, '-').replace(/\\./g, '-')}\">
              <span>\${ip}</span>
              <span class="status-icon status-checking">🔄</span>
            </div>
          \`).join('')}
        </div>
        <br>
        <b>检测时间:</b> \${new Date().toLocaleString()}
      \`;
      resultDiv.style.display = 'block';
      
      // 并发检查所有IP
      const checkPromises = ips.map(ip => checkIPStatus(\`\${ip}:\${portRemote}\`));
      const results = await Promise.all(checkPromises);
      
      // 更新结果
      results.forEach((result, index) => {
        const ip = ips[index];
        const ipElement = document.getElementById(\`ip-\${ip.replace(/[\\[\\]:]/g, '-').replace(/\\./g, '-')}\`);
        
        if (result.success) {
          ipElement.className = 'ip-result ip-valid';
          ipElement.querySelector('.status-icon').innerHTML = '✅';
          ipElement.querySelector('.status-icon').className = 'status-icon status-valid';
        } else {
          ipElement.className = 'ip-result ip-invalid';
          ipElement.querySelector('.status-icon').innerHTML = '❌';
          ipElement.querySelector('.status-icon').className = 'status-icon status-invalid';
        }
      });
      
      // 根据整体结果设置背景色
      const validCount = results.filter(r => r.success).length;
      if (validCount === results.length) {
        resultDiv.className = 'success result-all-valid';
      } else if (validCount === 0) {
        resultDiv.className = 'error result-all-invalid';
      } else {
        resultDiv.className = 'success result-partial';
      }
    }
    
    async function checkIPStatus(ip) {
      try {
        const response = await fetch(\`./check?proxyip=\${encodeURIComponent(ip)}\`);
        const data = await response.json();
        return data;
      } catch (error) {
        return { success: false, error: error.message };
      }
    }
    
    // 支持回车键提交
    document.getElementById('proxyip').addEventListener('keypress', function(event) {
      if (event.key === 'Enter') {
        event.preventDefault();
        document.getElementById('checkBtn').click();
      }
    });
    
    function copyToClipboard(element) {
      const text = element.textContent;
      navigator.clipboard.writeText(text).then(() => {
        // 添加"已复制"效果
        element.classList.add('copied');
        setTimeout(() => {
          element.classList.remove('copied');
        }, 2000);
      }).catch(err => {
        console.error('复制失败:', err);
      });
    }
  </script>
</body>
</html>
`;

  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" }
  });
}
