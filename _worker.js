import { connect } from 'cloudflare:sockets';

let 临时TOKEN, 永久TOKEN;
let parsedSocks5Address = {};

// ---------- 公共工具 ----------
async function 双重哈希(文本) {
  const 编码器 = new TextEncoder();
  const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
  const 第一次十六进制 = Array.from(new Uint8Array(第一次哈希)).map(b => b.toString(16).padStart(2, '0')).join('');
  const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
  return Array.from(new Uint8Array(第二次哈希)).map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function fetchDNSRecords(domain, type) {
  const query = new URLSearchParams({ name: domain, type: type });
  const url = `https://cloudflare-dns.com/dns-query?${query.toString()}`;
  const res = await fetch(url, { method: 'GET', headers: { Accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(`获取DNS记录失败: ${res.statusText}`);
  const data = await res.json();
  return data.Answer || [];
}

const ipv4Regex = new RegExp('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$');
const ipv6Regex = new RegExp('^(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$|^::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^::$');

// ---------- 简化的 NAT64 辅助：fetchCdnCgiTrace/parseCdnCgiTrace ----------
async function fetchCdnCgiTrace(ipv6Address) {
  try {
    const socket = connect({ hostname: ipv6Address.includes(':') ? `[${ipv6Address}]` : ipv6Address, port: 80 });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    try {
      const req = `GET /cdn-cgi/trace HTTP/1.1\r\nHost: [${ipv6Address}]\r\nUser-Agent: cf-worker/nat64\r\nConnection: close\r\n\r\n`;
      await writer.write(new TextEncoder().encode(req));
      let chunks = [];
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      const total = chunks.reduce((s, c) => s + c.length, 0);
      const buf = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      const text = new TextDecoder().decode(buf);
      const headerEnd = text.indexOf('\r\n\r\n');
      if (headerEnd === -1) return { success: false, error: '无效的HTTP响应' };
      const headers = text.slice(0, headerEnd);
      const body = text.slice(headerEnd + 4);
      const m = headers.match(/HTTP\/\d\.\d\s+(\d+)/);
      const code = m ? m[1] : null;
      if (code !== '200') return { success: false, error: `HTTP状态码: ${code || '未知'}` };
      return { success: true, data: body };
    } finally {
      try { await writer.close(); } catch (e) {}
      try { await reader.cancel(); } catch (e) {}
      try { await socket.close(); } catch (e) {}
    }
  } catch (e) {
    return { success: false, error: e.message || String(e) };
  }
}
// 解析域名并返回 A / AAAA 的地址数组（用于 ProxyIP 批量检测）
// 调用位置：/resolve 路由
async function resolveDomainForProxy(domain) {
  if (!domain || typeof domain !== 'string') throw new Error('missing domain');
  // 移除路径/端口等
  const clean = domain.split('/')[0].trim();
  // 查询 A 和 AAAA 记录（并发）
  const [aResp, aaaaResp] = await Promise.all([
    fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(clean)}&type=A`, { headers: { Accept: 'application/dns-json' } }).catch(() => null),
    fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(clean)}&type=AAAA`, { headers: { Accept: 'application/dns-json' } }).catch(() => null)
  ]);

  const ips = [];

  if (aResp && aResp.ok) {
    try {
      const j = await aResp.json();
      if (j && Array.isArray(j.Answer)) {
        for (const r of j.Answer) {
          if (r && r.type === 1 && r.data) ips.push(r.data);
        }
      }
    } catch (e) { /* ignore parse errors */ }
  }

  if (aaaaResp && aaaaResp.ok) {
    try {
      const j = await aaaaResp.json();
      if (j && Array.isArray(j.Answer)) {
        for (const r of j.Answer) {
          if (r && r.type === 28 && r.data) ips.push(`[${r.data}]`); // wrap IPv6 with brackets for later use
        }
      }
    } catch (e) { /* ignore parse errors */ }
  }

  if (ips.length === 0) throw new Error('No A or AAAA records found');
  // 去重并返回
  return Array.from(new Set(ips));
}

function parseCdnCgiTrace(text) {
  const out = {};
  if (!text) return out;
  const lines = text.trim().split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    const k = line.slice(0, idx);
    const v = line.slice(idx + 1);
    out[k] = v;
  }
  return out;
}

// ---------- SOCKS5 / HTTP helpers ----------
function socks5AddressParser(address) {
  // 接受多种输入：
  // socks5://user:pass@host:port
  // socks5h://user:pass@host:port
  // user:pass@host:port
  // [ipv6]:port
  // host:port
  if (!address || typeof address !== 'string') throw new Error('无效的 SOCKS5 地址');

  // 去掉协议前缀（如果有）
  const protoIndex = address.indexOf('://');
  if (protoIndex !== -1) {
    address = address.slice(protoIndex + 3);
  }

  // 去掉可能的前后空白
  address = address.trim();

  // 最后一个 '@' 分隔认证和 host 部分（用户名中可能包含 @，所以用 lastIndexOf）
  const lastAt = address.lastIndexOf('@');
  let authPart = null;
  let hostPart = address;
  if (lastAt !== -1) {
    authPart = address.slice(0, lastAt);
    hostPart = address.slice(lastAt + 1);
  }

  let username, password;
  if (authPart) {
    const idx = authPart.indexOf(':');
    if (idx === -1) {
      // 如果没有冒号，视为无效认证格式
      throw new Error('认证格式错误，期望 username:password@host:port');
    }
    username = authPart.slice(0, idx);
    password = authPart.slice(idx + 1);
  }

  // 解析 hostPart，支持 [ipv6]:port、ipv4:port 或 域名:port
  let hostname = hostPart;
  let port = 1080; // 默认端口，如果你希望默认 80 或 443 可调整

  // IPv6 带方括号 [::1]:443
  if (hostPart.startsWith('[')) {
    const endBracket = hostPart.indexOf(']');
    if (endBracket === -1) throw new Error('IPv6 地址缺少右方括号');
    hostname = hostPart.slice(0, endBracket + 1); // 包含 []
    const after = hostPart.slice(endBracket + 1);
    if (after.startsWith(':')) {
      const p = after.slice(1).replace(/[^\d]/g, '');
      if (p.length === 0) throw new Error('端口格式错误');
      port = Number(p);
    }
  } else {
    // 非 IPv6，查找最后一个冒号作为端口分隔（域名中可能含多个冒号不常见）
    const lastColon = hostPart.lastIndexOf(':');
    if (lastColon !== -1 && hostPart.indexOf(':') === lastColon) {
      // 只有一个冒号，常见 ipv4:port 或 domain:port
      const host = hostPart.slice(0, lastColon);
      const p = hostPart.slice(lastColon + 1).replace(/[^\d]/g, '');
      if (p.length > 0) {
        hostname = host;
        port = Number(p);
      }
    } else if (lastColon !== -1 && hostPart.indexOf(':') !== lastColon) {
      // 含多个冒号但没有方括号，可能是裸 IPv6（不推荐），强制要求方括号
      throw new Error('IPv6 地址必须使用方括号，如 [2001:db8::1]:port');
    }
  }

  if (!hostname) throw new Error('主机名解析失败');
  if (isNaN(port) || port <= 0 || port > 65535) throw new Error('端口必须为 1-65535 的数字');

  return {
    username,          // 可能为 undefined
    password,          // 可能为 undefined
    hostname,          // 含方括号的 IPv6 或普通 host
    port               // 数值端口
  };
}


async function httpConnect(addressRemote, portRemote) {
  const { username, password, hostname, port } = parsedSocks5Address;
  const sock = await connect({ hostname, port });
  const writer = sock.writable.getWriter();
  let req = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\nHost: ${addressRemote}:${portRemote}\r\n`;
  if (username && password) req += `Proxy-Authorization: Basic ${btoa(username + ':' + password)}\r\n`;
  req += `Connection: close\r\n\r\n`;
  await writer.write(new TextEncoder().encode(req));
  writer.releaseLock();
  const reader = sock.readable.getReader();
  let buf = '';
  const dec = new TextDecoder();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) buf += dec.decode(value, { stream: true });
    if (buf.includes('\r\n\r\n')) break;
  }
  reader.releaseLock();
  if (!buf.startsWith('HTTP/1.1 200') && !buf.startsWith('HTTP/1.0 200')) {
    try { await sock.close(); } catch (e) {}
    throw new Error('HTTP CONNECT 未返回 200');
  }
  return sock;
}

async function checkHttpProxy(hostname, port, path) {
  const sock = await httpConnect(hostname, port);
  try {
    const req = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
    const writer = sock.writable.getWriter();
    await writer.write(new TextEncoder().encode(req));
    writer.releaseLock();
    const reader = sock.readable.getReader();
    let out = ''; const dec = new TextDecoder();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      out += dec.decode(value, { stream: true });
    }
    reader.releaseLock(); await sock.close();
    return out;
  } catch (e) { try { await sock.close(); } catch (er) {} throw e; }
}

async function socks5Connect(addressType, addressRemote, portRemote) {
  const { username, password, hostname, port } = parsedSocks5Address;
  let socket = null;
  try {
    socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    const r1 = (await reader.read()).value;
    if (!r1 || r1.length < 2) throw new Error('SOCKS5 握手失败');
    if (r1[1] === 0x02) {
      if (!username || !password) throw new Error('需要用户名/密码认证但未提供');
      const enc = new TextEncoder(); const u = enc.encode(username); const p = enc.encode(password);
      const buf = new Uint8Array(3 + u.length + p.length);
      buf[0] = 1; buf[1] = u.length; buf.set(u, 2); buf[2 + u.length] = p.length; buf.set(p, 3 + u.length);
      await writer.write(buf);
      const r2 = (await reader.read()).value;
      if (!r2 || r2.length < 2 || r2[1] !== 0x00) throw new Error('SOCKS5 认证失败');
    }
    const enc = new TextEncoder();
    if (addressType === 2) {
      const domainBytes = enc.encode(addressRemote);
      const buf = new Uint8Array(5 + domainBytes.length + 2);
      buf[0] = 5; buf[1] = 1; buf[2] = 0; buf[3] = 3; buf[4] = domainBytes.length;
      buf.set(domainBytes, 5);
      buf[5 + domainBytes.length] = portRemote >> 8;
      buf[6 + domainBytes.length] = portRemote & 0xff;
      await writer.write(buf);
    } else if (addressType === 1) {
      const parts = addressRemote.split('.').map(Number);
      const buf = new Uint8Array(4 + 4 + 2);
      buf[0] = 5; buf[1] = 1; buf[2] = 0; buf[3] = 1;
      buf.set(parts, 4);
      buf[8] = portRemote >> 8; buf[9] = portRemote & 0xff;
      await writer.write(buf);
    } else throw new Error('不支持该 addressType');
    const res = (await reader.read()).value;
    if (!res || res.length < 2) throw new Error('SOCKS5 响应无效');
    if (res[1] !== 0x00) throw new Error(`SOCKS5 连接失败，错误代码:${res[1]}`);
    writer.releaseLock(); reader.releaseLock();
    return socket;
  } catch (e) { if (socket) try { await socket.close(); } catch (_) {} throw e; }
}

async function checkSocks5Proxy(hostname, port, path) {
  const sock = await socks5Connect(2, hostname, port);
  try {
    const req = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`;
    const writer = sock.writable.getWriter(); await writer.write(new TextEncoder().encode(req)); writer.releaseLock();
    const reader = sock.readable.getReader(); let out = ''; const dec = new TextDecoder();
    while (true) { const { value, done } = await reader.read(); if (done) break; out += dec.decode(value, { stream: true }); }
    reader.releaseLock(); await sock.close(); return out;
  } catch (e) { try { await sock.close(); } catch (_) {} throw e; }
}

// ---------- NAT64 / DNS64 helpers ----------
function isIPv4(str) { const parts = str.split('.'); return parts.length === 4 && parts.every(p=>{ const n=Number(p); return Number.isInteger(n)&&n>=0&&n<=255; }); }
function isIPv6(str) { return str.includes(':'); }

function buildDNSQuery(domain) {
  const parts = domain.split('.');
  const nameLen = parts.reduce((s,p)=>s+1+p.length,1);
  const buf = new ArrayBuffer(12 + nameLen + 4);
  const view = new DataView(buf); let offset=0;
  view.setUint16(offset, Math.floor(Math.random()*65535)); offset+=2;
  view.setUint16(offset, 0x0100); offset+=2;
  view.setUint16(offset, 1); offset+=2;
  view.setUint16(offset, 0); offset+=6;
  for (const label of parts) { view.setUint8(offset++, label.length); for (let i=0;i<label.length;i++) view.setUint8(offset++, label.charCodeAt(i)); }
  view.setUint8(offset++,0); view.setUint16(offset,28); offset+=2; view.setUint16(offset,1); offset+=2;
  return new Uint8Array(buf,0,offset);
}

async function queryDNS64AAAA(dnsServer, domain) {
  const socket = connect({ hostname: dnsServer, port: 53 });
  const writer = socket.writable.getWriter(); const reader = socket.readable.getReader();
  try {
    const q = buildDNSQuery(domain); const withLen = new Uint8Array(q.length+2); withLen[0]=q.length>>8; withLen[1]=q.length&0xff; withLen.set(q,2);
    await writer.write(withLen);
    let chunks=[]; let total=0; let expected=null;
    while(true){
      const { value, done } = await reader.read(); if (done) break; chunks.push(value); total+=value.length;
      if (expected===null && total>=2) expected=(chunks[0][0]<<8)|chunks[0][1];
      if (expected!==null && total>=expected+2) break;
    }
    const full=new Uint8Array(total); let off=0; for(const c of chunks){ full.set(c,off); off+=c.length; }
    const payload = full.slice(2); const view = new DataView(payload.buffer);
    let idx=12; while(payload[idx]!==0) idx+=payload[idx]+1; idx+=5;
    const answers=[]; const ancount=view.getUint16(6);
    for(let i=0;i<ancount;i++){
      if ((payload[idx]&0xC0)===0xC0) idx+=2; else { while(payload[idx]!==0) idx+=payload[idx]+1; idx++; }
      const type=view.getUint16(idx); idx+=2; idx+=2; idx+=4; const rdlen=view.getUint16(idx); idx+=2;
      if (type===28 && rdlen===16){ const parts=[]; for(let j=0;j<8;j++) parts.push(view.getUint16(idx+j*2).toString(16)); answers.push(parts.join(':')); }
      idx+=rdlen;
    }
    return answers;
  } finally { try{ await writer.close(); }catch{} try{ await reader.cancel(); }catch{} try{ await socket.close(); }catch{} }
}

// ---------- ProxyIP helpers ----------
// 更新的 CheckProxyIP：测量 responseTime
async function CheckProxyIP(proxyIP, colo='CF') {
  let portRemote = 443;
  let target = proxyIP;

  if (proxyIP.includes(']:')) {
    portRemote = Number(proxyIP.split(']:')[1]);
    target = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
    const parts = proxyIP.split(':');
    portRemote = Number(parts.pop());
    target = parts.join(':');
  }

  let socket = null;
  const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

  try {
    socket = connect({ hostname: target, port: portRemote });

    const writer = socket.writable.getWriter();
    const req = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: CheckProxyIP/worker\r\nConnection: close\r\n\r\n";
    await writer.write(new TextEncoder().encode(req));
    writer.releaseLock();

    const reader = socket.readable.getReader();
    let data = new Uint8Array(0);
    const MAX_READ_MS = 5000;
    const deadline = ((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) + MAX_READ_MS;

    while (true) {
      const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      if (now > deadline) {
        try { await reader.cancel(); } catch (e) {}
        try { await socket.close(); } catch (e) {}
        return { success: false, proxyIP: target, portRemote, colo, responseTime: -1, message: '读取响应超时', timestamp: new Date().toISOString() };
      }

      const race = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 200))
      ]);

      const { value, done } = race;
      if (done && !value) {
        break;
      }
      if (value) {
        const merged = new Uint8Array(data.length + value.length);
        merged.set(data);
        merged.set(value, data.length);
        data = merged;

        const textSoFar = new TextDecoder().decode(data);
        if (textSoFar.includes("\r\n\r\n")) {
          const lower = textSoFar.toLowerCase();
          const looksLikeCloudflare = lower.includes('cloudflare') && textSoFar.includes('CF-RAY');
          const hasBody = data.length > 100;
          const elapsed = Math.round(((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) - startTime);

          if (looksLikeCloudflare && hasBody) {
            try { await reader.cancel(); } catch (e) {}
            try { await socket.close(); } catch (e) {}
            return {
              success: true,
              proxyIP: target,
              portRemote,
              colo,
              responseTime: elapsed,
              message: '检测通过',
              timestamp: new Date().toISOString()
            };
          } else {
            const isExpected = textSoFar.includes("The plain HTTP request was sent to HTTPS port") || lower.includes('400 bad request');
            if (isExpected && hasBody) {
              try { await reader.cancel(); } catch (e) {}
              try { await socket.close(); } catch (e) {}
              return {
                success: true,
                proxyIP: target,
                portRemote,
                colo,
                responseTime: elapsed,
                message: '检测通过 (预期的 HTTP->HTTPS 响应)',
                timestamp: new Date().toISOString()
              };
            }
          }
        }
      }
      if (race.done) break;
    }

    try { await reader.cancel(); } catch (e) {}
    try { await socket.close(); } catch (e) {}
    return { success: false, proxyIP: target, portRemote, colo, responseTime: -1, message: '未检测到有效的 Cloudflare 响应', timestamp: new Date().toISOString() };
  } catch (err) {
    try { if (socket) await socket.close(); } catch (e) {}
    return { success: false, proxyIP: -1, portRemote: -1, colo, responseTime: -1, message: err.message || String(err), timestamp: new Date().toISOString() };
  }
}

// ---------- IP info ----------
async function getIpInfo(ip) {
  let finalIp = ip; let allIps = null;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    const [a,aaaa]=await Promise.all([fetchDNSRecords(ip,'A').catch(()=>[]), fetchDNSRecords(ip,'AAAA').catch(()=>[])]);
    const ipv4s=a.map(r=>r.data).filter(Boolean); const ipv6s=aaaa.map(r=>r.data).filter(Boolean);
    allIps=[...ipv4s,...ipv6s]; if (allIps.length===0) throw new Error(`无法解析域名 ${ip} 的 IP 地址`);
    finalIp = allIps[Math.floor(Math.random()*allIps.length)];
  }
  const r = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(finalIp)}`); if (!r.ok) throw new Error(`HTTP error: ${r.status}`);
  const data = await r.json();
  data.timestamp = new Date().toISOString();
  if (allIps) { data.domain = ip; data.resolved_ip = finalIp; data.ips = allIps; data.dns_info = { total_ips: allIps.length, ipv4_count: allIps.filter(a=>ipv4Regex.test(a)).length, ipv6_count: allIps.filter(a=>ipv6Regex.test(a)).length, selected_ip: finalIp, all_ips: allIps }; }
  return data;
}

// ---------- HTML 页面 / 路由 ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null';
    const timestamp = Math.ceil(Date.now() / (1000*60*60*12));
    临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
    永久TOKEN = env.TOKEN || 临时TOKEN;

    const path = url.pathname.toLowerCase();

    if (path === '/check') {
      const type = (url.searchParams.get('type')||'').toLowerCase();
      try {
        if (type === 'socks5') {
          const proxy = url.searchParams.get('socks5') || url.searchParams.get('proxy');
          if (!proxy) return new Response(JSON.stringify({ success:false, error:'missing socks5 parameter'}), { status:400, headers:{'Content-Type':'application/json'} });
          parsedSocks5Address = socks5AddressParser(proxy);
          const trace = await checkSocks5Proxy('check.socks5.090227.xyz', 80, '/cdn-cgi/trace');
          const m = trace.match(/ip=([^\r\n]+)/);
          const ip = m ? m[1].trim() : null;
          if (!ip) throw new Error('未能解析 ip');
          const info = await getIpInfo(ip);
          return new Response(JSON.stringify({ success:true, proxy:'socks5://'+proxy, ...info }, null,2), { headers:{'Content-Type':'application/json'} });
        } else if (type === 'http') {
          const proxy = url.searchParams.get('http') || url.searchParams.get('proxy');
          if (!proxy) return new Response(JSON.stringify({ success:false, error:'missing http parameter'}), { status:400, headers:{'Content-Type':'application/json'} });
          parsedSocks5Address = socks5AddressParser(proxy);
          const trace = await checkHttpProxy('check.socks5.090227.xyz', 80, '/cdn-cgi/trace');
          const m = trace.match(/ip=([^\r\n]+)/);
          const ip = m ? m[1].trim() : null;
          if (!ip) throw new Error('未能解析 ip');
          const info = await getIpInfo(ip);
          return new Response(JSON.stringify({ success:true, proxy:'http://'+proxy, ...info }, null,2), { headers:{'Content-Type':'application/json'} });
        } else if (type === 'nat64' || type === 'dns64') {
          const dns64 = url.searchParams.get('nat64') || url.searchParams.get('dns64') || 'dns64.cmliussss.net';
          const host = url.searchParams.get('host') || 'cf.hw.090227.xyz';
          let ipv6 = '解析失败';
          if (dns64.includes('/96')) {
            const a = await fetchDNSRecords(host,'A').catch(()=>[]);
            const ipv4 = (a[0] && a[0].data) || null; if (!ipv4) throw new Error('未找到 IPv4 记录');
            const parts = ipv4.split('.').map(n=>Number(n).toString(16).padStart(2,'0'));
            const prefix = dns64.split('/96')[0];
            ipv6 = prefix + parts[0] + parts[1] + ':' + parts[2] + parts[3];
          } else {
            const answers = await queryDNS64AAAA(dns64, host).catch(()=>[]);
            if (answers && answers.length) ipv6 = answers[0]; else throw new Error('DNS64 查询失败或未返回 AAAA');
          }
          const traceResult = await fetchCdnCgiTrace(ipv6);
          if (!traceResult.success) return new Response(JSON.stringify({ success:false, nat64_ipv6:ipv6, error:traceResult.error }, null,2), { status:500, headers:{'Content-Type':'application/json'} });
          const parsed = parseCdnCgiTrace(traceResult.data);
          return new Response(JSON.stringify({ success:true, nat64_ipv6:ipv6, trace_data:parsed, timestamp:new Date().toISOString() }, null,2), { headers:{'Content-Type':'application/json'} });
        } else if (type === 'proxyip') {
          // 支持多种格式：1.2.3.4:443  或 1.1.1.1,443  或 domain:port  或 [ipv6]:port
          let proxyipRaw = url.searchParams.get('proxyip');
          if (!proxyipRaw) return new Response(JSON.stringify({ success:false, error:'missing proxyip parameter'}), { status:400, headers:{'Content-Type':'application/json'} });
          // 允许用户用逗号分隔 ip,port 的写法（例如 1.1.1.1,443），把逗号替换为冒号并移除多余空格
          const proxyip = proxyipRaw.replace(/\s*,\s*/g, ':').trim();
          if (env.TOKEN) { if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) return new Response(JSON.stringify({ status:"error", message:"ProxyIP 查询失败: 无效的TOKEN", timestamp:new Date().toISOString() }, null,2), { status:403, headers:{'Content-Type':'application/json'} }); }
          const colo = request.cf?.colo || 'CF';
          const res = await CheckProxyIP(proxyip, colo);
          return new Response(JSON.stringify(res, null, 2), { status: res.success?200:502, headers:{'Content-Type':'application/json'} });
        } else {
          return new Response(JSON.stringify({ success:false, error:'请提供 type 参数 (socks5|http|nat64|proxyip)' }, null,2), { status:400, headers:{'Content-Type':'application/json'} });
        }
      } catch (e) {
        return new Response(JSON.stringify({ success:false, error: e.message || String(e) }, null,2), { status:500, headers:{'Content-Type':'application/json'} });
      }
    }

    if (path === '/ip-info') {
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN && url.searchParams.get('token') !== 永久TOKEN)) {
        return new Response(JSON.stringify({ status:"error", message:"IP查询失败: 无效的TOKEN", timestamp:new Date().toISOString() }, null,2), { status:403, headers:{'Content-Type':'application/json'} });
      }
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) return new Response(JSON.stringify({ status:"error", message:"IP参数未提供" }, null,2), { status:400, headers:{'Content-Type':'application/json'} });
      if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1,-1);
      try { const data = await getIpInfo(ip); return new Response(JSON.stringify(data, null,2), { headers:{'Content-Type':'application/json'} }); } catch (e) { return new Response(JSON.stringify({ status:"error", message:e.message }, null,2), { status:500, headers:{'Content-Type':'application/json'} }); }
    }

    if (path === '/resolve') {
      if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN && url.searchParams.get('token') !== 永久TOKEN)) {
        return new Response(JSON.stringify({ status:"error", message:"域名查询失败: 无效的TOKEN", timestamp:new Date().toISOString() }, null,2), { status:403, headers:{'Content-Type':'application/json'} });
      }
      const domain = url.searchParams.get('domain');
      if (!domain) return new Response(JSON.stringify({ success:false, error:'missing domain parameter' }, null,2), { status:400, headers:{'Content-Type':'application/json'} });
      try { const ips = await resolveDomainForProxy(domain); return new Response(JSON.stringify({ success:true, domain, ips }, null,2), { headers:{'Content-Type':'application/json'} }); } catch (e) { return new Response(JSON.stringify({ success:false, error:e.message }, null,2), { status:500, headers:{'Content-Type':'application/json'} }); }
    }

    // 简洁前端页面（当无永久 TOKEN 时）
    if (!env.TOKEN) {
      const page = `<!doctype html>
      <html lang="zh-CN">
      <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
      <title>联合检测 — SOCKS5 / HTTP / NAT64 / ProxyIP</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      <style>
      :root {
        --bg1: linear-gradient(135deg,#667eea 0%,#764ba2 100%);
        --muted:#6c757d;
        --accent:#2f80ed;
        --max-width:960px;
      }
      
      *{box-sizing:border-box;margin:0;padding:0}
      html,body{height:100%}
      
      body{
        font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans SC","PingFang SC","Microsoft YaHei",Arial;
        background: var(--bg1);
        background-attachment: fixed;   /* 背景固定，避免分层 */
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
        color:#222;
        -webkit-font-smoothing:antialiased;
        -moz-osx-font-smoothing:grayscale;
        display:flex;
        flex-direction:column;
        min-height:100vh; /* 页面最小高度 = 视口高度 */
      }
      
      .container{
        flex:1; /* 占满剩余空间 */
        width:100%;
        max-width:var(--max-width);
        margin:0 auto;
        display:flex;
        flex-direction:column;
        gap:16px;
        padding:28px;
        padding-bottom:40px; /* 保证底部始终有空间 */
      }
      
      .card,
      .output-card {
        background:#fff; /* 统一白色卡片风格 */
        border-radius:12px;
        padding:16px;
        box-shadow:0 6px 20px rgba(0,0,0,0.08);
      }
      
      .header{display:flex;align-items:center;justify-content:space-between}
      .title h1{font-size:22px;color:#fff}
      .title p{color:rgba(255,255,255,0.92);font-size:13px}
      
      .form-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
      .select,.input,.btn{
        height:44px;
        border-radius:10px;
        font-size:14px;
      }
      .select{
        min-width:140px;
        padding:0 12px;
        border:1px solid #e0e0e0;
        background:#fff;
      }
.input{
  flex:1;
  width:100%;
  min-width:0;
  padding:10px 14px;
  line-height:1.4;
  font-size:15px;
  border:1px solid #e0e0e0;
  background:#fff;
  color:#222;
  border-radius:10px;
}
.input.small-input{max-width:280px}
.btn{
  background:linear-gradient(135deg,var(--accent),#1866d6);
  border:0;
  color:#fff;
  font-weight:600;
  cursor:pointer;
  padding:0 16px;
  white-space:nowrap;
  transition:all 0.15s ease;
}
      .btn:hover{filter:brightness(1.05);transform:translateY(-1px)}
      
      .output-wrapper{margin-top:12px}
      .output-header{font-size:13px;color:var(--muted);margin-bottom:6px}
      #outputText{
        padding:12px;
        margin:0;
        font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,"Roboto Mono","Noto Sans Mono";
        font-size:13px;
        line-height:1.45;
        color:#111;
        background:#fff;
        border:1px solid #eee;
        border-radius:8px;
        white-space:pre-wrap;
        word-break:break-word;
        overflow:visible;
        min-height:400px; /* 默认更大，避免缩小 */
      }
      
      .footer{
        text-align:center;
        color:rgba(255,255,255,0.9);
        font-size:13px;
        margin-top:auto;       /* 自动推到底部 */
        padding-bottom:20px;   /* 固定留白 */
      }
      
      @media(max-width:720px){
        .form-row{flex-direction:column;align-items:stretch}
        .select,.btn{width:100%}
      }
      </style>
      </head>
      <body>
      <div class="container" role="main">
        <header class="header">
          <div class="title">
            <h1>联合检测</h1>
            <p>支持 SOCKS5 / HTTP / NAT64 / ProxyIP 的快速检测与信息展示</p>
          </div>
        </header>
      
        <main>
          <section class="card" aria-labelledby="panelTitle">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
              <div id="panelTitle" style="font-size:13px;color:var(--muted)">检测面板</div>
              <div style="font-size:13px;color:var(--muted)">页面会调用本 Worker 的 /check /resolve /ip-info 接口完成检测</div>
            </div>
      
            <div id="formArea">
              <div class="form-row">
                <select id="modeSelect" class="select" aria-label="选择检测类型" title="检测类型">
                  <option value="socks5">SOCKS5</option>
                  <option value="http">HTTP</option>
                  <option value="nat64">NAT64</option>
                  <option value="proxyip">ProxyIP</option>
                </select>
      
                <input id="inputMain" class="input" placeholder="例如：socks5://user:pass@host:port 或 1.2.3.4:443 或 domain:port" aria-label="检测地址">
                <input id="inputSecondary" class="input small-input" placeholder="NAT64 时填写要解析的 host（例如 cf.hw.090227.xyz）" style="display:none" aria-label="NAT64 host">
                <button id="runBtn" class="btn">开始检测</button>
              </div>
      
              <div class="output-wrapper" id="outputWrapper" aria-live="polite">
                <div class="output-card">
                  <div class="output-header">
                    <div style="display:flex;justify-content:space-between;align-items:center;">
                      <div style="font-size:13px;color:var(--muted)">检测输出</div>
                    </div>
                  </div>
      
                  <pre id="outputText" role="region" aria-label="检测输出">等待检测...</pre>
                </div>
              </div>
      
            </div>
          </section>
        </main>
      
        <div class="footer">© 2025 联合检测 — 基于 Cloudflare Workers，前端调用 /check /resolve /ip-info 接口完成检测</div>
      </div>

      <!-- 模态结构（用于 token 过期提示，只有一个确定按钮） -->
      <div id="modalBackdrop" class="modal-backdrop" role="dialog" aria-modal="true" style="display:none">
        <div class="modal" role="document" aria-labelledby="modalTitle">
          <div class="modal-title" id="modalTitle">检测失败</div>
          <div class="modal-body" id="modalBody">TOKEN 无效或已过期，请点击确定刷新界面以继续操作。</div>
          <div class="modal-actions">
            <button id="modalOk" class="modal-btn">确定</button>
          </div>
        </div>
      </div>

      <script>
      (function(){
        const modeSelect = document.getElementById('modeSelect');
        const inputMain = document.getElementById('inputMain');
        const inputSecondary = document.getElementById('inputSecondary');
        const runBtn = document.getElementById('runBtn');
        const outputText = document.getElementById('outputText');
        const modalBackdrop = document.getElementById('modalBackdrop');
        const modalBody = document.getElementById('modalBody');
        const modalOk = document.getElementById('modalOk');

        // sessionStorage 键名
        const SS_KEY = 'joint-check-state-v1';

        // 恢复表单状态（选择项与输入框），但不恢复输出
        function restoreState() {
          try {
            const raw = sessionStorage.getItem(SS_KEY);
            if (!raw) return;
            const s = JSON.parse(raw);
            if (s.mode) modeSelect.value = s.mode;
            if (typeof s.inputMain === 'string') inputMain.value = s.inputMain;
            if (typeof s.inputSecondary === 'string') inputSecondary.value = s.inputSecondary;
            updateUI();
          } catch (e) {
            // 忽略解析错误
          }
        }

        // 保存当前表单（不保存输出）
        function saveState() {
          try {
            const s = {
              mode: modeSelect.value,
              inputMain: inputMain.value,
              inputSecondary: inputSecondary.value
            };
            sessionStorage.setItem(SS_KEY, JSON.stringify(s));
          } catch (e) {}
        }

        // 当页面刷新后需要清空输出区
        function clearOutput() {
          outputText.textContent = '';
        }

        function updateUI(){
          const mode = modeSelect.value;
          inputSecondary.style.display = mode === 'nat64' ? 'inline-block' : 'none';

          if (mode === 'nat64') {
            inputMain.placeholder = '[2001:67c:2960:6464::/96]:443';
            inputSecondary.placeholder = 'Nat64时填写要解析的host';
          } else if(mode === 'proxyip') {
            inputMain.placeholder = 'ProxyIP 例：1.2.3.4:443 或 1.1.1.1,443 或 domain:port';
            inputSecondary.placeholder = '';
          } else if(mode === 'socks5') {
            inputMain.placeholder = 'socks5://user:pass@host:port 或 host:port';
            inputSecondary.placeholder = '';
          } else if(mode === 'http') {
            inputMain.placeholder = 'http://user:pass@host:port 或 host:port';
            inputSecondary.placeholder = '';
          }
          // 保存选择/输入的状态
          saveState();
        }

        modeSelect.addEventListener('change', updateUI);

        // 页面加载时恢复状态并清空输出
        restoreState();
        clearOutput();

        function showOutput(text){
          outputText.textContent = text;
        }

        // 显示自定义模态（只有确定按钮）
        function showModal(message) {
          modalBody.textContent = message || 'TOKEN 无效或已过期，请点击确定刷新界面以继续操作。';
          modalBackdrop.style.display = 'flex';
          modalOk.focus();
        }

        function hideModal() {
          modalBackdrop.style.display = 'none';
        }

        // 当检测返回 token 过期后，展示模态；点击确定则刷新（已保存表单）
        async function handleResponse(res) {
          const status = res.status;
          let bodyText = '';
          try { bodyText = await res.text(); } catch(e){ bodyText = ''; }
          // 尝试解析为 JSON
          let j = null;
          try { j = JSON.parse(bodyText); } catch(e){ j = null; }

          const msg = (j && (j.message || j.error)) ? (j.message || j.error) : bodyText;

          // 判断是否为 token 过期/无效错误：403 或 文本包含 “无效的TOKEN”
          if (status === 403 || (typeof msg === 'string' && msg.includes('无效的TOKEN'))) {
            // 在输出区显示服务端返回的错误供用户查看
            showOutput(typeof msg === 'string' && msg ? msg : ('HTTP ' + status));
            // 显示模态并在确定时刷新
            showModal(typeof msg === 'string' && msg ? msg : ('HTTP ' + status + '：TOKEN 无效或已过期'));
            return true; // 已处理
          }

          return false; // 非 token 错误
        }

        async function callCheck(params){
          showOutput('检测中...');
          try {
            const res = await fetch('/check' + params);
            // 若返回非 2xx，先尝试处理 token 过期的情况
            if (!res.ok) {
              const handled = await handleResponse(res);
              if (handled) return;
              // 不是 token 问题，显示响应文本或 JSON
              let text;
              try { text = await res.text(); } catch(e) { text = 'HTTP error: ' + res.status; }
              // 尝试格式化 JSON
              try {
                const parsed = JSON.parse(text);
                showOutput(JSON.stringify(parsed, null, 2));
              } catch (e) {
                showOutput(text);
              }
              return;
            }
            // OK 响应
            const j = await res.json();
            showOutput(JSON.stringify(j, null, 2));
          } catch(err){
            // 网络层错误或 fetch 抛出
            const msg = err && err.message ? err.message : String(err);
            // 若错误信息包含 token 相关提示，也做相同处理
            if (msg.includes('TOKEN') || msg.includes('无效的TOKEN')) {
              showModal('TOKEN 无效或已过期，请点击确定刷新页面以继续。');
              return;
            }
            showOutput('请求失败: ' + msg);
          }
        }

        runBtn.addEventListener('click', ()=>{
          const mode = modeSelect.value;
          const v = inputMain.value.trim();
          // 保存状态以便在 token 过期后重载仍能恢复
          saveState();

          if(mode === 'nat64'){
            const server = inputMain.value.trim();
            const host = inputSecondary.value.trim() || 'cf.hw.090227.xyz';
            const q = server ? ('?type=nat64&nat64=' + encodeURIComponent(server) + '&host=' + encodeURIComponent(host)) : ('?type=nat64&host=' + encodeURIComponent(host));
            callCheck(q);
            return;
          }
          if(!v){ alert('请输入检测目标'); return; }

          if(mode === 'proxyip') {
            // 支持 1.2.3.4:443 / 1.1.1.1,443 / domain:port / [ipv6]:port
            const normalized = v.replace(/\s*,\s*/g, ':');
            callCheck('?type=proxyip&proxyip=' + encodeURIComponent(normalized));
            return;
          }

          if(mode === 'socks5') callCheck('?type=socks5&socks5=' + encodeURIComponent(v));
          else if(mode === 'http') callCheck('?type=http&http=' + encodeURIComponent(v));
        });

        inputMain.addEventListener('keypress', (e)=>{ if(e.key==='Enter') runBtn.click(); });
        inputSecondary.addEventListener('keypress', (e)=>{ if(e.key==='Enter') runBtn.click(); });

        // 点击模态确定：保存表单状态（已保存）并刷新页面；刷新后 restoreState() 会恢复输入并 clearOutput() 清空输出
        modalOk.addEventListener('click', ()=>{
          saveState();
          hideModal();
          location.reload();
        });

        // 在离开页面前保存表单状态
        window.addEventListener('beforeunload', saveState);
      })();
      </script>
      </body>
      </html>`;

      return new Response(page, { headers: { 'Content-Type':'text/html;charset=UTF-8' } });
    }

    // 如果有永久 TOKEN，则返回简短提示页面（不暴露 UI）
    return new Response('<!doctype html><html><body><h3>Service running. Use /check endpoint.</h3></body></html>', { headers: { 'Content-Type':'text/html;charset=UTF-8' } });
  }
};

