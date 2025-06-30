#!/usr/bin/env python
# coding: utf-8

import requests
import argparse
import sys
import re
import json
from collections import deque
from requests.packages import urllib3
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u http://www.baidu.com")
    parser.add_argument("-u", "--url", help="The website")
    parser.add_argument("-c", "--cookie", help="The website cookie")
    parser.add_argument("-f", "--file", help="The file contains url or js")
    parser.add_argument("-ou", "--outputurl", help="Output file name. ")
    parser.add_argument("-os", "--outputsubdomain", help="Output file name. ")
    parser.add_argument("-osens", "--outputsensitive", help="Output sensitive information file")
    parser.add_argument("-j", "--js", help="Find in js file", action="store_true")
    parser.add_argument("-d", "--deep", help="Deep find", action="store_true")
    parser.add_argument("-rd", "--recursivedepth", type=int, default=3, 
                       help="Recursive crawling depth (default: 3)")
    parser.add_argument("-brute", "--bruteforce", action="store_true", 
                       help="Enable path bruteforce based on discovered paths")
    parser.add_argument("-delay", "--delay", type=float, default=0.5,
                       help="Delay between requests in seconds (default: 0.5)")
    return parser.parse_args()

def extract_URL(JS):
    pattern_raw = r"""
      (?:"|')                               # Start newline delimiter
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
        |
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\$$$$]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
        |
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
        |
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
      )
      (?:"|')                               # End newline delimiter
    """
    pattern = re.compile(pattern_raw, re.VERBOSE)
    result = re.finditer(pattern, str(JS))
    if result == None:
        return None
    js_url = []
    return [match.group().strip('"').strip("'") for match in result
            if match.group() not in js_url]

def Extract_html(URL):
    header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
              "Cookie": args.cookie}
    try:
        response = requests.get(URL, headers=header, timeout=10, verify=False)
        response.raise_for_status()
        return response.content.decode("utf-8", "ignore")
    except Exception as e:
        print(f"Error accessing {URL}: {str(e)}")
        return None

def process_url(URL, re_URL):
    black_url = ["javascript:"]  # Add some keyword for filter url.
    URL_raw = urlparse(URL)
    ab_URL = URL_raw.netloc
    host_URL = URL_raw.scheme
    
    if not re_URL:
        return None
    
    if re_URL[0:2] == "//":
        result = host_URL + ":" + re_URL
    elif re_URL[0:4] == "http":
        result = re_URL
    elif re_URL[0:2] != "//" and re_URL not in black_url:
        if re_URL[0:1] == "/":
            result = host_URL + "://" + ab_URL + re_URL
        else:
            if re_URL[0:1] == ".":
                if re_URL[0:2] == "..":
                    result = host_URL + "://" + ab_URL + re_URL[2:]
                else:
                    result = host_URL + "://" + ab_URL + re_URL[1:]
            else:
                result = host_URL + "://" + ab_URL + "/" + re_URL
    else:
        result = URL
    return result

def find_last(string, str):
    positions = []
    last_position = -1
    while True:
        position = string.find(str, last_position + 1)
        if position == -1:
            break
        last_position = position
        positions.append(position)
    return positions

# ================== 增强功能 1: 高级敏感信息检测 ==================
def detect_sensitive_info(url, content):
    # 排除静态资源
    static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', 
                         '.tif', '.tiff', '.webp', '.woff', '.woff2', '.ttf', '.eot', '.otf', 
                         '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.pdf', '.doc', 
                         '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
    
    # 排除包含以下路径的URL
    exclude_paths = ['/static/', '/public/', '/assets/', '/cdn/', '/dist/', '/build/', '/media/', '/uploads/']
    
    # 解析URL，获取路径
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # 检查是否为静态资源扩展名
    if any(path.endswith(ext) for ext in static_extensions):
        return []
    
    # 检查是否在排除路径中
    if any(ex_path in path for ex_path in exclude_paths):
        return []
    
    sensitive_types = []
    patterns = {
        # 文件下载接口检测
        'download': re.compile(r'(download|dload|down|dl\b|getfile|fileget|fileDownload|export)(/[^/]*)?$', re.IGNORECASE),
        # 文件上传接口检测
        'upload': re.compile(r'(upload|up\b|import|filepost|filePush|fileput|attachment)(/[^/]*)?$', re.IGNORECASE),
        # 密钥信息检测
        'secret': re.compile(r'secret|key|password|pwd|passwd|credential|token|auth|private', re.IGNORECASE),
        # 备份文件检测
        'backup': re.compile(r'backup|bak|dump|archive', re.IGNORECASE),
        # 配置文件检测
        'config': re.compile(r'config|cfg|setting|conf', re.IGNORECASE),
        # 数据库相关 - 更精确的匹配，要求是独立的单词或者出现在路径中
        'database': re.compile(r'(^|/)(db|database|sql|mongo|redis|es)($|/)', re.IGNORECASE),
        # 管理员接口
        'admin': re.compile(r'(^|/)(admin|manage|super|root|controller)($|/)', re.IGNORECASE),
        # 新增敏感信息检测
        'aes_key': re.compile(r'aes[_-]?key[=:]\s*[\'"]([a-f0-9]{16,64})[\'"]', re.IGNORECASE),
        'aes_iv': re.compile(r'aes[_-]?iv[=:]\s*[\'"]([a-f0-9]{8,32})[\'"]', re.IGNORECASE),
        'swagger': re.compile(r'swagger-ui|swagger\.json|/v2/api-docs', re.IGNORECASE),
        'spring_boot': re.compile(r'/actuator|/heapdump|/env|/metrics|/trace', re.IGNORECASE),
        'app_credentials': re.compile(r'(app(lication)?[_-]?(id|secret|key)[=:]\s*[\'"]([a-f0-9]{8,64})[\'"])', re.IGNORECASE),
        'cloud_key': re.compile(r'(aliyun|tencent|aws|azure|gcp)[_-]?(access|secret)[_-]?key[=:]\s*[\'"]([a-f0-9]{20,60})[\'"]', re.IGNORECASE),
        'phone_number': re.compile(r'1[3-9]\d{9}'),
        'credentials': re.compile(r'(username|user|u)[=:]\s*[\'"]([^\'"]+)[\'"][\s,;]*(password|pass|pwd)[=:]\s*[\'"]([^\'"]+)[\'"]'),
        'druid': re.compile(r'druid/index.html', re.IGNORECASE),
        'prometheus': re.compile(r'/metrics|/prometheus', re.IGNORECASE),
        'docker': re.compile(r'/containers/json|/images/json', re.IGNORECASE),
        'graphql': re.compile(r'graphql', re.IGNORECASE),
        'jdbc': re.compile(r'jdbc:(mysql|postgresql|sqlserver):', re.IGNORECASE),
        'elasticsearch': re.compile(r'_search\?|/_cat', re.IGNORECASE),
        'api_key': re.compile(r'(?:api[_-]?key|access[_-]?token|secret[_-]?key)[=:]\s*[\'"]([a-f0-9]{32,64})[\'"]', re.IGNORECASE),
        'oauth': re.compile(r'(client[_-]?(id|secret)|redirect[_-]?uri)[=:]\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    }
    
    # 在URL中检测敏感关键词
    for key, pattern in patterns.items():
        if pattern.search(url):
            sensitive_types.append(key)
    
    # 在内容中检测敏感信息
    if content:
        content_lower = content.lower()
        
        # 特殊检测：Swagger UI
        if 'swagger-ui' in content_lower or '/v2/api-docs' in content_lower:
            sensitive_types.append('swagger')
        
        # 特殊检测：Spring Boot Actuator
        if '/actuator' in url or 'spring boot' in content_lower:
            sensitive_types.append('spring_boot')
        
        # 检测密钥格式
        if re.search(r'api[_-]?key', content_lower) or \
           re.search(r'password\s*[=:]\s*[\'"]?[a-z0-9]{12,}[\'"]?', content_lower) or \
           re.search(r'secret\s*[=:]\s*[\'"]?[a-z0-9]{12,}[\'"]?', content_lower):
            sensitive_types.append('secret')
        
        # 检测文件下载链接
        if re.search(r'href=[\'"][^\'"]*\.(zip|tar|gz|rar|sql|bak|db|dump)[\'"]', content_lower):
            sensitive_types.append('download')
            sensitive_types.append('backup')
    
    return list(set(sensitive_types))  # 去重

# ================== 增强功能 2: 路径智能推测与爆破 ==================
def path_bruteforce(base_url, paths, output_file=None):
    """基于已知路径智能推测新接口"""
    parsed = urlparse(base_url)
    base_path = parsed.path
    
    # 提取路径中的关键部分
    path_segments = set()
    for path in paths:
        path_segments.update([seg for seg in path.split('/') if seg and len(seg) > 2])
    
    # 常见接口模式
    common_patterns = [
        "/{base}/v1/{endpoint}",
        "/api/{base}/{endpoint}",
        "/{base}/api/{endpoint}",
        "/{base}/v1/api/{endpoint}",
        "/gateway/{base}/{endpoint}",
        "/{base}-api/{endpoint}",
        "/{base}/service/{endpoint}"
    ]
    
    # 常见端点
    common_endpoints = [
        "user", "login", "auth", "token", "config", 
        "setting", "info", "data", "list", "detail",
        "create", "update", "delete", "export", "import",
        "search", "query", "mobile", "phone", "verify"
    ]
    
    # 组合路径
    generated_paths = set()
    for base_seg in path_segments:
        for pattern in common_patterns:
            for endpoint in common_endpoints:
                generated_path = pattern.format(base=base_seg, endpoint=endpoint)
                generated_paths.add(generated_path)
    
    # 测试生成的路径
    valid_paths = []
    for path in generated_paths:
        test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            if response.status_code < 400:  # 200-399 都算有效
                print(f"[+] Found valid path: {test_url} ({response.status_code})")
                valid_paths.append(test_url)
                
                # 检测敏感信息
                sensitive_types = detect_sensitive_info(test_url, response.text)
                if sensitive_types:
                    print(f"  [!] Sensitive info detected: {', '.join(sensitive_types)}")
        except Exception as e:
            continue
    
    # 输出结果
    if output_file and valid_paths:
        with open(output_file, "a") as f:
            for path in valid_paths:
                f.write(path + "\n")
    
    return valid_paths

# ================== 增强功能 3: 递归式信息提取 ==================
def recursive_crawl(start_url, max_depth=3, visited=None, output_file=None):
    """递归爬取页面并提取信息"""
    if visited is None:
        visited = set()
    
    if max_depth <= 0 or start_url in visited:
        return [], []
    
    visited.add(start_url)
    print(f"[*] Crawling: {start_url} (Depth: {max_depth})")
    
    results = []
    sensitive_info = []
    all_urls = set()
    
    try:
        # 获取页面内容
        html_content = Extract_html(start_url)
        if not html_content:
            return [], []
        
        # 提取当前页面的所有URL
        urls_from_page, _ = find_by_url(start_url)
        all_urls.update(urls_from_page)
        
        # 检测当前页面的敏感信息
        current_sensitive = detect_sensitive_info(start_url, html_content)
        if current_sensitive:
            sensitive_info.append((start_url, current_sensitive))
            print(f"  [!] Sensitive info: {', '.join(current_sensitive)}")
        
        # 使用BeautifulSoup提取链接
        soup = BeautifulSoup(html_content, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a')]
        links += [img.get('src') for img in soup.find_all('img')]
        links += [link.get('href') for link in soup.find_all('link')]
        links += [script.get('src') for script in soup.find_all('script')]
        
        # 处理并规范化URL
        valid_links = set()
        for link in links:
            if link and not link.startswith(('javascript:', 'mailto:', 'tel:')):
                abs_link = urljoin(start_url, link)
                if abs_link not in visited and abs_link not in valid_links:
                    valid_links.add(abs_link)
        
        # 递归爬取
        for link in valid_links:
            if args.delay > 0:
                time.sleep(args.delay)
                
            new_urls, new_sensitive = recursive_crawl(
                link, 
                max_depth-1, 
                visited, 
                output_file
            )
            all_urls.update(new_urls)
            sensitive_info.extend(new_sensitive)
            
    except Exception as e:
        print(f"  [x] Error crawling {start_url}: {str(e)}")
    
    return list(all_urls), sensitive_info

# ================== 增强功能 4: Webpack解析模块 ==================
def extract_webpack_modules(js_content):
    """解析Webpack打包的JS文件"""
    modules = {}
    
    # Webpack模块标识模式
    module_pattern = re.compile(
        r"\/\*\*+\/\s*\n?\s*(\d+):\s*\/\*.*?\*\/\s*\n?\s*function\s*$\w+,\s*\w+,\s*\w+$\s*{\s*"  # 模块ID和函数声明
        r"(?:\/\*.*?\*\/\s*\n)?"  # 可能的注释
        r"(.*?)\n\s*}",  # 模块内容
        re.DOTALL
    )
    
    # 提取所有模块
    for match in module_pattern.finditer(js_content):
        module_id = match.group(1)
        module_content = match.group(2)
        modules[module_id] = module_content
    
    # 提取模块中的字符串
    extracted_strings = []
    string_pattern = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', re.DOTALL)
    
    for module_id, content in modules.items():
        # 跳过非常小的模块
        if len(content) < 20:
            continue
            
        # 查找所有字符串
        strings = string_pattern.findall(content)
        if strings:
            # 连接连续字符串
            combined = "".join([s[1:-1] for s in strings])
            if len(combined) > 10:  # 过滤短字符串
                extracted_strings.append(combined)
    
    return extracted_strings

# ================== 增强功能 5: 整合Webpack处理 ==================
def find_by_url(url, js=False):
    if js == False:
        try:
            print("url:" + url)
        except:
            print("Please specify a URL like https://www.baidu.com")
            
        html_raw = Extract_html(url)
        if html_raw == None: 
            print("Fail to access " + url)
            return [], html_raw
            
        html = BeautifulSoup(html_raw, "html.parser")
        html_scripts = html.findAll("script")
        script_array = {}
        script_temp = ""
        
        for html_script in html_scripts:
            script_src = html_script.get("src")
            if script_src == None:
                script_temp += html_script.get_text() + "\n"
            else:
                purl = process_url(url, script_src)
                script_content = Extract_html(purl)
                if script_content:
                    script_array[purl] = script_content
                    
                    # ========== Webpack处理 ==========
                    if "webpack" in script_content.lower():
                        print(f"[*] Webpack detected in {purl}, extracting modules...")
                        webpack_strings = extract_webpack_modules(script_content)
                        for s in webpack_strings:
                            script_temp += s + "\n"
                            
        script_array[url] = script_temp
        
        allurls = []
        for script in script_array:
            if not script_array[script]:
                continue
                
            temp_urls = extract_URL(script_array[script])
            if not temp_urls: 
                continue
                
            for temp_url in temp_urls:
                full_url = process_url(script, temp_url)
                if full_url and full_url not in allurls:
                    allurls.append(full_url)
        
        result = []
        for singerurl in allurls:
            url_raw = urlparse(url)
            domain = url_raw.netloc
            positions = find_last(domain, ".")
            miandomain = domain
            if len(positions) > 1:
                miandomain = domain[positions[-2] + 1:]
                
            suburl = urlparse(singerurl)
            subdomain = suburl.netloc
            if miandomain in subdomain or subdomain.strip() == "":
                if singerurl.strip() not in result:
                    result.append(singerurl)
                    
        return result, html_raw
        
    # 如果是JS文件
    return sorted(set(extract_URL(Extract_html(url)))), None

# ================== 原有功能 ==================
def find_subdomain(urls, mainurl):
    url_raw = urlparse(mainurl)
    domain = url_raw.netloc
    miandomain = domain
    positions = find_last(domain, ".")
    if len(positions) > 1:
        miandomain = domain[positions[-2] + 1:]
        
    subdomains = []
    for url in urls:
        suburl = urlparse(url)
        subdomain = suburl.netloc
        if subdomain.strip() == "":
            continue
            
        if miandomain in subdomain:
            if subdomain not in subdomains:
                subdomains.append(subdomain)
                
    return subdomains

def output_sensitive_info(sensitive_info, output_file=None):
    if not sensitive_info:
        print("\nNo sensitive information found")
        return
    
    print("\n" + "="*50)
    print(f"Found {len(sensitive_info)} sensitive endpoints:")
    print("="*50)
    
    content = ""
    for url, types in sensitive_info:
        type_str = ', '.join(types)
        line = f"[{type_str}] {url}"
        print(line)
        content += line + "\n"
    
    if output_file:
        with open(output_file, "w", encoding='utf-8') as f:
            f.write(content)
        print(f"\nSensitive information saved to: {output_file}")

def giveresult(urls, domain, sensitive_info=None):
    if not urls:
        print("No URLs found")
        return
        
    print("\n" + "="*50)
    print(f"Found {len(urls)} URLs:")
    print("="*50)
    
    content_url = ""
    content_subdomain = ""
    for url in urls:
        content_url += url + "\n"
        print(url)
    
    subdomains = find_subdomain(urls, domain)
    print("\n" + "="*50)
    print(f"Found {len(subdomains)} Subdomains:")
    print("="*50)
    
    for subdomain in subdomains:
        content_subdomain += subdomain + "\n"
        print(subdomain)
    
    # 保存URL结果
    if args.outputurl:
        with open(args.outputurl, "a", encoding='utf-8') as fobject:
            fobject.write(content_url)
        print(f"\nSaved {len(urls)} URLs to: {args.outputurl}")
    
    # 保存子域名结果
    if args.outputsubdomain:
        with open(args.outputsubdomain, "a", encoding='utf-8') as fobject:
            fobject.write(content_subdomain)
        print(f"Saved {len(subdomains)} subdomains to: {args.outputsubdomain}")
    
    # 输出敏感信息
    if sensitive_info:
        output_sensitive_info(sensitive_info, args.outputsensitive)
    
    # ================== 路径爆破 ==================
    if args.bruteforce and urls:
        print("\n" + "="*50)
        print("Starting path bruteforce based on discovered paths...")
        print("="*50)
        
        # 收集所有路径
        all_paths = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.path:
                all_paths.add(parsed.path)
        
        if all_paths:
            bruteforce_results = path_bruteforce(domain, all_paths)
            if bruteforce_results:
                print(f"\nFound {len(bruteforce_results)} new paths through bruteforce:")
                for path in bruteforce_results:
                    print(f"  - {path}")
                
                # 将新发现的路径添加到结果中
                urls.extend(bruteforce_results)
                
                # 保存到输出文件
                if args.outputurl:
                    with open(args.outputurl, "a", encoding='utf-8') as fobject:
                        for path in bruteforce_results:
                            fobject.write(path + "\n")
                    print(f"Added {len(bruteforce_results)} new paths to: {args.outputurl}")
        else:
            print("No valid paths found for bruteforce")
    else:
        print("\nSkipping path bruteforce (disabled or no paths found)")

# ================== 主程序 ==================
if __name__ == "__main__":
    import time
    
    args = parse_args()
    
    if not args.url and not args.file:
        print("Error: Please specify a URL with -u or a file with -f")
        sys.exit(1)
    
    # 处理单个URL
    if args.file is None:
        if args.recursivedepth > 1:  # 递归爬取
            print(f"\nStarting recursive crawl (depth: {args.recursivedepth})...")
            urls, sensitive_info = recursive_crawl(
                args.url, 
                max_depth=args.recursivedepth
            )
            giveresult(urls, args.url, sensitive_info)
        else:  # 普通模式
            urls, html_content = find_by_url(args.url)
            sensitive_info = []
            if urls:
                for url in urls:
                    sensitive_types = detect_sensitive_info(url, html_content)
                    if sensitive_types:
                        sensitive_info.append((url, sensitive_types))
            giveresult(urls, args.url, sensitive_info)
    else:  # 处理文件中的URL
        if args.js:
            urls, sensitive_info = find_by_file(args.file, js=True)
        else:
            urls, sensitive_info = find_by_file(args.file)
        
        domain = urls[0] if urls else ""
        giveresult(urls,)