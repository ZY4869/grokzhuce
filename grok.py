import os, json, random, string, time, re, struct
import threading
import concurrent.futures
from urllib.parse import urljoin, urlparse
from curl_cffi import requests
from bs4 import BeautifulSoup

from g import EmailService, TurnstileService, UserAgreementService, NsfwSettingsService

# 基础配置
site_url = "https://accounts.x.ai"
DEFAULT_IMPERSONATE = "chrome120"
CHROME_PROFILES = [
    {"impersonate": "chrome110", "version": "110.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome119", "version": "119.0.0.0", "brand": "chrome"},
    {"impersonate": "chrome120", "version": "120.0.0.0", "brand": "chrome"},
    {"impersonate": "edge99", "version": "99.0.1150.36", "brand": "edge"},
    {"impersonate": "edge101", "version": "101.0.1210.47", "brand": "edge"},
]
def get_random_chrome_profile():
    profile = random.choice(CHROME_PROFILES)
    if profile.get("brand") == "edge":
        chrome_major = profile["version"].split(".")[0]
        chrome_version = f"{chrome_major}.0.0.0"
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome_version} Safari/537.36 Edg/{profile['version']}"
        )
    else:
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{profile['version']} Safari/537.36"
        )
    return profile["impersonate"], ua
PROXIES = {
    "http": "http://127.0.0.1:7890",
    "https": "http://127.0.0.1:7890"
}

# 动态获取的全局变量
config = {
    "site_key": "0x4AAAAAAAhr9JGVDZbrZOo0",
    "action_id": None,
    "state_tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22sign-up%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fsign-up%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
}

FLARESOLVERR_URL = "http://localhost:8191/v1"

post_lock = threading.Lock()
file_lock = threading.Lock()
success_count = 0
start_time = time.time()
target_count = 100
stop_event = threading.Event()
output_file = None
NSFW_ENABLE_RETRIES = 3

def _get_cf_clearance_via_flaresolverr(target_url="https://grok.com", timeout=120):
    """通过 FlareSolverr 获取 cf_clearance cookie。"""
    import urllib.request, urllib.error
    payload = json.dumps({
        "cmd": "request.get",
        "url": target_url,
        "maxTimeout": timeout * 1000,
        "proxy": {"url": PROXIES.get("http", "")},
    }).encode("utf-8")
    req = urllib.request.Request(
        FLARESOLVERR_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout + 10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "ok":
            cookies = data.get("solution", {}).get("cookies", [])
            for c in cookies:
                if c.get("name") == "cf_clearance":
                    print(f"[+] FlareSolverr 获取 cf_clearance 成功")
                    return c["value"]
        print(f"[-] FlareSolverr 未返回 cf_clearance: {data.get('status')}")
    except Exception as e:
        print(f"[-] FlareSolverr 请求失败: {e}")
    return None

def _decode_jwt_payload(jwt_token):
    """解码 JWT payload 部分"""
    parts = jwt_token.split('.')
    payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
    payload = payload.replace('-', '+').replace('_', '/')
    import base64
    return json.loads(base64.b64decode(payload))

def _extract_set_cookie_urls(jwt_token, max_depth=5):
    """从嵌套的 set-cookie JWT 链中提取所有 set-cookie URL"""
    urls = []
    current_jwt = jwt_token
    for _ in range(max_depth):
        try:
            data = _decode_jwt_payload(current_jwt)
            config = data.get("config", {})
            success_url = config.get("success_url", "")
            if "set-cookie?q=" in success_url:
                urls.append(success_url)
                current_jwt = success_url.split("set-cookie?q=")[1]
            else:
                break
        except Exception:
            break
    return urls

def _follow_set_cookie_chain(first_url, impersonate, proxies):
    """逐一访问 set-cookie URL 链，收集所有域名的 cookie"""
    all_cookies = {}
    with requests.Session(impersonate=impersonate, proxies=proxies) as s:
        # 先访问第一层 URL
        try:
            resp = s.get(first_url, allow_redirects=True)
            for c in s.cookies.jar:
                if c.name in ("sso", "sso-rw"):
                    all_cookies[f"{c.name}@{c.domain}"] = c.value
                    all_cookies[c.name] = c.value
        except Exception:
            pass

        # 从第一层 JWT 中解码出后续的 set-cookie URLs
        jwt_token = first_url.split("set-cookie?q=")[1] if "set-cookie?q=" in first_url else ""
        if jwt_token:
            nested_urls = _extract_set_cookie_urls(jwt_token)
            for url in nested_urls:
                try:
                    resp = s.get(url, allow_redirects=True)
                    for c in s.cookies.jar:
                        if c.name in ("sso", "sso-rw"):
                            all_cookies[f"{c.name}@{c.domain}"] = c.value
                            all_cookies[c.name] = c.value
                except Exception:
                    continue

        # 收集 grok.com 域名下的所有 cookies（包括 __cf_bm 等）
        grok_cookies = {}
        for c in s.cookies.jar:
            if c.domain and "grok.com" in c.domain:
                grok_cookies[c.name] = c.value
        all_cookies["_grok_all"] = grok_cookies
    return all_cookies

def _enable_default_nsfw(nsfw_service, sso, sso_rw, impersonate, user_agent, extra_cookies):
    """确保新注册账号在写出前已默认开启 NSFW。遇到 403 时尝试通过 FlareSolverr 获取 cf_clearance。"""
    last_error = "unknown"
    cf_clearance = None
    for attempt in range(1, NSFW_ENABLE_RETRIES + 1):
        nsfw_result = nsfw_service.enable_nsfw(
            sso=sso,
            sso_rw=sso_rw,
            impersonate=impersonate,
            user_agent=user_agent,
            proxies=PROXIES,
            extra_cookies=extra_cookies,
            cf_clearance=cf_clearance,
        )
        if not nsfw_result.get("ok", False):
            last_error = nsfw_result.get("error") or f"status={nsfw_result.get('status_code')}"
            # 遇到 403 时尝试 FlareSolverr 获取 cf_clearance
            if nsfw_result.get("status_code") == 403 and not cf_clearance:
                print(f"[*] NSFW 遇到 403，尝试 FlareSolverr 绕过 Cloudflare...")
                cf_clearance = _get_cf_clearance_via_flaresolverr()
                if cf_clearance:
                    extra_cookies = dict(extra_cookies or {})
                    extra_cookies["cf_clearance"] = cf_clearance
            time.sleep(1)
            continue

        unhinged_result = nsfw_service.enable_unhinged(
            sso=sso,
            sso_rw=sso_rw,
            impersonate=impersonate,
            user_agent=user_agent,
            proxies=PROXIES,
            extra_cookies=extra_cookies,
        )
        if unhinged_result.get("ok", False):
            return True, attempt, None

        last_error = unhinged_result.get("error") or f"status={unhinged_result.get('status_code')}"
        time.sleep(1)
    return False, NSFW_ENABLE_RETRIES, last_error

def generate_random_name() -> str:
    length = random.randint(4, 6)
    return random.choice(string.ascii_uppercase) + ''.join(random.choice(string.ascii_lowercase) for _ in range(length - 1))

def generate_random_string(length: int = 15) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def encode_grpc_message(field_id, string_value):
    key = (field_id << 3) | 2
    value_bytes = string_value.encode('utf-8')
    length = len(value_bytes)
    payload = struct.pack('B', key) + struct.pack('B', length) + value_bytes
    return b'\x00' + struct.pack('>I', len(payload)) + payload

def encode_grpc_message_verify(email, code):
    p1 = struct.pack('B', (1 << 3) | 2) + struct.pack('B', len(email)) + email.encode('utf-8')
    p2 = struct.pack('B', (2 << 3) | 2) + struct.pack('B', len(code)) + code.encode('utf-8')
    payload = p1 + p2
    return b'\x00' + struct.pack('>I', len(payload)) + payload

def send_email_code_grpc(session, email):
    url = f"{site_url}/auth_mgmt.AuthManagement/CreateEmailValidationCode"
    data = encode_grpc_message(1, email)
    headers = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1", "x-user-agent": "connect-es/2.1.1", "origin": site_url, "referer": f"{site_url}/sign-up?redirect=grok-com"}
    try:
        # print(f"[debug] {email} 正在发送验证码请求...")
        res = session.post(url, data=data, headers=headers, timeout=15)
        # print(f"[debug] {email} 请求结束，状态码: {res.status_code}")
        return res.status_code == 200
    except Exception as e:
        print(f"[-] {email} 发送验证码异常: {e}")
        return False

def verify_email_code_grpc(session, email, code):
    url = f"{site_url}/auth_mgmt.AuthManagement/VerifyEmailValidationCode"
    data = encode_grpc_message_verify(email, code)
    headers = {"content-type": "application/grpc-web+proto", "x-grpc-web": "1", "x-user-agent": "connect-es/2.1.1", "origin": site_url, "referer": f"{site_url}/sign-up?redirect=grok-com"}
    try:
        res = session.post(url, data=data, headers=headers, timeout=15)
        # print(f"[debug] {email} 验证响应状态: {res.status_code}, 内容长度: {len(res.content)}")
        return res.status_code == 200
    except Exception as e:
        print(f"[-] {email} 验证验证码异常: {e}")
        return False

def register_single_thread():
    # 错峰启动，防止瞬时并发过高
    time.sleep(random.uniform(0, 5))

    try:
        email_service = EmailService()
        turnstile_service = TurnstileService()
        user_agreement_service = UserAgreementService()
        nsfw_service = NsfwSettingsService()
    except Exception as e:
        print(f"[-] 服务初始化失败: {e}")
        return

    # 修正：直接从 config 获取
    final_action_id = config["action_id"]
    if not final_action_id:
        print("[-] 线程退出：缺少 Action ID")
        return

    current_email_id = None  # 追踪当前邮箱ID，确保异常时能清理
    current_email = None

    while True:
        try:
            if stop_event.is_set():
                if current_email_id:
                    try: email_service.delete_email(current_email_id)
                    except: pass
                return
            impersonate_fingerprint, account_user_agent = get_random_chrome_profile()
            with requests.Session(impersonate=impersonate_fingerprint, proxies=PROXIES) as session:
                # 预热连接
                try: session.get(site_url, timeout=10)
                except: pass

                password = generate_random_string()

                try:
                    email_id, email = email_service.create_email()
                    current_email_id = email_id
                    current_email = email
                except Exception as e:
                    print(f"[-] 邮箱服务抛出异常: {e}")
                    email_id, email, current_email_id, current_email = None, None, None, None

                if not email:
                    time.sleep(5); continue

                if stop_event.is_set():
                    email_service.delete_email(current_email_id)
                    current_email_id, current_email = None, None
                    return

                print(f"[*] 开始注册: {email}")

                # Step 1: 发送验证码
                if not send_email_code_grpc(session, email):
                    email_service.delete_email(current_email_id)
                    current_email_id, current_email = None, None
                    time.sleep(5); continue

                # Step 2: 获取验证码
                verify_code = email_service.fetch_verification_code(current_email_id)
                if not verify_code:
                    email_service.delete_email(current_email_id)
                    current_email_id, current_email = None, None
                    continue

                # Step 3: 验证验证码
                if not verify_email_code_grpc(session, email, verify_code):
                    email_service.delete_email(current_email_id)
                    current_email_id, current_email = None, None
                    continue

                # Step 4: 注册重试循环
                for attempt in range(3):
                    if stop_event.is_set():
                        email_service.delete_email(current_email_id)
                        current_email_id, current_email = None, None
                        return
                    task_id = turnstile_service.create_task(site_url, config["site_key"])
                    token = turnstile_service.get_response(task_id)

                    if not token or token == "CAPTCHA_FAIL":
                        continue

                    headers = {
                        "user-agent": account_user_agent, "accept": "text/x-component", "content-type": "text/plain;charset=UTF-8",
                        "origin": site_url, "referer": f"{site_url}/sign-up", "cookie": f"__cf_bm={session.cookies.get('__cf_bm','')}",
                        "next-router-state-tree": config["state_tree"], "next-action": final_action_id
                    }
                    payload = [{
                        "emailValidationCode": verify_code,
                        "createUserAndSessionRequest": {
                            "email": email, "givenName": generate_random_name(), "familyName": generate_random_name(),
                            "clearTextPassword": password, "tosAcceptedVersion": "$undefined"
                        },
                        "turnstileToken": token, "promptOnDuplicateEmail": True
                    }]

                    with post_lock:
                        res = session.post(f"{site_url}/sign-up", json=payload, headers=headers)

                    if res.status_code == 200:
                        # 从响应中提取 set-cookie URL
                        match = re.search(r'(https://[^",\s]+set-cookie\?q=\S+?)(?:\d+:|")', res.text)
                        if not match:
                            print(f"[-] {email} 未找到set-cookie URL")
                            email_service.delete_email(current_email_id)
                            current_email_id, current_email = None, None
                            break
                        first_url = match.group(1)
                        # 用新 session 逐层访问 set-cookie 链获取 SSO cookies
                        cookies = _follow_set_cookie_chain(first_url, impersonate_fingerprint, PROXIES)
                        sso = cookies.get("sso")
                        sso_rw = cookies.get("sso-rw", sso or "")
                        # grok.com 域名的 sso 和全部 cookies 用于 NSFW
                        sso_grok = cookies.get("sso@.grok.com", sso)
                        sso_rw_grok = cookies.get("sso-rw@.grok.com", sso_grok)
                        grok_extra_cookies = cookies.get("_grok_all", {})
                        if not sso:
                            print(f"[-] {email} 未获取到SSO，复用邮箱重试")
                            break

                        tos_result = user_agreement_service.accept_tos_version(
                            sso=sso,
                            sso_rw=sso_rw,
                            impersonate=impersonate_fingerprint,
                            user_agent=account_user_agent,
                            proxies=PROXIES,
                        )
                        tos_hex = tos_result.get("hex_reply") or ""
                        if not tos_result.get("ok") or not tos_hex:
                            print(f"[-] {email} TOS接受失败，复用邮箱重试")
                            break

                        nsfw_ok, nsfw_attempts, nsfw_error = _enable_default_nsfw(
                            nsfw_service=nsfw_service,
                            sso=sso_grok,
                            sso_rw=sso_rw_grok,
                            impersonate=impersonate_fingerprint,
                            user_agent=account_user_agent,
                            extra_cookies=grok_extra_cookies,
                        )
                        nsfw_label = "yes" if nsfw_ok else "no"
                        if not nsfw_ok:
                            print(f"[-] {email} NSFW 开启失败({nsfw_attempts}次): {nsfw_error}，账号仍保存(nsfw=no)")

                        with file_lock:
                            global success_count
                            if success_count >= target_count:
                                if not stop_event.is_set():
                                    stop_event.set()
                                print(f"[*] 已达到目标数量，删除邮箱: {email}")
                                email_service.delete_email(current_email_id)
                                current_email_id, current_email = None, None
                                break
                            try:
                                import csv as _csv
                                with open(output_file, "a", newline="", encoding="utf-8") as f:
                                    _csv.writer(f).writerow([sso, "ssoBasic", nsfw_label, email])
                            except Exception as write_err:
                                print(f"[-] 写入文件失败: {write_err}")
                                email_service.delete_email(current_email_id)
                                current_email_id, current_email = None, None
                                break
                            success_count += 1
                            avg = (time.time() - start_time) / success_count
                            print(f"[OK] 注册成功: {success_count}/{target_count} | {email} | SSO: {sso[:15]}... | 平均: {avg:.1f}s | NSFW: {nsfw_label.upper()}")
                            email_service.delete_email(current_email_id)
                            current_email_id, current_email = None, None
                            if success_count >= target_count and not stop_event.is_set():
                                stop_event.set()
                                print(f"[*] 已达到目标数量: {success_count}/{target_count}，停止新注册")
                        break  # 跳出 for 循环，继续 while True 注册下一个

                    time.sleep(3)
                else:
                    # 如果重试 3 次都失败 (for 循环没有被 break)
                    email_service.delete_email(current_email_id)
                    current_email_id, current_email = None, None
                    time.sleep(5)

        except Exception as e:
            print(f"[-] 异常: {str(e)[:50]}")
            if current_email_id:
                try:
                    email_service.delete_email(current_email_id)
                except:
                    pass
                current_email_id, current_email = None, None
            time.sleep(5)

def main():
    print("=" * 60 + "\nGrok 注册机\n" + "=" * 60)
    
    # 1. 扫描参数
    print("[*] 正在初始化...")
    start_url = f"{site_url}/sign-up"
    with requests.Session(impersonate=DEFAULT_IMPERSONATE, proxies=PROXIES) as s:
        try:
            html = s.get(start_url).text
            # Key
            key_match = re.search(r'sitekey":"(0x4[a-zA-Z0-9_-]+)"', html)
            if key_match: config["site_key"] = key_match.group(1)
            # Tree
            tree_match = re.search(r'next-router-state-tree":"([^"]+)"', html)
            if tree_match: config["state_tree"] = tree_match.group(1)
            # Action ID
            soup = BeautifulSoup(html, 'html.parser')
            js_urls = [urljoin(start_url, script['src']) for script in soup.find_all('script', src=True) if '_next/static' in script['src']]
            for js_url in js_urls:
                js_content = s.get(js_url).text
                match = re.search(r'7f[a-fA-F0-9]{40}', js_content)
                if match:
                    config["action_id"] = match.group(0)
                    print(f"[+] Action ID: {config['action_id']}")
                    break
        except Exception as e:
            print(f"[-] 初始化扫描失败: {e}")
            return

    if not config["action_id"]:
        print("[-] 错误: 未找到 Action ID")
        return

    # 2. 启动
    try:
        t = int(input("\n并发数 (默认1): ").strip() or 1)
    except: t = 1

    try:
        total = int(input("注册数量 (默认1): ").strip() or 1)
    except: total = 1

    global target_count, output_file
    target_count = max(1, total)

    import csv as _csv
    os.makedirs("keys", exist_ok=True)
    output_file = "keys/grok_accounts.csv"
    if not os.path.exists(output_file):
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            _csv.writer(f).writerow(["token", "pool", "nsfw", "email"])

    print(f"[*] 启动 {t} 个线程，目标 {target_count} 个")
    print(f"[*] 输出: {output_file}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=t) as executor:
        futures = [executor.submit(register_single_thread) for _ in range(t)]
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    main()
