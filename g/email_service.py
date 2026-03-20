"""邮箱服务类 - 适配 bczy.site API"""
import os
import re
import time
import random
import string
import requests
from dotenv import load_dotenv


class EmailService:
    BASE_URL = "https://bczy.site/api"
    EXCLUDED_SUFFIXES = [".de"]
    EXPIRY_TIME = 3600000  # 1小时

    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("BCZY_API_KEY")
        if not self.api_key:
            raise ValueError("Missing: BCZY_API_KEY")
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        self._domains = None

    def _get_domains(self):
        """获取可用域名列表，排除 .de 后缀"""
        if self._domains:
            return self._domains
        try:
            res = requests.get(
                f"{self.BASE_URL}/config",
                headers={"X-API-Key": self.api_key},
                timeout=10,
            )
            if res.status_code == 200:
                data = res.json()
                raw = data.get("emailDomains") or data.get("domains") or ""
                if isinstance(raw, str):
                    domains = [d.strip() for d in raw.split(",") if d.strip()]
                else:
                    domains = list(raw)
                self._domains = [
                    d for d in domains
                    if not any(d.endswith(suffix) for suffix in self.EXCLUDED_SUFFIXES)
                ]
                if not self._domains:
                    self._domains = domains[:1] if domains else ["moemail.app"]
                return self._domains
        except Exception as e:
            print(f"[-] 获取域名列表失败: {e}")
        self._domains = ["moemail.app"]
        return self._domains

    def create_email(self, domain_override=None):
        """创建临时邮箱 POST /api/emails/generate"""
        try:
            if domain_override:
                domain = domain_override
            else:
                domains = self._get_domains()
                domain = random.choice(domains)
            name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            res = requests.post(
                f"{self.BASE_URL}/emails/generate",
                headers=self.headers,
                json={
                    "name": name,
                    "expiryTime": self.EXPIRY_TIME,
                    "domain": domain,
                },
                timeout=10,
            )
            if res.status_code == 200:
                data = res.json()
                email_id = data.get("id") or data.get("emailId")
                address = data.get("address") or data.get("email") or f"{name}@{domain}"
                return email_id, address
            print(f"[-] 创建邮箱失败: {res.status_code} - {res.text}")
            return None, None
        except Exception as e:
            print(f"[-] 创建邮箱失败: {e}")
            return None, None

    def fetch_verification_code(self, email_id, max_attempts=30):
        """轮询获取验证码 GET /api/emails/{emailId}"""
        for _ in range(max_attempts):
            try:
                res = requests.get(
                    f"{self.BASE_URL}/emails/{email_id}",
                    headers={"X-API-Key": self.api_key},
                    timeout=10,
                )
                if res.status_code == 200:
                    data = res.json()
                    messages = data.get("messages", data if isinstance(data, list) else [])
                    for msg in messages:
                        code = self._extract_code(msg, email_id)
                        if code:
                            return code
            except Exception:
                pass
            time.sleep(2)
        return None

    def _extract_code(self, message, email_id):
        """从邮件内容中提取验证码"""
        msg_id = message.get("id") or message.get("messageId")

        # 优先从 subject 提取（格式: "822-AHD xAI confirmation code"）
        subject = message.get("subject") or ""
        code = self._parse_code(subject)
        if code:
            return code

        # 尝试从 body/html 提取
        text = message.get("content") or message.get("body") or message.get("text") or message.get("html") or ""
        code = self._parse_code(text)
        if code:
            return code

        # 获取完整邮件内容
        if msg_id and email_id:
            try:
                res = requests.get(
                    f"{self.BASE_URL}/emails/{email_id}/{msg_id}",
                    headers={"X-API-Key": self.api_key},
                    timeout=10,
                )
                if res.status_code == 200:
                    detail = res.json()
                    # 响应可能包在 "message" 里
                    msg_detail = detail.get("message", detail)
                    for field in ("subject", "content", "body", "text", "html"):
                        code = self._parse_code(msg_detail.get(field) or "")
                        if code:
                            return code
            except Exception:
                pass
        return None

    @staticmethod
    def _parse_code(text):
        """从文本中解析验证码（6位字母数字，或带连字符的 xxx-xxx 格式）"""
        if not text:
            return None
        # 匹配 xxx-xxx 格式（字母数字混合，如 822-AHD）
        match = re.search(r'\b([A-Za-z0-9]{3}-[A-Za-z0-9]{3})\b', text)
        if match:
            return match.group(1).replace("-", "")
        # 匹配连续6位字母数字
        match = re.search(r'\b([A-Za-z0-9]{6})\b', text)
        if match:
            return match.group(1)
        return None

    def delete_email(self, email_id_or_address):
        """bczy.site API 无直接删除接口，邮箱会自动过期"""
        return True
