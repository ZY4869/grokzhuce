"""为已注册账号批量开启 NSFW + Unhinged 模式。"""
import csv
import time

from g import NsfwSettingsService

PROXIES = {
    "http": "http://127.0.0.1:7890",
    "https": "http://127.0.0.1:7890",
}
INPUT_FILE = "keys/grok_accounts.csv"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def main():
    rows = []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            rows.append(row)

    pending = [r for r in rows if len(r) >= 4 and r[2] == "no"]
    if not pending:
        print("[*] 所有账号已开启 NSFW，无需操作")
        return

    print(f"[*] 共 {len(pending)} 个账号需要开启 NSFW")

    nsfw_service = NsfwSettingsService()
    success = 0
    failed = 0

    for row in rows:
        if len(row) < 4 or row[2] != "no":
            continue

        sso, email = row[0], row[3]
        print(f"[*] 处理: {email}")

        result = nsfw_service.enable_nsfw(
            sso=sso, sso_rw=sso, impersonate="chrome120",
            user_agent=USER_AGENT, proxies=PROXIES,
        )

        if not result.get("ok"):
            err = result.get("error") or f"status={result.get('status_code')}"
            print(f"[-] {email} NSFW 失败: {err}")
            failed += 1
            continue

        unhinged = nsfw_service.enable_unhinged(
            sso=sso, sso_rw=sso, impersonate="chrome120",
            user_agent=USER_AGENT, proxies=PROXIES,
        )

        if unhinged.get("ok"):
            row[2] = "yes"
            success += 1
            print(f"[OK] {email} NSFW + Unhinged 开启成功")
        else:
            err = unhinged.get("error") or f"status={unhinged.get('status_code')}"
            print(f"[!] {email} NSFW OK 但 Unhinged 失败: {err}")
            row[2] = "nsfw_only"
            success += 1

        time.sleep(1)

    with open(INPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    print(f"\n{'='*40}")
    print(f"[结果] 成功: {success}, 失败: {failed}, 总计: {len(pending)}")
    print(f"[*] 已更新 {INPUT_FILE}")


if __name__ == "__main__":
    main()
