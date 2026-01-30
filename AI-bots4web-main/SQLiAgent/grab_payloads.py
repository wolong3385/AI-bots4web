import requests
import os

# 定义高质量的开源 SQLi 载荷源 (GitHub Raw 原始数据链接)
# 来源 1: PayloadsAllTheThings 通用列表
# 来源 2: SecLists 渗透测试字典
# 来源 3: 专门针对 SQLite 的注入技术文档 [2]
PAYLOAD_SOURCES = {
    "General_SQLi_Intruder": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQL-Injection",
    "SecLists_Generic_Fuzzing": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    "SQLite_Special_Payloads": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/SQLite%20Injection.md"
}


def download_training_data():
    # 1. 在当前项目下创建一个专门存放载荷的文件夹
    folder_name = "training_payloads"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"[*] 已创建载荷存放目录: {folder_name}")

    print("[*] 正在从 GitHub 抓取开源载荷库，请稍候...")

    for name, url in PAYLOAD_SOURCES.items():
        try:
            # 2. 发送网络请求获取纯文本内容 [3]
            response = requests.get(url, timeout=20)
            response.raise_for_status()

            # 3. 将内容写入本地 txt 文件
            file_path = os.path.join(folder_name, f"{name}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(response.text)

            # 统计抓取的条数（按行计算）
            count = len(response.text.splitlines())
            print(f"[+] 抓取成功: {name} (获取到 {count} 条数据)")

        except Exception as e:
            print(f"[!] 抓取 {name} 失败，原因: {e}")


if __name__ == "__main__":
    download_training_data()
    print("\n[✔] 载荷收集任务完成。")
    print("[*] 提示：你可以打开项目目录下的 'training_payloads' 文件夹查看这些文件。")