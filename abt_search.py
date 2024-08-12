from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import urllib3
from lxml import html
import requests
import os
import argparse
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium import webdriver
import sys

# 禁用 SSL 证书警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 初始化 WebDriver
def init_driver(chrome_path, headless=True):
    if not os.path.exists(chrome_path):
        raise FileNotFoundError(f"ChromeDriver 未在路径 {chrome_path} 找到")

    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--ignore-certificate-errors")  # 忽略 SSL 证书错误
    chrome_options.add_argument("--allow-insecure-localhost")  # 允许不安全的本地主机连接
    service = Service(chrome_path)
    return webdriver.Chrome(service=service, options=chrome_options)


# 登录网站
def login(driver, url, username, password):
    driver.get(url)
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.NAME, 'usr'))
    )
    username_input = driver.find_element(By.NAME, 'usr')
    password_input = driver.find_element(By.NAME, 'pwd')
    username_input.send_keys(username)
    password_input.send_keys(password)
    password_input.send_keys(Keys.RETURN)


# 获取token和cookies
def fetch_token_and_cookies(driver, target_url, ip_1, target_url_1):
    cookies = {cookie['name']: cookie['value'] for cookie in driver.get_cookies()}
    headers = {
        'Host': '192.168.255.14',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://192.168.255.14',
        'Connection': 'keep-alive',
        'Referer': target_url,
        'Cookie': '; '.join([f"{key}={value}" for key, value in cookies.items()]),
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'frame',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=4'
    }

    data_1 = {
        'page': 1,
        'rows': 99999,
    }

    try:
        # 发送POST请求
        response = requests.post(target_url, data=data_1, headers=headers, verify=False)
        res_text = response.text
        # 判断IP是否已被封禁
        if ip_1 in res_text:
            print(ip_1 + "已封禁")
            print("输入F进行解封，输入其他直接推出")
            user_input = input("输入命令行参数: ")
            if user_input.strip() == 'F':#将进行解封操作
                url_2 = f"https://192.168.255.14/webui/?g=sec_ad_blacklist_delete&name={ip_1}"
                response = requests.get(url=url_2,headers=headers,verify=False)
                print(ip_1 + "已删除")


                sys.exit()  # 结束脚本
        else:
            print(ip_1 + "未封禁")
            print("输入T进行封禁，输入其他直接推出")
            user_input = input("输入命令行参数: ")
            if user_input.strip() == 'T':  # 将'some_condition'替换为具体条件
                response = requests.post(target_url_1, headers=headers, verify=False)
                tree = html.fromstring(response.content)
                token = tree.xpath('//*[@id="body"]/form/input/@value')

                if token:
                    data = {
                        'src_ip': ip_1,
                        'age': '-1',
                        'submit_post': 'sec_ad_blacklist_addsave',
                        'token': token[0]
                    }
                    # 再次发送POST请求以封禁IP
                    response = requests.post(target_url_1, data=data, headers=headers, verify=False)

                    if 'time' in response.text:
                        print(f"IP {ip_1} 封禁成功")
                        sys.exit()
                    else:
                        print(f"IP {ip_1} 封禁失败")
                        sys.exit()
                else:
                    print(f"无法获取token，无法封禁IP {ip_1}")
                    sys.exit()
    except requests.RequestException as e:
        print(f"请求失败: {e}")
        sys.exit()


def main(ip_1, chrome_path, url, username, password, target_url, target_url_1):
    driver = init_driver(chrome_path)
    try:
        login(driver, url, username, password)
        fetch_token_and_cookies(driver, target_url, ip_1, target_url_1)
    except Exception as e:
        print(f'发生错误: {e}')
    finally:
        driver.quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="发送POST请求以封禁IP地址。")
    parser.add_argument('-f', '--ip', required=True, help="要封禁的IP地址")
    args = parser.parse_args()
    ip_1 = args.ip
    chrome_path = './chromedriver.exe'
    url = 'https://192.168.255.14/'
    username = ''  #输入用户
    password = ''  #输入密码
    target_url_1 = "https://192.168.255.14/webui/?g=sec_ad_blacklist_add"
    target_url = "https://192.168.255.14/webui/?g=sec_ad_blacklist_jsondata"

    main(ip_1, chrome_path, url, username, password, target_url, target_url_1)
