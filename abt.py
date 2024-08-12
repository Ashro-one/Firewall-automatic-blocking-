from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import urllib3
from lxml import html
import requests
import argparse
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium import webdriver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def init_driver(chrome_path, headless=True):
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--ignore-certificate-errors")  # 忽略 SSL 证书错误
    chrome_options.add_argument("--allow-insecure-localhost")  # 允许不安全的本地主机连接
    service = Service(chrome_path)
    return webdriver.Chrome(service=service, options=chrome_options)


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


def fetch_token_and_cookies(driver, target_url, ip):
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

    #ip封禁
    response = requests.post(target_url, headers=headers, verify=False)
    tree = html.fromstring(response.content)
    token = tree.xpath('//*[@id="body"]/form/input/@value')

    if token:
        data = {
            'src_ip': ip,
            'age': '-1',#默认永久封 300为封5分钟
            'submit_post': 'sec_ad_blacklist_addsave',
            'token': token[0]
        }
        response = requests.post(target_url, data=data, headers=headers, verify=False)
        if 'time' in response.text:
            print(f"IP {ip} 封禁成功")
        else:
            print(f"IP {ip} 封禁失败")
    else:
        print(f"无法获取token，无法封禁IP {ip}")


def main(ip_file, chrome_path, url, username, password, target_url):
    driver = init_driver(chrome_path)
    try:
        login(driver, url, username, password)
        with open(ip_file, 'r') as file:
            ips = file.readlines()
        for ip in ips:
            ip = ip.strip()
            fetch_token_and_cookies(driver, target_url, ip)
    except Exception as e:
        print(f'An error occurred: {e}')
    finally:
        driver.quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send POST requests to block IP addresses.")
    parser.add_argument('-f', '--file', required=True, help="Path to the IP address file.")
    args = parser.parse_args()

    chrome_path = './chromedriver.exe'
    url = 'https://192.168.255.14/'
    username = ''  #输入用户名
    password = ''  #输入密码
    target_url = "https://192.168.255.14/webui/?g=sec_ad_blacklist_add"

    main(args.file, chrome_path, url, username, password, target_url)
