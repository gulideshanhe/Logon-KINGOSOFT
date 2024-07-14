import base64
import hashlib

import requests
from bs4 import BeautifulSoup

import queryParams


# http://t.csdnimg.cn/5hVov

class KINGOSOFT():
    def __init__(self, username: str, password: str, mainURL: str) -> bool:
        self.mainURL = mainURL
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": self.mainURL,
        "Pragma": "no-cache",
        "Referer": f"{self.mainURL}/student/",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
    }
        self.sessionID = self.session.get(f"{self.mainURL}/custom/js/GetKingoEncypt.jsp", headers= self.headers).cookies["JSESSIONID"]
    
    def sign(self,DES_KEY: str = "93015171955021563496877", SIGN_TIME: str = "2024-07-02 17:17:17") -> bool:
        username = base64.b64encode(str(f"{self.username};;"+self.sessionID).encode('utf-8')).decode('utf-8')
        params = f"_u={username}&_p={md5(md5(self.password)+md5(""))}&randnumber=&isPasswordPolicy=1&txt_mm_expression=13&txt_mm_length=8&txt_mm_userzh=0&hid_flag=1&hidlag=1"
        # params中后面参数暂时不需改动，实际意义暂不清楚 2024-07-14
        # 对params进行DES加密，但此加密方法用pyDES库**无法复现**
        DES_params, TOKEN = queryParams.get_params(DES_KEY, SIGN_TIME, params)
        # 目前服务器并不会对时间进行校验；如果后续登录失败，可首先检查是否由于**时间校验失败导致**
        date = {
            "params": DES_params,
            "token": TOKEN,
            "timestamp": SIGN_TIME,
            "deskey": DES_KEY,
            "ssessionid": self.sessionID
        }
        response = self.session.post(f"{self.mainURL}/cas/logon.action", headers= self.headers, data= date)
        print(response.text)
        if "操作成功!" in response.text:
            print("登录cookie:", self.session.cookies["JSESSIONID"])
            return True
        elif "账号或密码有误!" in response.text:
            print("账号或密码有误!")
            return False
        else:
            assert False, "意外错误，请检查代码！"
        
    def get_grade(self) -> list:
        data = {
            "sjxz": "sjxz3", # sjxz1：查询入学以来成绩 sjxz2：查询学年成绩 sjxz3：查询学期成绩
            "ysyx": "yscj", #yscj：查询原始成绩 yxcj：查询有效成绩
            "zx": "1", # 主修是否查询 0：不查询 1：查询
            "fx": "1", # 辅修是否查询 0：不查询 1：查询
            "rxnj": "2023", # 入学年级
            "btnExport": r"%B5%BC%B3%F6", # GBK编码的“导出”，意义不明
            "xn": "2023", # 查询学年
            "xn1": "2024", # 截止学年
            "xq": "1", # 学期 0：上学期 1：下学期
            "ysyxS": "on",
            "sjxzS": "on",
            "zxC": "on",
            "fxC": "on",
            "xsjd": "1",
            "menucode_current": "S40303"
        }
        response = self.session.post(f"{self.mainURL}/student/xscj.stuckcj_data.jsp", headers= self.headers, data= data)
        
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.select("table")[-1].select("tr")
        class_grade = []
        for tr in table[1:]:
            td = tr.select("td")
            class_grade.append((td[1].text, td[12].text))
            # td[1]是课程名称，td[12]是综合成绩。8是平时成绩，9是期中成绩，10是期末成绩
            # 可能某些学校设置只返回综合成绩，不公开平时成绩等，就需要**改动索引**
        return class_grade
            

def md5(text: str) -> str:
    md5 = hashlib.md5()
    md5.update(text.encode())
    return md5.hexdigest()


if __name__ == '__main__':
    kingosoft = KINGOSOFT("username", "password", "URL")
    if kingosoft.sign():
        grade = kingosoft.get_grade()
        print(grade)
    else:
        pass
