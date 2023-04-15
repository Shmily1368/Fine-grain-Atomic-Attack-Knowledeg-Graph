# a=[1,2,3,4,5]
# del a[3:]
# print(a)

import requests
from bs4 import BeautifulSoup

# 爬取问题的URL
question_url = "https://www.zhihu.com/question/31280672"

# 获取问题的HTML代码
question_html = requests.get(question_url).text

# 解析HTML代码
soup = BeautifulSoup(question_html, "html.parser")

# 获取所有回答的链接
answers = soup.find_all("div", class_="qa-item")

# 打印所有回答的内容
for answer in answers:
    answer_url = answer.find("a")["href"]
    answer_text = answer.text.strip()
    print(answer_url, answer_text)