
from sqlalchemy import create_engine
from urllib import parse
import sys
from sqlalchemy import text
sys.path.append("/opt/openfbi/fbi-bin/lib/")
import pandas as pd
import pymysql
import threading
import time
# 数据库连接设置
engine = {
    "host": "127.0.0.1",
    "port": "3306",
    "database": "dcap_data",
    "user": "sddm",
    "password": "Cii@2019#DCAP"
}

pwd = parse.quote_plus(engine["password"])
db_link = f"mysql+pymysql://{engine['user']}:{pwd}@{engine['host']}:{engine['port']}/{engine['database']}"
db_engine = create_engine(db_link)

# 生成数据
data = {
    'name': [f'Name_{i}' for i in range(1, 100001)],
    'age': [i % 100 for i in range(1, 100001)]  # 生成 1-99 的年龄
}

df = pd.DataFrame(data)

# 批量插入数据
df.to_sql('new_table', con=db_engine, if_exists='append', index=False, chunksize=5000)

print("10 万条数据已成功插入到 'new_table'。")
