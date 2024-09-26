import pandas as pd
from sqlalchemy import create_engine, text
import sys
from urllib import parse
import threading
import time
import random

sys.path.append("/opt/openfbi/fbi-bin/lib/")
import pymysql


def load_data_by_db(ptree, params=None):
    engine = {
        "host": "127.0.0.1",
        "port": "3306",
        "database": "dcap_data",
        "user": "sddm",
        "password": "Cii@2019#DCAP"
    }

    pwd = parse.quote_plus(engine["password"])
    db_link = "mysql+pymysql://{}:{}@{}:{}/{}".format(
        engine["user"], pwd, engine["host"], engine["port"], engine["database"]
    )
    engines = create_engine(db_link, pool_pre_ping=True)

    try:
        if "query" in ptree:
            if params:
                df = pd.read_sql(ptree["query"], engines, params=params, dtype_backend="pyarrow")
            else:
                df = pd.read_sql(ptree["query"], engines, dtype_backend="pyarrow")
        else:
            raise Exception("不完整的原语，缺少查询指令!")
    finally:
        engines.dispose()


def update_data(start_id, end_id):
    engine = {
        "host": "127.0.0.1",
        "port": "3306",
        "database": "dcap_data",
        "user": "sddm",
        "password": "Cii@2019#DCAP"
    }

    pwd = parse.quote_plus(engine["password"])
    db_link = "mysql+pymysql://{}:{}@{}:{}/{}".format(
        engine["user"], pwd, engine["host"], engine["port"], engine["database"]
    )
    engines = create_engine(db_link, pool_pre_ping=True)

    try:
        with engines.connect() as conn:
            for i in range(start_id, end_id):
                new_name = f'Updated_Name_{i}-{i+1}'
                conn.execute(text(f"UPDATE new_table SET name='{new_name}' WHERE id={i}"))
            conn.commit()
            print(f"更新成功: {start_id} 到 {end_id - 1}")
    except Exception as e:
        print(f"更新错误: {e}")


def query_data():
    time.sleep(1)  # 确保更新线程先运行
    ptree = {
        "query": "SELECT name FROM new_table WHERE name IN ('Updated_Name_2-3','Updated_Name_65-66','Updated_Name_78-79','Updated_Name_97-98','Updated_Name_86-87')"
    }

    try:
        result_df = load_data_by_db(ptree)
        print(result_df)
    except Exception as e:
        print(f"查询时出错: {e}")


if __name__ == '__main__':
    # 创建并启动更新线程
    update_thread = threading.Thread(target=update_data, args=(1, 100000))  # 更新十万条记录
    update_thread.start()

    # 创建多个查询线程
    query_threads = []
    for _ in range(10):  # 启动10个查询线程
        query_thread = threading.Thread(target=query_data)
        query_threads.append(query_thread)
        query_thread.start()

    update_thread.join()
    for query_thread in query_threads:
        query_thread.join()
