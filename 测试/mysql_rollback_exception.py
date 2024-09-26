import pandas as pd
from sqlalchemy import create_engine, text
import sys
from urllib import parse
import threading
import time

sys.path.append("/opt/openfbi/fbi-bin/lib/")
import pymysql


def load_data_by_db(ptree):
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
        if "with" in ptree:
            df = pd.read_sql(ptree["with"], engines, dtype_backend="pyarrow")
        elif "query" in ptree:
            df = pd.read_sql(ptree["query"], engines, dtype_backend="pyarrow")
        elif "exec" in ptree:
            conn = engines.connect()
            try:
                conn.execute(text(ptree["exec"]))
                conn.commit()
                df = pd.DataFrame([[ptree["exec"], "ok!"]])
            except Exception as e:
                conn.rollback()
                df = pd.DataFrame([[e]])
            finally:
                conn.close()
        else:
            raise Exception("不完整的原语，缺少with关键字!")
    finally:
        engines.dispose()

    return df


def lock_transaction():
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
            conn.execute(text("BEGIN"))  # 开始事务

            # 故意引发错误的更新语句
            for i in range(1, 100001):
                if i == 50000:  # 在第 50000 条时引发错误
                    conn.execute(text("UPDATE new_table SET non_existent_column = 1 WHERE id = 1"))
                else:
                    conn.execute(text(f"UPDATE new_table SET age = {i % 100} WHERE id = {i}"))

            conn.execute(text("COMMIT"))  # 提交事务
    except Exception as e:
        print(f"更新数据时发生错误: {e}")
        # 不进行回滚，故意留下事务未处理状态


def try_access():
    time.sleep(1)  # 确保更新线程先运行
    ptree = {
        "query": "SELECT src_id, database_name, COUNT(*) AS count FROM metatables WHERE src_id IN (24, 23, 22, 21, 20, 19, 18, 17, 14, 16, 15, 2, 13, 12, 11, 10, 9, 8, 7, 6, 5) GROUP BY src_id, database_name"
    }

    result_df = load_data_by_db(ptree)
    print(result_df)


if __name__ == '__main__':
    # 创建两个线程以模拟并发
    t1 = threading.Thread(target=lock_transaction)
    t2 = threading.Thread(target=try_access)

    t1.start()
    t2.start()

    t1.join()
    t2.join()
