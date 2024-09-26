# -*- coding: utf-8 -*-
"""
@author by gjw on 20201008
@version 1.0
@describe fshow 处理show原语的集合

"""

import sys

sys.path.append("lib")
import pandas as pd
import numpy as np
from numpy import NaN

try:
    import ujson as json
except:
    import json

from driver.esql_client import Esql_Client
from driver.ESql import ESql, Elasticsearch, ESql_query
from driver.esql3 import Esql3
from driver.jdbc_client import JDBC_Client
from driver.pyssdb import Client

import gc
from datetime import datetime, timedelta
import math
import re
import time
import random
import threading
import hashlib
import traceback
import _pickle as pickle
import gzip
import pymysql
from sqlalchemy import create_engine
from sqlalchemy.types import *
import requests
import xlrd
import xlwt
import glob

from .fglobals import *
from .fsys import *
from .fssdb import *
from multiprocessing import shared_memory, resource_tracker

try:
    from driver.clickhouse_driver import Client as CHK_Client
except:
    from clickhouse_driver import Client as CHK_Client

default_workspace = "public"
__workSpace = "../workspace/"
__script_dir = "script/"


def load_data_by_csv(ptree):
    if ptree["by"].find("__") == 0 and ptree["by"][2:len(ptree["runtime"].user) + 2] != ptree["runtime"].user:
        error = "你 [%s] 没有权限load该数据文件!" % (ptree["runtime"].user)
        raise Exception(error)

    if "with" in ptree:
        if ptree["with"].find("encoding") >= 0:
            cmd = "pd.read_csv(__workSpace+ptree['by'],%s)" % (ptree["with"])
            df = eval(cmd)
        else:
            try:
                cmd = "pd.read_csv(__workSpace+ptree['by'],%s,encoding='gb18030',dtype_backend='pyarrow',engine='pyarrow')" % (
                ptree["with"])
                df = eval(cmd)
            except:
                cmd = "pd.read_csv(__workSpace+ptree['by'],%s,encoding='utf-8',dtype_backend='pyarrow',engine='pyarrow')" % (
                ptree["with"])
                df = eval(cmd)
    else:
        # 默认gbk,用windows的人比较多,如果出错使用utf8
        try:
            df = pd.read_csv(__workSpace + ptree["by"], encoding="gb18030", index_col=0, dtype_backend="pyarrow",
                             engine='pyarrow')
        except:
            df = pd.read_csv(__workSpace + ptree["by"], encoding="utf-8", index_col=0, dtype_backend="pyarrow",
                             engine='pyarrow')
    return df


def load_data_by_excel(ptree):
    if ptree["by"].find("__") == 0 and ptree["by"][2:len(ptree["runtime"].user) + 2] != ptree["runtime"].user:
        error = "你 [%s] 没有权限load该数据文件!" % (ptree["runtime"].user)
        raise Exception(error)

    if "with" in ptree:
        cmd = "pd.read_excel(__workSpace+ptree['by'],%s, na_filter=False,dtype_backend='pyarrow')" % (ptree["with"])
        df = eval(cmd)
    else:
        df = pd.read_excel(__workSpace + ptree["by"], na_filter=False, sheet_name=0, dtype_backend="pyarrow")
    return df


def load_data_by_pkl(ptree):
    if ptree["by"].find("__") == 0 and ptree["by"][2:len(ptree["runtime"].user) + 2] != ptree["runtime"].user:
        error = "你 [%s] 没有权限load该数据文件!" % (ptree["runtime"].user)
        raise Exception(error)

    if ptree["by"].startswith("dev/shm"):
        df = pd.read_pickle("/" + ptree["by"])
    else:
        df = pd.read_pickle(__workSpace + ptree["by"])
    return df


def load_data_by_pq(ptree):
    if ptree["by"].find("*") < 0:
        return load_data_by_pq_singlefile(__workSpace + ptree["by"], ptree)
    else:
        dfs = []
        fs = glob.glob(__workSpace + ptree["by"])
        for f in fs:
            dfs.append(load_data_by_pq_singlefile(f, ptree))
        if len(dfs) == 0:
            return pd.DataFrame()
        else:
            return pd.concat(dfs)


def load_data_by_pq_singlefile(f, ptree):
    if "with" in ptree:
        """
        过滤规则的用法：
        To filter out data. Filter syntax: [[(column, op, val), …],…] where op is [==, =, >, >=, <, <=, !=, in, not in] 
        The innermost tuples are transposed into a set of filters applied through an AND operation. 
        The outer list combines these sets of filters through an OR operation. 
        A single list of tuples can also be used, meaning that no OR operation between set of filters is to be conducted.

        """
        cond = eval(ptree["with"])  # 过滤条件： [("foo", ">", 2)]
        df = pd.read_parquet(f, engine="pyarrow", dtype_backend="pyarrow", filters=cond)
    else:
        df = pd.read_parquet(f, engine="pyarrow", dtype_backend="pyarrow")
    return df


"""
xlink的文件路径：
/dev/shm/xlink_df:xlink_name:df_name.fat

"""


def load_data_by_fat(ptree):
    if ptree["by"].find("dev/shm") >= 0:  # 流调试是使用的DF
        # modify by gjw on 2024-0411 精准的流调试
        if ptree["by"].endswith("*.fat"):
            fs = glob.glob("/" + ptree["by"])
            if len(fs) == 0:
                df = pd.DataFrame()
            else:
                for f in fs:  # 多个df全部装载
                    try:
                        df = pd.read_feather(f, dtype_backend="pyarrow", use_threads=False)
                        name = f.split(".")[0].split(":")[2]
                        o = FbiTable(name, df)
                        fbi_global.runtime.put(o)
                    except:
                        pass
        else:
            df = pd.read_feather("/" + ptree["by"], dtype_backend="pyarrow", use_threads=False)
    else:
        df = pd.read_feather(__workSpace + ptree["by"], dtype_backend="pyarrow", use_threads=False)
    return df


def load_data_by_json(ptree):
    # add by gjw on 20200424 JSON方式
    if "as" in ptree and ptree["as"] == "json":
        with open(ptree["by"], "r") as f:
            b = json.loads(f.read())
            return b

    if ptree["by"].find("__") == 0 and ptree["by"][2:len(ptree["runtime"].user) + 2] != ptree["runtime"].user:
        error = "你 [%s] 没有权限load该数据文件!" % (ptree["runtime"].user)
        raise Exception(error)

    if "with" in ptree and ptree["with"] == "csv":
        """
        from io import StringIO
        s = StringIO()
        s.write("[")
        #i=0
        for line in open(__workSpace+ptree["by"]):
            s.write("%s,"%(line[:-1].strip())) #-1 是去掉换行符
        s.seek(s.tell()-1)
        s.write("]")
        s.flush()
        s.seek(0)
        """
        buf = ""
        b = time.time()
        with open(__workSpace + ptree["by"]) as f:
            while True:
                lines = f.readlines(1000000)  # 一百万
                if len(lines) == 0: break
                buf += ",".join(lines)
                buf += ","
            s = "[%s]" % (buf[0:-1])
            logger.info(time.time() - b)
            df = pd.read_json(s, orient="records")
            logger.info(time.time() - b)
    elif "with" in ptree:
        df = pd.read_json(__workSpace + ptree["by"], orient=ptree["with"])
    else:
        df = pd.read_json(__workSpace + ptree["by"], orient="split")
    return df


def load_data_by_udb(ptree):
    df = __load_rowdata_by_udb(ptree)
    return df


# author zry
def query_shard_address(es, index_name, shard_id):
    """ Get transport_address by index's shard id
    :param index_name:
    :param shard_id:
    :return: list. node's transport_address
    """
    address_es = []
    shards_info = es.search_shards(index_name)
    # print(json.dumps(shards_info, indent=4))
    try:
        nodes, shards = shards_info['nodes'], shards_info['shards'][shard_id]
    except:
        raise Exception("表 %s 或 分片 %d 未找到！" % (index_name, shard_id))
    for shard in shards:
        if shard['shard'] == shard_id:
            node_name = shard['node']
            address = nodes[node_name]['transport_address']
            address_es.append(address[6:-1] if address.startswith('inet[/') else address)
    return address_es[0]


def get_index_routing(es, scan):
    esql_query = ESql_query(es)
    ret = esql_query.parse_sql(scan)
    _from = ret["from"][0].split(".")

    scan_options = {"size": 10, "routing": None}
    if len(ret["with"]) > 0:
        opt = " ".join(ret["with"])
        a = opt.split(" and ")
        for o in a:
            options = o.split("=")
            scan_options[options[0].strip()] = int(options[1].strip())
    return _from[0], scan_options["routing"]


def __load_rowdata_by_udb(ptree):
    by = get_key(ptree["by"])

    if by == "":
        raise Exception("[%s]链接未找到!" % (ptree["by"]))

    ip_port = by.split(":")
    t = threading.current_thread()

    if get_key("fast_scan") == "1" and ("scan" in ptree):
        try:
            es = Elasticsearch([{'host': ip_port[0], 'port': int(ip_port[1])}, ])

            if "scan" in ptree and ptree["scan"].find("routing") > 0:
                _index, _routing = get_index_routing(es, ptree["scan"])
                _ip_port = query_shard_address(es, _index, _routing)
                es = Elasticsearch([{'host': _ip_port.split(":")[0], 'port': int(ip_port[1])}, ])
            esql = ESql(es)
        except Exception as e:
            logger.error(traceback.format_exc())
            raise Exception("连接名错误或未找到！%s" % (e))
    else:
        if "with" in ptree:  # use the esql3 add by gjw on 20160525
            user_pass = ptree["with"].split("/")
            try:
                host_url = "http://%s" % (by)
                esql = Esql3(host_url, user_pass[0].strip(), user_pass[1].strip())
            except Exception as e:
                raise Exception("连接名错误或未找到！%s" % (e))
        else:  # 使用esql2,
            try:
                esql = Esql_Client(ip_port[0].encode("utf8"), int(ip_port[1]))
            except Exception as e:
                raise Exception("连接名错误或未找到！%s" % (e))

    # add by gjw on 20160517
    dfs = []
    if "scan" in ptree:
        res = esql.do_sql(ptree["scan"])

        if res["msg"] != "": raise Exception(res["msg"])
        if res["count"] == 0:
            return pd.DataFrame()
        else:
            count = res["count"]

        i = 0
        real_count = 0
        have_next = True  # add by gjw on 20170728 是否还有数据
        while have_next:
            if "id" not in res:
                raise Exception("scan has error,not load the all data! please check " + res["msg"])
            res = esql.do_sql("scroll from %s" % (res["id"]))
            if res["count"] == 0:
                have_next = False
            elif res["count"] == -1:  # add by gjw on 20161124
                raise Exception("scroll超时，本次任务结束！")
            else:
                real_count += len(res["result"])  # add by gjw on 20170728

            if len(res["result"]) == 0:
                break

            # df = pd.DataFrame(res["result"]["data"],index=res["result"]["index"])
            df = pd.DataFrame(res["result"])
            df = df.set_index("_id")
            df.index.name = "_id"
            dfs.append(df)
            if t.ident in global_tasks:
                global_tasks[t.ident]["progress"] = "%s / %s" % (real_count, count)
            i += 1
            if i % 20 == 0:
                mem = meminfo()
                if (int(mem['MemFree']) + int(mem['Cached']) / 2) / 1024 < 512:
                    df2 = pd.concat(dfs)
                    if t.ident in global_tasks:
                        global_tasks[t.ident]["progress"] = "%s / %s" % (df2.index.size, count)

                    o = FbiTable(ptree["Ta"], df)
                    ptree["runtime"].put(o)
                    raise Exception("system not have the enough memory, break loading!!!"
                                    "already load %d data can use " % (df2.index.size))
    # end while

    else:  # query
        if "query" in ptree:
            query = ptree["query"]
        else:
            query = "show tables"
        res = esql.do_sql(query)
        if res["msg"] != "": raise Exception(res["msg"])
        df = pd.DataFrame(res["result"])
        dfs.append(df)
    if len(dfs) != 0:
        df2 = pd.concat(dfs)
        if t.ident in global_tasks:
            global_tasks[t.ident]["progress"] = "%s / %s" % (df2.index.size, df2.index.size)
    else:
        df2 = pd.DataFrame()
    return df2


# 处理es7
def load_data_by_es(ptree):
    t = threading.current_thread()
    by = get_key(ptree["by"])
    if by == "":
        raise Exception("[%s]链接未找到!或者为没有权限使用" % (ptree["by"]))
    try:
        from driver.ESql7 import ESql, Elasticsearch, ESql_query
        if by[0:4] != "http":  # add by gjw on 20221027 简写的链接方式host:port
            ip_port = by.split(":")
            es = Elasticsearch([{'host': ip_port[0], 'port': int(ip_port[1])}, ])
        else:
            es = Elasticsearch(list(map(lambda x: x.strip(), by.split(";"))),
                               verify_certs=True)  # modify by gjw on 20220628 支持es集群

        esql = ESql(es)
        res = esql.do_sql(ptree["with"])
        if res["msg"] != "": raise Exception(res["msg"])
        df = pd.DataFrame(res["result"])
        df2 = pd.DataFrame(data=[res["count"]], columns=["count"])
    except Exception as e:
        raise Exception("执行[%s]语句出现异常 %s" % (ptree["with"], e))
    finally:
        es.transport.close()  # 关闭链接
    # 返回DF表
    if len(ptree["Ta"].split(",")) == 2:
        return df, df2
    return df


# add by gjw on 20151217
def load_data_by_ssdb2(ptree):
    if "by" not in ptree:
        ptree["by"] = "ssdb0"

    if ptree["by"] == "ssdb0":  # 默认使用同一个链接
        c = fbi_global.get_ssdb0()
    elif ptree["by"] in ssdb_links:
        c = ssdb_links[ptree["by"]]
    else:
        if ptree["by"].find(":") < 0:
            by = get_key(ptree["by"])
        else:
            by = ptree["by"]
        try:
            ip_port = by.split(":")
            c = Client(ip_port[0], int(ip_port[1]))
        except:
            raise Exception("连接错误或未找到！")
        ssdb_links[ptree["by"]] = c

    res = c.get(b64(ptree["with"]))
    if res == None:
        df = pd.DataFrame()
    else:
        df = pickle.loads(res)
    return df


# 全局的DB链接池,用于load和store db
global_db_pools = {}


def get_db_conn(link):
    from .fssdb import get_key
    if link not in global_db_pools:
        global_db_pools[link] = []
    if len(global_db_pools[link]) > 0:
        return global_db_pools[link].pop()

    # 新建链接
    db_link = get_key(link)
    if db_link == "":
        raise Exception("连接错误或未找到！")
    if db_link[0] == '{' and db_link[-1] == '}':  # add by gjw mysql的json连接
        json_link = json.loads(db_link)
        from urllib import parse
        pwd = parse.quote_plus(json_link["password"])
        # db_link="mysql+mysqlconnector://{}:{}@{}:{}/{}".format(json_link["user"],pwd,json_link["host"],json_link["port"],json_link["database"])
        db_link = "mysql+pymysql://{}:{}@{}:{}/{}".format(json_link["user"], pwd, json_link["host"], json_link["port"],
                                                          json_link["database"])
    try:
        engine = create_engine(db_link, pool_pre_ping=True)
    except Exception as e:
        raise Exception("连接%s,出现异常%s" % (db_link, e))

    return engine


def put_db_conn(link, engine):
    if len(global_db_pools[link]) > 5:  # 最多5个链接
        engine.dispose()
    global_db_pools[link].append(engine)


def load_data_by_db(ptree):
    engine = get_db_conn(ptree["by"])

    try:
        if "with" in ptree:
            df = pd.read_sql(ptree["with"], engine, dtype_backend="pyarrow")
        elif "query" in ptree:
            df = pd.read_sql(ptree["query"], engine, dtype_backend="pyarrow")
        elif "exec" in ptree:
            try:

                # modify by gjw on 2024-0726  适应新的版本
                # engine.execute(ptree["exec"])

                from sqlalchemy import text
                conn = engine.connect()
                conn.execute(text(ptree["exec"]))
                conn.commit()
                df = pd.DataFrame([[ptree["exec"], "ok!"]])
            except Exception as e:
                conn.rollback()
                df = pd.DataFrame([[ptree["exec"], "错误:%s" % (e)]])
        else:
            raise Exception("不完整的原语，缺少with关键字!")
    finally:
        put_db_conn(ptree["by"], engine)
    return df


# ckh的连接池
ckh_link_pools = {}


def get_ckh_conn_by_link(link):
    if link not in ckh_link_pools or len(ckh_link_pools[link]) == 0:
        ckh_link_pools[link] = []
        db_link = get_key(link)
        if db_link == "":
            raise Exception("连接错误或未找到！")
        try:
            # add by gjw on 2024-0220 支持指定db
            configs = db_link.split(":")
            ssl = False
            if len(configs) == 4:
                host, port, user, passwd = configs
                db = "default"
            elif len(configs) == 5:
                host, port, user, passwd, db = configs
            elif len(configs) == 6:
                host, port, user, passwd, db, ssl = configs
                ssl = True
            else:
                host, port, user, passwd, db, ssl, key_file, cert_file = configs
                ssl = True

            if len(configs) < 8:
                client = CHK_Client(host=host, port=int(port), user=user, password=passwd, database=db, secure=ssl)
            else:
                client = CHK_Client(host=host, port=int(port), user=user, password=passwd, database=db, secure=ssl,
                                    keyfile=key_file, certfile=cert_file)
        except Exception as e:
            raise Exception("连接%s,出现异常%s" % (db_link, e))
    else:
        client = ckh_link_pools[link].pop()
    return client


def put_ckh_conn_by_link(link, client):
    if link not in ckh_link_pools:
        ckh_link_pools[link] = []
    ckh_link_pools[link].append(client)


def load_data_by_ckh(ptree):
    client = get_ckh_conn_by_link(ptree["by"])
    data, columns = client.execute(ptree["with"], with_column_types=True)
    df = pd.DataFrame(data, columns=[r[0] for r in columns])
    put_ckh_conn_by_link(ptree["by"], client)
    return df


def load_data_by_sqlite(ptree):
    conn = "sqlite:///../workspace/%s" % (ptree["by"])
    if "with" in ptree:
        df = pd.read_sql_table(ptree["with"], conn, dtype_backend="pyarrow")
    elif "query" in ptree:
        df = pd.read_sql(ptree["query"], conn, dtype_backend="pyarrow")
    else:
        raise Exception("不完整的原语，缺少with或query关键字!")
    return df


# add by gjw on 20151216
def load_data_by_jdbc(ptree):
    if ptree["by"].find(":") < 0:
        by = get_key(ptree["by"])
    else:
        by = ptree["by"]
    ip_port = by.split(":")

    try:
        jdbc = JDBC_Client(ip_port[0], int(ip_port[1]), ptree["with"])
    except:
        raise Exception("连接名错误或未找到！")

    res = jdbc.do_query(ptree["query"])

    if res["success"] == False:
        raise Exception("%s,error:%s" % (res["msg"], res["error"]));

    # add by gjw on 20160323 translate the columns to lower
    str_columns = json.dumps(res["columns"])
    lower_columns = json.loads(str_columns.lower())
    df = pd.DataFrame(res["data"], columns=lower_columns)
    del res
    gc.collect()
    return df


# ssdb其他类型的查询
def _ssdb_scan(link, scan, Ta):
    if (scan.find("=>*") > 1):
        data = link.hgetall(scan.strip()[0:-3])
    elif (scan.find("=>") > 1):
        try:
            start, end, count = scan.split(",")
            name, start = start.strip().split("=>")
            name, end = end.strip().split("=>")
            count = count.strip()
        except:
            raise Exception("[HashMap]scan的正确格式: name=>skey,name=>ekey,count")
        if count == "-":
            count = link.hsize(name.strip())
        data = link.hscan(name.strip(), start.strip(), end.strip(), count)
    else:  # KV对象的scan
        try:
            start, end, count = scan.split(",")
            count = count.strip()
        except:
            raise Exception("[KV]scan的正确格式: skey,ekey,count")
        data = link.scan(start.strip(), end.strip(), count)

    # 处理返回的数据
    length = len(data)
    dfs = []
    counts = []
    for i in range(0, length, 2):
        k = data[i]
        d = data[i + 1]
        if d != "":
            res = json.loads(d)
        else:
            res = {"data": [], "index": [], "columns": []}
        df = pd.DataFrame(res["data"], columns=res["columns"], index=res["index"])
        df["@k"] = k
        dfs.append(df)
        counts.append([k, df.index.size])
    if len(dfs) > 0:
        dfz = pd.concat(dfs)
    else:
        dfz = pd.DataFrame()
    dfc = pd.DataFrame(data=counts, columns=["name", "count"])

    # 返回DF表
    if len(Ta.split(",")) == 2:
        return dfz, dfc
    else:
        return dfz


# ssdb其他类型的查询
def _ssdb_query2(link, query, Ta):
    action, name, start, end = query.split(",")
    name = b64(name.strip())
    action = action.strip()
    if action == "qrange":
        data = link.qrange(name, start.strip(), end.strip())
        size = link.qsize(name)
        data2 = [[name.strip(), size]]
    # add by gjw on 2020-0304
    elif action == "qpop":
        size = start.strip()
        data = link.qrange(name, 0, size)
        link.qpop_front(name, size)
        qsize = link.qsize(name)
        data2 = [[name.strip(), qsize]]
    elif action == "qclear":
        qsize = link.qsize(name)
        data = ['{"count":%s}' % (qsize)]
        link.qclear(name)
        data2 = []
    elif action == "qslice":
        data = link.qslice(name, start.strip(), end.strip())
        size = link.qsize(name)
        data2 = [[name, size]]
    elif action == "qlast":
        size = link.qsize(name)
        start = 0 if size - int(end.strip()) < 0 else size - int(end.strip())
        data = link.qrange(name, str(start), str(size))
        data.reverse()
        data2 = [[name, size if size - int(end.strip()) < 0 else int(end.strip())]]
    elif action == "qlist":
        index = link.qlist(name, start.strip(), 180)
        size0 = int(end.strip())
        data = []
        for i in index:
            idata = link.qrange(i, "0", size0)  # 满足条件的第一个name的前xx条数据
            data.extend(idata)
            if len(data) > size0:
                data = data[0:size0]
                break;
        data2 = []
        count = 0
        ssum = 0
        for key_name in index:
            size = link.qsize(key_name)
            data2.append([key_name, size])
            count += 1
            ssum += size
        data2.append(["count", count])
        data2.append(["sum", ssum])
    elif action == "qrlist":  # 倒序, add by gjw on 2021-1027
        index = link.qlist(name, start.strip(), 180)
        size0 = int(end.strip())
        if index:
            index.reverse()
        data = []
        for i in index:
            idata = link.qrange(i, "0", size0)  # 满足条件的第一个name的前xx条数据
            if idata:
                idata.reverse()
                data.extend(idata)
            if len(data) > size0:
                data = data[0:size0]
                break;
        data2 = []
        count = 0
        ssum = 0
        for key_name in index:
            size = link.qsize(key_name)
            data2.append([key_name, size])
            count += 1
            ssum += size
        data2.append(["count", count])
        data2.append(["sum", ssum])
    else:
        data = []
        data2 = []
    try:
        data = map(lambda x: json.loads(x), data)
        df = pd.DataFrame(list(data))
    except Exception as e:
        df = pd.DataFrame([["%s" % (e)]], columns=["装载数据存在如下错误:"])
    df2 = pd.DataFrame(data=data2, columns=["name", "size"])

    # 返回DF表
    if len(Ta.split(",")) == 2:
        return df, df2
    else:
        return df


# add by gjw on 2023-1214,加载参数
def load_data_by_param(ptree):
    if "with" not in ptree:
        return None
    ret = fbi_global.get_param(ptree["with"])
    if ret:
        res = json.loads(ret)
        df = pd.DataFrame(res["data"], columns=res["columns"], index=res["index"])
    else:
        df = pd.DataFrame()
    return df


# 从ssdb获取数据
def load_data_by_ssdb(ptree):
    # add by gjw on 2023-1214，先加载参数
    df = load_data_by_param(ptree)
    try:
        if not df.empty:  # 一定要这样判断才行, 出错就继续走
            return df
    except:
        pass
    # 正式从ssdb进行加载
    if "by" not in ptree:
        ptree["by"] = "ssdb0"
    # add by gjw on 2021-1224 将信息发往远程节点
    if ptree["by"].find("@") > 0:
        ssdb, node = ptree["by"].split("@")
        node_info = get_slaver_by_name(node)
        if node_info == None:  # 节点不存在
            error = "节点信息不存在[%s]!" % (node)
            raise Exception(error)
        ptree["by"] = ssdb
        d = remote_ssdb_rw(node_info[0], node_info[1], node, ptree)  # 发送到远程节点运行
        if "data" in d:
            res = json.loads(d["data"])
            df = pd.DataFrame(res["data"], columns=res["columns"], index=res["index"])
            return df
        else:
            return pd.DataFrame()
    # end if
    if ptree["by"] == "ssdb0":  # 默认使用同一个链接
        c = fbi_global.get_ssdb0()
    elif ptree["by"] in ssdb_links:
        c = ssdb_links[ptree["by"]]
    else:
        if ptree["by"].find(":") < 0:
            by = get_key(ptree["by"])
        else:
            by = ptree["by"]
        try:
            ip_port = by.split(":")
            c = Client(ip_port[0], int(ip_port[1]))
        except:
            raise Exception("连接错误或未找到！")
        ssdb_links[ptree["by"]] = c

    # modify by gjw 20161117 增加对with的支持，标准使用with,兼容query
    if "with" in ptree:
        # add by gjw on 20200424 处理as json
        pwith = re.split("\s+", ptree["with"])
        if len(pwith) >= 3:
            if "as" in pwith:
                ptree["as"] = pwith[2]
                ptree["with"] = pwith[0]
        key = b64(ptree["with"])
        key = key.strip()
        if key.find("=>*") > 0:  # add by gjw on 2022-0610 用来处理行的hashmap
            data = c.hgetall(key[0:-3])
            length = len(data)
            indexs = []
            rows = []
            for i in range(0, length, 2):
                try:
                    indexs.append(data[i])
                    d = data[i + 1]
                    res = json.loads(d)
                    rows.append(res)
                except:
                    pass
            return pd.DataFrame(rows, index=indexs)
        elif key.find("=>") > 0:
            name, k = key.split("=>")
            res = c.hget(name, k)
        else:
            res = c.get(key)
    elif "query" in ptree:
        return _ssdb_query2(c, ptree["query"], ptree["Ta"])  # 增加对LIST类型的查询
    elif "scan" in ptree:
        return _ssdb_scan(c, ptree["scan"], ptree["Ta"])  # 增加对hashmap类型的查询
    elif "exec" in ptree:  # 执行某个动作函数
        res = eval("""c.{}""".format(ptree["exec"]))
        return pd.DataFrame(data=[[res]])
    else:
        raise Exception("未知的关键字!");

    if res == None:
        return pd.DataFrame()
    res = json.loads(res)

    # add by gjw on 20200424 处理json类型
    if "as" in ptree and ptree["as"] == "json":
        return res
    # add by gjw on 20161028 处理复合索引
    if "index" in res and len(res["index"]) > 1 and isinstance(res["index"][0], list):
        if len(res["index"][0]) > 3: raise Exception("数据超过三重索引,暂不支持加载！")
        muli_index = []

        def dd0(x):
            return x[0]

        def dd1(x):
            return x[1]

        def dd2(x):
            return x[2]

        a = list(map(dd0, res["index"]))
        muli_index.append(a)
        b = list(map(dd1, res["index"]))
        muli_index.append(b)
        if len(res["index"][0]) == 3:
            c = list(map(dd0, res["index"]))
            muli_index.append(c)
        df = pd.DataFrame(res["data"], columns=res["columns"], index=muli_index)
    else:
        df = pd.DataFrame(res["data"], columns=res["columns"], index=res["index"])
    return df


# 从ssdb获取数据
def load_data_by_redis(ptree):
    if "by" not in ptree:
        ptree["by"] = "redis0"
    import redis
    if ptree["by"] not in redis_links:
        link = get_key(ptree["by"])
        link = link.split(":")
        if len(link) < 2:
            raise Exception("{}链接未找到或不符合格式: {}".format(ptree["by"], link))
        if len(link) == 3:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True, password=link[2])
        elif ptree["by"] in ["redis0", "redis1", "redis2"]:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True,
                                 password='4d7d4f6ef5d627f43a65d9b4b2ccc875')
        else:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True)
    else:
        client = redis_links[ptree["by"]]

    # do
    if "with" in ptree:
        res = client.get(ptree["with"])
        if res == None or res == "":
            return pd.DataFrame()

        res = json.loads(res)
        df = pd.DataFrame(res["data"], columns=res["columns"], index=res["index"])
    elif "scan" in ptree:  # add by gjw on 20220817
        key = ptree["scan"]
        try:
            p = client.pipeline()
            p.lrange(key, 0, 10000 - 1)
            data = p.execute()
        except Exception as e:
            raise Exception("scan redis {} 出错: {}".format(key, e))
        result = []
        for r in data[0]:
            a = json.loads(r)
            result.append(a)
        df = pd.DataFrame(result)
    elif "drop" in ptree:  # 删除
        key = ptree["drop"]
        try:
            p = client.pipeline()
            p.ltrim(key, 10000, -1)
            data = p.execute()
        except Exception as e:
            raise Exception("drop redis {} 出错: {}".format(key, e))
        df = pd.DataFrame(data)
    elif "query" in ptree:  # 查询长度
        key = ptree["query"]
        try:
            p = client.pipeline()
            p.llen(key)
            data = p.execute()
        except Exception as e:
            raise Exception("query redis {} 出错: {}".format(key, e))
        df = pd.DataFrame(data)
    else:
        raise Exception("缺少with或scan、drop,query关键字!")

    # 成功了再放入
    redis_links[ptree["by"]] = client

    return df


# end fun

#######################################Store############################

redis_links = {}


# 存储df到redis
def store_to_redis(ptree):
    if "by" not in ptree:
        ptree["by"] = "redis0"
    import redis
    if ptree["by"] not in redis_links:
        link = get_key(ptree["by"])
        link = link.split(":")
        if len(link) < 2:
            raise Exception("{}链接未找到或不符合格式: {}".format(ptree["by"], link))
        if len(link) == 3:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True, password=link[2])
        elif ptree["by"] in ["redis0", "redis1", "redis2"]:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True,
                                 password='4d7d4f6ef5d627f43a65d9b4b2ccc875')
        else:
            client = redis.Redis(host=link[0], port=int(link[1]), decode_responses=True)

    else:
        client = redis_links[ptree["by"]]

    df = ptree["runtime"].get(ptree["store"]).df
    if "as" in ptree:  # 存储成list类型
        for k, row in df.iterrows():
            try:
                client.rpush(ptree["with"], row.to_json(orient="index", date_format='iso', date_unit='us'))
            except:
                pass
    elif "push" in ptree:
        d_str = df.to_json(orient="split")
        d = json.loads(d_str)
        a = datetime.now()
        now_ms = f"{a.hour:02d}:{a.minute:02d}:{a.second:02d}"
        d["index"] = [now_ms]
        # 保存最后60个信息
        push_list = ptree["push"] + ":liutu60"
        llen = client.llen(push_list)
        if llen > 60:
            client.lpop(push_list)
        client.rpush(push_list, json.dumps(d))
        client.publish(ptree["push"], json.dumps(d))
    elif "with" in ptree:
        client.set(ptree["with"], df.fillna("").to_json(orient="split"))
    else:
        raise Exception("未找到with、push关键字")
    # 成功了再放入
    redis_links[ptree["by"]] = client
    return 0


# add by gjw on 20151021
def store_to_csv(ptree):
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df
    if "with" in ptree:
        cmd = "df.to_csv(__workSpace+ptree['by'], %s)" % (ptree["with"])
        exec(cmd)
    else:
        df.to_csv(__workSpace + ptree["by"], encoding="gb18030", index_label="index")


def store_to_excel(ptree):
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df
    if "with" in ptree:
        cmd = "df.to_excel(__workSpace+ptree['by'], %s)" % (ptree["with"])
        exec(cmd)
    else:
        df.to_excel(__workSpace + ptree["by"], sheet_name='0', index_label="index")


# add by gjw on 20151208
def store_to_pkl(ptree):
    df = ptree["runtime"].get(ptree["store"]).df
    if "as" in ptree and ptree["as"] == "dict":
        d = df.to_dict(orient="index")
        with open(f'/data/xlink/{ptree["by"]}', "wb+") as f:
            pickle.dump(d, f)
    else:
        df.to_pickle(__workSpace + ptree["by"])


# add by gjw on 20151208
def store_to_pq(ptree):
    import os
    file_path = __workSpace + ptree["by"]
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    df = ptree["runtime"].get(ptree["store"]).df
    df.to_parquet(file_path)


# add by gjw on 20151208
def store_to_fat(ptree):
    import os
    file_path = __workSpace + ptree["by"]
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    df = ptree["runtime"].get(ptree["store"]).df
    df.to_feather(file_path)


def store_to_json(ptree):
    o = ptree["runtime"].get(ptree["store"])
    if o.type == 1:
        o.df.to_json(__workSpace + ptree["by"], orient="split")
    else:
        with open(ptree["by"], "w+") as f:
            f.write(json.dumps(o.vue))
    return 0


# 远程读写ssdb
def remote_ssdb_rw(host, AK, node, ptree):
    # add by gjw on 20230406
    if "runtime" in ptree:
        ptree_data = ptree.copy()
        del ptree_data["runtime"]
    else:
        ptree_data = ptree.copy()
    req_data = json.dumps(ptree_data)
    q = {"ptree": New_encrypt(AK, req_data), "name": node}
    url = '%s/db/ssdb_rw' % (host.strip())
    r = requests.post(url, q, verify=False, timeout=(3, 1200))
    if r.status_code == 200:
        data = New_decrypt(AK, r.text)
        d = json.loads(data)
        if d["ret"] == -1:
            raise Exception("ssdb操作失败,原因[%s]" % (d["msg"]))
    else:
        raise Exception("ssdb操作失败,服务端返回[%s]" % (r.status_code))
    return d


# ssdb的长链接,和系统配置数据ssdb的默认链接
ssdb_links = {}


# add by gjw on 20151116
def store_to_ssdb(ptree):
    if "by" not in ptree:
        ptree["by"] = "ssdb0"

    # add by gjw on 2021-1224 将信息发往远程节点
    if ptree["by"].find("@") > 0:
        ssdb, node = ptree["by"].split("@")
        node_info = get_slaver_by_name(node)
        if node_info == None:  # 节点不存在
            error = "节点信息不存在[%s]!" % (node)
            raise Exception(error)
        ptree["by"] = ssdb
        df = ptree["runtime"].get(ptree["store"]).df
        ptree["data"] = df.to_json(orient="split", date_format='iso', date_unit='s')
        remote_ssdb_rw(node_info[0], node_info[1], node, ptree)  # 发送到远程节点运行
        return 0

    if ptree["by"] == "ssdb0":  # 默认使用同一个链接
        c = fbi_global.get_ssdb0()
    elif ptree["by"] in ssdb_links:
        c = ssdb_links[ptree["by"]]
    else:
        if ptree["by"].find(":") < 0:
            by = get_key(ptree["by"])
        else:
            by = ptree["by"]
        try:
            ip_port = by.split(":")
            c = Client(ip_port[0], int(ip_port[1]))
        except:
            raise Exception("连接错误或未找到！")
        ssdb_links[ptree["by"]] = c

    key = b64((ptree["with"]))

    # add by gjw on 20200522 存储json对象的多种方式KV,HashMap
    obj = ptree["runtime"].get(ptree["store"])
    if obj.type == 2:
        o = json.dumps(obj.vue)
        if key.find("=>") > 0:  # HashMap
            name, key = key.split("=>")
            c.hset(name, key, o)
        else:
            c.set(key, o)
        return 0

    # default csv
    df = obj.df

    # 增加多种类型的存储方式
    if "as" in ptree:
        if ptree["as"] == "Q" or ptree["as"] == "Queue":
            # add by gjw on 2023-0224 空的df表，不存为队列
            if df.index.size == 0: return 0
            batch = []
            i = 0
            for index, row in df.iterrows():
                row['index'] = index
                batch.append(row.to_json(orient="index", date_format='iso', date_unit='s'))
                i += 1
                if i % 100 == 0:
                    c.qpush(key, *batch)
                    batch.clear()
            c.qpush(key, *batch)
        elif ptree["as"] == "H" or ptree["as"] == "HashMap":  # add by gjw on 2022-0610
            for index, row in df.iterrows():
                c.hset(key, index, row.to_json(orient="index", date_format='iso', date_unit='s'))
        else:
            c.set(key, df.to_json(orient="split", date_format='iso', date_unit='s'))
            # as 参数用来定义key的存活时间
            c.expire(key, int(ptree["as"]))
    elif key.find("=>") > 0:  # HashMap
        name, key = key.split("=>")
        c.hset(name, key, df.to_json(orient="split", date_format='iso', date_unit='s'))
    else:
        c.set(key, df.to_json(orient="split", date_format='iso', date_unit='s'))
    return 0


def store_to_ckh(ptree):
    client = get_ckh_conn_by_link(ptree["by"])
    df = ptree["runtime"].get(ptree["store"]).df
    data = df.to_dict(orient='records')
    client.execute("insert into %s (%s) values" % (ptree["with"], ",".join(df.columns)), data)
    put_ckh_conn_by_link(ptree["by"], client)
    return 0


# add by gjw on 20151116
def store_to_ssdb2(ptree):
    if "by" not in ptree:
        ptree["by"] = "ssdb0"
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df

    if ptree["by"] == "ssdb0":  # 默认使用同一个链接
        c = fbi_global.get_ssdb0()
    elif ptree["by"] in ssdb_links:
        c = ssdb_links[ptree["by"]]
    else:
        if ptree["by"].find(":") < 0:
            by = get_key(ptree["by"])
        else:
            by = ptree["by"]
        try:
            ip_port = by.split(":")
            c = Client(ip_port[0], int(ip_port[1]))
        except:
            raise Exception("连接错误或未找到！")
        ssdb_links[ptree["by"]] = c

    key = b64((ptree["with"]))
    c.set(key, pickle.dumps(df))
    return 0


#
# 存储到es的通用方法
def __store_to_es(es, df, index, doc_type="_doc", noid=True):
    retry = int(get_key("bulk_retry") or "10")
    size = int(get_key("bulk_size") or "5000")
    from driver.ESql7 import helpers
    # 初始化
    body = []
    i = 0
    count = df.index.size
    t = threading.current_thread()
    for _id, row in df.iterrows():
        if noid:
            title = {"index": {"_index": index, "_type": doc_type}}
        else:
            title = {"index": {"_index": index, "_type": doc_type, "_id": _id}}

        # 非常关键，这个才能真正去掉NaN的数据
        row = row.dropna()
        r = {}
        for k, v in row.items():
            if k == "_parent":
                title["index"]["_parent"] = v
                continue
            if k != "_parent" and k != "_index" and k != "_type" and k != "_id":
                r[k] = v
        body.append(title)
        body.append(r)
        i += 1
        if i % size == 0:
            try:
                # modify by gjw on 20160616
                # res = esql.do_sql("bulk into "+json.dumps(body))
                write = retry
                while (write):
                    result = es.bulk(body=body, request_timeout=300)
                    if result["errors"] == True:
                        j = 0
                        for item in result["items"]:
                            # add by gjw on 20170731,增加ES1.x和ES2.x的错误处理方式
                            if "index" in item:
                                error_record = item["index"]  # ES1.x
                            elif "create" in item:
                                error_record = item["create"]  # ES2.x

                            if error_record["status"] == 429:
                                write -= 1
                                time.sleep(1)
                                if write == 0:
                                    logger.error("集群繁忙,超过重试次数 %d,放弃写入任务！" % (retry))
                                    raise Exception("集群繁忙,超过重试次数 %d,放弃写入任务！" % (retry))
                                break;
                            j += 1
                            if "error" in error_record:
                                if t.ident in global_tasks:
                                    global_tasks[t.ident]["progress"] = "%s / %s" % (j, count)
                                logger.error(
                                    "sotre to es has [%d] error!  info : %s" % (len(result["items"]), json.dumps(item)))
                                raise Exception(
                                    "sotre to es has [%d] error!  info : %s" % (len(result["items"]), json.dumps(item)))
                    else:
                        write = 0
                body = []
                if t.ident in global_tasks:
                    global_tasks[t.ident]["progress"] = "%s / %s" % (i, count)
            except Exception as e:
                raise Exception("批量入库失败,%s" % (e))
    # end for

    # 处理不足5000的
    if len(body) > 0:
        try:
            write = retry
            while (write):
                result = es.bulk(body=body, request_timeout=300)
                if result["errors"] == True:
                    for item in result["items"]:
                        # add by gjw on 20170731,增加ES1.x和ES2.x的错误处理方式
                        if "index" in item:
                            error_record = item["index"]  # ES1.x
                        elif "create" in item:
                            error_record = item["create"]  # ES2.x

                        if error_record["status"] == 429:
                            write -= 1
                            time.sleep(0.01)
                            if write == 0:
                                raise Exception("集群繁忙,超过重试次数 %d,放弃写入任务！" % (retry))
                            break;
                        if "error" in error_record:
                            raise Exception(
                                "sotre to es has [%d] error!  info : %s" % (len(result["items"]), json.dumps(item)))
                else:
                    write = 0
            res = es.indices.flush(index=index)
            if t.ident in global_tasks:
                global_tasks[t.ident]["progress"] = "%s / %s" % (i, count)
        except Exception as e:
            raise Exception("批量入库失败2,%s" % (e))
    # end if
    return 0


# add by gjw on 20151209
def store_to_udb(ptree):
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df

    if df.index.size == 0:
        return 0
    if ptree["by"].find(":") < 0:
        by = get_key(ptree["by"])
    else:
        by = ptree["by"]

    ip_port = by.split(":")
    try:
        es = Elasticsearch([{'host': ip_port[0], 'port': int(ip_port[1])}, ])
    except Exception as e:
        raise Exception("连接名错误或未找到！%s" % (e))

    noid = False
    index_type = ptree["with"].split(".")
    if len(index_type) == 1:
        index_type.append("base")
    elif len(index_type) == 2:
        # add by gjw on 20170812,直接noid
        if index_type[1] == "noid":
            index_type[1] = "base"
            noid = True
    elif len(index_type) == 3:
        noid = True
    # call the __store_to_es function
    __store_to_es(es, df, index_type[0], index_type[1], noid)
    return 0


def store_to_es(ptree):
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df

    if df.index.size == 0:
        return 0
    if ptree["by"].find(":") < 0:
        by = get_key(ptree["by"])
    else:
        by = ptree["by"]
    try:
        from driver.ESql7 import Elasticsearch
        if by[0:4] != "http":  # add by gjw on 20221027 简写的链接方式host:port
            ip_port = by.split(":")
            es = Elasticsearch([{'host': ip_port[0], 'port': int(ip_port[1])}, ])
        else:
            es = Elasticsearch(list(map(lambda x: x.strip(), by.split(";"))),
                               verify_certs=True)  # modify by gjw on 20220628 支持es集群
    except Exception as e:
        raise Exception("连接名错误或未找到！%s" % (e))

    if "with" not in ptree:
        raise Exception("缺少with参数：index or index.noid")

    index_type = ptree["with"].split(".")
    if len(index_type) == 1:
        index = index_type[0].strip()
        noid = False
    else:
        index = index_type[0].strip()
        noid = True
    # call the __store_to_es function
    try:
        __store_to_es(es, df, index, "_doc", noid)
    finally:
        es.transport.close()  # 关闭链接
    return 0


# add by gjw on 20151209
def store_to_jdbc(ptree):
    # default csv
    df = ptree["runtime"].get(ptree["store"]).df
    if df.index.size == 0:
        return 0
    dbname_tname_pkname = ptree["with"].split(":")
    if len(dbname_tname_pkname) < 3:
        raise Exception("数据库名:表名:主键名，请正确设置 %s" % (ptree["with"]))

    if ptree["by"].find(":") < 0:
        by = get_key(ptree["by"])
    else:
        by = ptree["by"]

    ip_port = by.split(":")
    try:
        jdbc = JDBC_Client(ip_port[0], int(ip_port[1]), dbname_tname_pkname[0].strip())
    except:
        raise Exception("连接名错误或未找到！")

    # 如果列里存在同名的主键，则用主键替代index
    if dbname_tname_pkname[2].strip() in df.dtypes:
        df = df.set_index(dbname_tname_pkname[2].strip())
        df.index.name = dbname_tname_pkname[2].strip()

    dtypes = {}
    for k, v in df.dtypes.items():
        if v.name == "object":
            dtypes[k] = "string"
        else:
            dtypes[k] = v.name
    dtypes[dbname_tname_pkname[2].strip()] = df.index.dtype.name
    s = json.dumps(dtypes)

    size = int(get_key("bulk_size") or "3000")
    count = df.index.size
    errors = []
    t = threading.current_thread()
    for i in range(int(count / size + 1)):
        data = df[i * size:i * size + size].to_json(orient="split")

        res = jdbc.do_post(dbname_tname_pkname[1].strip(), dbname_tname_pkname[2].strip(), data, types=s)
        if res["success"] == False:
            errors.append("%s,error:%s" % (res["msg"], res["error"]))
        if t.ident in global_tasks:
            global_tasks[t.ident]["progress"] = "%s / %s" % (i * size + size, count)
    # end for
    if len(errors) > 0:
        raise Exception(errors[0]);
    return 0


def store_to_db(ptree):
    df = ptree["runtime"].get(ptree["store"]).df
    if df.index.size == 0: return 1

    engine = get_db_conn(ptree["by"])
    try:
        df.to_sql(ptree["with"], engine, if_exists="append", index=False)
    except Exception as e:
        raise Exception("存储失败:{}".format(e))
    finally:
        put_db_conn(ptree["by"], engine)
    return 0


def store_to_sqlite(ptree):
    db_link = "sqlite:///../workspace/%s" % (ptree["by"])
    try:
        engine = create_engine(db_link)
    except Exception as e:
        raise Exception("连接%s,出现异常%s" % (db_link, e))
    df = ptree["runtime"].get(ptree["store"]).df
    try:
        df.to_sql(ptree["with"], engine, if_exists="append", index=False)
    except:
        engine.dispose()
    return 0


# add by gjw on 2022-1130
def store_to_shm(ptree):
    df = ptree["runtime"].get(ptree["store"]).df
    buf = pickle.dumps(df)

    if os.path.exists("/dev/shm/psm_" + ptree["by"]):
        os.remove("/dev/shm/psm_" + ptree["by"])

    shm = shared_memory.SharedMemory(name="psm_" + ptree["by"], create=True, size=len(buf))
    resource_tracker.unregister(shm._name, 'shared_memory')
    shm.buf[:] = buf[:]  # copy
    shm.close()

    return 0


def load_data_by_shm(ptree):
    shm = shared_memory.SharedMemory(name="psm_" + ptree["by"])
    resource_tracker.unregister(shm._name, 'shared_memory')
    df = pickle.loads(shm.buf)
    shm.close()
    return df


load_funs = {
    "csv": load_data_by_csv,
    "excel": load_data_by_excel,
    "udb": load_data_by_udb,
    "jdbc": load_data_by_jdbc,
    "rest": load_data_by_jdbc,
    "pkl": load_data_by_pkl,
    "ssdb": load_data_by_ssdb,
    "db": load_data_by_db,
    "es": load_data_by_es,
    "json": load_data_by_json,
    "sqlite": load_data_by_sqlite,
    "ssdb2": load_data_by_ssdb2,
    "ckh": load_data_by_ckh,
    "ck": load_data_by_ckh,
    "redis": load_data_by_redis,
    "shm": load_data_by_shm,
    "pq": load_data_by_pq,
    "fat": load_data_by_fat,
    "param": load_data_by_param,
}

# add by gjw on 20151116
store_funs = {
    "csv": store_to_csv,
    "excel": store_to_excel,
    "ssdb": store_to_ssdb,
    "pkl": store_to_pkl,
    "udb": store_to_udb,
    "jdbc": store_to_jdbc,
    "rest": store_to_jdbc,
    "db": store_to_db,
    "es": store_to_es,
    "json": store_to_json,
    "sqlite": store_to_sqlite,
    "ssdb2": store_to_ssdb2,
    "ckh": store_to_ckh,
    "ck": store_to_ckh,
    "redis": store_to_redis,
    "shm": store_to_shm,
    "pq": store_to_pq,
    "fat": store_to_fat,

}

####
if __name__ == "__main__":
    pass


