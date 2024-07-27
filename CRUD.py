# /bin/python
# -*- coding: utf-8 -*-
"""
CRUD.py
用来处理智能表单的后端相应函数
#=========================
"""
import pandas as pd

from datetime import datetime
import os
import sys
import urllib.request, urllib.error, urllib.parse
import json

__workSpace = "../workspace/"
sys.path.append("../lib")
sys.path.append("./lib")
sys.path.append("../")

from avenger.fsys import b64, hash_sha1
from avenger.fglobals import *
from avenger.fbiobject import FbiObject
from avenger.fbiprocesser import add_the_error

ssdb0 = fbi_global.get_ssdb0()


def build_query_nodes(df, p=""):
    """
	2022-0316 gjw
	构造查询条件和节点列表
	"""
    node_p = p
    nodes_df = df.query("name=='{}'".format(node_p))
    if nodes_df.index.size == 0:
        raise Exception("没有找到相应的节点信息name=='{}'".format(node_p))
    id = nodes_df.index[0]

    q = df.drop([id], axis=0)

    # 获取字符串形式的列表
    nodes_str = nodes_df.loc[id, "value"]
    nodes = []
    if nodes_str != "":
        for node in nodes_str.split(","):
            nodes.append([node[1:-1]])

    n = pd.DataFrame(data=nodes, columns=[node_p])
    return q, n


# 查询的入口函数，支持排序
def query_mtable(df, p=""):
    """
	@author： gjw
	@date: 20210305
	@函数：query_mtable
	@参数：link_name(链接名),table_name(表名),cond(可选条件)
	@描述：根据df里的查询条件，来查询数据进行返回
	@返回：符合条件的记录和结果条数
	@示例 a=@udf df by  CRUD.query_mtable with (@link_name,@table_name)
	@示例 a=@udf df by  CRUD.query_mtable with (@link_name,@table_name,sex=1 and yy='22')
	"""
    try:
        ps = p.strip().split(",")
        link_name, table_name = ps[0:2]
        link_name = link_name.strip()
        table_name = table_name.strip()

        # add by gjw on 20230307 ,可选的自定义条件
        if len(ps) >= 3:

            my_cond = ",".join(ps[2:])
        else:

            my_cond = ""
    except:
        raise Exception("参数错误！正确参数：link_name(链接名),table_name(表名)")
    # 处理查询条件
    # add by gjw on 20201016 ,增加多租户的查询条件

    user = fbi_global.get_user()
    user_info = ssdb0.hget('user', user)
    cur_user = json.loads(user_info)
    resouce_group = cur_user["datas"].split(";")
    rgs = ["'public'", "'%s'" % (user), "'%s'" % (cur_user["tool"])]
    if cur_user["tool"] != "" and cur_user["tool"] != "ALL":
        for g in resouce_group:
            if g != "":
                rgs.append("'%s'" % (g))
        if my_cond == "":
            my_cond = " owner in ({})".format(",".join(rgs))
        else:
            my_cond += " and  owner in ({})".format(",".join(rgs))
    sql = []
    sql1 = []
    sql2 = []
    # add by gjw on 2022-0722,增加一个or的标识
    or_flag = False
    for index, row in df.iterrows():
        name = row['name']
        value = row['value']
        # add rzc 去除空值 on 2024/7/16
        if pd.isna(name):
            continue
        if row["type"] == "string":
            if value != "":
                sql.append(" %s='%s' " % (name, value))
        elif row["type"] == "like":
            if value != "":
                sql.append(" {} like '%%{}%%' ".format(name, value))
        elif row["type"] == "not like":
            if value != "":
                sql.append(" {} not like '%%{}%%' ".format(name, value))
        elif row["type"] == "llike":
            if value != "":
                sql.append(" {} like '{}%%' ".format(name, value))
        elif row["type"] == "not llike":
            if value != "":
                sql.append(" {} not like '{}%%' ".format(name, value))
        elif row["type"] == "number":
            if value != "":
                sql.append("%s = %s" % (name, value))
        elif row["type"] == ">":
            if value:
                if isinstance(value, int):
                    sql.append("%s > %s" % (name, value))
                else:
                    sql.append("%s > '%s'" % (name, value))
        elif row["type"] == "<":
            if value:
                if isinstance(value, int):
                    sql.append("%s < %s" % (name, value))
                else:
                    sql.append("%s < '%s'" % (name, value))
        elif row["type"] == ">=":
            if value:
                if isinstance(value, int):
                    sql.append("%s >= %s" % (name, value))
                else:
                    sql.append("%s >= '%s'" % (name, value))
        elif row["type"] == "<=":
            if value:
                if isinstance(value, int):
                    sql.append("%s <= %s" % (name, value))
                else:
                    sql.append("%s <= '%s'" % (name, value))
        elif row["type"] == "!=":
            if value:
                if isinstance(value, int):
                    sql.append("%s != %s" % (name, value))
                else:
                    sql.append("%s != '%s'" % (name, value))
        elif row["type"] == "in":
            if value != "" and value != "[]":
                # sql.append("%s in (%s) " % (name, value.replace(",", "\,")))
                sql.append("%s in (%s) " % (name, value))
        elif row["type"] == "not in":
            if value != "" and value != "[]":
                # sql.append("%s not in (%s) " % (name, value.replace(",", "\,")))
                sql.append("%s not in (%s) " % (name, value))
        elif row["type"] == "json":
            if value != "":
                sql.append("( %s !=''  and JSON_CONTAINS(%s \,'[%s]') )" % (name, name, value))
                # sql.append("( %s !=''  and JSON_CONTAINS(%s \,'[%s]') )" % (name, name, value.replace(",", "\,")))
        elif row["type"] == "or":  # 2022-0721 或的组合
            or_flag = True
        elif row["type"] == "order":
            sql1.append("%s %s" % (name, value))
        else:
            sql2.append("%s %s" % (name, value))
    if sql1 == []:
        l1 = ["sign"]  # 没有order by条件
    else:
        l1 = [":".join(sql1)]
    l2 = [sql2[0]]
    sql.extend(l1)
    sql.extend(l2)
    p2 = "%s,%s,%s" % (link_name, table_name, ",".join(sql))

    # add by rzc on 2024/7/15 添加字段查询
    if "field_name" in df:
        query_name = df["field_name"].dropna()
        query_name = query_name[query_name != ""].to_list()

    else:
        query_name = []
    if or_flag:
        # df2, df3 = query_mtable_or2(my_cond, p2)
        df2, df3 = query_contion_or(my_cond, link_name, table_name, sql, query_name)
    else:
        # df2, df3 = query_mtable2(my_cond, p2)
        df2, df3 = query_contion_and(my_cond, link_name, table_name, sql, query_name)
    return df2, df3


def query_contion_or(my_cond, config_name, table_name, sql, query_name):
    """
        @函数：query_contion_or
        @参数： config_name(配置),table_name(表名)
        @描述：根据配置信息来or确定等来查询数据,可以处理in
        @返回： 符合条件的记录
        """
    conds = []
    mydefine_sql = sql[-1]  # limit10
    mydefine_sql1 = sql[-2]  # v
    i = 1
    for cond in sql[0:-2]:  #
        cond = cond.replace("``", ",")
        i += 1
        conds.append(cond)
    endsql = "order by "
    if mydefine_sql1 == "sign":
        endsql = ""
    else:
        for per in mydefine_sql1.split(":"):
            endsql = endsql + per + ","
        endsql = endsql[:-1]
    # 拼装出来的条件
    cond_sql = " or ".join(conds)
    if mydefine_sql.find("limit") >= 0 and mydefine_sql.find("|") >= 0:
        mydefine_sql = mydefine_sql.replace("|", ",")

    # 添加查询条件
    filed_query = ",".join(query_name)
    if not filed_query:
        filed_query = "*"
    else:
        filed_query = filed_query + ",id"
    # 四种场景
    if my_cond == "" and cond_sql != "":
        sql = "select %s from %s where  %s  %s %s " % (filed_query, table_name.strip(), cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), cond_sql)
    elif my_cond != "" and cond_sql != "":
        sql = "select %s from %s where ( %s ) and ( %s ) %s %s " % (filed_query,
                                                                    table_name.strip(), my_cond, cond_sql, endsql,
                                                                    mydefine_sql)
        sql_count = "select count(id) from %s where ( %s ) and ( %s )" % (table_name.strip(), my_cond, cond_sql)
    elif my_cond != "" and cond_sql == "":
        sql = "select %s from %s where  %s  %s %s " % (filed_query, table_name.strip(), my_cond, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), my_cond)
    else:
        sql = "select %s from %s %s %s " % (filed_query, table_name.strip(), endsql, mydefine_sql)
        sql_count = "select count(id) from %s " % (table_name.strip())
    # logger.error(sql)
    # logger.error(sql_count)
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql("", p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    p2 = "%s,%s" % (config_name.strip(), sql_count)
    df3 = load_mysql_sql("", p2)
    # add by gjw on 20231123 增加debug_sql的调试
    sql_df = pd.DataFrame([[sql], [sql_count]])
    debug_sql = FbiTable("debug_sql", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")
    return df2, df3


def query_contion_and(my_cond, config_name, table_name, sql, query_name):
    """
    @函数：query_mtable2
    @参数： config_name(配置),table_name(表名),col1=xxx,col2=xxx,
    @描述：根据配置信息来AND确定等来查询数据,可以处理in
    @返回： 符合条件的记录
    @示例：a=@udf df by CRUD.query_mtable2 with (@like_name,@table_name,col1=xxx,col2=xxx)
    """
    conds = []
    mydefine_sql = sql[-1]  # limit10
    mydefine_sql1 = sql[-2]  # v
    i = 1
    for cond in sql[0:-2]:  #
        cond = cond.replace("``", ",")
        i += 1
        conds.append(cond)
    endsql = "order by "
    if mydefine_sql1 == "sign":
        endsql = ""
    else:
        for per in mydefine_sql1.split(":"):
            endsql = endsql + per + ","
        endsql = endsql[:-1]
    # 拼装出来的条件
    cond_sql = " and ".join(conds)
    if mydefine_sql.find("limit") >= 0 and mydefine_sql.find("|") >= 0:
        mydefine_sql = mydefine_sql.replace("|", ",")

    # 添加查询条件
    filed_query = ",".join(query_name)
    if not filed_query:
        filed_query = "*"
    else:
        filed_query = filed_query + ",id"
    # 四种场景
    if my_cond == "" and cond_sql != "":
        sql = "select %s from %s where  %s  %s %s " % (filed_query, table_name.strip(), cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), cond_sql)
    elif my_cond != "" and cond_sql != "":
        sql = "select %s from %s where ( %s ) and ( %s ) %s %s " % (filed_query,
                                                                    table_name.strip(), my_cond, cond_sql, endsql,
                                                                    mydefine_sql)
        sql_count = "select count(id) from %s where ( %s ) and ( %s )" % (table_name.strip(), my_cond, cond_sql)
    elif my_cond != "" and cond_sql == "":
        sql = "select %s from %s where  %s  %s %s " % (filed_query, table_name.strip(), my_cond, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), my_cond)
    else:
        sql = "select %s from %s %s %s " % (filed_query, table_name.strip(), endsql, mydefine_sql)
        sql_count = "select count(id) from %s " % (table_name.strip())
    # logger.error(sql)
    # logger.error(sql_count)
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql("", p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    p2 = "%s,%s" % (config_name.strip(), sql_count)
    df3 = load_mysql_sql("", p2)
    # add by gjw on 20231123 增加debug_sql的调试
    sql_df = pd.DataFrame([[sql], [sql_count]])
    debug_sql = FbiTable("debug_sql", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")
    return df2, df3


def query_mtable2(my_cond, p=""):
    """
	@函数：query_mtable2
	@参数： config_name(配置),table_name(表名),col1=xxx,col2=xxx,
	@描述：根据配置信息来AND确定等来查询数据,可以处理in
	@返回： 符合条件的记录
	@示例：a=@udf df by CRUD.query_mtable2 with (@like_name,@table_name,col1=xxx,col2=xxx)
	"""

    # 处理逗号
    s = p.strip().replace("\,", "``")
    try:
        ps = s.split(",")
        config_name, table_name = ps[0:2]
    except:
        raise Exception(
            "参数错误: config_name(配置),table_name(表名),col1=xx1,coln=xxn,(查询条件),其他子句如order by or limit等(必须有)")

    conds = []
    mydefine_sql = ps[-1]
    mydefine_sql1 = ps[-2]
    i = 1
    for cond in ps[2:-2]:
        cond = cond.replace("``", ",")
        i += 1
        """
		cond = cond.strip()
		if cond.find("''") > 0 or cond.find('""') > 0 or cond.find("()") > 0 or cond.find("[]") > 0:  # 字符串查询为空的不要
			continue
		is_null = False
		for flag in ["=", ">", ">=", "<", "<=", "!=", "in", "not in"]:
			if cond.find(flag) == len(cond) - 1:  # 数字类查询不为空
				is_null = True
				break
		if not is_null:  # 正常的条件加入
			conds.append(cond)
		"""
        conds.append(cond)
    # end for
    # 页面条件
    endsql = "order by "
    if mydefine_sql1 == "sign":
        endsql = ""
    else:
        for per in mydefine_sql1.split(":"):
            endsql = endsql + per + ","
        endsql = endsql[:-1]
    # 拼装出来的条件
    cond_sql = " and ".join(conds)

    if mydefine_sql.find("limit") >= 0 and mydefine_sql.find("|") >= 0:
        mydefine_sql = mydefine_sql.replace("|", ",")

    # 四种场景
    if my_cond == "" and cond_sql != "":
        sql = "select * from %s where  %s  %s %s " % (table_name.strip(), cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), cond_sql)
    elif my_cond != "" and cond_sql != "":
        sql = "select * from %s where ( %s ) and ( %s ) %s %s " % (
            table_name.strip(), my_cond, cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where ( %s ) and ( %s )" % (table_name.strip(), my_cond, cond_sql)
    elif my_cond != "" and cond_sql == "":
        sql = "select * from %s where  %s  %s %s " % (table_name.strip(), my_cond, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), my_cond)
    else:
        sql = "select * from %s %s %s " % (table_name.strip(), endsql, mydefine_sql)
        sql_count = "select count(id) from %s " % (table_name.strip())

    # logger.error(sql)
    # logger.error(sql_count)
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql("", p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    p2 = "%s,%s" % (config_name.strip(), sql_count)
    df3 = load_mysql_sql("", p2)
    # add by gjw on 20231123 增加debug_sql的调试
    sql_df = pd.DataFrame([[sql], [sql_count]])
    debug_sql = FbiTable("debug_sql", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")
    return df2, df3


def query_mtable_or2(my_cond, p=""):
    """
	@函数：query_mtable_or2
	@参数： config_name(配置),table_name(表名),col1=xxx,col2=xxx,
	@描述：根据配置信息来OR确定等来查询数据,可以处理in
	@返回： 符合条件的记录
	@示例：a=@udf df by CRUD.query_mtable_or2 with (@like_name,@table_name,col1=xxx,col2=xxx)
	"""

    # 处理逗号
    s = p.strip().replace("\,", "``")
    try:
        ps = s.split(",")
        config_name, table_name = ps[0:2]
    except:
        raise Exception(
            "参数错误: config_name(配置),table_name(表名),col1=xx1,coln=xxn,(查询条件),其他子句如order by or limit等(必须有)")

    conds = []
    mydefine_sql = ps[-1]
    mydefine_sql1 = ps[-2]
    i = 1
    for cond in ps[2:-2]:
        cond = cond.replace("``", ",")
        i += 1
        cond = cond.strip()
        if cond.find("''") > 0 or cond.find('""') > 0 or cond.find("()") > 0 or cond.find(
                "[]") > 0:  # 字符串查询为空的不要
            continue
        is_null = False
        for flag in ["=", ">", ">=", "<", "<=", "!=", "in", "not in"]:
            if cond.find(flag) == len(cond) - 1:  # 数字类查询不为空
                is_null = True
                break
        if not is_null:  # 正常的条件加入
            conds.append(cond)
    # end for
    # 页面条件
    endsql = "order by "
    if mydefine_sql1 == "sign":
        endsql = ""
    else:
        for per in mydefine_sql1.split(":"):
            endsql = endsql + per + ","
        endsql = endsql[:-1]

    cond_sql = " or ".join(conds)

    if mydefine_sql.find("limit") >= 0 and mydefine_sql.find("|") >= 0:
        mydefine_sql = mydefine_sql.replace("|", ",")

    # 四种场景
    if my_cond == "" and cond_sql != "":
        sql = "select * from %s where ( %s ) %s %s " % (table_name.strip(), cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), cond_sql)
    elif my_cond != "" and cond_sql != "":
        sql = "select * from %s where ( %s ) and ( %s ) %s %s " % (
            table_name.strip(), my_cond, cond_sql, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where ( %s ) and ( %s )" % (table_name.strip(), my_cond, cond_sql)
    elif my_cond != "" and cond_sql == "":
        sql = "select * from %s where ( %s ) %s %s " % (table_name.strip(), my_cond, endsql, mydefine_sql)
        sql_count = "select count(id) from %s where %s" % (table_name.strip(), my_cond)
    else:
        sql = "select * from %s %s %s " % (table_name.strip(), endsql, mydefine_sql)
        sql_count = "select count(id) from %s " % (table_name.strip())

    # logger.error(sql)
    # logger.error(sql_count)
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql("", p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    p2 = "%s,%s" % (config_name.strip(), sql_count)
    df3 = load_mysql_sql("", p2)
    sql_df = pd.DataFrame([[sql], [sql_count]])
    debug_sql = FbiTable("debug_sql", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")
    return df2, df3


# 分组统计的入口函数,支持mysql和sqlite
def group_mtable(df, p=""):
    """
	@author： gjw
	@date: 20200928
	@函数：group_mtable
	@参数：link_name(链接名),table_name(表名)
	@描述：根据df里的查询条件和分组条件进行统计
	@返回：统计的结果
	@示例 a=@udf df by CRUD.group_mtable with (@link_name,@table_name)
	a=@udf df by CRUD.group_mtable with (@link_name,@table_name,sex=1 and yy='22')

	"""
    try:
        ps = p.strip().split(",")
        link_name, table_name = ps[0:2]
        link_name = link_name.strip()
        table_name = table_name.strip()
        if len(ps) >= 3:
            my_cond = ",".join(ps[2:])
        else:
            my_cond = ""
    except:
        raise Exception("参数错误！正确参数：link_name(链接名),table_name(表名)")
    # 处理查询条件
    sql = []
    sql1 = []
    sql2 = []
    group = {}
    rel = " and "
    # add by gjw on 20201016 ,增加多租户的查询条件
    user = fbi_global.get_user()
    user_info = ssdb0.hget('user', user)
    cur_user = json.loads(user_info)
    resouce_group = cur_user["datas"].split(";")
    rgs = ["'public'", "'%s'" % (user), "'%s'" % (cur_user["tool"])]
    if cur_user["tool"] != "" and cur_user["tool"] != "ALL":
        for g in resouce_group:
            if g != "":
                rgs.append("'%s'" % (g))
        if my_cond == "":
            my_cond = " owner in ({})".format(",".join(rgs))
        else:
            my_cond += " and  owner in ({})".format(",".join(rgs))
    for index, row in df.iterrows():
        name = row['name']
        value = row['value']
        if row["type"] == "string":
            if value != "":
                sql.append(" %s='%s' " % (name, value))
        elif row["type"] == "like":
            if value != "":
                sql.append(" {} like '%%{}%%' ".format(name, value))
        elif row["type"] == "not like":
            if value != "":
                sql.append(" {} not like '%%{}%%' ".format(name, value))
        elif row["type"] == "llike":
            if value != "":
                sql.append(" {} like '{}%%' ".format(name, value))
        elif row["type"] == "not llike":
            if value != "":
                sql.append(" {} not like '{}%%' ".format(name, value))
        elif row["type"] == "number":
            if value != "":
                sql.append("%s = %s" % (name, value))
        elif row["type"] == ">":
            if value:
                if isinstance(value, int):
                    sql.append("%s > %s" % (name, value))
                else:
                    sql.append("%s > '%s'" % (name, value))
        elif row["type"] == "<":
            if value:
                if isinstance(value, int):
                    sql.append("%s < %s" % (name, value))
                else:
                    sql.append("%s < '%s'" % (name, value))
        elif row["type"] == ">=":
            if value:
                if isinstance(value, int):
                    sql.append("%s >= %s" % (name, value))
                else:
                    sql.append("%s >= '%s'" % (name, value))
        elif row["type"] == "<=":
            if value:
                if isinstance(value, int):
                    sql.append("%s <= %s" % (name, value))
                else:
                    sql.append("%s <= '%s'" % (name, value))
        elif row["type"] == "!=":
            if value != "":
                sql.append("%s != %s" % (name, value))
        elif row["type"] == "in":
            if value != "" and value != "[]":
                sql.append("%s in (%s) " % (name, value.replace(",", "\,")))
        elif row["type"] == "not in":
            if value != "" and value != "[]":
                sql.append("%s not in (%s) " % (name, value.replace(",", "\,")))
        elif row["type"] == "json":
            if value != "":
                sql.append("( %s !=''  and JSON_CONTAINS(%s \,'[%s]') )" % (name, name, value.replace(",", "\,")))
        elif row["type"] == "group":
            group["fields"] = name
            group["funs"] = value
        elif row["type"] == "or":
            rel = " or "
        else:
            pass
    df2 = _group_table(link_name, table_name, ",".join(sql), group, rel, my_cond)
    # 参数和条件DF作为hash
    key = "cache:CRUD:{}".format(hash_sha1(p.strip() + df.to_json(orient="split", date_format='iso', date_unit='s')))
    c = fbi_global.get_ssdb0()
    c.set(key, df2.fillna("").to_json(orient="split", date_format='iso', date_unit='s'))
    c.expire(key, 300)
    return df2


def _group_table(config_name, table_name, sql, group, rel, my_cond):
    """
	@函数：group_mtable2,内部函数不对外
	@参数： link_name(配置),table_name(表名),sql条件,group信息
	@描述：根据配置信息来确定等来查询数据,可以处理in
	@返回： 符合条件的记录  
	"""

    # 处理逗号
    s = sql.strip().replace("\,", "``")
    try:
        ps = s.split(",")
    except:
        raise Exception("参数错误: col1=xx1,coln=xxn,(查询条件),其他子句如order by or limit等(必须有)")

    conds = []
    mydefine_sql1 = ps[-1]  # order 语句
    i = 1
    for cond in ps:
        cond = cond.replace("``", ",")
        i += 1
        cond = cond.strip()
        """
		if cond.find("''") > 0 or cond.find('""') > 0  or cond.find("()") > 0 or cond.find(
				"[]") > 0:  # 字符串查询为空的不要
			continue
		is_null = False
		for flag in ["=", ">", ">=", "<", "<=", "!=", "in", "not in"]:
			if cond.find(flag) == len(cond) - 1:  # 数字类查询不为空
				is_null = True
				break
		if not is_null:  # 正常的条件加入
			conds.append(cond)
		"""
        conds.append(cond)
    # end for

    cond_sql = rel.join(conds)

    select_field = "{},{}".format(group["fields"], group["funs"])

    # 四种场景
    if my_cond == "" and cond_sql != "":
        sql = "select %s from %s where %s  group by %s" % (select_field, table_name.strip(), cond_sql, group["fields"])
    elif my_cond != "" and cond_sql != "":
        sql = "select %s from %s where ( %s ) and ( %s )  group by %s" % (
            select_field, table_name.strip(), my_cond, cond_sql, group["fields"])
    elif my_cond != "" and cond_sql == "":
        sql = "select %s from %s where %s  group by %s" % (select_field, table_name.strip(), my_cond, group["fields"])
    else:
        sql = "select %s from %s  group by %s" % (select_field, table_name.strip(), group["fields"])

    # add by gjw on 20231123 增加debug_sql的调试
    sql_df = pd.DataFrame([[sql]])
    debug_sql = FbiTable("debug_sql_group", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")

    p1 = "%s,%s" % (config_name.strip(), sql)
    if get_db_type(config_name.strip()) == "mysql":
        df2 = load_mysql_sql("", p1)
    else:
        df2 = load_s3_sql("", p1)
    return df2


# 增加mysql的默认配置项目
def make_cfg(config):
    if "charset" not in config:
        config["charset"] = "utf8"
    if "use_unicode" not in config:
        config["use_unicode"] = True
    if "get_warnings" not in config:
        config["get_warnings"] = True
    return config


def get_db_type(p):
    """
	@函数：get_db_type
	@参数：str
	@描述：获取db类型
	@返回：
	"""
    try:
        config_name = p.split(",")[0].strip()
    except:
        raise Exception("数据库链接出错!")
    if config_name == "":
        raise Exception("数据库链接为指定!")
    # add by gjw on 2020-1228
    if config_name.endswith(".db"):
        return "sqlite"
    else:
        return "mysql"


def create_table(df, p=""):
    """
	@author： wly
	@date: 20181129
	@函数：create_table
	@参数：链接名,表名,中文表名，可选唯一索引字段
	@描述： 参考阿里的标准，建一个单表
	@返回：
	@示例：a=@udf df by  CRUD.create_table with (@link_name,@table_name,@中文表名)
	"""
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        p = p.replace('"', '')  # 去除表名中的"号
        if len(p.split(",")) > 3:  # 中文表明后面增加了唯一索引字段
            df2 = create_mtableB(df, p)
        else:
            df2 = create_mtable(df, p)
    elif dbtype == "sqlite":
        df2 = create_stable(df, p)
    else:
        df2 = 0
    return df2


def drop_table(df, p=None):
    """
    @函数：drop_table
    @参数：链接名,表名,中文表名
    @描述： 参考阿里的标准，建一个单表
    @返回：
    @示例：a=@udf df by  CRUD.drop_table with (@link_name,@table_name,@中文表名)
    """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2 = drop_mtable(df, p)
    elif dbtype == "sqlite":
        df2 = drop_stable(df, p)
    else:
        df2 = 0
    return df2


def query_table(df, p=""):
    """
	@函数：query_table
	@参数：config_name,表名,中文表名
	@描述：参考阿里的标准，查询表
	@返回：
	@示例：a=@udf df by  CRUD.query_table with (@link_name,@table_name)
	"""
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2, df3 = query_mtable(df, p)
    elif dbtype == "sqlite":
        df2, df3 = query_stable(df, p)
    else:
        df2, df3 = 0, 0

    c = fbi_global.get_ssdb0()
    key = "cache:CRUD:{}".format(hash_sha1(p.strip() + df.to_json(orient="split", date_format='iso', date_unit='s')))
    v = df2.to_json(orient="split", date_format='iso', date_unit='s')
    v = v.replace('"null"', '').replace("null", "0")
    c.set(key, v)
    c.expire(key, 300)
    key2 = "cache:CRUD:count:{}".format(
        hash_sha1(p.strip() + df.to_json(orient="split", date_format='iso', date_unit='s')))
    v = df3.to_json(orient="split", date_format='iso', date_unit='s')
    v = v.replace('"null"', '').replace("null", "0")
    c.set(key2, v)
    c.expire(key2, 300)
    return df2, df3


def save_table(df, p=""):
    """
    @函数：save_table
    @参数： 链接名,表名
    @描述：参考阿里的标准，建一个单表
    @返回：
    @示例：a=@udf df by  CRUD.save_table with (@link_name,@table_name)
    """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        dfs = save_object_mtable(df, p)
    elif dbtype == "sqlite":
        dfs = save_object_stable(df, p)
    else:
        dfs = 0
    return dfs


def delete_table(df, p=""):
    """
    @函数：delete_table
    @参数：链接名,表名,pk_id
    @描述：参考阿里的标准，建一个单表
    @返回：
    @示例：a=@udf df by  CRUD.delete_table with (@link_name,@table_name,@pk_id)
    """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2 = delete_object_mtable(df, p)
    elif dbtype == "sqlite":
        df2 = delete_object_stable(df, p)
    else:
        df2 = 0
    return df2


def is_exist_table(df, p=""):
    """
	@函数：is_exist_table
	@参数：config_name,表名
	@描述：判断表是否存在
	@返回：
	@示例：a=@udf df by  CRUD.is_exist_table with (@link_name,@table_name)
   """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2 = is_exist_mtable(df, p)
    elif dbtype == "sqlite":
        df2 = is_exist_stable(df, p)
    else:
        df2 = 0
    return df2


def get_object_table(df, p=""):
    """
    @函数：get_object_table
    @参数：链接名,表名,pk_id
    @描述：
    参考阿里的标准，建一个单表
    @返回：
    @示例：a=@udf df by  CRUD.get_object_table with (@link_name,@table_name,@pk_id)
    """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        dd = get_object_mtable_id(df, p)
    elif dbtype == "sqlite":
        dd = get_object_stable_id(df, p)
    else:
        dd = 0
    return dd


def load_sql(df, p=""):
    """
      @date: 20200712
      @函数：load_sql
      @参数：config_name,表名
      @描述：判断表是否存在
      @返回：
      @示例：a=@udf df by  CRUD.load_sql with (@link_name,@table_name)
      """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2 = load_mysql_sql(df, p)
    else:
        df2 = 0
    return df2


def get_object_stable(df, p=""):
    """
	@author： gjw
	@date: 20171004
	@函数：get_object_mtable
	@参数：
	config_name(配置),table_name(表名),id(主键)
	@描述：
	根据表名和id来加载对象
	@返回：
	无返回值
	"""
    try:
        config_name, table_name, pk_id = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),id(主键)")
    sql = "select * from %s where id=%s" % (table_name.strip(), pk_id.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_s3_sql(df, p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    return df2


def create_mtable(df, p=""):
    """
	@author： gjw
	@date: 20170930
	@函数：create_mtable
	@参数：链接名,表名,中文名
	@描述：参考阿里的标准，建一个单表
	@返回：
	@示例：a=@udf df by  CRUD.create_mtable with (@link_name,@table_name,@中文表名)
	"""
    ps = p.split(",")
    table_name = ps[1]
    zh_name = ps[2]
    db = mpool_get_connection(ps[0])
    cursor = db.cursor()

    col_def = []
    row_dict = df.iloc[0].to_dict()
    for k, v in row_dict.items():
        col_def.append("%s %s ," % (k, v))

    sql = """
	CREATE TABLE IF NOT EXISTS %s (
	id bigint NOT NULL comment 'ID',
	gmt_create DATETIME DEFAULT CURRENT_TIMESTAMP comment '创建时间',
	gmt_modified DATETIME DEFAULT CURRENT_TIMESTAMP comment '修改时间',
	creator varchar(128) DEFAULT 'public' comment '创建者',
	owner varchar(128) DEFAULT 'public' comment '拥有者',
	%s
	PRIMARY KEY (id)
	) DEFAULT CHARSET=utf8mb4 comment '%s';
	""" % (table_name.strip(), "\n".join(col_def), zh_name.strip())

    logger.error(sql)
    ret = cursor.execute(sql.strip())
    # add by gjw on 2022-0824 增加id索引
    ret = cursor.execute("alter table %s add index index_id (id)" % (table_name.strip()))
    # add by gjw on 2021-0908 增加索引
    ret = cursor.execute("ALTER TABLE %s ADD INDEX index_gmt_modified(gmt_modified);" % (table_name.strip()))
    try:
        seq_sql = "INSERT INTO seq VALUES('%s',1);" % (table_name.strip())
        # logger.info(seq_sql)
        cursor.execute(seq_sql)
    except:
        pass
    db.commit()
    cursor.close()
    mpool_put_connection(ps[0], db)
    # db.close()
    df2 = pd.DataFrame([[sql]], columns=["sql"])
    return df2


def create_mtableB(df, p=""):
    """
	@author： gjw
	@date: 20170930
	@函数：create_mtable
	@参数：链接名,表名,中文名
	@描述：创建一张自增ID的表，有唯一索引字段，可以自己更新
	@返回：
	@示例：a=@udf df by  CRUD.create_mtableB with (@link_name,@table_name,@中文表名,唯一索引字段1,唯一索引字段2,...)
	"""
    ps = p.split(",")
    table_name = ps[1].strip()
    zh_name = ps[2].strip()
    db = mpool_get_connection(ps[0].strip())
    cursor = db.cursor()

    col_def = []
    row_dict = df.iloc[0].to_dict()
    for k, v in row_dict.items():
        col_def.append("%s %s ," % (k, v))

    sql = """
	CREATE TABLE IF NOT EXISTS %s (
	id bigint NOT NULL  AUTO_INCREMENT comment 'ID',
	gmt_create DATETIME DEFAULT CURRENT_TIMESTAMP comment '创建时间',
	gmt_modified DATETIME DEFAULT CURRENT_TIMESTAMP comment '修改时间',
	creator varchar(128) DEFAULT 'public'  comment '创建者',
	owner varchar(128) DEFAULT 'public' comment '拥有者',
	%s
	PRIMARY KEY (id)
	) DEFAULT CHARSET=utf8mb4 comment '%s';
	""" % (table_name, "\n".join(col_def), zh_name)

    logger.error(sql)
    ret = cursor.execute(sql.strip())
    # add by gjw on 2022-0824 增加id索引
    ret = cursor.execute("alter table %s add index index_id (id)" % (table_name))
    # add by gjw on 2024-0505 创建唯一索引
    unique = ",".join(ps[3:])
    ret = cursor.execute(f"CREATE UNIQUE INDEX  {table_name}_unique_index ON {table_name}({unique})")

    db.commit()
    cursor.close()
    mpool_put_connection(ps[0], db)
    df2 = pd.DataFrame([[sql]], columns=["sql"])
    return df2


def drop_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171114
    @函数：drop_mtable
    @参数： 链接名,表名
    @描述： 参考阿里的标准，删除一个单表
    @返回：无返回值
    @示例：a=@udf df by  CRUD.drop_mtable with (@link_name,@table_name)
    """
    try:
        ps = p.split(",")
        sql = "DROP TABLE IF  EXISTS " + ps[1].strip()
    except:
        raise Exception("参数解析出错!")

    db = mpool_get_connection(ps[0])
    cursor = db.cursor()

    ##logger.info(sql)
    ret = cursor.execute(sql.strip())
    seq_sql = "delete from seq where name ='%s';" % (ps[1].strip())
    ##logger.info(sql)
    cursor.execute(seq_sql)
    db.commit()
    cursor.close()
    # db.close()
    mpool_put_connection(ps[0], db)
    df2 = pd.DataFrame([[sql]], columns=["sql"])
    return df2


def exec_mysql_sql(df, p=""):
    """
    @author： gjw
    @date: 20170719
    @函数：exec_mysql_sql
    @参数： 链接名,sql语句
    @描述： 执行sql语句
    @返回：无返回值
    @示例：a=@udf df by  CRUD.exec_mysql_sql with (@link_name,@sql语句)
    """
    try:
        ps = p.split(",")
        sql = ",".join(ps[1:])
    except:
        raise Exception("参数解析出错!")
    db = mpool_get_connection(ps[0])
    cursor = db.cursor()
    cursor.execute(sql.strip())
    try:
        data = cursor.fetchall()
        col_name = cursor.column_names
        col_name = [tuple[0] for tuple in cursor.description]
        df1 = pd.DataFrame(data, columns=col_name)
    except Exception:
        df1 = pd.DataFrame()
    db.commit()
    cursor.close()
    # db.close()
    mpool_put_connection(ps[0], db)
    return df1


def delete_mobject_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171710
    @函数：delete_mobject_mtable
    @参数：config_name(配置),table_name(表名)
    @描述：根据配置和表名来删除多个对象
    @返回： 无返回值
    @示例：a=@udf df by  CRUD.delete_mobject_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    for pk_id in df.index:
        sql = "delete from %s where id=%s" % (table_name.strip(), pk_id)
        p1 = "%s,%s" % (config_name.strip(), sql)
        df2 = exec_mysql_sql(df, p1)
    return df


def get_seq_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171025
    @函数：get_seq_mtable
    @参数：config_name(配置),table_name(表名)
    @描述：获取序列号
    @返回：无返回值
    @示例：a=@udf df by CRUD.get_seq_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    sql = "select seq('%s',%d) as %s " % (table_name.strip(), 1, table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql(df, p1)
    return df2


def get_seqs_mtable(df, p=""):
    """
    @author： wly
    @date: 20200123
    @函数：get_seqs_mtable
    @参数： link_name(配置),table_name(表名),count(个数)
    @描述：获取序列号
    @返回：无返回值
    @示例：a=@udf df by  CRUD.get_seq_mtable with (@link_name,@table_name,@count)
    """
    try:
        config_name, table_name, count = p.split(",")
        count = int(count)
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),count(个数)")
    sql = "select seq('%s',%d) as  %s " % (table_name.strip(), count, table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql(df, p1)
    max_value = df2.loc[0, table_name]
    values = []
    for i in range(count):
        values.append(max_value + i + 1)
    dfz = pd.DataFrame(values, columns=[table_name])
    dfz['seq19821221'] = list(range(0, count))
    dfz.set_index('seq19821221', inplace=True)
    return dfz


def delete_object_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171004
    @函数：delete_object_mtable
    @参数：link_name(链接名),table_name(表名),id(主键)
    @描述：根据表名和id来删除对象
    @返回：无返回值
    @示例：a=@udf df by  CRUD.delete_object_mtable with (@link_name,@table_name,@id)
    """
    try:
        config_name, table_name, pk_id = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),id(主键)")
    sql = "delete from %s where id=%s" % (table_name.strip(), pk_id.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = exec_mysql_sql(df, p1)
    return df2


def batch_delete_users(df, p=""):
    """
    @author： wly
    @date: 20200219
    @函数：batch_delete_users
    @参数：link_name(配置),table_name(表名)
    @描述：根据表名和name列来删除对象，
    @返回： 无返回值
    @示例：a=@udf df by CRUD.batch_delete_users with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    names = df["name"]
    # namestr = "','".join(names)
    # sql = "delete from %s where name in ('%s')" % (table_name.strip(), namestr.strip())
    # #logger.info(sql)
    for name in names:
        sql = "delete from %s where name = ('%s')" % (table_name.strip(), name.strip())
        p1 = "%s,%s" % (config_name.strip(), sql)
        df2 = exec_mysql_sql(df, p1)
    return df


def get_curseq_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171025
    @函数：get_curseq_mtable
    @参数：config_name(配置),table_name(表名)
    @描述：根据配置和表名，来获取该表的当前id
    @返回：无返回值
    @示例：a=@udf df by CRUD.get_curseq_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    sql = "select val from seq WHERE name='%s'" % (table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql(df, p1)
    return df2


def get_lastid_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171025
    @函数：get_lastid_mtable
    @参数： config_name(配置),table_name(表名)
    @描述：根据配置和表名，来获取该表的最后的id值
    @返回： 无返回值
    @示例：a=@udf df by CRUD.get_lastid_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    sql = "select val-1 from seq WHERE name='%s'" % (table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql(df, p1)
    return df2


def init_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171025
    @函数：init_mtable
    @参数：config_name
    @描述：参考阿里的标准，在每个库中初始化一个seq序列号生成器
    @返回：
    @示例：a=@udf  CRUD.init_mtable with (@like_name)
    """
    config_name = p
    """
    config_str = get_key(config_name.strip())
    config = json.loads(config_str)
    config = make_cfg(config)
    """
    db = mpool_get_connection(config_name)
    # db = mysql.connector.Connect(**config)
    cursor = db.cursor()

    seq_table = """
	CREATE TABLE IF NOT EXISTS seq (
	  name varchar(40) NOT NULL,
	  val int UNSIGNED NOT NULL,
	  PRIMARY KEY  (name)
	) DEFAULT CHARSET=utf8;
	"""
    seq_drop = """
	DROP FUNCTION IF EXISTS seq;
	"""

    seq_fun = """
	CREATE FUNCTION seq(seq_name char (40),batch_count int) returns int
	begin
	 declare value integer;
	 set value =0;
	 select val into value from seq WHERE name=seq_name  for update;
	 UPDATE seq SET val=val+batch_count WHERE name=seq_name;
	 RETURN value;
	end
	"""
    cursor.execute(seq_table)
    cursor.execute(seq_drop)
    cursor.execute(seq_fun)
    db.commit()
    cursor.close()
    # db.close()
    mpool_put_connection(config_name, db)
    return df


def init_stable(df, p=""):
    """
	@author： gjw
	@date: 20171025
	@函数：init_mtable
	@参数：
	config_name
	@描述：
	参考阿里的标准，在每个库中初始化一个seq序列号生成器
	@返回：
	"""
    dbfile = p
    conn = db_conn_w(dbfile)
    name = df.index.name
    sql = """
	CREATE TABLE IF NOT EXISTS seq (
	  name varchar(40) NOT NULL,
	  val int UNSIGNED NOT NULL,
	  PRIMARY KEY  (name)
	)
	"""
    c = conn.cursor()
    c.execute(sql)
    conn.commit()
    conn.close()
    return df


def load_mysql_sql(df, p=""):
    """
    @author： gjw
    @date: 20170719
    @函数：load_mysql_sql
    @参数：config_name,sql
    @描述：从mysql中加载sql语句要的数据
    @返回： df表
    @示例：a=@udf df by CRUD.load_mysql_sql with (@like_name,@sql)
    """
    try:
        ps = p.split(",")
        sql = ",".join(ps[1:])
    except:
        raise Exception("参数解析错误!")
    db = mpool_get_connection(ps[0])
    cursor = db.cursor()
    # logger.error(sql.strip())
    cursor.execute(sql.strip())
    col_name_list = [tuple[0] for tuple in cursor.description]
    result = cursor.fetchall()
    dfz = pd.DataFrame(columns=col_name_list, data=result)
    cursor.close()
    db.commit()
    # db.close()
    mpool_put_connection(ps[0], db)
    return dfz


def load_mysql_sql_cache(df, p=""):
    """
    @author： gjw
    @date: 20170719
    @函数：load_mysql_sql
    @参数：config_name,sql
    @描述：从mysql中加载sql语句要的数据
    @返回： df表
    @示例：a=@udf df by CRUD.load_mysql_sql with (@like_name,@sql)
    """
    try:
        ps = p.split(",")
        sql = ",".join(ps[1:])
    except:
        raise Exception("参数解析错误!")
    db = mpool_get_connection(ps[0])
    cursor = db.cursor()
    # logger.error(sql.strip())
    cursor.execute(sql.strip())
    col_name_list = [tuple[0] for tuple in cursor.description]
    result = cursor.fetchall()
    dfz = pd.DataFrame(columns=col_name_list, data=result)
    key = "cache:CRUD:{}".format(hash_sha1(p.strip()))
    c = fbi_global.get_ssdb0()
    c.set(key, dfz.fillna("").to_json(orient="split", date_format='iso', date_unit='s'))
    c.expire(key, 300)
    cursor.close()
    db.commit()
    mpool_put_connection(ps[0], db)
    return dfz


def get_mobject_mtable(df, p=""):
    """
    @author： gjw
    @date: 20171103
    @函数：get_mobject_mtable
    @参数： like_name(配置),table_name(表名)
    @描述： 根据表名和id来加载对象
    @返回： 无返回值
    @示例：a=@udf df by CRUD.get_mobject_mtable with (@like_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    dfs = []
    for pk_id in df.index:
        sql = "select * from %s where id=%s" % (table_name.strip(), pk_id)
        p1 = "%s,%s" % (config_name.strip(), sql)
        df2 = load_mysql_sql(df, p1)
        df2 = df2.set_index("id")
        df2.index.name = "id"
        dfs.append(df2)
    return pd.concat(dfs)


def get_object_mtable_id(df, p=""):
    """
    @函数：get_object_mtable_id
    @参数：config_name(配置),table_name(表名),pk_id
    @描述：根据表名和id来加载对象
    @返回：无返回值
    @示例：a=@udf df by CRUD.get_object_mtable_id with (@like_name,@table_name,@pk_id)
    """
    try:
        config_name, table_name, pk_id = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),pk_id")
    sql = "select * from %s where id=%s" % (table_name.strip(), pk_id)
    p1 = "%s,%s" % (config_name.strip(), sql)
    df2 = load_mysql_sql(df, p1)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    return df2


def save_object_mtable(df, p=""):
    """
	@author： gjw
	@date: 2023-1201
	@函数：save_object_mtable
	@参数：config_name(配置),table_name(表名),json_fileld(可选json字段)
	@描述： 存储DF表到mysql中，index为0则新增，否则修改,字段名对应 根据阿里对表的定义来做，
	@返回： 无返回值
	@示例：a=@udf df by CRUD.save_object_mtable with (@like_name,@table_name)
	"""
    try:
        ps = p.split(",")
        config_name = ps[0].strip()
        table_name = ps[1].strip()
    except:
        raise Exception("参数错误!")
    if df.index.size == 0:
        # raise Exception("空表不用保存!")
        return df
    # db = mysql.connector.Connect(**config)

    user = fbi_global.get_user()
    try:
        user_info = ssdb0.hget('user', user)
        cur_user = json.loads(user_info)
    except:
        cur_user = {"tool": "ALL"}
    # add by gjw on 20201112 增加默认属性的获取
    data_owner = ssdb0.get('sys_data:%s:%s' % (config_name, table_name))
    owner = "public"
    if data_owner == "private":
        owner = user
    elif data_owner == "group":
        if cur_user["tool"] == "ALL" or cur_user["tool"] == "":
            owner = "public"
        else:
            owner = cur_user["tool"]
    else:
        owner = "public"

    db = mpool_get_connection(config_name)

    # add by gjw on 2024-0425 自动提交减少锁的行为
    db.autocommit(True)
    cursor = db.cursor()

    # 新增的数据
    df.index = df.index.astype(int)
    df2 = df.query("index==0")
    if df2.index.size > 0:  # 新增
        # 获取ID
        cursor.execute("select seq('%s',%s) as seq" % (table_name, df2.index.size))
        result = cursor.fetchone()
        beginid = result['seq']

        # 判断序列号,为0则重新初始化一下
        if beginid == 0:
            beginid = 1  # add by gjw on 20221014,为0是不行的
            try:
                seq_sql = "INSERT INTO seq VALUES('%s',%d);" % (table_name.strip(), beginid + df2.index.size)
                cursor.execute(seq_sql)
            except:
                pass
        df2 = df2.copy()
        cursor.close()

        now = datetime.now()
        df2["gmt_create"] = now.strftime("%Y-%m-%d %H:%M:%S")
        df2["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")

        df2["creator"] = user
        df2["owner"] = owner
        # add by gjw on 2022-0208 id必须在最后
        df2["id"] = list(range(beginid, beginid + df2.index.size))
        df2 = df2.set_index('id')
        df2["id"] = list(range(beginid, beginid + df2.index.size))
        # 准备新增
        xp = ["%s" for i in df2.columns]

        sql = "INSERT INTO %s (%s) VALUES (%s)" % (table_name, ",".join(df2.columns), ",".join(xp))
        # logger.info("SQL: " + sql)
        errors = []
        for i in range(int(df2.index.size / 5000) + 1):
            df0 = df2[i * 5000:i * 5000 + 5000]
            # logger.info("insert count: %d" % (df0.index.size))
            try:
                cursor = db.cursor()
                cursor.executemany(sql, df0.to_records(index=False).tolist())
            except Exception as me:
                raise me
            finally:
                cursor.close()
        # end

        if len(errors) > 0:
            cols = ["error_message"]
            cols.extend(df2.columns)
            df2 = pd.DataFrame(errors, columns=cols)
            add_the_error("CRUD Insert have the {} errors, error0: {}".format(len(errors), errors[0]))

    # 修改的数据
    dfu = df.query("index > 0")
    if dfu.index.size > 0:
        dfu = dfu.copy()
        now = datetime.now()
        dfu["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")
        # 删除gmt_create列和id列
        if "gmt_create" in dfu.columns:
            dfu = dfu.drop(["gmt_create"], axis=1)
        if "id" in dfu.columns:
            dfu = dfu.drop(["id"], axis=1)
        if len(ps) == 2:  # 没有json字段，正常更新
            xp = [i + " = %s" for i in dfu.columns]
            # id必须在最后
            dfu["id"] = dfu.index
            sql = "UPDATE %s SET %s  WHERE id=" % (table_name, ",".join(xp))
            sql = sql + "%s"

            errors = []
            for i in range(int(dfu.index.size / 1000) + 1):
                j = i * 1000
                df0 = dfu.iloc[j:j + 1000]
                try:
                    cursor = db.cursor()
                    cursor.executemany(sql, df0.to_records(index=False).tolist())
                except Exception as me:
                    raise me
                finally:
                    cursor.close()
            # end
            if len(errors) > 0:
                cols = ["error_message"]
                cols.extend(dfu.columns)
                dfu = pd.DataFrame(errors, columns=cols)
                add_the_error("CRUD Update have the {} errors, error0: {}".format(len(errors), errors[0]))

        else:  # add by gjw on 20201109 >2,有json字段要做更新append处理的情况
            json_fields = ps[2].strip()
            if len(ps) > 3:
                limit_name = ps[3].strip()
            else:
                limit_name = 20
            # modify by gjw on 2024-0412 更新超过的json数据
            index_tuple = tuple([int(index) for index in dfu.index.tolist()])
            if len(index_tuple) > 1:
                limit_sql = "update {table} set {col}= json_remove({col},'$[0]')  where json_length({col}) >= {limit} and ID in {ids}".format(
                    table=table_name, col=json_fields, limit=limit_name, ids=index_tuple)
            else:
                limit_sql = "update {table} set {col}= json_remove({col},'$[0]')  where json_length({col}) >= {limit} and ID={id}".format(
                    table=table_name, col=json_fields, limit=limit_name, id=index_tuple[0])

            cursor = db.cursor()
            cursor.execute(limit_sql)
            cursor.close()
            xp = []
            for col in dfu.columns:
                if col == json_fields:  # json字段
                    # mariadb　写法
                    # xp.append(col + " = json_array_append(" +col+ " ,'$', JSON_DETAILED( %s )) ")
                    xp.append(col + " = json_array_append(" + col + " ,'$', CAST( %s AS JSON )) ")
                # xp.append(col + " = json_array_append(" +col+ " ,'$', %s ) ")
                else:
                    xp.append(col + " = %s")

            # id必须在最后
            dfu["id"] = dfu.index
            sql = "UPDATE %s SET %s  WHERE id=" % (table_name, ",".join(xp))
            sql = sql + "%s"
            errors = []
            for i in range(int(dfu.index.size / 1000) + 1):
                j = i * 1000
                df0 = dfu.iloc[j:j + 1000]
                try:
                    cursor = db.cursor()
                    cursor.executemany(sql, df0.to_records(index=False).tolist())
                except Exception as me:
                    raise me
                finally:
                    cursor.close()
            # end

            if len(errors) > 0:
                cols = ["error_message"]
                cols.extend(dfu.columns)
                dfu = pd.DataFrame(errors, columns=cols)
                add_the_error("CRUD Update_Json have the {} errors, error0: {}".format(len(errors), errors[0]))
    # end
    # end if
    # 返回结果
    if df2.index.size > 0 and dfu.index.size > 0:
        dfs = pd.concat([df2, dfu])
    elif df2.index.size > 0:
        dfs = df2
    elif dfu.index.size > 0:
        dfs = dfu
    else:
        dfs = pd.DataFrame([[-1]], columns=["id"])

    mpool_put_connection(ps[0], db)
    dfs = dfs.set_index('id')
    dfs.index.name = 'id'
    dfs.index = dfs.index.astype(int)
    return dfs


def mtable_upsert(df, p=""):
    """
	@author： gjw
	@date: 2024-0505
	@函数：mtable_upsert
	@参数：config_name(配置),table_name(表名),json_fileld(可选json字段)
	@描述： 存储DF表到mysql中，index为0则新增，否则修改,字段名对应 根据阿里对表的定义来做，
	@返回： 无返回值
	@示例：a=@udf df by CRUD.mtable_upsert with (@like_name,@table_name)
	"""
    try:
        ps = p.split(",")
        config_name = ps[0].strip()
        table_name = ps[1].strip()
    except:
        raise Exception("参数错误!")
    if df.index.size == 0:
        return df

    db = mpool_get_connection(config_name)

    # add by gjw on 2024-0425 自动提交减少锁的行为
    db.autocommit(True)
    cursor = db.cursor()

    df2 = df

    now = datetime.now()

    df2["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")

    xp = ["%s" for i in df2.columns]

    upx = []
    for i in df2.columns:
        if len(ps) == 3 and ps[2].strip() == i:
            # json_array_append(" +col+ " ,'$', CAST( %s AS JSON )) "
            upx.append(f"{i}=  json_array_append({i}, '$', CAST(Values({i}) as JSON)) ")
        else:
            upx.append(f"{i}=Values({i})")

    sql = "INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s" % (
        table_name, ",".join(df2.columns), ",".join(xp), ",".join(upx))
    # logger.info("SQL: " + sql)
    errors = []
    for i in range(int(df2.index.size / 5000) + 1):
        df0 = df2[i * 5000:i * 5000 + 5000]
        # logger.info("insert count: %d" % (df0.index.size))
        try:
            cursor.executemany(sql, df0.to_records(index=False).tolist())
        except Exception as me:
            raise me
    cursor.close()
    mpool_put_connection(ps[0], db)
    return df2


def save_table_T(df, p=""):
    """
	@author： gjw
	@date: 2023-1201
	@函数：save_table_T ,采用事物操作，要么全成功，要么全失败
	@参数：config_name(配置),table_name(表名),json_fileld(可选json字段)
	@描述： 存储DF表到mysql中，index为0则新增，否则修改,字段名对应 根据阿里对表的定义来做，
	@返回： 无返回值
	@示例：a=@udf df by CRUD.save_object_mtable with (@like_name,@table_name)
	"""
    try:
        ps = p.split(",")
        config_name = ps[0].strip()
        table_name = ps[1].strip()
    except:
        raise Exception("参数错误!")
    if df.index.size == 0:
        return df

    user = fbi_global.get_user()
    try:
        user_info = ssdb0.hget('user', user)
        cur_user = json.loads(user_info)
    except:
        cur_user = {"tool": "ALL"}
    # add by gjw on 20201112 增加默认属性的获取
    data_owner = ssdb0.get('sys_data:%s:%s' % (config_name, table_name))
    owner = "public"
    if data_owner == "private":
        owner = user
    elif data_owner == "group":
        if cur_user["tool"] == "ALL" or cur_user["tool"] == "":
            owner = "public"
        else:
            owner = cur_user["tool"]
    else:
        owner = "public"

    db = mpool_get_connection(config_name)

    # modify by gjw on 2024-0425 事物提交
    db.autocommit(False)
    cursor = db.cursor()

    # 新增的数据
    df.index = df.index.astype(int)
    df2 = df.query("index==0")
    if df2.index.size > 0:  # 新增
        # 获取ID
        cursor.execute("select seq('%s',%s) as seq" % (table_name, df2.index.size))
        result = cursor.fetchone()
        beginid = result['seq']

        # 判断序列号,为0则重新初始化一下
        if beginid == 0:
            beginid = 1  # add by gjw on 20221014,为0是不行的
            try:
                seq_sql = "INSERT INTO seq VALUES('%s',%d);" % (table_name.strip(), beginid + df2.index.size)
                cursor.execute(seq_sql)
            except:
                pass
        df2 = df2.copy()

        now = datetime.now()
        df2["gmt_create"] = now.strftime("%Y-%m-%d %H:%M:%S")
        df2["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")

        df2["creator"] = user
        df2["owner"] = owner
        # add by gjw on 2022-0208 id必须在最后
        df2["id"] = list(range(beginid, beginid + df2.index.size))
        df2 = df2.set_index('id')
        df2["id"] = list(range(beginid, beginid + df2.index.size))
        # 准备新增
        xp = ["%s" for i in df2.columns]

        sql = "INSERT INTO %s (%s) VALUES (%s)" % (table_name, ",".join(df2.columns), ",".join(xp))
        errors = []
        for i in range(int(df2.index.size / 10000) + 1):
            df0 = df2[i * 10000:i * 10000 + 10000]
            try:
                cursor.executemany(sql, df0.to_records(index=False).tolist())
            except Exception as e:
                cursor.close()
                db.rollback()
                mpool_put_connection(ps[0], db)
                raise e

    # 修改的数据
    dfu = df.query("index > 0")
    if dfu.index.size > 0:
        dfu = dfu.copy()
        now = datetime.now()
        dfu["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")
        # 删除gmt_create列和id列
        if "gmt_create" in dfu.columns:
            dfu = dfu.drop(["gmt_create"], axis=1)
        if "id" in dfu.columns:
            dfu = dfu.drop(["id"], axis=1)
        if len(ps) == 2:  # 没有json字段，正常更新
            xp = [i + " = %s" for i in dfu.columns]
            # id必须在最后
            dfu["id"] = dfu.index
            sql = "UPDATE %s SET %s  WHERE id=" % (table_name, ",".join(xp))
            sql = sql + "%s"

            errors = []
            for i in range(int(dfu.index.size / 5000) + 1):
                j = i * 5000
                df0 = dfu.iloc[j:j + 5000]
                try:
                    cursor.executemany(sql, df0.to_records(index=False).tolist())
                except Exception as e:
                    db.rollback()
                    mpool_put_connection(ps[0], db)
                    raise e
        else:  # add by gjw on 20231218 >2,有json字段要做更新append处理的情况
            json_fields = ps[2].strip()
            if len(ps) > 3:
                limit_name = ps[3].strip()
            else:
                limit_name = 20

            # modify by gjw on 2024-0412 更新超过的json数据
            index_tuple = tuple([int(index) for index in dfu.index.tolist()])
            if len(index_tuple) > 1:
                limit_sql = "update {table} set {col}= json_remove({col},'$[0]')  where json_length({col}) >= {limit} and ID in {ids}".format(
                    table=table_name, col=json_fields, limit=limit_name, ids=index_tuple)
            else:
                limit_sql = "update {table} set {col}= json_remove({col},'$[0]')  where json_length({col}) >= {limit} and ID ={id}".format(
                    table=table_name, col=json_fields, limit=limit_name, id=index_tuple[0])
            cursor.execute(limit_sql)

            xp = []
            for col in dfu.columns:
                if col == json_fields:  # json字段
                    ##mariadb　写法
                    # xp.append(col + " = json_array_append(" +col+ " ,'$', JSON_DETAILED( %s )) ")
                    ##mysql8 写法
                    xp.append(col + " = json_array_append(" + col + " ,'$', CAST( %s AS JSON )) ")
                else:  # 其他字段
                    xp.append(col + " = %s")

            # id必须在最后
            dfu["id"] = dfu.index
            sql = "UPDATE %s SET %s  WHERE id=" % (table_name, ",".join(xp))
            sql = sql + "%s"
            errors = []
            for i in range(int(dfu.index.size / 5000) + 1):
                j = i * 5000
                df0 = dfu.iloc[j:j + 5000]
                try:
                    cursor.executemany(sql, df0.to_records(index=False).tolist())
                except Exception as e:
                    cursor.close()
                    db.rollback()
                    mpool_put_connection(ps[0], db)
                    raise e
    # end
    # end if
    # 返回结果
    if df2.index.size > 0 and dfu.index.size > 0:
        dfs = pd.concat([df2, dfu])
    elif df2.index.size > 0:
        dfs = df2
    elif dfu.index.size > 0:
        dfs = dfu
    else:
        dfs = pd.DataFrame([[-1]], columns=["id"])

    cursor.close()
    db.commit()
    mpool_put_connection(ps[0], db)
    dfs = dfs.set_index('id')
    dfs.index.name = 'id'
    dfs.index = dfs.index.astype(int)
    return dfs


def desc_mtable(df, p=''):
    """
    @函数：desc_table
    @参数：
    link_name(链接名),table_name(表名)
    @描述： 查看关系表的字段信息
    @返回：
    @示例：a=@udf df by CRUD.desc_table with (@like_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    sql = "SHOW FULL COLUMNS FROM %s" % (table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df1 = load_mysql_sql(df, p1).loc[:, ['Field', 'Type', 'Default', 'Comment']]
    df1.rename(columns={'Field': 'field', 'Comment': 'realname', 'Default': 'default', 'Type': 'type'}, inplace=True)
    df1.fillna("", inplace=True)
    return df1


def desc_table(df, p=""):
    """
    @author： wly
    @date: 20200422
    @函数：desc_table
    @参数：config_name,表名,中文表名
    @描述：参考阿里的标准，查询表
    @返回：
    @示例：a=@udf df by  CRUD.desc_table with (@link_name,@table_name)
    """
    dbtype = get_db_type(p)
    if dbtype == "mysql":
        df2 = desc_mtable(df, p)
    else:
        df2 = 0
    return df2


def is_exist_mtable(df, p=""):
    """
    @date: 20200509
    @函数：is_exist_mtable
    @参数：config_name,表名
    @描述：判断表是否存在
    @返回：
    @示例：a=@udf df by  CRUD.is_exist_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")
    sql = "show tables like '%s'" % (table_name.strip())
    p1 = "%s,%s" % (config_name.strip(), sql)
    df1 = load_mysql_sql(df, p1)
    if df1.empty:
        return pd.DataFrame([False], columns=['exist_table'])
    else:
        return pd.DataFrame([True], columns=['exist_table'])

    # 根据df表生成esql所需的sql语句


def get_sql(df, p=""):
    """
	@date: 20200712
	@函数：get_sql
	@参数：fields,con,group_by,agg_fun,having 作为df表的字段
	@描述：根据参数组装sql语句
	@返回： df表,有一个select的记录sql和 select count(*)的sql
	@示例：a=@udf df by CRUD.get_sql with (link,table)
	"""
    table = p.strip()
    fields = df.loc[0, "fields"]
    con = df.loc[0, "con"]
    group_by = df.loc[0, "group_by"]
    agg_fun = df.loc[0, "agg_fun"]
    having = df.loc[0, "having"]
    order = df.loc[0, "order_by"]
    limit = df.loc[0, "limit"]
    res_field = fields.split(",")
    res = agg_fun.split(",")
    res_field.extend(res)
    result = ",".join(list(filter(None, res_field)))
    if having.strip() == "":
        having_sql = ""
    else:
        having_sql = " having " + having
    if group_by.strip() == "":
        group_by_sql = ""
    else:
        group_by_sql = " group by " + group_by
    if con.strip() == "":
        con_sql = ""
    else:
        con_sql = " where " + con
    if order.strip() == "":
        order_sql = ""
    else:
        order_sql = " order by " + order
    if limit.strip() == "":
        limit_sql = " limit 100"
    else:
        limit_sql = "  " + str(limit)
    if result == "":
        result = "*"
    sql = "select " + result + " from " + table + con_sql + group_by_sql + having_sql + order_sql + limit_sql
    # modify by gjw on 2021-0425 count(*) 去掉 + order_sql+limit_sql
    # modify by gjw on 2022-0619 改为 clickhouse支持的count()函数
    sql_count = "select count() from " + table + con_sql + group_by_sql + having_sql

    data = {
        "sql": sql,
        "sql_count": sql_count
    }
    dfz = pd.DataFrame([data])
    return dfz


#####################sqlite3的支持#######################
# 读的时候采用unicode
import fcntl


def db_conn(dbfile):
    import sqlite3
    dbfile = dbfile.strip()
    conn = sqlite3.connect("/opt/openfbi/fbi-bin/db/tables/" + dbfile)
    conn.text_factory = str
    return conn


# 写的时候使用str
def db_conn_w(dbfile):
    import sqlite3
    dbfile = dbfile.strip()
    FILE = "/opt/openfbi/fbi-bin/db/tables/" + dbfile + ".lock"
    if not os.path.exists(FILE):
        # create the counter file if it doesn't exist
        file = open(FILE, "w")
        file.write("0")
        file.close()
    # 检查锁
    lock = open(FILE, "r+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    conn = sqlite3.connect("/opt/openfbi/fbi-bin/db/tables/" + dbfile)
    conn.text_factory = str
    return conn, lock


def create_stable(df, p=""):
    """
    @author： gjw
    @date: 20170930
    @函数：create_stable
    @参数：
    dbfile,表名
    @描述：
    参考阿里的标准，建一个单表，对应s3
    @返回：
    """
    dbfile, table_name, zh = p.split(",")
    conn, lock = db_conn_w(dbfile.strip())
    try:
        cursor = conn.cursor()

        col_def = []
        row_dict = df.iloc[0].to_dict()
        for k, v in row_dict.items():
            col_def.append("%s %s ," % (k, v.split("comment")[0]))

        sql = """
        CREATE TABLE IF NOT EXISTS %s (
            id bigint NOT NULL ,
            gmt_create DATETIME DEFAULT NULL,
            gmt_modified DATETIME DEFAULT NULL,
            creator varchar(128),
	        owner varchar(128),
            %s
            PRIMARY KEY (id)
        );
        """ % (table_name.strip(), "\n".join(col_def))

        # logger.info(sql)
        ret = cursor.execute(sql.strip())
        # 初始化SEQ表
        seq_table = """
        CREATE TABLE IF NOT EXISTS seq (
            name varchar(40) NOT NULL,
            val int UNSIGNED NOT NULL,
            PRIMARY KEY  (name)
        )
        """
        cursor.execute(seq_table)
        try:
            seq_sql = "INSERT INTO seq VALUES('%s',1);" % (table_name.strip())
            cursor.execute(seq_sql)
        except:
            pass
        conn.commit()
        cursor.close()
        conn.close()
        df2 = pd.DataFrame([[sql]], columns=["sql"])
    finally:
        lock.close()
    return df2


def is_exist_stable(df, p=""):
    """
    @author： gjw
    @date: 20200509
    @函数：is_exist_stable
    @参数：config_name,表名
    @描述：判断表是否存在
    @返回：
    @示例：a=@udf df by  CRUD.is_exist_mtable with (@link_name,@table_name)
    """
    try:
        config_name, table_name = p.split(",")
        config_name = config_name.strip()
        table_name = table_name.strip()
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名)")

    conn = db_conn(config_name)
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' and name ='%s'" % (table_name))
    rs = c.fetchall()
    if len(rs) == 0:
        dfs = pd.DataFrame([False], columns=['exist_table'])
    else:
        dfs = pd.DataFrame([True], columns=['exist_table'])
    conn.close()
    return dfs


def drop_stable(df, p=""):
    """
    @author： gjw
    @date: 20171114
    @函数：drop_stable
    @参数：
    config_name,表名
    @描述：
    参考阿里的标准，建一个单表,对应sqlite3的库
    @返回：
    """
    dbfile, table_name = p.split(",")
    db, lock = db_conn_w(dbfile.strip())
    try:
        cursor = db.cursor()
        sql = "DROP TABLE IF  EXISTS " + table_name.strip()
        # logger.info(sql)
        ret = cursor.execute(sql.strip())
        seq_sql = "delete from seq where name ='%s';" % (table_name.strip())
        cursor.execute(seq_sql)
        db.commit()
        cursor.close()
        db.close()
    finally:
        lock.close()
    df2 = pd.DataFrame([[sql]], columns=["sql"])
    return df2


# 查询的入口函数，支持排序
def query_stable(df, p=""):
    """
    @author： gjw
    @date: 20201228
    @函数：query_stable
    @参数：link_name(链接名),table_name(表名)
    @描述：根据df里的查询条件，来查询数据进行返回
    @返回：符合条件的记录和结果条数
    @示例 a=@udf df by  CRUD.query_mtable with (@link_name,@table_name)
    """
    try:
        ps = p.strip().split(",")
        link_name, table_name = ps[0:2]
        link_name = link_name.strip()
        table_name = table_name.strip()
    except:
        raise Exception("参数错误！正确参数：link_name(链接名),table_name(表名)")
    # 处理查询条件
    # add by gjw on 20201016 ,增加多租户的查询条件

    user = fbi_global.get_user()
    user_info = ssdb0.hget('user', user)
    cur_user = json.loads(user_info)
    resouce_group = cur_user["datas"].split(";")
    rgs = ["'public'", "'%s'" % (user), "'%s'" % (cur_user["tool"])]
    if "ALL" != cur_user["tool"]:
        for g in resouce_group:
            if g != "":
                rgs.append("'%s'" % (g))
            # df = df.append({"name":"owner","type":"in","value":",".join(rgs)},ignore_index=True)
        i = df.index.size
        df.loc[i] = {"name": "owner", "type": "in", "value": ",".join(rgs)}
    sql = []
    sql1 = []
    sql2 = []
    for index, row in df.iterrows():
        name = row['name']
        value = row['value']
        if row["type"] == "string":
            sql.append(" %s='%s' " % (name, value))
        elif row["type"] == "like":
            sql.append(" %s like '%%%s%%' " % (name, value))
        elif row["type"] == "not like":
            sql.append(" %s not like '%%%s%%' " % (name, value))
        elif row["type"] == "number":
            sql.append("%s = %s" % (name, value))
        elif row["type"] == ">":
            if isinstance(value, int):
                sql.append("%s > %s" % (name, value))
            else:
                sql.append("%s > '%s'" % (name, value))
        elif row["type"] == "<":
            if isinstance(value, int):
                sql.append("%s < %s" % (name, value))
            else:
                sql.append("%s < '%s'" % (name, value))
        elif row["type"] == ">=":
            if isinstance(value, int):
                sql.append("%s >= %s" % (name, value))
            else:
                sql.append("%s >= '%s'" % (name, value))
        elif row["type"] == "<=":
            if isinstance(value, int):
                sql.append("%s <= %s" % (name, value))
            else:
                sql.append("%s <= '%s'" % (name, value))
        elif row["type"] == "!=":
            sql.append("%s != %s" % (name, value))
        elif row["type"] == "in":
            sql.append("%s in (%s) " % (name, value.replace(",", "\,")))
        elif row["type"] == "not in":
            sql.append("%s not in (%s) " % (name, value.replace(",", "\,")))
        elif row["type"] == "json":
            sql.append(" JSON_CONTAINS(%s \,'[%s]')" % (name, value.replace(",", "\,")))
        elif row["type"] == "order":
            sql1.append("%s %s" % (name, value))
        else:
            sql2.append("%s %s" % (name, value))
    if sql1 == []:
        l1 = ["sign"]  # 没有order by条件
    else:
        l1 = [":".join(sql1)]
    l2 = [sql2[0]]
    sql.extend(l1)
    sql.extend(l2)
    p2 = "%s,%s,%s" % (link_name, table_name, ",".join(sql))
    df2, df3 = query_stable_and_count(df, p2)
    return df2, df3


def query_stable_and_count(df, p=""):
    """
    @author： gjw
    @date: 20201228
    @函数：基于query_mtable2
    @参数： config_name(配置),table_name(表名),col1=xxx,col2=xxx,
    @描述：根据配置信息来确定等来查询数据,可以处理in
    @返回： 符合条件的记录
    @示例：a=@udf df by CRUD.query_mtable2 with (@like_name,@table_name,col1=xxx,col2=xxx)
    """
    # 处理逗号
    s = p.strip().replace("\,", "``")
    try:
        ps = s.split(",")
        config_name, table_name = ps[0:2]
    except:
        raise Exception(
            "参数错误: config_name(配置),table_name(表名),col1=xx1,coln=xxn,(查询条件),其他子句如order by or limit等(必须有)")

    conds = []
    mydefine_sql = ps[-1]
    mydefine_sql1 = ps[-2]
    i = 1
    for cond in ps[2:-2]:
        cond = cond.replace("``", ",")
        i += 1
        cond = cond.strip()
        if cond.find("''") > 0 or cond.find('""') > 0 or cond.find("%%") > 0 or cond.find("()") > 0 or cond.find(
                "[]") > 0:  # 字符串查询为空的不要
            continue
        is_null = False
        for flag in ["=", ">", ">=", "<", "<=", "!=", "in", "not in"]:
            if cond.find(flag) == len(cond) - 1:  # 数字类查询不为空
                is_null = True
                break
        if not is_null:  # 正常的条件加入
            conds.append(cond)
    # end for
    # 页面条件
    endsql = "order by "
    if mydefine_sql1 == "sign":
        endsql = ""
    else:
        for per in mydefine_sql1.split(":"):
            endsql = endsql + per + ","
        endsql = endsql[:-1]
    cond_sql = ""
    if len(conds) == 1:
        cond_sql = "where " + conds[0]
    elif len(conds) > 1:
        cond_sql = " and ".join(conds)
        cond_sql = "where (%s)" % (cond_sql)
    else:
        cond_sql = ""
    # add by wly 20181228
    if mydefine_sql.find("limit") >= 0 and mydefine_sql.find("|") >= 0:
        mydefine_sql = mydefine_sql.replace("|", ",")

    sql = "select * from %s %s %s %s " % (table_name.strip(), cond_sql, endsql, mydefine_sql)
    # logger.info(sql)
    sql_count = "select count(id) from %s %s %s" % (table_name.strip(), cond_sql, endsql)
    # logger.info(sql_count)

    # add by gjw on 20231123 增加debug_sql的调试
    sql_df = pd.DataFrame([[sql], [sql_count]])
    debug_sql = FbiTable("debug_sql", sql_df)
    fbi_global.get_runtime().put_with_ws(debug_sql, "system_debug")

    conn = db_conn(config_name.strip())
    df2 = pd.read_sql(sql.strip(), conn)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    df3 = pd.read_sql(sql_count.strip(), conn)
    return df2, df3


# 获取序列号（sqlite3）
def get_seq_s3(conn, p):
    name = p.strip()
    c = conn.cursor()
    c.execute("SELECT val FROM seq WHERE name='%s'" % (name.strip()));
    rs = c.fetchone()
    seq_id = rs[0]
    next_seq = seq_id + 1
    c.execute("update seq set val=%d where name='%s' " % (next_seq, name.strip()));
    conn.commit()
    return seq_id


def save_object_stable(df, p=""):
    """
    @author： gjw
    @date: 20170930
    @函数：save_object_stable
    @参数：
    config_name(配置),table_name(表名)
    @描述：
    存储DF表到mysql中，index为0则新增，否则修改,字段名对应
    根据阿里对表的定义来做，
    @返回：
    无返回值
    """
    dbfile, table_name = p.split(",")
    table_name = table_name.strip()
    db, lock = db_conn_w(dbfile.strip())
    try:
        cursor = db.cursor()
        # 新增的数据
        df2 = df.query("index==0")

        user = fbi_global.get_user()
        user_info = ssdb0.hget('user', user)
        cur_user = json.loads(user_info)
        # add by gjw on 20201112 增加默认属性的获取
        data_owner = ssdb0.get('sys_data:%s:%s' % (dbfile, table_name))
        owner = "public"
        if data_owner == "private":
            owner = user
        elif data_owner == "group":
            if cur_user["tool"] == "ALL" or cur_user["tool"] == "":
                owner = "public"
            else:
                owner = cur_user["tool"]
        else:
            owner = "public"
        if df2.index.size > 0:
            # 获取ID
            beginid = get_seq_s3(db, table_name)
            now = datetime.now()
            df2["gmt_create"] = now.strftime("%Y-%m-%d %H:%M:%S")
            df2["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")
            df2["creator"] = user
            df2["owner"] = owner
            df2["id"] = list(range(beginid, beginid + df2.index.size))
            xp = ["?" for i in df2.columns]
            sql = "INSERT INTO %s (%s) VALUES (%s)" % (table_name, ",".join(df2.columns), ",".join(xp))
            # logger.info("SQL: "+sql)
            for i in range(int(df2.index.size / 5000) + 1):
                # logger.info("data: %s to %s"%(i*5000,i*5000+5000))
                df0 = df2[i * 5000:i * 5000 + 5000]
                cursor.executemany(sql, df0.to_records(index=False).tolist())
            #
            sql2 = "update seq set val=%s where name='%s'" % (beginid + df2.index.size, table_name)
            cursor.execute(sql2)

        # 修改的数据
        dfu = df.query("index > 0")
        now = datetime.now()
        dfu["gmt_modified"] = now.strftime("%Y-%m-%d %H:%M:%S")
        if dfu.index.size > 0:
            xp = [i + " = ?" for i in dfu.columns]
            dfu["id"] = dfu.index
            sql = "UPDATE %s SET %s  WHERE id=" % (table_name, ",".join(xp))
            sql = sql + "?"
            # logger.info("SQL: "+sql)
            for i in range(int(dfu.index.size / 5000) + 1):
                # logger.info("data: %s to %s"%(i*5000,i*5000+5000))
                df0 = dfu[i * 5000:i * 5000 + 5000]
                cursor.executemany(sql, df0.to_records(index=False).tolist())
        cursor.close()
        db.commit()
        db.close()
        dfs = pd.concat([df2, dfu])
        dfs = dfs.set_index('id')
        dfs.index.name = 'id'
    finally:
        lock.close()
    return dfs


def get_object_stable_id(df, p=""):
    """
    @author： gjw
    @date: 20171004
    @函数：get_object_mtable
    @参数：
    config_name(配置),table_name(表名),id(主键)
    @描述：
    根据表名和id来加载对象
    @返回：
    无返回值
    """
    try:
        config_name, table_name, pk_id = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),id(主键)")
    sql = "select * from %s where id=%s" % (table_name.strip(), pk_id.strip())
    conn = db_conn(config_name.strip())
    df2 = pd.read_sql(sql.strip(), conn)
    df2 = df2.set_index("id")
    df2.index.name = "id"
    return df2


def delete_object_stable(df, p=""):
    """
    @author： gjw
    @date: 20171004
    @函数：delete_object_stable
    @参数：
    config_name(配置),table_name(表名),id(主键)
    @描述：
    根据表名和id来删除对象
    @返回：
    无返回值
    """
    try:
        config_name, table_name, pk_id = p.split(",")
    except:
        raise Exception("参数错误: config_name(配置),table_name(表名),id(主键)")
    sql = "delete from %s where id=%s" % (table_name.strip(), pk_id.strip())

    conn, lock = db_conn_w(config_name.strip())
    try:
        c = conn.cursor()
        c.execute(sql)
        conn.commit()
        conn.close()
    finally:
        lock.close()
    return df


def exec_s3_sql(df, p=""):
    """
    执行SQL语句在s3的数据库上
    @参数:db_file,sql
    """
    l3 = p.split(",")
    conn, lock = db_conn_w(l3[0].strip())
    try:
        c = conn.cursor()
        c.execute(",".join(l3[1:]).strip())
        conn.commit()
        conn.close()
    finally:
        lock.close()
    return df


def load_s3_sql(df, p=""):
    """
    @author： gjw
    @date: 20160706
    @函数：s3_load,从sqlite3文件中加载数据
    @参数：
    dbfile,select * from tname xxx
    @描述：
    从sqlite3文件中按sql语句加载数据
    @返回：
    df表
    """
    ps = p.split(",")
    dbfile = ps[0].strip()
    sql = ",".join(ps[1:])
    conn = db_conn(dbfile)
    dfz = pd.read_sql(sql.strip(), conn)
    return dfz
