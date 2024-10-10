def query_mtable(df, p=""):
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

    if sql1 == []:
        l1 = ["sign"]  # 没有order by条件
    else:
        l1 = [":".join(sql1)]
    #l2 = [sql2[0]]
    sql.extend(l1)
    #sql.extend(l2)
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

    return df2, df3
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
if __name__ == '__main__':
    import pandas as pd

    datas = {
        "columns": [
            "name",
            "value",
            "type"
        ],
        "index": [
            0,
            1,
            2,
            3,
            4
        ],
        "data": [
            {
                "index": 0,
                "name": "src_id",
                "value": "\"1\"",
                "type": "in"
            },
            {
                "index": 1,
                "name": "file_name",
                "value": "",
                "type": "like"
            },
            {
                "index": 2,
                "name": "label_name",
                "value": "",
                "type": "like"
            },
            {
                "index": 3,
                "name": "classify_name",
                "value": "",
                "type": "like"
            },
            {
                "index": 4,
                "name": "classify_id",
                "value": 0,
                "type": "!="
            }
        ]
    }
    df = pd.DataFrame(data=datas.get("data"), columns=datas.get("columns"), index=datas.get("index"))
    print(df)
    p = "link_name,table_name"
    query_mtable(df,p)