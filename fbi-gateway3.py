#!/opt/fbi-base/bin/python
# -*- coding: utf-8 -*-


# import imp
# from bottle import route, run, static_file, request, response, default_app, template,\
#     redirect, download_file
##########################################################
'''
使用fastapi框架替换boot框架
'''
import uvicorn
from fastapi import Response
from pydantic import BaseModel
from fastapi.requests import Request
from typing import List, Dict, Any
from typing import Union, List, Optional
from fastapi.responses import HTMLResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Query, Body, File, UploadFile, Form  # API对象
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
####################from pkgutil import extend_path#####################################
import json
import orjson
import ujson
import sys

sys.path.append("lib")
from multiprocessing import Process, current_process
from urllib.parse import quote
import traceback
import os, signal, shutil
import time
import hashlib
from datetime import datetime
import copy
import urllib3
from urllib.parse import urlencode

import random
import base64
import zipfile
import glob
import pandas as pd

pd.options.future.infer_string = True
from avenger.sysrule import build_sysrule
from avenger.fbicommand import run_command2, run_block_in_sync
from avenger.fsys import *
from avenger.fssdb import *
from avenger.fastbi import compile_fbi
from avenger.fglobals import *
from avenger.fio import *
from avenger.fbiobject import FbiEngMgr

# 使用fastapi

root = FastAPI()
root.mount("/static", StaticFiles(directory="static"), name="static")
# 创建一个static(模板)对象，便于之后重用
templates = Jinja2Templates(directory="static")
templatess = Jinja2Templates("/opt/openfbi/mPig/html/bi")
# add by gjw on 2022-1012 支持扩展的请求函数
try:
    from fbi_extends import *
except:
    pass

# add by gjw on 2022-0511 注册信号，装载脚本
import avenger.fsys

# 全局的session会话时间
timeout = get_key2("session_timeout") or "3600"
itimeout = int(timeout)

# 获取授权信息
c, s = rd_Authorization()
fbi_global.size = c
fbi_global.dbd_size = s

ssdb0 = fbi_global.get_ssdb0()
# 引擎管理`
fbi_eng_mgr = FbiEngMgr(ssdb0)
# 用户管理
fbi_user_mgr = FbiUserMgr(ssdb0)

#
import logging
from logging.handlers import RotatingFileHandler

# 初始化主root
root_logger = logging.getLogger('fbi-gateway')
root_logger.setLevel(logging.INFO)
# 创建一个handler，用于写入日志文件
# 定义一个RotatingFileHandler，最多备份3个日志文件，每个日志文件最大10M
fh = RotatingFileHandler('logs/fbi_gateway3.log', maxBytes=10 * 1024 * 1024, backupCount=3)

# 定义handler的输出格式
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
# 给logger添加handler
root_logger.addHandler(fh)
# 不向上传播到root
root_logger.propagate = 0

# add by gjw on 2021-0907 更好的记录udf中发生的错误
from avenger.fglobals import logger

# 给logger添加handler
logger.addHandler(fh)
# 不向上传播到root
logger.propagate = 1


# 当前时间
@root.get('/now')
async def system_now():
    now = datetime.now().isoformat()[0:19]
    curtime = {"now": now, "timestamp": int(time.time() * 1000)}

    # return curtime
    return {"code": 200, "data": {"success": "true"}, "msg": "成功", "now": now, "timestamp": int(time.time() * 1000)}


@root.get('/format/')
async def fbi_format(response: Response, request: Request,
                     fbi_sesion: str = Query(...),
                     name: str = Query(...)):
    # 格式化FbI
    ret = check_session(request, response, fbi_sesion)

    if ret != 0:
        return "{}"
    session = request.cookies.get("fbi_session") or request.query_params["fbi_session"]
    fbi_name = request.query_params["name"]
    fbi_name = fbi_name.replace("--", "/")
    format_script(file_path["fbi"] + fbi_name, get_user_by_session(session)[0])
    return '{"code":200,"data":{ "success":true}, "msg":"成功"}'


@root.get('/list')
async def list_alltable(request: Request, response: Response, fbi_session: str = Query(...)):
    fbi_session = request.query_params["fbi_session"]
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return "{}"
    return {"code": 200, "data": {list(fbi_global.get_runtime().wss.keys())}, "msg": "请求成功"}


def hash_str(x):
    h = hashlib.sha1()
    y = x[2:3] + x[1:4] + x[0:2] + x[5] + x
    h.update(y.encode("utf8"))
    return h.hexdigest()


# 免密登录
# 使用示例:http://ip/app?user=ddd&AK=27a9a7d16a8ab627cd6718d400a491864e4db3f4&key=use:zy
# 可以添加端口号：
# http://ip/app?user=ddd&AK=27a9a7d16a8ab627cd6718d400a491864e4db3f4&key=use:zy&port=80
# 更改密码，要验证老密码
@root.post('/up_auth_key/')
async def up_auth_key(item: dict, request: Request, response: Response,
                      fbi_session: str = Query(None),
                      old_auth_key: str = Query(None),
                      auth_key: str = Query(None),
                      name: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        user = item
        # 校验老密码
        if "old_auth_key" not in user:
            raise Exception("不能修改密码，请升级UI版本到2022-0324之后!")
        old_pwd = user["old_auth_key"]
        old_pwd = base64.b64decode(old_pwd).decode("utf8")

        pwd = user["auth_key"]
        pwd = base64.b64decode(pwd).decode("utf8")
        if len(pwd) < 8: raise Exception("新密码不能少于8位!")
        session = request.cookies.get("fbi_session") or request.query_params["fbi_session"]
        if user["name"] == get_user_by_session(session)[0]:
            auth_code = fbi_user_mgr.auth2_user(user["name"], pwd, request.client.host)  # 任意用户都可以修改

            if auth_code == 1:
                fbi_user_mgr.update_passwd(user["name"], old_pwd)
                return {"code": 200, "data": {"success": True}, "msg": "成功"}
            else:
                raise Exception("旧密码验证失败，无法更新密码!")
        else:
            raise Exception("非当前用户无法更新密码!")
    except Exception as e:
        return '{"code":202,"data":{"success":false},"msg":"%s"}' % (e)


# 日志跟踪
@root.post('/putlog')
async def putlog(item: dict, request: Request, response: Response,
                 fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        d = item
        session = request.cookies.get("fbi_session") or item.get("fbi_session")
        user = get_user_by_session(session)[0]
        d["user"] = user
        d["remote_addr"] = request.client.host
        d["remote_route"] = ";".join(request.url.path)
        d["timestamp"] = datetime.now().isoformat()
        ssdb0.qpush("Q_log_%s" % (d["timestamp"][0:10]), json.dumps(d))
        # 修改设置请求头方法格式
        response.headers["Content-Type"] = 'application/json; charset=UTF-8'
        response.set_cookie("fbi_session", session, max_age=itimeout, path="/")
        return {"code": 200, "data": {"success": "true"}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": "false"}, "msg": "%s" % (e)}


# 发送消息
@root.post('/send_mq/')
async def send_mq(request: Request, response, Response,
                  fbi_session: str = Query(None),
                  mq: str = Query(None),
                  msg: str = Query(None),
                  ):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        import redis
        mq = request.query_params.get("mq")
        link = request.query_params.get("msg")
        # 验证msg的内容是不是标准json
        link_json = json.loads(link)
        r = redis.Redis(config["redis_host"], port=config["redis_port"], decode_responses=True,
                        password=config["redis_password"])
        r.publish(mq, json.dumps(link_json))
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": "false"}, "msg": "%s" % (e)}


# 检查redis是否正常
@root.get('/check_redis/')
async def check_redis(request: Request, response, Response,
                      fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        import redis
        r = redis.Redis(config["redis_host"], port=config["redis_port"], decode_responses=True,
                        password=config["redis_password"])
        r.ping()
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": "false"}, "msg": "%s" % (e)}


# 校验会话是否合法,0为合法
def check_session(request, response, fbi_session: str = Query(None)):
    session = request.cookies.get("fbi_session") or fbi_session
    if session == "": return "你没有访问权限"
    fbi_session = "fbi_session:%s" % (session)
    if ssdb0.exists(fbi_session) == "0": return "你没有访问权限"
    return 0


# modify by gjw on 2020
# 返回用户名和用户是否具有开发权限
def get_user_by_session(session):
    fbi_session = "fbi_session:%s" % (session)
    v = ssdb0.get(fbi_session)
    if v != None and v != "":
        user, isadmin = v.split(":")
    else:
        user = ""
        isadmin = "N"
    return user, isadmin


# add by gjw on 20201215 检查有无开发人员的权限
def check_isadmin(request, fbi_session):
    session = fbi_session or request.cookies.get("fbi_session")
    if not session:
        raise Exception("你没有访问权限")
    user, isadmin = get_user_by_session(session)
    if (isadmin != "Y"):
        raise Exception("{}没有权限，不能操作!".format(user))
    return user


# add by gjw on 2020-1223
# 返回fbi状态
@root.get('/fbi_stats')
async def query_fbi_stats(request: Request, response: Response,
                          fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        with open('/dev/shm/fbi_stats', 'r') as f:
            a = f.read()
            res = json.loads(a)
            engs = []
            for eng in res["engs"]:
                for k, v in eng.items():
                    v["port"] = k
                    engs.append(v)
            res["engs"] = engs
    except:
        a = "{}"
    return {"code": 200, "data": res, "msg": "请求成功"}


# 会话保活接口
@root.get('/KA')
async def KA(request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        session = request.cookies.get("fbi_session") or fbi_session or ""
        fbi_session = "fbi_session:%s" % (session)
        user, isadmin = get_user_by_session(session)

        # 新session
        session = get_session_id(user)
        key = "fbi_session:%s" % (session)

        # add by gjw on 2022-0516 记录用户最后的会话
        last_Key = "{}:last_fbisession".format(user)

        ssdb0.delete(fbi_session)

        ssdb0.set(key, user + ":" + isadmin)  # 当前session
        ssdb0.set(last_Key, session)
        ssdb0.expire(key, itimeout)
        response.set_cookie("fbi_session", session, max_age=itimeout, path="/")
        return {"code": 200, "data": {"success": True, "fbi_session": session}, "msg": "成功"}
    except Exception as e:
        return '{"code":500, "data":{"success":false},"msg":"%s","traceback":"%s"}' % (e, traceback.format_exc())


# 门户应用的登出
@root.get('/logout2')
async def logout2(request: Request, response: Response,
                  fbi_session: str = Query(None),
                  remote_route: str = Query(None)):
    try:
        session = request.cookies.get("fbi_session") or fbi_session
        fbi_session = "fbi_session:%s" % (session)
        user_name = get_user_by_session(session)[0]
        ssdb0.delete(fbi_session)
        response.delete_cookie("fbi_session", path="/")
        log_session(user_name, request.client.host, "".join(";%s" % (request.url.path)), "注销", "应用", \
                    "user:%s" % (user_name), "成功", "")
        return json.loads('{"code":200, "data":{"success":true}, "msg":"成功"}')
    except Exception as e:
        response.delete_cookie("fbi_session")
        return '{"code":500, data:{"success":false},"msg":"%s}' % (e)


# add by gjw on 20210421
# 开发平台的注销
@root.get('/logout')
async def logout(request: Request, response: Response,
                 fbi_session: str = Query(None)):
    try:
        session = request.cookies.get("fbi_session") or fbi_session
        fbi_session = "fbi_session:%s" % (session)
        user_name = get_user_by_session(session)[0]
        ssdb0.delete(fbi_session)

        # add by gjw on 2022-0213　可以有多个相同用户同时登录后台
        user_session_key = "user_session:{}:".format(user_name)
        # 删除所有正在登录的用户的session
        user_sessions = ssdb0.keys(user_session_key, user_session_key + "~", 1000)
        for user_session in user_sessions:
            user, name, session = user_session.split(":")
            ssdb0.delete(user_session)
            ssdb0.delete("fbi_session:{}".format(session))
        response.delete_cookie("fbi_session", path="/")
        log_session(user_name, request.client.host, "".join(";%s" % (request.url.path)), "注销", "平台", \
                    "user:%s" % (user_name), "成功", "")
        return json.loads('{"code":200, "data":{"success":true}, "msg":"成功"}')
    except Exception as e:
        response.delete_cookie("fbi_session")
        return '{"code":500, data:{"success":false},"msg":"%s}' % (e)


# 检查key是否为配置数据的key
def check_ssdb_key_is_cfg(key):
    k = key.split(":")
    if k[0] in ["word", "qes", "am", "modeling"] or k[0][0:-1] == "dashboard":
        return True
    return False


# 写权限的
def check_ssdb_key_is_write(key):
    k = key.split(":")
    if k[0] in ["word", "qes", "am", "modeling", "sys_data", "nav", "use", "sys_data", "qes_table"] or k[0][
                                                                                                       0:-1] == "dashboard":
        return True
    if k[0] in ["fbi_session", "SysRule"]:  # 系统级的数据，不允许管理员写入
        raise Exception("没有写权限!")
    return False


# add by gjw on 2020-1222,检查是否有获取面板类配置数据的权限,True为失败
def check_sysrule_dbds_failed(session, key_string):
    user, isadmin = get_user_by_session(session)
    if user == None or user == "": return True
    if isadmin == "Y": return False
    if user == "admin": return False

    SysRule = ssdb0.get("SysRule:dbds:%s" % (user))
    SysRule_list = json.loads(SysRule)

    keys = key_string.split(",")
    for key in keys:
        if check_ssdb_key_is_cfg(key):
            try:
                if key not in SysRule_list:
                    return True
            except:
                return True
    # False 为成功
    return False


# 获取数据key
@root.get('/query/{db}/{key}')
async def ssdb_query_json(db, key, request: Request, response: Response,
                          fbi_session: str = Query(None)):
    response.headers["Content-Type"] = 'application/json; charset=UTF-8'
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = request.cookies.get("fbi_session") or fbi_session
    if check_sysrule_dbds_failed(session, key): return {'code': 403, 'msg': '%s' % (ret)}
    ret = ssdb0.get(b64(key))
    if ret == None:
        ret = {}
    else:
        ret = ujson.loads(ret)
    return {'code': 200, 'data': {'val': ret}, 'msg': '成功'}


# 获取单个数据源
@root.get('/query/{db}')
async def ssdb_query_muli(db, request: Request, response: Response,
                          fbi_session: str = Query(None),
                          key: str = Query(None),
                          _: str = Query(None)):
    print("key", key)
    print("_", _)
    print("123456")
    response.headers["Content-Type"] = 'application/json; charset=UTF-8'
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    res = request.method
    print("请求方法", res)
    key = request.query_params.get("key")
    print("类型", type(key))
    print(db)
    print(key)
    if not key:
        # key = item.get("key")
        key = key

    # 暂时删除
    # session = request.cookies.fbi_session or request.query.fbi_session
    # if check_sysrule_dbds_failed(session, key): return json.dumps({'code': 403, 'msg': '%s' % (ret)})

    def hgetitem(key):
        if key.find("=>") > 0:
            name, subkey = key.split('=>')
            if key.endswith('=>*'):
                hvalue = ssdb0.hgetall(b64(name))
                name_key = [b64(name) + "=>" + k for k in hvalue[::2]]
                r_key = [name + "=>" + db64(k) for k in hvalue[::2]]
                subvalue = hvalue[1::2]
                newvalue = []
                for value in subvalue:
                    if value == None:
                        value1 = {}
                    else:
                        try:
                            value1 = json.loads(value)
                        except ValueError as e:
                            value1 = value
                    newvalue.append(value1)
                return dict(zip(r_key, newvalue))
            else:
                subvalue = ssdb0.hget(b64(name), b64(subkey))
                if subvalue == None:
                    subvalue1 = {}
                else:
                    try:
                        subvalue1 = json.loads(subvalue)
                    except ValueError as e:
                        subvalue1 = subvalue
                return {key: subvalue1}
        else:
            value = ssdb0.get(b64(key))
            if value == None:
                value1 = {}
            else:
                try:
                    value1 = json.loads(value)
                except ValueError as e:
                    value1 = value
            return {key: value1}

    result = {}
    keys = key.split(',')
    # 多个key
    for key in keys:
        result.update(hgetitem(key))
    return {'code': 200, 'data': result, 'msg': '成功'}


# 获取多个数据key
@root.post('/query/{db}')
async def ssdb_query_muli(item: dict, db, request: Request, response: Response,
                          fbi_session: str = Query(None),
                          key: str = Query(None),
                          _: str = Query(None)):
    print("key", key)
    print("_", _)
    print("123456")
    response.headers["Content-Type"] = 'application/json; charset=UTF-8'
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    res = request.method
    print(item)
    print("请求方法", res)
    # key = request.query_params.get("key")
    for K in item.keys():
        key = K
    print("类型", type(key))
    print(db)
    print(key)
    if not key:
        key = item.get("key")

    # 暂时删除
    # session = request.cookies.fbi_session or request.query.fbi_session
    # if check_sysrule_dbds_failed(session, key): return json.dumps({'code': 403, 'msg': '%s' % (ret)})

    def hgetitem(key):
        if key.find("=>") > 0:
            name, subkey = key.split('=>')
            if key.endswith('=>*'):
                hvalue = ssdb0.hgetall(b64(name))
                name_key = [b64(name) + "=>" + k for k in hvalue[::2]]
                r_key = [name + "=>" + db64(k) for k in hvalue[::2]]
                subvalue = hvalue[1::2]
                newvalue = []
                for value in subvalue:
                    if value == None:
                        value1 = {}
                    else:
                        try:
                            value1 = json.loads(value)
                        except ValueError as e:
                            value1 = value
                    newvalue.append(value1)
                return dict(zip(r_key, newvalue))
            else:
                subvalue = ssdb0.hget(b64(name), b64(subkey))
                if subvalue == None:
                    subvalue1 = {}
                else:
                    try:
                        subvalue1 = json.loads(subvalue)
                    except ValueError as e:
                        subvalue1 = subvalue
                return {key: subvalue1}
        else:
            value = ssdb0.get(b64(key))
            if value == None:
                value1 = {}
            else:
                try:
                    value1 = json.loads(value)
                except ValueError as e:
                    value1 = value
            return {key: value1}

    print("key:", hgetitem(key))
    result = {}
    keys = key.split(',')
    # 多个key
    for key in keys:
        result.update(hgetitem(key))
    return {'code': 200, 'data': result, 'msg': '成功'}


# 删除key
@root.get('/del/{db}/{key}')
async def ssdb_del(db: str, key: str, request: Request, response: Response,
                   fbi_session: str = Query(None)):
    try:
        check_isadmin(request, fbi_session)
        ssdb0.delete(b64(key))
        # return '{"code":200, "data":{"success":true}, "msg":"成功"}'
        return {"code": 200, "data": {"success": "true"}, "msg": "成功"}
    except Exception as e:
        # return '{"code":500, data:{"success":false},"msg":"%s}' % (e)
        return {"code": 500, "data": {"success": "false"}, "msg": "%s" % (e)}


@root.post('/put/{db}/{key}')
async def ssdb_put(db,
                   key,
                   request: Request,
                   response: Response,
                   fbi_session: str = Query(None)):
    datas = await request.body()
    datas = json.loads(datas)
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        value = datas
        value = json.dumps(value)
        if key.find("=>") > 0:
            name, subkey = key.split("=>")
            ssdb0.hset(b64(name), b64(subkey), value)
        else:
            # add by gjw on 2020-1222, 配置数据只有开发权限才能保存
            if check_ssdb_key_is_write(key):
                check_isadmin(request, fbi_session)
            ssdb0.set(b64(key), value)

        return {"code": 200, "data": {"success": "true"}, "msg": "成功"}
    except Exception as e:

        return {"code": "500", "data": {"success": "false"}, "msg": "%s" % (e)}


# 临时key数据
@root.post('/put300/{db}/{key}')
async def ssdb_put300(db, key, item: dict, request: Request, response: Response,
                      fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        value = item
        value = json.dumps(value)
        ssdb0.set(b64(key), value)
        ssdb0.expire(b64(key), 300)

        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:

        return {"code": 500, "data": {"success": False}, "msg": "%s" % (e)}


# 执行udf函数
@root.post('/udf/{pkg_fun}')
@root.get('/udf/{pkg_fun}')
async def udf_fun(pkg_fun, request: Request, response: Response,
                  fbi_ssession: str = Query(None),
                  df: str = Query(None),
                  p: str = Query(None)):
    ret = check_session(request, response, fbi_ssession)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        from avenger.fbiprocesser import _dump_df
        response.headers["Content-Type"] = 'application/json; charset=UTF-8'
        df_json = request.query_params.get("df")
        p = request.query_params.get("p")
        pkg, fun = pkg_fun.split(".")
        result = {"status": 0, "dfs": {}}
        try:
            if df_json == None or df_json == "":
                df = pd.DataFrame()
            else:
                df = pd.read_json(df_json)
            exec("from udf.%s import %s " % (pkg, fun))
            dfs = eval("%s(df,p)" % (fun))
            if isinstance(dfs, pd.DataFrame):
                result["dfs"][0] = _dump_df(dfs)
            else:
                for i, dfz in enumerate(dfs):
                    result["dfs"][i] = _dump_df(dfz)
        except Exception as e:
            result["status"] = 1
            result["errors"] = e.__str__()
        finally:
            if "udf.%s" % (pkg) in sys.modules:
                del (sys.modules["udf.%s" % (pkg)])
        res = json.loads(result['dfs'][0])
        result['dfs'][0] = res
        return {"code": 200, "data": result, "msg": "成功"}
    except Exception as e:
        return e.__str__()


# 检查是否存在XSS攻击
def check_xss(callback):
    keys = ["<", ">", "'", '"', "%", "*", "$"]
    for i in keys:
        if i in callback:
            raise Exception("可能存在XSS攻击，不执行后续请求!")


# 扫描多个key
@root.post('/scan/{db}/{skey}/{ekey}')
async def ssdb_scan_json(
        item: dict,
        request: Request,
        response: Response,
        db: str,
        skey: str,
        ekey: str,
        count=100,
        fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    page = item.get('page')
    pagesize = item.get('pagesize')
    response.headers["Content-Type"] = 'application/json; charset=UTF-8'
    count = fbi_global.dbd_size
    a = ssdb0.scan(skey, ekey, count)
    length = len(a)
    b = []
    for i in range(0, length, 2):
        try:
            res = json.loads(a[i + 1])
        except:
            continue
        if len(res) == 0:
            continue
        if isinstance(res, list):
            y = res[0]
        else:
            y = res
        y['key'] = a[i]
        b.append(y)
    total = len(b)

    page_data = b[(page - 1) * pagesize:(page) * pagesize]

    if total % pagesize == 0:
        pages = int(total / pagesize)
    else:
        pages = int(total / pagesize) + 1

    return {"code": 200,
            "data": {'records': page_data, 'current': page, 'pageSize': pagesize, 'pages': pages, 'total': total},
            "msg": "请求成功"}


# 获取字典
@root.get('/scan/dd')
async def ssdb_scan_dd(request: Request, response: Response,
                       fbi_session: str = Query(None),
                       ):
    response.headers["Content-Type"] = 'application/json; charset=UTF-8'
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    # page = request.json.get('page')
    # pagesize = request.json.get('pagesize')
    a = ssdb0.keys("dd:", "dd:~", 10000)
    b = []
    for i in a:
        d = {}.fromkeys(['id'], i)
        b.append(d)

    return {"code": 200, "data": {"records": b}, "msg": "请求成功"}


# 获取字典的描述信息
@root.post('/scan/dd2')
async def ssdb_scan_dd2(item: dict, request: Request, response: Response,
                        fbi_session: str = Query(None)):
    try:
        response.headers["Content-Type"] = 'application/json; charset=UTF-8'
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        page = item.get('page')
        pagesize = item.get('pagesize')
        a = ssdb0.scan("dd2:", "dd2:~", 10000)
        length = len(a)
        b = []
        dd2_key = []
        for i in range(0, length, 2):
            res = json.loads(a[i + 1])
            res['key'] = a[i]
            b.append(res)
            dd2_key.append(a[i])

        dd2_key = map(lambda x: x[4:], dd2_key)
        a = ssdb0.keys("dd:", "dd:~", 10000)
        dd_key = map(lambda x: x[3:], a)
        dd = list(set(dd_key) - set(dd2_key))
        dd2 = map(lambda x: "dd2:" + x, dd)
        for k in dd2:
            d = {k: '{"id":"%s"}' % (k[4:])}
            rei = json.loads(d.get(k))
            b.append(rei)

        total = len(b)
        b = b[(int(page) - 1) * int(pagesize):int(page) * int(pagesize)]
        return {"code": 200,
                "data": {'records': b, 'current': page, 'pageSize': pagesize, 'pages': page, 'total': total},
                "msg": "请求成功"}
    except Exception as e:
        return e.__str__()

# rzc 新增图形面板分页查询功能
@root.post("/full/{db}/{skey}/{ekey}")
async def ssdb_full_dbd(item: dict,
                        db: str,
                        skey: str,
                        ekey: str,
                        request: Request,
                        response: Response,
                        fbi_session: str = Query(None)):
    user = check_isadmin(request, fbi_session)

    response.headers["Content-Type"] = "application/json;charset=UTF-8"
    count = fbi_global.dbd_size
    page = int(item.get("page"))
    pagesize = int(item.get("pagesize"))
    text = item.get("keyword")
    a = ssdb0.scan(skey, ekey, count)
    length = len(a)
    b = []
    for i in range(0, length, 2):
        if a[i].find(text) >= 0 or a[i + 1].find(text) >= 0:
            try:
                res = json.loads(a[i + 1])
            except:
                continue
            if len(res) == 0:
                continue
            if isinstance(res, list):
                y = res[0]
            else:
                y = res
            y['key'] = a[i]
            b.append(y)
    total = len(b)

    page_data = b[(page - 1) * pagesize:page * pagesize]

    if total % int(pagesize) == 0:
        pages = int(total / pagesize)
    else:
        pages = int(total / pagesize) + 1
    return {
        "code": 200,
        "data": {'records': page_data, "total": total, "current": page, "pagesize": pagesize, "pages": pages},
        "msg": "请求成功"

    }

# 获取define的值
@root.get('/define/{key}')
async def get_define(key: str, request: Request, response: Response,
                     fbi_session: str = Query(None), ):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    value = get_key(key)

    return {'code': 200, 'data': {'value': value}, 'msg': '成功'}


PK = ""


# 获取PK码
@root.get('/PK')
async def get_PK(request: Request, response: Response,
                 fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    global PK
    if PK == "":
        PK = get_key("PK")

    return {'code': 200, 'data': {'PK': PK}, 'msg': '成功，生成的PK为%s' % (PK)}


# 所有用户信息
@root.get('/list_user')
async def list_user(request: Request, response: Response, fbi_session: str = Query(None)):
    try:
        user = check_isadmin(request, fbi_session)
    except Exception as e:
        return e.__str__()
    users = fbi_user_mgr.get_all_user2(user)

    return {"code": 200, "data": users, "msg": "成功"}


# 单个用户信息
@root.get('/get_user/{name}')
async def list_user_by_name(name, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    res = fbi_user_mgr.get_user_by_name(name)

    return {"code": 200, "data": res, "msg": "成功"}


# 管理的验证
@root.post('/auth')
async def post_auth(request: Request, response: Response, item: dict):
    # auth认证的实体函数,登录开发平台
    return auth(request, response, item)


def auth(request, response, item):
    try:
        failed_session = get_key2("failed_session") or "60"
        # 登陆失败重试次数
        retry_count = get_key2("retry_count") or "3"
        fail_key = "FAIL:%s" % (request.client.host)
        fail_cnt = ssdb0.get(fail_key)
        try:
            retry_count = int(retry_count)
        except:
            retry_count = 3
        user = item
        pwd = user["auth_key"]
        pwd = base64.b64decode(pwd).decode("utf8")
        pwd = str(pwd).strip()
        if fail_cnt != None and int(fail_cnt) >= retry_count:
            log_session(user["name"], request.client.host,
                        "".join(";%s" % (request.url.path)), "登录", "平台", \
                        "user:%s " % (user["name"]), "失败",
                        "连续[%s]次登录失败,请过会再试!" % (retry_count))
            raise Exception("连续登录失败,请过会再试!")

        if len(pwd) < 8:
            log_session(user["name"], request.client.host,
                        ";".join(";%s" % (request.url.path)), "登录", "平台", \
                        "user:%s,auth_key:%s" % (user["name"], pwd), "失败",
                        "验证失败，密码小于8位!")
            raise Exception("验证失败，密码小于8位!")
        auth_code = fbi_user_mgr.auth_user(user["name"], pwd,
                                           request.client.host)
        if auth_code == 1:
            # 设置cookie
            # 返回portal和nav
            ret = fbi_user_mgr.get_user_by_name(user["name"])
            # 获取session
            session = get_session_id(user["name"])
            key = "fbi_session:%s" % (session)
            # add by gjw on 2022-0213　可以有多个相同用户同时登录后台
            user_sessions = "user_session:{}:{}".format(user["name"],
                                                        session)

            # add by gjw on 2022-0519 返回eng
            eng = fbi_eng_mgr.get_user_eng(user["name"])

            ssdb0.set(key, user["name"] + ":" + ret["isadmin"])
            ssdb0.set(user_sessions, session)
            ssdb0.expire(key, itimeout)
            ssdb0.expire(user_sessions, itimeout)

            response.set_cookie("fbi_session", session, max_age=itimeout,
                                path="/")
            response.set_cookie("eng", eng, max_age=itimeout, path="/")
            response.set_cookie("work_space", "public", max_age=itimeout,
                                path="/")

            log_session(user["name"], request.client.host,
                        "".join(request.url.path), "登录", "平台", \
                        "user:%s" % (user["name"]), "成功", "")
            return {"code": 200, "data": {"success": True, "fbi_session": session}, "msg": "登录成功"}

        elif auth_code == 0:
            log_session(user["name"], request.client.host,
                        "".join(";%s" % (request.url.path)), "登录", "平台",
                        "user:%s,auth_key:%s" % (user["name"], pwd), "失败",
                        "验证失败，请确认用户名和密码有效再登录!")
            raise Exception("验证失败，请确认用户名和密码有效再登录!")
        else:
            log_session(user["name"], request.client.host,
                        "".join(";%s" % (request.url.path)), "登录", "平台",
                        "user:%s " % (user["name"]), "失败",
                        "验证失败，您的ip不允许登陆该账户!")
            raise Exception("验证失败，您的ip不允许登陆该账户!")
    except Exception as e:

        try:
            # add by gjw on 20180302
            if ssdb0.exists(fail_key) == "0":  # 不存在
                ssdb0.set(fail_key, 1)
                ssdb0.expire(fail_key, 50)
            else:
                ssdb0.incr(fail_key, 1)  # 存在加1
                ssdb0.expire(fail_key, 50)
        except Exception as e2:
            return {"code": 204, "data": {"success": "false"}, "msg": "认证出错:%s-%s" % (e, e2)}
        return {"code": 202, "data": {"success": "false", "failed_session": "%s" % (failed_session)}, "msg": "%s" % (e),
                'traceback': "{}".format(traceback.format_exc())}


# add by gjw on 20200201, 集群添加节点
@root.post('/addnode')
async def addnode(item: dict, request: Request, response: Response):
    d = {"ret": -1}
    datas = item["data"]
    data = New_decrypt(CK, datas)
    host, user, passwd = data.split(",")
    auth_code = fbi_user_mgr.auth_user(user.strip(), passwd.strip(), request.client.host)
    if auth_code == 1:
        d["ret"] = 0
        # 生成之后run的秘钥 sha1(data+当前日期)
        AK = my_hash(data)
        name = item["name"]
        add_master(name, request.client.host, AK, user)
        d["AK"] = New_encrypt(CK, AK)
        d["msg"] = "添加节点成功!"
        loglog(user, request.client.host, ";".join(request.url.path), "集群认证", "后台系统", \
               "添加节点成功!user:%s" % (user), "成功", "")
    elif auth_code == 0:
        d["msg"] = "验证失败，请确认用户名和密码有效再添加!"
        loglog(user, request.url.host, ";".join(request.url.path), "集群认证", "后台系统", \
               "user:%s,auth_key:%s" % (user, passwd), "失败", d["msg"])
    else:
        d["msg"] = "验证失败，您的ip不允许登陆该账户!"
        loglog(user, request.client.host, ";".join(request.url.path), "集群认证", "后台系统", \
               "user:%s,auth_key:%s" % (user, passwd), "失败", d["msg"])
    return d


# add by gjw on 20200201, 集权节点运行远程任务,结果信息在是完整加密的json内容，确保对方的身份
@root.post('/node')
async def node_run(request: Request, response: Response,
                   item: dict, ):
    d = {"ret": -1}
    datas = item["data"]
    node = item["name"]
    eng = item["eng"]
    block = item["blocks"]
    node_info = get_master_by_name(node)
    if node_info == None:
        d["msg"] = "[%s]节点信息在远程找不到!" % (node)
        return New_encrypt(node_info[1], json.dumps(d))
    if node_info[0] != request.client.host:
        d["msg"] = "[%s]master主机信息不匹配!" % (request.client.host)
        return New_encrypt(node_info[1], json.dumps(d))
    try:
        data = New_decrypt(node_info[1], datas)
    except:
        d["msg"] = "不能识别的通信回话!"
        return New_encrypt(node_info[1], json.dumps(d))
    # 运行
    if eng == "0":  # 同步执行
        d = local_runp("127.0.0.1", eng, data, "public", node_info[2])
    elif block == "block":
        d = local_run_block("127.0.0.1", eng, data, "public", node_info[2])
    elif eng == "9000":  # 采用本地定时调度引擎执行， 2022-0318

        put_timer("{}_{}".format(node, time.time()), "* * * * * *", data)
        d["ret"] = 0
        d["error"] = ""
        d["result"] = []
    else:  # 异步执行
        d = local_run("127.0.0.1", eng, data, "public", node_info[2])

    if "result" in d and isinstance(d["result"], list) and len(d["result"]) > 0:
        d["result"][0]["TI"] = "%s:%s" % (d["result"][0]["TI"], node)
    return New_encrypt(node_info[1], json.dumps(d))


# add by gjw on 20211224, 集权节点ssdb交互
@root.post('/ssdb_rw')
async def ssdb_rw(request: Request, response: Response, item: dict):
    from avenger.fio import load_data_by_ssdb, store_to_ssdb
    d = {"ret": -1}
    datas = item["ptree"]
    node = item["name"]

    node_info = get_master_by_name(node)
    if node_info == None:
        d["msg"] = "[%s]节点信息在远程找不到!" % (node)
        return New_encrypt(node_info[1], json.dumps(d))
    if node_info[0] != request.client.host:
        d["msg"] = "[%s]master主机信息不匹配!" % (request.client.host)
        return New_encrypt(node_info[1], json.dumps(d))
    try:
        data = New_decrypt(node_info[1], datas)
    except:
        d["msg"] = "不能识别的通信回话!"
        return New_encrypt(node_info[1], json.dumps(d))
    # 正式业务处理
    try:
        d["ret"] = 0
        ptree = json.loads(data)
        key = b64(ptree["with"])
        if ptree["Action"] == "load":
            value = ssdb0.get(key)
            if value != None:
                d["data"] = value
        elif ptree["Action"] == "store":
            ssdb0.set(key, ptree["data"])
            if "as" in ptree:
                ssdb0.expire(key, int(ptree["as"]))
        else:
            d["msg"] = "不能识别的原语!"
    except:
        d["ret"] = -1
        d["msg"] = "原语执行出错"

    return New_encrypt(node_info[1], json.dumps(d))


# 使用队列记录操作日志
def loglog(user, ip, route, action, nav, params, result, reason):
    d = {}
    d["user"] = user
    d["remote_addr"] = ip
    d["remote_route"] = route,
    d["timestamp"] = datetime.now().isoformat()
    d["action"] = action
    d["nav_name"] = nav
    d["params"] = params
    d["operate_result"] = result
    d["failed_reason"] = reason
    ssdb0.qpush("Q_log_%s" % (d["timestamp"][0:10]), json.dumps(d))


# 使用队列记录回话日志（登录和登出）
# add 登录登出会同时记录到操作日志中
def log_session(user, ip, route, action, nav, params, result, reason):
    d = {}
    d["user"] = user
    d["remote_addr"] = ip
    d["remote_route"] = route,
    d["timestamp"] = datetime.now().isoformat()
    d["action"] = action
    d["nav_name"] = nav
    d["params"] = params
    d["operate_result"] = result
    d["failed_reason"] = reason
    ssdb0.qpush("Q_log2_%s" % (d["timestamp"][0:10]), json.dumps(d))
    ssdb0.qpush("Q_log_%s" % (d["timestamp"][0:10]), json.dumps(d))


# add by gjw on 20200319,获取登录token
@root.get('/login_token')
async def get_token():
    token = random.randint(0, 1000)
    key = "token:%s:%s" % (request.remote_addr, token)
    ssdb0.set(key, "Y")
    ssdb0.expire(key, 1800)
    return '{"token":%s}' % (token)
    # return json.loads('{"token":%s}' % (token))


# 门户的验证
@root.post('/auth2')
async def post_auth2(item: dict, request: Request, response: Response):
    return auth2(item, request, response)


# auth2认证的实体函数
def auth2(item, request, response):
    try:
        # modify by gjw on 2021-0315 登录失败锁定时间
        lock_times = get_key2("failed_session") or "60"
        try:
            lock_times = int(lock_times)
        except:
            lock_times = 60
        # 登陆失败重试次数
        retry_count = get_key2("retry_count") or "3"
        try:
            retry_count = int(retry_count)
        except:
            retry_count = 3

        fail_key = "FAIL:%s" % (request.client.host)
        fail_cnt = ssdb0.get(fail_key)

        user = item
        pwd = user["auth_key"]
        # pwd = item.auth_key
        pwd = base64.b64decode(pwd).decode("utf8")
        pwd = pwd.strip()
        if fail_cnt != None and int(fail_cnt) >= retry_count:
            log_session(item.name, request.client.host, "".join(";%s" % (request.url.path)), "登录", "应用", \
                        "user:%s " % (item.name), "失败", "连续[%s]次登录失败,请过会再试!" % (retry_count))
            raise Exception("连续登录失败,请过会再试!")

        if len(pwd) < 6:
            log_session(item.name, request.client.host, "".join(";%s" % (request.url.path)), "登录", "应用", \
                        "user:%s,auth_key:%s" % (item.name, pwd), "失败", "验证失败，密码小于6位!")
            raise Exception("验证失败，请确认用户名和密码有效再登录!")
        auth2_code = fbi_user_mgr.auth2_user(user["name"], pwd, request.client.host)
        if auth2_code == 1:
            # 返回portal和nav,其实是port和app
            ret = fbi_user_mgr.get_user_by_name(user["name"])
            # max_age=itimeout,
            if ret["nav"] == "":
                raise Exception("没有指定的应用，无法登录!")

            # 获取session
            session = get_session_id(user["name"])
            key = "fbi_session:%s" % (session)

            # add by gjw on 2022-0516 记录用户最后的会话
            last_Key = "{}:last_fbisession".format(user["name"])
            last_session = ssdb0.get(last_Key)
            if last_session != None and last_session != "":
                ssdb0.delete("fbi_session:%s" % (last_session))

            ssdb0.set(last_Key, session)
            ssdb0.set(key, user["name"] + ":" + ret["isadmin"])
            ssdb0.expire(key, itimeout)

            # add by gjw on 2020-1222 增加系统规则的生成函数
            build_sysrule(ssdb0, ret)

            # add by gjw on 2022-0519
            if ret["isadmin"] == "Y":
                eng = fbi_eng_mgr.get_user_eng(user["name"])
            else:
                eng = ""

            response.set_cookie("fbi_session", session, path="/")
            response.set_cookie("eng", eng, path="/")
            response.set_cookie("work_space", "public", path="/")
            log_session(
                user["name"],
                request.client.host,
                "".join(request.url.path),
                "登录",
                "应用",
                "user:%s,isDev:%s,eng:%s,app:[%s]" % (
                    user["name"], ret.get('isadmin', ''), ret.get('pot', ''), ret.get('nav', '')),
                "成功",
                ""
            )
            return {"code": 200,
                    "data": {"success": True, "fbi_session": session, "portal": eng, "nav": ret.get('nav', '')},
                    "msg": "成功"}
        elif auth2_code == 0:
            log_session(
                user["name"],
                request.client.host,
                "".join(";%s" % (request.url.path)),
                "登录",
                "应用",
                "user:%s,auth_key:%s" % (user["name"], pwd),
                "失败",
                "验证失败，请确认用户名和密码有效再登录!"
            )
            raise Exception("验证失败，请确认用户名和密码有效再登录!")
        else:
            log_session(
                user["name"],
                request.client.host,
                "".join(";%s" % (request.url.path)),
                "登录",
                "应用",
                "user:%s" % (user["name"]),
                "失败",
                "验证失败，您的ip不允许登陆该账户!"
            )
            raise Exception("验证失败，您的ip不允许登陆该账户!")
    except Exception as e:
        try:
            # add by gjw on 20180302()
            if ssdb0.exists(fail_key) == "0":  # 不存在
                ssdb0.set(fail_key, 1)
                ssdb0.expire(fail_key, lock_times)
            else:
                ssdb0.incr(fail_key, 1)  # 存在加1
                ssdb0.expire(fail_key, lock_times)
        except Exception as e2:
            return {"code": 204, "data": {"success": False, "failed_session": "{}".format(traceback.format_exc())},
                    "msg": "应用认证出错:{}-{}".format(e, e2)}
        return {"code": 202, "data": {"success": False}, "msg": "{}".format(e)}


# get SN码
@root.get('/verify_SN')
async def get_SN(request: Request, response: Response,
                 fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    sn = get_key("SN")
    if sn == "":
        return get_key("PK")
    else:
        return {"code": 200, "data": {"success": "true"}, "msg": "成功"}


# 授权状态
@root.get('/aks')
async def get_aks(request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    x = get_key("PK")
    y = get_key("SN")
    aks = yyy(x, y)
    return "'code':200, 'data':{'state':%s}, 'msg':'成功'" % (aks[0])


# 授权状态
@root.get('/days')
async def get_days(request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    days = have_days()
    return "'code':200, 'data':{'days':%s}, 'msg':'成功'" % (days)


file_path = {
    "data": "../workspace/",
    "udf": "udf/",
    "fbi": "script/",
    "xlink": "script/xlinks/",
    "ffdb": "ffdb/",
    "lib": "lib/",
    "tpl_word": "../workspace/temp_word/"
}


# 给所有引擎发重新装载脚本的信号
def send_reload_signal_to_all(fastbi_file):
    with open("/dev/shm/fastbi_file", "w+") as f:
        f.write(fastbi_file)
    try:
        with open('/dev/shm/fbi_stats', 'r') as f:
            a = f.read()
        a_json = json.loads(a)
    except:
        a_json = {"engs": []}
    for eng in a_json["engs"]:
        for k, v in eng.items():
            try:
                os.kill(v["pid"], signal.SIGUSR2)
            except Exception as e:
                # logger.waring("send_signal_to_all has error,%s "%(e))
                pass
    with open('/dev/shm/fbi-gateway', 'r') as f2:
        lines = f2.readlines(1024)
        for pid in lines[1:]:
            try:
                os.kill(int(pid), signal.SIGUSR2)
            except:
                pass


# end function


# 新建XLink脚本
@root.post('/putxlink')
async def put_xlink(item: dict, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:

        # ID = request.params.get("ID")
        # meta_name = request.params.get('meta_name')
        # meta_desc = request.params.get('meta_desc')
        cfg = item

        with open(file_path["fbi"] + "system/xlink.md") as f:
            xlink = f.read()
        with open(file_path["xlink"] + cfg["ID"] + ".xlk", "w") as f:
            f.write(xlink.format(ID=cfg["ID"], meta_name=cfg["meta_name"], meta_desc=cfg["meta_desc"]))
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 上传文件 rzc
@root.post('/putfile')
async def putfile(request: Request, response: Response,filetype : str = Form(None),subdir: str = Form(None), fbi_session: str = Query(None),
                  file: UploadFile = File(...)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        ftype = filetype
        subdir = subdir or ""
        # form_data = await request.form()
        upload = file
        nums = upload.filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        suffix = upload.filename[nums:]
        if suffix not in [".csv", ".txt", ".json", ".zip", ".gz", ".xls", ".xlsx", ".pkl", ".db", ".pyc"
                                                                                                  ".bz2", ".dat",
                          ".mmdb", ".data", ".jpg", ".png", ".jpeg", ".ttc",
                          ".py", ".xml", ".rar", ".pdf", ".fbi", ".list", ".rules", ".xlk", ".xz"]:
            raise Exception("非法的文件格式！")
        if suffix == ".xlk":
            subdir = "xlinks/"
            save_path = os.path.join(file_path[ftype], subdir, upload.filename)

            with open(save_path, "wb") as buffer:
                data = upload.file.read()
                buffer.write(data)
            # os.rename(file_path[ftype] + subdir + upload.filename, file_path[ftype] + subdir + upload.filename)
            from avenger.xlink import compile_xlk
            try:
                compile_xlk(subdir + upload.filename)
            except Exception as e:
                raise Exception("%s xlink文件出错 %s" % (upload.filename, e))
        else:
            save_path = os.path.join(file_path[ftype], subdir, upload.filename)
            with open(save_path, "wb") as buffer:
                data = upload.file.read()
                buffer.write(data)
            # os.rename(file_path[ftype] + subdir + upload.filename, file_path[ftype] + subdir + upload.filename)
        if ftype == "fbi":
            try:
                compile_fbi(subdir + upload.filename)
                send_reload_signal_to_all(upload.filename)
            except Exception as e:
                raise Exception("%s 编译出错 %s" % (subdir + upload.filename, e))
        elif ftype == "lib":
            import subprocess
            ret = subprocess.call(
                ["tar", "-xvf", file_path[ftype] + subdir + upload.filename, "-C", file_path[ftype]])
        else:
            pass
        return {"code": 200, "data": {"success": True}, "msg": "上传成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 上传文件
# @root.post('/putfile')
# async def putfile(item: dict, request: Request, response: Response, fbi_session: str = Query(None),
#                   jUploaderFile: UploadFile = File(...)):
#     try:
#         ret = check_session(request, response, fbi_session)
#         if ret != 0:
#             return {'code': 403, 'msg': '%s' % (ret)}
#         ftype = item["filetype"]
#         subdir = item["subdir"] or ""
#         form_data = await request.form()
#         upload = form_data.get("jUploaderFile")
#
#         nums = upload.raw_filename.rfind(".")
#
#         if (nums == -1): raise Exception("非法的文件!")
#         suffix = upload.raw_filename[nums:]
#
#         if suffix not in [".csv", ".txt", ".json", ".zip", ".gz", ".xls", ".xlsx", ".pkl", ".db", ".pyc"
#                                                                                                   ".bz2", ".dat",
#                           ".mmdb", ".data", ".jpg", ".png", ".jpeg", ".ttc",
#                           ".py", ".xml", ".rar", ".pdf", ".fbi", ".list", ".rules", ".xlk", ".xz"]:
#             raise Exception("非法的文件格式！")
#         # print ftype,upload.filename,upload.raw_filename,type(upload.raw_filename)
#         if suffix == ".xlk":
#             subdir = "xlinks/"
#             upload.save(file_path[ftype] + subdir, True)
#             os.rename(file_path[ftype] + subdir + upload.filename, file_path[ftype] + subdir + upload.raw_filename)
#             from avenger.xlink import compile_xlk
#             try:
#                 compile_xlk(subdir + upload.raw_filename)
#             except Exception as e:
#                 raise Exception("%s xlink文件出错 %s" % (upload.raw_filename, e))
#         else:
#             upload.save(file_path[ftype] + subdir, True)
#             os.rename(file_path[ftype] + subdir + upload.filename, file_path[ftype] + subdir + upload.raw_filename)
#         if ftype == "fbi":
#             try:
#                 compile_fbi(subdir + upload.raw_filename)
#                 send_reload_signal_to_all(upload.raw_filename)
#             except Exception as e:
#                 raise Exception("%s 编译出错 %s" % (subdir + upload.raw_filename, e))
#         elif ftype == "lib":
#             import subprocess
#             ret = subprocess.call(
#                 ["tar", "-xvf", file_path[ftype] + subdir + upload.raw_filename, "-C", file_path[ftype]])
#         else:
#             pass
#         return {'success': 0, 'file_name': '%s' % (subdir + upload.raw_filename)}
#     except Exception as e:
#
#         return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


image_path = "/opt/openfbi/mPig/html/images/logo/"


# 上传logo图片
@root.post('/putfile2')
async def putfile2(
        request: Request,
        response: Response,
        fbi_session: str = Query(None),
        portal: str = Query(None),
        name: str = Form(...),
        jUploaderFile: UploadFile = File(...)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        form_date = await request.form()
        portal = request.query_params.get("portal")
        upload = form_data.get("jUploaderFile")
        nums = upload.raw_filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        upload.save(image_path, True)
        os.rename(image_path + upload.filename, image_path + portal + ".gif")
        return {"code": 200, 'data': {"success": True}, "msg": "成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 上传图片
@root.post('/putfile3')
async def putfile3(request: Request, response: Response,
                   fbi_session: str = Query(None),
                   jUploaderFile: UploadFile = File(...)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        form_date = await request.form()
        ret = {"success": True}
        upload = form_data.get("jUploaderFile")
        nums = upload.raw_filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        if upload.raw_filename[nums:] not in [".gif", ".png", ".jpeg", ".jpg"]:
            raise Exception("非法的文件格式！")
        upload.save(image_path, True)
        ret["filename"] = upload.filename
        df = {"index": [1], "columns": ["image"], "data": [["/images/logo/" + ret["filename"]]]}
        ssdb0.set("IMG:" + ret["filename"], json.dumps(df))
        return {"code": 200, "data": ret, "msg": "成功"}
    except Exception as e:

        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 上传文件
@root.post('/putfile4')
async def putfile4(item: dict, request: Request, response: Response,
                   fbi_session: str = Query(None),
                   jUploaderFile: UploadFile = File(...)):
    # 加上时间标记的文件
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        a = int(time.time())
        form_date = request.form()
        ftype = item["filetype"]
        subdir = item["subdir"] or ""
        upload = form_date.get('jUploaderFile')
        nums = upload.raw_filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        if upload.raw_filename[nums:] not in [".gif", ".png", ".jpeg", ".jpg"]:
            raise Exception("非法的文件格式！")
        upload.save(file_path[ftype] + subdir, True)
        new_name = upload.raw_filename[0:nums] + "_" + str(a) + upload.raw_filename[nums:]
        os.rename(file_path[ftype] + subdir + upload.filename, file_path[ftype] + subdir + new_name)
        return {'code': 200, 'success': 0, 'file_name': '%s' % (subdir + new_name), 'msg': '成功'}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 复制脚本
@root.post('/cp_fbi')
async def copy_script(item: dict, request: Request, response: Response,
                      fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        check_isadmin(request, fbi_session)

        src_file = item["src"]
        name = item["obj"]
        syss = ["crud", "word_temp", "user_man", "oper_log", "es7_query", "dict"]
        if src_file.find("--") > 0:
            dir_v = src_file.split("--")[0]
            if dir_v in syss:
                src_file = "system/" + src_file
        src_file = src_file.replace("--", "/")
        if name.find("--") > 0:
            os.makedirs(file_path["fbi"] + "/".join(name.split("--")[0:-1]), exist_ok=True)
            name = name.replace("--", "/")
        #return {"src":src_file,"name":name}
        shutil.copy(file_path["fbi"] + src_file, file_path["fbi"] + name)
        compile_fbi(name)
        #send_reload_signal_to_all(name)
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}

# 复制docx文件
@root.post('/cp_template')
async def copy_work(item: dict, request: Request, response: Response,
                    fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        check_isadmin(request, fbi_session)

        src_file = item["src"]
        name = item["obj"]
        syss = ["crud", "word_temp", "user_man", "oper_log", "es7_query", "dict"]
        if src_file.find("--") > 0:
            dir_v = src_file.split("--")[0]
            if dir_v in syss:
                src_file = "system/" + src_file
        src_file = src_file.replace("--", "/")  # flfj_report/template.docx
        if name.find("--") > 0:
            os.makedirs(file_path["tpl_word"] + "/".join(name.split("--")[0:-1]),
                        exist_ok=True)  # ../workspace/temp_word/cehsirzc/template.docx
            name = name.replace("--", "/")  # wordtpl_cehsirzc/make_tpl.fbi
        # return {"src":src_file,"name":name}
        shutil.copy(file_path["tpl_word"] + src_file, file_path[
            "tpl_word"] + name)  # ../workspace/temp_word/flfj_report/template.docx, /workspace/temp_word/cehsirzc/template.docx
        # compile_fbi(name)
        # send_reload_signal_to_all(name)
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# defines的编辑
@root.post('/DFEditing')
async def post_DFEditing(item: dict,
                         request: Request,
                         response: Response,
                         fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        oper = item["oper"]
        if oper == "del":
            key = item["id"]
            value = ""
        else:
            key = item["key"]
            value = item["value"]
        session = request.query_params["fbi_session"] or request.query_params["fbi_session"] or request.cookies.get(
            "fbi_session")
        put_key(key, value, "as", get_user_by_session(session)[0])
        return {"code": 200, "data": {"success": True}, "msg": "编辑成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 在线编辑，保存代码
@root.post('/put_fbi')
async def put_fbi(item: dict,
                  request: Request,
                  response: Response,
                  fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        user = check_isadmin(request, fbi_session)

        req = item
        name = req["name"]
        
        if name[0] == '"' and name[-1] == '"':
            name = name[1:-1]
        if name.startswith("-"): raise Exception("文件名不合法!")
        if name.startswith("/"): raise Exception("文件名不合法!")
        if name.find("..") > 0: raise Exception("文件名不合法!")

        data = req["data"]
        data = base64.b64decode(data.encode("utf8")).decode("utf8")
        #return {"name":name,"data":data}
        if name.find("--") > 0:
            os.makedirs(file_path["fbi"] + "/".join(name.split("--")[0:-1]), exist_ok=True)
            os.makedirs(file_path["ffdb"] + "/".join(name.split("--")[0:-1]), exist_ok=True)
            name = name.replace("--", "/")
        nums = name.rfind(".")
        if (nums == -1): raise Exception("不能识别的脚本文件!")
        # if name[nums:] not in [".fbi",".xlk"] :raise Exception("文件名不合法,只能以.fbi或.xlk结尾!")

        # add by gjw on 2021-0820
        if name.startswith("system"):
            raise Exception("系统脚本,不能在线编辑! [%s]" % (name))

        now = datetime.now().isoformat()
        # add by gjw on 2020　考虑增加脚本的版本问题
        if os.path.exists(file_path["fbi"] + name):
            shutil.copy(file_path["fbi"] + name, file_path["ffdb"] + name + "_" + now)
        
        with open(file_path["fbi"] + name, "wb+") as f:
            f.write("#LastModifyDate:　{}    Author:   {}\n".format(now, user).encode("utf8"))
            f.write(data.encode("utf8"))
        #return {"name":name[nums:]}
        if name[nums:] == ".xlk":
            from avenger.xlink import compile_xlk
            compile_xlk(name)
        else:
            compile_fbi(name)
            #send_reload_signal_to_all(name)
        # "保存成功"})
        return {"code": 200, "data": {"success": True}, "msg": "保存成功"}
    except Exception as e:
        # "保存出错: "+e.__str__()})
        return {'code': 500, "data": {'success': False}, 'msg': "保存出错: " + e.__str__()}


# #上传模板文件
@root.post('/put_tempfile')
async def post_tempfile(filetype: str = Form(None), subdir: str = Form(None),
                        fbi_session: str = Query(None),
                        file: UploadFile = File(...)):
    try:
        # ret = check_session(request, response,fbi_session)
        # if ret != 0:
        #   return {'code': 403, 'msg': '%s' % (ret)}

        upload = file
        ftype = filetype
        nums = upload.filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        destDir = file_path[ftype] + subdir
        dest_abs_dir = os.path.abspath(destDir)
        if not os.path.exists(dest_abs_dir):
            os.makedirs(dest_abs_dir)
        else:
            shutil.rmtree(dest_abs_dir)
            os.makedirs(dest_abs_dir)
        # print ftype,upload.filename,upload.raw_filename,type(upload.raw_filename)
        # upload.save(file_path[ftype] + subdir, True)
        data = upload.file.read()
        with open(file_path[ftype] + subdir + upload.filename, "wb+") as f:
            f.write(data)

        filename2 = file_path[ftype] + subdir + upload.filename
        import zipfile
        zf = zipfile.ZipFile(filename2)
        if not ("".join(zf.namelist()).endswith(".docx")):
            shutil.rmtree(dest_abs_dir)
            raise Exception("上传的压缩包必须是docx文件")
        try:
            zf.extractall(path=destDir)
        except RuntimeError as e:
            root_logger.error("zipfile extra error: %s" % (e))
        name1 = file_path[ftype] + subdir + "".join(zf.namelist())
        name2 = file_path[ftype] + subdir + "template.docx"
        os.rename(name1, name2)
        zf.close()
        return {"code": 200, "data": {"success": True}, "msg": "上传成功"}
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__(),
                'traceback': "{}".format(traceback.format_exc())}


"""
上传单个图片文件也可以上传图片压缩包zip
"""


@root.post('/put_files')
async def put_images(request: Request, response: Response,
                     fbi_session: str = Query(None),
                     jUploaderFile: UploadFile = File(...), ):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        ret = {"success": True}
        form_date = request.form()
        upload = form_date.get('jUploaderFile')

        nums = upload.raw_filename.rfind(".")
        if (nums == -1): raise Exception("非法的文件!")
        if upload.raw_filename[nums:] not in [".gif", ".png", ".jpeg", ".jpg", ".zip"]:
            raise Exception("非法的文件格式！")
        image_names = []
        # 创建一个临时文件夹来处理zip包解压动作
        source_dir = os.path.join(image_path, 'temp_{}'.format(str(int(time.time()))))
        os.makedirs(source_dir)
        # 保存用户上传的zip包
        upload.save(source_dir)
        zip_name = upload.filename
        zip_path = os.path.join(source_dir, zip_name)

        if zipfile.is_zipfile(zip_path):
            # 解压用户上传的zip包
            shutil.unpack_archive(os.path.join(source_dir, zip_name), source_dir)
            # 将图片保存到logo文件夹下面
            for fn in os.listdir(source_dir):
                if fn != zip_name:
                    fp = os.path.join(source_dir, fn)
                    if os.path.isdir(fp):
                        for c in os.listdir(fp):
                            try:
                                shutil.copy2(os.path.join(fp, c), image_path)
                                image_names.append(c)
                            except:
                                pass
                    elif os.path.isfile(fn):
                        shutil.copy2(fp, image_path)
                        image_names.append(fn)
        else:
            shutil.copy2(zip_path, image_path)
            image_names.append(zip_name)
        # 清理
        shutil.rmtree(source_dir)
        ret["filename"] = image_names
        return ret
    except Exception as e:
        ret["success"] = False
        ret["error"] = e.__str__()
        return ret


# 保存登录配置
@root.post('/put_login')
async def post_put_login(item: dict,
                         request: Request,
                         response: Response,
                         fbi_session: str = Query(None)):
    try:
        # add by gjw on 20180422
        ret = check_session(request, response)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        data = item["data"]
        f = open("/opt/openfbi/mPig/html/bi/login.json", "wb+")
        f.write(data.encode("utf8"))
        f.close()
        return "<font color='white'>保存成功</font>"
    except Exception as e:
        return "<font color='red'>保存失败,%s</font>" % (e)


# 更新cookie
@root.post('/ch_cookie', response_class=HTMLResponse)
async def ch_cookie(item: dict, request: Request, response: Response,
                    fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        name = item["k"]
        data = item["v"]
        response.set_cookie(name, data, path="/")
        return ""
    except Exception as e:
        return "<font color='red'>失败,%s</font>" % (e)


@root.post('/run_block')
async def post_run_block(item: dict, request: Request, response: Response,
                         fbi_session: str = Query(None)):
    session = request.cookies.get("fbi_session")
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    server = "127.0.0.1"

    port = item.get("eng") or request.cookies.get("eng") or "9002"

    # 原语
    block_code = item.get("block")
    block_code = base64.b64decode(block_code.encode("utf8")).decode("utf8")
    # 处理中文工作区
    work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
    if work_space[0] == '"' and work_space[-1] == '"':
        work_space = work_space[1:-1]

    if server == "127.0.0.1":
        # 本地直接执行需要的是用户，add by gjw on 20171006
        d = local_run_block(server, port, block_code, work_space, get_user_by_session(session)[0])
    else:
        # remote_run 会调用远程机器的remote_run,所以需要session
        d = local_run_block(server, port, block_code, work_space, session)

    d["server"] = server
    d["port"] = port

    if "work_space" in d:
        response.set_cookie("work_space", d["work_space"])
    response.set_cookie("eng", port)
    if "name" in d:
        response.set_cookie("cur_df", d["name"])
    return {"code": 200, "data": d, "msg": "成功"}


@root.post('/run_blocks')
async def post_run_blocks(item: dict, request: Request, response: Response,
                          fbi_session: str = Query(None)):
    # add by gjw on 20200915 增加对后台引擎的同步代码块执行功能
    session = item.get("fbi_session") or request.cookies.get("fbi_session")
    ret = check_session(request, response, fbi_session)

    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    server = "127.0.0.1"
    port = item.get("eng") or request.cookies.get("eng") or "9002"

    # 原语
    block_code = item.get("block")
    block_code = base64.b64decode(block_code.encode("utf8")).decode("utf8")
    # 处理中文工作区
    work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
    if work_space[0] == '"' and work_space[-1] == '"':
        work_space = work_space[1:-1]

    d = local_run_blocks(server, port, block_code, work_space, get_user_by_session(session)[0])

    d["server"] = server
    d["port"] = port

    if "work_space" in d:
        response.set_cookie("work_space", d["work_space"])
    response.set_cookie("eng", port)
    if "name" in d:
        response.set_cookie("cur_df", d["name"])
    return {"code": 200, "data": d, "msg": "请求成功"}


@root.post('/run_blockp')
async def post_run_blockp(item: dict, request: Request, response: Response,
                          fbi_session: str = Query(None)):
    try:
        session = request.cookies.get("fbi_session")
        # add by gjw on 20170304,是否验证登录身份
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        # 原语
        # block_code = request.json.getter("block")
        block_code = item.get("block")
        block_code = base64.b64decode(block_code.encode("utf8")).decode("utf8")
        # 处理中文工作区
        # work_space = request.json.getter("work_space") or request.cookies.work_space or "public"
        work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
        if work_space[0] == '"' and work_space[-1] == '"':
            work_space = work_space[1:-1]
        ret, error, datas = run_block_in_sync(block_code, work_space, get_user_by_session(session)[0])

        datas2 = {}
        for k, v in datas.items():
            datas2[k] = json.loads(v)
        end = time.time()

        d = {"code": 200,
             "data": {"prmtv": "", "ret": ret, "error_info": error, 'error_count': ret, "action": 0, "result": [],
                      "datas": datas2}, "msg": "成功"}
        if "work_space" in d:
            response.set_cookie("work_space", d["work_space"])
        return d
    except Exception as e:
        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 显示工作区的数据文件
@root.get('/list_data')
async def list_data(request: Request, response: Response,
                    fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    a = os.listdir(file_path['data'])
    b = copy.copy(a)
    for f in b:
        if f.find(".") == 0:
            a.remove(f)
    a.sort()
    # d = {"data": a}
    d = []
    for i in a:
        c = dict.fromkeys(['list_data_name'], i)
        d.append(c)
    return {"code": 200, "data": d, "msg": "请求成功"}


# Fbi文件的历史列表
@root.get('/history_fbi')
async def fbi_history(request: Request, response: Response,
                      fbi_session: str = Query(None),
                      filename: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    filename = filename.replace("--", "/")
    a = []
    for filepath in glob.glob(file_path['ffdb'] + "/" + filename + "*"):
        a.append(filepath)

    a.sort(reverse=True)
    return {"code": 200, "data": a, "msg": "请求成功"}


# 返回Fbi文件的历史版本内容
@root.get('/version_fbi')
async def fbi_version(request: Request, response: Response,
                      fbi_session: str = Query(None),
                      filename: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    # filename = request.query_params["filename"]
    try:
        with open(filename, "r") as f:
            a = f.read()
        return {'code': 200, "data": a, 'msg': "请求成功"}
    except Exception as e:

        return {'code': 500, "data": {'success': False}, 'msg': e.__str__()}


# 显示工作区的数据文件
@root.post('/list_data2')
async def list_data2(item: dict, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = item.get("fbi_session") or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    # 开始
    pids = {}
    ids = []
    no_access_dirs = []  # 不能访问的目录
    i = 0
    ids.append({"id": i, "pId": i, "name": "数据目录", "open": "true", "dir_name": "/", "chkDisabled": "true"})
    pids[file_path['data']] = i
    i += 1
    page = item['page']
    pagesize = item['pagesize']
    for path, d, files in os.walk(file_path['data'], True):
        d.sort()
        for name in d:
            dir_name = os.path.join(path, name)[len(file_path['data']):] + "/"
            real_path = os.path.join(path, name)
            if name.find("__") == 0 and name[2:] != user and user != "superFBI":  # 不是自己的私有目录不能添加，superFBI可以看全部
                no_access_dirs.append(os.path.join(path, name))
            else:
                ids.append({"id": i, "pId": pids[path], "name": name, "isParent": "true", "dir_name": dir_name,
                            "url": real_path})
                if os.path.join(path, name) not in pids:
                    pids[os.path.join(path, name)] = i
                i += 1
                if i >= 4096: break
        # endif
        # endfor
        files.sort()
        for filename in files:
            if filename.find(".") != 0 and path not in no_access_dirs:
                real_path = os.path.join(path, filename)
                filesize = os.path.getsize(real_path) / 1024 / 1024
                ids.append(
                    {"id": i, "pId": pids[path], "name": "%s [%sM]" % (filename, round(filesize, 2)), "url": real_path})
                i += 1
                if i >= 4096: break
        if i >= 4096: break
    # end for
    # end for
    # d = {"data": ids}
    total = len(ids)
    ids = ids[(int(page) - 1) * int(pagesize):int(page) * int(pagesize)]
    return {"code": 200, "data": {'records': ids, 'current': page, 'pageSize': pagesize, 'pages': page, 'total': total},
            "msg": "请求成功"}


# 显示所有脚本
@root.post('/list_fbi')
async def list_fbi(item: dict, request: Request, response: Response,
                   fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = item.get("fbi_session") or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    # 开始
    pids = {}  # 父节点
    ids = []  # 所有节点
    no_access_dirs = []  # 不能访问的目录
    i = 0
    ids.append({"id": i, "pId": i, "name": "脚本目录", "open": "true", "dir_name": "/", "chkDisabled": "true"})
    pids[file_path['fbi']] = i
    i += 1
    page = item['page']
    pagesize = item['pagesize']
    for path, d, files in os.walk(file_path['fbi'], True):
        d.sort()
        for name in d:
            dir_name = os.path.join(path, name)[len(file_path['fbi']):] + "/"
            if name.find("__") == 0 and name[2:] != user and user != "superFBI":  # 不是自己的私有目录不能添加,superFBI可以看全部
                no_access_dirs.append(os.path.join(path, name))
            else:
                ids.append({"id": i, "pId": pids[path], "name": name, "isParent": "true", "dir_name": dir_name})
                if os.path.join(path, name) not in pids:
                    pids[os.path.join(path, name)] = i
                i += 1
        # endif
        files.sort()
        for filename in files:
            if path not in no_access_dirs:
                ids.append({"id": i, "pId": pids[path], "name": filename,
                            "url": "/db/dls/" + os.path.join(path, filename)[7:].replace("/", "--"),
                            "target": "_blank"})
                i += 1
    # endfor
    # endfor
    # d = {"data": ids}
    # return json.dumps(d)
    total = len(ids)
    ids = ids[(int(page) - 1) * int(pagesize):int(page) * int(pagesize)]

    return {"code": 200, "data": {'records': ids, 'current': page, 'pageSize': pagesize, 'pages': page, 'total': total},
            "msg": "请求成功"}


# 根据关键字搜索脚本内容
@root.post('/search_fbi')
async def search_fbi(item: dict, request: Request, response: Response,
                     fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = item.get("fbi_session") or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    key_word = item['keyword']

    # 开始
    no_access_dirs = []  # 不能访问的目录
    result = []  # 结果列表
    page = item['page']
    pagesize = item['pagesize']
    for path, d, files in os.walk(file_path['fbi'], True):
        d.sort()
        for name in d:  # 目录
            if name.find("__") == 0 and name[2:] != user and user != "superFBI":  # 不是自己的私有目录不能添加,superFBI可以看全部
                no_access_dirs.append(os.path.join(path, name))
        # endif
        files.sort()
        for filename in files:  # 文件
            if path not in no_access_dirs:
                # ids.append({"id":i,"pId":pids[path],"name":filename,"url":"/db/dls/"+os.path.join(path, filename)[7:].replace("/","--"),"target":"_blank"})
                with open(os.path.join(path, filename)) as f:
                    try:
                        lines = f.readlines()
                        file_hits = []
                        for i, line in enumerate(lines):
                            if line.find(key_word) >= 0:
                                file_hits.append({"num": i, "line": line})
                        if len(file_hits) > 0:
                            mtime = os.path.getmtime(os.path.join(path, filename))
                            result.append({"name": filename, "url": os.path.join(path, filename)[7:].replace("/", "--"),
                                           "hits": file_hits, "mtime": mtime})
                    except:
                        pass
    # end with
    # endfor
    # endfor
    result.sort(key=lambda x: x["mtime"], reverse=True)
    total = len(result)
    result = result[(int(page) - 1) * int(pagesize):int(page) * int(pagesize)]

    return {"code": 200,
            "data": {'records': result, 'current': page, 'pageSize': pagesize, 'pages': page, 'total': total},
            "msg": "请求成功"}


# 根据脚本的修改时间展示脚本列表
@root.post('/modified_fbi')
async def modified_fbi(item: dict, request: Request, response: Response,
                       fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = request.params.get("fbi_session") or request.cookies.fbi_session
    user = get_user_by_session(session)[0]

    # 开始
    no_access_dirs = []  # 不能访问的目录
    result = []
    page = item['page']
    pagesize = item['pagesize']
    for path, d, files in os.walk(file_path['fbi'], True):
        d.sort()
        for name in d:  # 目录
            if name.find("__") == 0 and name[2:] != user and user != "superFBI":  # 不是自己的私有目录不能添加,superFBI可以看全部
                no_access_dirs.append(os.path.join(path, name))
        # endif
        files.sort()
        for filename in files:  # 文件
            if path not in no_access_dirs:
                # ids.append({"id":i,"pId":pids[path],"name":filename,"url":"/db/dls/"+os.path.join(path, filename)[7:].replace("/","--"),"target":"_blank"})
                with open(os.path.join(path, filename)) as f:
                    try:
                        line = f.readline()
                        file_hits = []
                        file_hits.append({"num": 1, "line": line})
                        mtime = os.path.getmtime(os.path.join(path, filename))
                        result.append({"name": filename, "url": os.path.join(path, filename)[7:].replace("/", "--"),
                                       "hits": file_hits, "mtime": mtime})
                    except:
                        pass
    # end with
    # endfor
    # endfor
    result.sort(key=lambda x: x["mtime"], reverse=True)
    total = len(result)
    result = result[(int(page) - 1) * int(pagesize):int(page) * int(pagesize)]
    return {"code": 200,
            "data": {'records': result, 'current': page, 'pageSize': pagesize, 'pages': page, 'total': total},
            "msg": "请求成功"}


def local_run(host, port, prmtv, work_space="public", user=""):
    d = {"ret": 0, "error": ""}
    try:
        http = urllib3.PoolManager(timeout=1200.0)
        if user == None or user == "":
            user = "system"
        q = {"prmtv": prmtv, "work_space": work_space, "user": user}
        url = 'http://%s:%s/AI?%s' % (host, port, urlencode(q))
        r = http.request("GET", url)
        if r.status == 200:
            d = json.loads(r.data.decode())
        else:
            d["error"] = "server retun status %s" % (r.status)
            d["ret"] = 1
    except Exception as e:
        # logger.error(traceback.format_exc())
        d["prmtv"] = prmtv
        d["error"] = "remote run has error %s" % (e)
        d["ret"] = 1
    return d


def local_runp(host, port, prmtv, work_space="public", user="sys"):
    # 同步调用，支持push原语的结果
    try:
        ret, error, mresult, datas, cost = run_command2(work_space, prmtv, user)
        d = {"Cost": cost, "ret": ret, "error": error, 'error_count': ret, "action": 0, "result": mresult,
             "datas": datas}
    except Exception as e:
        root_logger.error("execp error: %s" % (e))
        te = traceback.format_exc()
        root_logger.error(te)
    return d


# 语句块调用
def local_run_block(host, port, prmtv, work_space="public", user=""):
    d = {}
    try:
        http = urllib3.PoolManager(timeout=1200.0)
        if user == None or user == "":
            user = "sys"
        q = {"block": prmtv, "work_space": work_space, "user": user}
        url = 'http://%s:%s/run_block2' % (host, port)
        r = http.request("POST", url, q)
        if r.status == 200:
            d = json.loads(r.data.decode())
        else:
            d["error"] = "server retun status %s" % (r.status)
            d["data"] = r.data.decode()
            d["ret"] = 1
    except Exception as e:
        # logger.error(traceback.format_exc())
        d["prmtv"] = prmtv
        d["error"] = "remote run has error %s" % (e)
        d["ret"] = 1
    return d


# 多行语句调用
def local_run_blocks(host, port, prmtv, work_space="public", user=""):
    d = {}
    try:
        http = urllib3.PoolManager(timeout=1200.0)
        if user == None or user == "":
            user = "sys"
        q = {"block": prmtv, "work_space": work_space, "user": user}
        url = 'http://%s:%s/run_blocks2' % (host, port)
        r = http.request("POST", url, q)
        if r.status == 200:
            d = json.loads(r.data.decode())
        else:
            d["error"] = "server retun status %s" % (r.status)
            d["data"] = r.data.decode()
            d["ret"] = 1
    except Exception as e:
        # logger.error(traceback.format_exc())
        d["prmtv"] = prmtv
        d["error"] = "remote run has error %s" % (e)
        d["ret"] = 1
    return d


# 添加用户
@root.post('/adduser')
async def adduser(item: dict, request: Request, response: Response,
                  fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}

    user = item

    try:
        if True:
            if user["isadmin"] == "Y" and fbi_user_mgr.get_user_count() > fbi_global.size:
                return {"code": 204, "data": {"success": False}, "msg": "分析-开发人员超出最大用户数限制!"}
            fbi_user_mgr.add_user(user)
        else:
            fbi_user_mgr.update_user(user)
        return {"code": 200, "data": {"success": True}, "msg": "添加成功"}
    except Exception as e:
        return {'code': 500, 'data': {'success': False}, 'msg': e.__str__()}


# 删除用户
@root.get('/deluser/{name}')
async def deluser(name, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        fbi_user_mgr.del_user(name)
        fbi_eng_mgr.revoke_user_eng(name)
        return {"code": 200, "data": {"success": True, "user": name}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": False}, "msg": e.__str__()}


# 用户时候存在
@root.get('/haveuser/{name}')
async def haveuser(name: str, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        ret = fbi_user_mgr.have_user(name)
        return {"code": 200, "data": {"success": True, "ishave": ret}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": False}, "msg": e.__str__()}


# add by gjw on 20201023,当前用户的用户信息
@root.get('/userinfo')
async def userinfo(request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        session = fbi_session or request.cookies.get("fbi_session")
        cur_user_name = get_user_by_session(session)[0]
        userinfo = fbi_user_mgr.get_user_by_name(cur_user_name)
        SysRole = ssdb0.get("SysRole:%s" % (userinfo["sys_role"]))
        if SysRole:
            userinfo["SysRole_Data"] = json.loads(SysRole)
        else:
            userinfo["SysRole_Data"] = ""
        return {"code": 200, "data": userinfo, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": False}, "msg": e.__str__()}


@root.get('/abci')
async def abci(request: Request, response: Response,
               fbi_session: str = Query(None),
               eng: str = Query(None),
               prmtv: str = Query(None),
               work_space: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        session = request.cookies.get("fbi_session")
        # heade = {
        # 	"Content-Type":'application/json; charset=UTF-8'
        # }
        # response.init_headers(heade)
        response.headers["Content-Type"] = "application/json; charset=UTF-8"
        user, isadmin = get_user_by_session(session)
        port = eng or request.cookies.get("eng") or "9002"
        # 原语
        # prmtv = item.get("prmtv")
        prmtv = prmtv
        if not prmtv:
            req_json = item
            prmtv = req_json["prmtv"]
        # 处理中文工作区
        work_space = work_space or request.cookies.get("work_space") or "public"
        if work_space[0] == '"' and work_space[-1] == '"':
            work_space = work_space[1:-1]
        server = "127.0.0.1"
        if isadmin == "Y":  # 管理员有引擎
            d = local_run(server, port, prmtv, work_space, user)
            #return d

            if "work_space" in d:
                response.set_cookie("work_space", d["work_space"], path="/")
            response.set_cookie("eng", port)
            if "cur_df" in d:
                response.set_cookie("cur_df", d["cur_df"], path="/")

            if  isinstance(d["result"], str):
                res = json.loads(d.get('result'))

                d['result'] = res

            return {"code": 200, "data": d, "msg": "成功"}
        else:  # 非开发人员
            d = {}

            if prmtv.startswith("run "):  # 使用后台定时器计算

                prmtv_new = "settimer sys1 by '* * * * * *' {}".format(prmtv)

                d = local_run(server, port, prmtv_new, work_space, user)

                # 为了让页面不出错
                d["result"] = [{"TI": "140390393317120@9002", "ST": "2022-10-13T10:12:39.388950",
                                "FID": "140390393317120:2022-10-13T10:12:39.388950"}]
            elif prmtv.startswith("check "):  # 统一返回运行结束

                d = {"code": 200,
                     "data": {"prmtv": "", "ret": 0, "error": "", "action": 0,
                              "result": {"find": "True", "isAlive": "False", "end_time": "", "progress": "0/0",
                                         "command": "FAST_MODE",
                                         "cost": "", "error_count": 0, "error_info": "", "depth": 1, "alive_tasks": 1}
                              },
                     "msg": "运行结束"
                     }
            else:
                d = {"code": 204, "data": {"prmtv": "", "ret": 1, "action": 0, "result": 0},
                     "msg": "非开发员不能执行其他原语！"}
            return d
    except Exception as e:
        d = {"code": 500, "data": {"errors": "{}".format(traceback.format_exc())}, "msg": "出错:{}".format(e)}
        return d


@root.post("/abci")
async def abci(item: dict, request: Request, response: Response,
               fbi_session: str = Query(None),
               eng: str = Query(None),
               prmtv: str = Query(None),
               work_space: str = Query(None)):
    ret = check_session(request, response, fbi_session)

    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:

        session = request.cookies.get("fbi_session")

        # heade = {
        # 	"Content-Type":'application/json; charset=UTF-8'
        # }

        # response.init_headers(heade)
        response.headers["Content-Type"] = "application/json; charset=UTF-8"
        user, isadmin = get_user_by_session(session)
        port = item.get("eng") or request.cookies.get("eng") or "9002"
        # 原语
        prmtv = item.get("prmtv")
        if not prmtv:
            req_json = item
            prmtv = req_json["prmtv"]
        # 处理中文工作区
        work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
        if work_space[0] == '"' and work_space[-1] == '"':
            work_space = work_space[1:-1]
        server = "127.0.0.1"
        if isadmin == "Y":  # 管理员有引擎
            d = local_run(server, port, prmtv, work_space, user)
            if "work_space" in d:
                #cookie_value = urlencode(d["work_space"])
                response.set_cookie("work_space", d["work_space"], path="/")
            response.set_cookie("eng", port)
            if "cur_df" in d:
                response.set_cookie("cur_df", d["cur_df"], path="/")

            if isinstance(d["result"], str):
                res = json.loads(d.get('result'))

                d['result'] = res

            return {"code": 200, "data": d, "msg": "成功"}
        else:  # 非开发人员
            d = {}

            if prmtv.startswith("run "):  # 使用后台定时器计算

                prmtv_new = "settimer sys1 by '* * * * * *' {}".format(prmtv)

                d = local_run(server, port, prmtv_new, work_space, user)

                # 为了让页面不出错
                d["result"] = [{"TI": "140390393317120@9002", "ST": "2022-10-13T10:12:39.388950",
                                "FID": "140390393317120:2022-10-13T10:12:39.388950"}]
            elif prmtv.startswith("check "):  # 统一返回运行结束

                d = {"code": 200,
                     "data": {"prmtv": "", "ret": 0, "error": "", "action": 0,
                              "result": {"find": True, "isAlive": False, "end_time": "", "progress": "0/0",
                                         "command": "FAST_MODE",
                                         "cost": "", "error_count": 0, "error_info": "", "depth": 1, "alive_tasks": 1}
                              },
                     "msg": "运行结束"
                     }

            else:
                d = {"code": 204, "data": {"prmtv": "", "ret": 1, "action": 0, "result": 0},
                     "msg": "非开发员不能执行其他原语！"}
            return d
    except Exception as e:
        d = {"code": 500, "data": {"errors": "{}".format(traceback.format_exc())}, "msg": "出错:{}".format(e)}
        return d


@root.get('/abcip')
async def abcip(request: Request, response: Response,
                prmtv: str = Query(None)):
    ret = check_session(request, response, request.cookies.get("fbi_session"))
    print("prmtv", prmtv)
    print("fbi_session", request.cookies.get("fbi_session"))
    item = {}
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        session = item.get("fbi_session") or request.cookies.get("fbi_session")
        response.headers["Content-Type"] = 'application/json; charset=UTF-8'
        # 原语
        # prmtv = item.get("prmtv")
        # if not prmtv:
        # req_json = item
        prmtv = prmtv
        print(type(prmtv))
        print("prmtv:", prmtv)
        print("dict(prmtv)", dir(prmtv))
        print("#" * 10)
        print(request.url.query)
        print(request.query_params)
        print(request.cookies)

        # 处理中文工作区
        work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
        if work_space[0] == '"' and work_space[-1] == '"':
            work_space = work_space[1:-1]
        if prmtv.find("check task") != -1:
            d = {"code": 200, "data": {"prmtv": "", "ret": 0, "action": 0, "result": {"isAlive": "false"}, "msg": ""}}
        else:
            try:
                user, isadmin = get_user_by_session(session)
                # add by gjw on 2020-1223 增加对执行脚本的权限校验,管理员不做检查,便于进行开发操作
                if isadmin == "N" and user != "admin":
                    try:
                        SysRule = ssdb0.get("SysRule:scripts:%s" % (user))
                        SysRule_dict = json.loads(SysRule)
                    except:
                        SysRule_dict = {}
                else:
                    SysRule_dict = {}
                ret, error, mresult, datas, cost = run_command2(work_space, prmtv, user, SysRule_dict)
                if isinstance(mresult, str):
                    res = json.loads(mresult)
                else:
                    res = mresult
                d = {"code": 200,
                     "data": {"Cost": cost, "ret": ret, "error_info": error, 'error_count': ret, "action": 0,
                              "result": res, "datas": datas}, "msg": "请求成功"}
            except Exception as e:
                root_logger.error("execp error: %s" % (e))
                te = traceback.format_exc()
                root_logger.error(te)
                return e.__str__()
        return d
    except  Exception as e:
        d = {"code": 500, "data": {"errors": "{}".format(traceback.format_exc())}, "msg": "出错:{}".format(e)}
        return d


# 门户调用脚本的进入点
@root.post('/abcip')
async def abcip(item: dict, request: Request, response: Response,
                fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        session = item.get("fbi_session") or request.cookies.get("fbi_session")
        response.headers["Content-Type"] = 'application/json; charset=UTF-8'
        # 原语
        prmtv = item.get("prmtv")
        if not prmtv:
            req_json = item
            prmtv = req_json["prmtv"]
        # 处理中文工作区
        work_space = item.get("work_space") or request.cookies.get("work_space") or "public"
        if work_space[0] == '"' and work_space[-1] == '"':
            work_space = work_space[1:-1]
        if prmtv.find("check task") != -1:
            d = {"code": 200, "data": {"prmtv": "", "ret": 0, "action": 0, "result": {"isAlive": "false"}, "msg": ""}}
        else:
            try:
                user, isadmin = get_user_by_session(session)
                # add by gjw on 2020-1223 增加对执行脚本的权限校验,管理员不做检查,便于进行开发操作
                if isadmin == "N" and user != "admin":
                    try:
                        SysRule = ssdb0.get("SysRule:scripts:%s" % (user))
                        SysRule_dict = json.loads(SysRule)
                    except:
                        SysRule_dict = {}
                else:
                    SysRule_dict = {}
                ret, error, mresult, datas, cost = run_command2(work_space, prmtv, user, SysRule_dict)
                if isinstance(mresult, str):
                    res = json.loads(mresult)
                else:
                    res = mresult
                d = {"code": 200,
                     "data": {"Cost": cost, "ret": ret, "error_info": error, 'error_count': ret, "action": 0,
                              "result": res, "datas": datas}, "msg": "请求成功"}
            except Exception as e:
                root_logger.error("execp error: %s" % (e))
                te = traceback.format_exc()
                root_logger.error(te)
                return e.__str__()
        return d
    except  Exception as e:
        d = {"code": 500, "data": {"errors": "{}".format(traceback.format_exc())}, "msg": "出错:{}".format(e)}
        return d


@root.get("/")
def index():
    return {"code": 403, "msg": "你没有权限操作"}


@root.get('/static/{filepath:path}')
async def server_static(filepath: str, request: Request, response: Response,
                        fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    return templates.TemplateResponse(filepath)


@root.get('/dbd/{filepath:path}', response_class=FileResponse)
async def server_dbd(filepath, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0: return RedirectResponse("/auth.h5")
    file_path_dbd = f"/opt/openfbi/mPig/html/dbd/{filepath}"
    return file_path_dbd


@root.get('/fbi/{filepath:path}', response_class=FileResponse)
async def server_fbi(filepath, request: Request, response: Response, fbi_session: str = Query(None)):
    if filepath in ["login.h5", "css/newlogin.css", "js/login.js"]:
        file_path_fbi1 = f"/opt/openfbi/mPig/html/fbi/{filepath}"
        return file_path_fbi1
    else:
        ret = check_session(request, response, fbi_session)
        if ret != 0: return RedirectResponse("/auth.h5")
    file_path_fbi2 = f"/opt/openfbi/mPig/html/fbi/{filepath}"
    return file_path_fbi2


@root.get('/bi/{filepath:path}', response_class=HTMLResponse)
async def server_bi(filepath, request: Request, response: Response, fbi_session: str = Query(None)):
    if filepath in ["login.json", "index.h5", "index.js"]:
        # file_path_bi1 = f"/opt/openfbi/mPig/html/bi/{filepath}"
        response.headers["Content-Type"] = "text/html"
        # html = ""
        # f = open(f"/opt/openfbi/mPig/html/bi/{filepath}","r")
        # for html_body in f.read():
        #    html+=html_body
        # file_path_bi1 = f"/opt/openfbi/mPig/html/bi{filepath}"
        return templatess.TemplateResponse(filepath, {"request": request})
        # return file_path_bi1
    else:
        ret = check_session(request, response, fbi_session)
        if ret != 0: return RedirectResponse("/auth.h5")
    file_path_bi2 = f"/opt/openfbi/mPig/html/bi/{filepath}"
    return file_path_bi2


@root.get('filepath:path}', response_class=FileResponse)
async def server_bi(filepath, request: Request, response: Response, fbi_session: str = Query(None)):
    if filepath in ["login.json", "index.h5", "index.js"]:
        file_path_bi1 = f"/opt/openfbi/mPig/html/bi/{filepath}"
        return file_path_bi1
    else:
        ret = check_session(request, response, fbi_session)
        if ret != 0: return RedirectResponse("/auth.h5")
    file_path_bi2 = f"/opt/openfbi/mPig/html/bi/{filepath}"
    return file_path_bi2


@root.get('/future/{filepath:path}', response_class=FileResponse)
async def server_future(filepath, request: Request, response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0: return RedirectResponse("/auth.h5")
    file_path_future = f"/opt/openfbi/mPig/html/future/{filepath}"
    return file_path_future


# 下载数据文件
@root.get('/workspace/{filepath:path}', response_class=FileResponse)
async def download_workspace(filepath, request: Request, response: Response,
                             fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0: return RedirectResponse("/auth.h5")
    session = fbi_session or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    if filepath.find("__") == 0 and filepath[2:len(user) + 2] != user:
        ret = 1
        error = "你 [%s] 没有权限下载该文件!" % (user)
        loglog(user, request.client.host, ";".join(request.url.path), "下载数据", "门户", \
               filepath, "失败", error)
        return error
    loglog(user, request.client.host, ";".join(request.url.path), "下载数据", "门户", \
           filepath, "成功", "")
    file_path_workspace = f"{file_path['data']}/{filepath}"
    return file_path_workspace


# 下载fileinfo的文件的服务
@root.get('/download/{filepath:path}', )
async def download_workspace(filepath, request: Request, response: Response,
                             fbi_session: str = Query(None),
                             file_name: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0: return RedirectResponse("/auth.h5")
    session = fbi_session or request.cookies.get("fbi_session")
    # file_name = filename
    file_name = quote(file_name)
    user = get_user_by_session(session)[0]
    loglog(user, request.client.host, ";".join(request.url.path), "下载文件", "门户", \
           filepath, "成功", "")
    return FileResponse(path=file_path['data'], filename=file_name)


# 删除数据文件
@root.get('/remove_data')
async def remove_workspace(request: Request, response: Response,
                           fbi_session: str = Query(None),
                           filepath: str = Query(None), ):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = fbi_session or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    # filepath = request.query_params["filename"]
    if filepath.find("__") == 0 and filepath[2:len(user) + 2] != user:
        error = "你 [%s] 没有权限删除该文件!" % (user)
        return {"code": 403, "data": {"success": False}, "msg": error}
    if os.path.isdir(filepath):
        os.removedirs(filepath)
    else:
        os.remove(filepath)
    return {"code": 200, "data": {"success": True}, "msg": "成功"}


# 删除fbi文件
@root.get('/remove_fbi')
async def remove_fbi(request: Request, response: Response,
                     fbi_session: str = Query(None),
                     filepath: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        user = check_isadmin(request, fbi_session)
        # filepath = request.query_params["filename"]
        filepath = filepath[len("/fbi_id/"):].replace("--", "/")
        if filepath.find("__") == 0 and filepath[2:len(user) + 2] != user:
            error = "你 [%s] 没有权限删除该文件!" % (user)
            return {"code": 403, "data": {"success": False}, "msg": error}
        os.remove(file_path['fbi'] + filepath)
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {"code": 500, "data": {"success": False}, "msg": e.__str__()}


# 创建数据目录
@root.get('/mkdir_data')
async def mkdir_data(request: Request, response: Response,
                     fbi_session: str = Query(None),
                     filepath: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    session = request.query_params["fbi_session"] or request.cookies.get("fbi_session")
    user = get_user_by_session(session)[0]
    filepath = filepath.replace("--", "/")
    os.makedirs(file_path['data'] + filepath, exist_ok=True)
    return {"code": 200, "data": {"success": True}, "msg": "成功"}


# 查看fbi脚本文件
@root.get('/fbi_script/{fbiname}')
async def view_fbi_script(fbiname, request: Request, response: Response,
                          fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}

        user = check_isadmin(request, fbi_session)

        if fbiname.find("__") == 0 and fbiname[2:len(user) + 2] != user and user != "superFBI":
            ret = 1
            error = "你 [%s] 没有权限查看该脚本!" % (user)
            return {"code": 403, "msg": error}

        if fbiname[0] == '"' and fbiname[-1] == '"':
            fbiname = fbiname[1:-1]
        d = {"code": 200, "data": "#FBI脚本文件\n#文件名: %s\n#作者: %s\n" % (fbiname, user), "msg": "请求成功"}
        try:
            fbiname = fbiname.replace("--", "/")
            f = open(file_path["fbi"] + fbiname)
            data = f.read()
            f.close()
            d["data"] = data
        except:
            return d
        return d
    except Exception as e:
        return {"code": 500, "data": {"success": False}, "msg": e.__str__()}


# 下载fbi脚本文件
@root.get('/dls/{fbiname}', )
async def download_fbi_script(fbiname, request: Request, response: Response,
                              fbi_session: str = Query(None)):
    try:
        ret = check_session(request, response, fbi_session)
        if ret != 0:
            return {'code': 403, 'msg': '%s' % (ret)}
        user = check_isadmin(request, fbi_session)
        if fbiname.find("__") == 0 and fbiname[2:len(user) + 2] != user and user != "superFBI":
            ret = 1
            error = "你 [%s] 没有权限查看该脚本!" % (user)
            return {"code": 403, "msg": error}
        if fbiname[0] == '"' and fbiname[-1] == '"':
            fbiname = fbiname[1:-1]
        fbiname = fbiname.replace("--", "/")
        path = file_path['fbi']
        print("path", path)
        return FileResponse("%s" % (path + fbiname), filename=fbiname)
    except Exception as e:
        return e.__str__()


# 高亮显示脚本的html
@root.get('/fbi_id/{name}')
async def fbi_id(name, request: Request, response: Response,
                 fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    return RedirectResponse("/static/fbi-view.html?name=%s" % (name))


@root.post('/base_pic/')
async def base_pic(item: dict, request: Request, response: Response,
                   fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    try:
        import base64
        data = item["data"]
        data_json = json.loads(data)
        key = data_json["key"]
        base64_value = data_json["base64"]
        pic_base_path = file_path["data"] + "pic_base/"
        if not os.path.exists(pic_base_path):
            os.makedirs(pic_base_path)
        with open(pic_base_path + key + ".txt", "w") as f:
            f.write(base64_value)
        return {"code": 200, "data": {"success": True}, "msg": "成功"}
    except Exception as e:
        return {"code": 403, "data": {"success": False}, "msg": e.__str__()}


# 显示对应的word模板的图片列表
@root.get('/list_word_pics/{id}')
async def list_word_pics(id, request: Request,
                         response: Response, fbi_session: str = Query(None)):
    ret = check_session(request, response, fbi_session)
    if ret != 0:
        return {'code': 403, 'msg': '%s' % (ret)}
    root_logger.info(file_path['tpl_word'] + id)
    a = os.listdir(file_path['tpl_word'] + id)
    root_logger.info(a)
    b = []
    for f in a:
        if f.endswith(".png") or f.endswith(".jpg") > 0:
            b.append(f)
    b.sort()
    d = {"data": b}
    return d


# esql的服务
@root.get('/esql/{id}/{sql}')
async def esql_service(id, sql, request: Request, response: Response,
                       fbi_session: str = Query(None)):
    conn = get_key(id)

    if conn == "":
        raise Exception("[%s]链接未找到!或者为没有权限使用" % (id))
    try:
        from driver.ESql7 import ESql, Elasticsearch, ESql_query
        if conn[0:4] != "http":  # add by gjw on 20221027 简写的链接方式host:port
            ip_port = conn.split(":")
            es = Elasticsearch([{'host': ip_port[0], 'port': int(ip_port[1])}, ])
        else:
            es = Elasticsearch(list(map(lambda x: x.strip(), conn.split(";"))),
                               verify_certs=True)  # modify by gjw on 20220628 支持es集群

        esql = ESql(es)
        res = esql.do_sql(sql)
        if res["msg"] != "": raise Exception(res["msg"])
        return res
    except Exception as e:
        raise Exception("执行[%s]语句出现异常 %s" % (sql, e))
    finally:
        es.transport.close()  # 关闭链接


@root.get("/test/")
def Test():
    return {"message": "测试成功"}


if __name__ == "__main__":
    uvicorn.run("fbi-gateway2:root", host="0.0.0.0", port=9999)
