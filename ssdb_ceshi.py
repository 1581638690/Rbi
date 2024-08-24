a = [
    "dd2:Yes_or_No",
    "{\"id\":\"Yes_or_No\",\"name\":\"是否\",\"ms\":\"0否，1是的常用字典\",\"editor\":\"admin\"}",
    "dd2:YorN",
    "{\"id\":\"YorN\",\"name\":\"是或否\",\"ms\":\"true or false\",\"editor\":\"admin\"}",
    "dd2:ceshi","{\"id\": \"ceshi\", \"name\": \"\测\试\键\值\", \"ms\": \"\", \"editor\": \"rzc\", \"date\": \"2024-08-24 09:37:37\"}",
    "dd2:classify_result_tree",
    "{\"id\":\"classify_result_tree\",\"name\":\"分类结果树\",\"ms\":\"分类结果树\",\"editor\":\"pjb\",\"date\":\"2022-06-21 11:37:21\"}",
    "dd2:data_dams_dbms",
    "{\"id\":\"data_dams_dbms\",\"name\":\"\",\"ms\":\"\",\"editor\":\"superFBI\",\"date\":\"2022-07-07 15:57:54\"}",
    "dd2:data_dbms_classify_details",
    "{\"id\":\"data_dbms_classify_details\",\"name\":\"分类详情\",\"ms\":\"分类详情\",\"editor\":\"pjb\",\"date\":\"2022-06-24 11:59:29\"}",
    "dd2:data_dbms_classifys",
    "{\"id\":\"data_dbms_classifys\",\"name\":\"关联分类\",\"ms\":\"打标任务对分类进行关联\",\"editor\":\"pjb\",\"date\":\"2022-06-17 09:02:03\"}",
    "dd2:data_dbms_database_tree",
    "{\"id\":\"data_dbms_database_tree\",\"name\":\"\",\"ms\":\"\",\"editor\":\"gsp\",\"date\":\"2023-09-05 11:45:34\"}",
    "dd2:data_dbms_level",
    "{\"id\":\"data_dbms_level\",\"name\":\"关联分级\",\"ms\":\"打标任务结果进行分级关联\",\"editor\":\"pjb\",\"date\":\"2022-06-17 11:01:03\"}",
    "dd2:future",
    "{\"id\":\"future\",\"name\":\"高级模块\",\"ms\":\"单独使用的模块\",\"editor\":\"superFBI\"}",
    "dd2:zichan_type",
    "{\"id\":\"zichan_type\",\"name\":\"资产类型\",\"ms\":\"资产类型\",\"editor\":\"admin\"}",
    "dd2:znsm:action",
    "{\"id\":\"znsm:action\",\"name\":\"网络监控-告警规则行为\",\"ms\":\"alert 告警，drop 丢弃 ，reject 拒绝\",\"editor\":\"superFBI\"}",
    "dd2:znsm:direction",
    "{\"id\":\"znsm:direction\",\"name\":\"网络监控-流向\",\"ms\":\"网络监控-流向,单向->,双向<>\",\"editor\":\"superFBI\"}",
    "dd2:znsm:protocol",
    "{\"id\":\"znsm:protocol\",\"name\":\"网络监控-协议\",\"ms\":\"网络监控-协议, 如tcp ,udp ,http 等\",\"editor\":\"superFBI\"}",
    "dd2:znsm:syslog",
    "{\"id\":\"znsm:syslog\",\"name\":\"网络监控-syslog协议类型\",\"ms\":\"Tcp,Udp,不输出\",\"editor\":\"superFBI\"}"
]
length = len(a)
import json
b = []
dd2_key = []
for i in range(0, length, 2):
    res = json.loads(a[i + 1])
    res['key'] = a[i]
    b.append(res)
    dd2_key.append(a[i])