# -*- coding: UTF-8 -*-
import DNS
import urllib
import pymongo
import threading
import socket
from datetime import datetime
socket.setdefaulttimeout(5)

def query_ttl(query):
    DNS.DiscoverNameServers()
    reqobj = DNS.Request()
    answerobj_a = reqobj.req(name=query, qtype=DNS.Type.NS, server="222.194.15.251")

    if not answerobj_a.answers:
        blank = ""
        return (blank,blank)
    else:
        return_ns = []
        for item in answerobj_a.answers:
            return_ns.append(item['data'])
        return_dict = []

        for items in answerobj_a.answers:
            server = items['data']
            query_2 = "www." + query
            answerobj_b = reqobj.req(name=query_2, qtype=DNS.Type.A, server=server)
            return_dict = return_dict + answerobj_b.answers
        if not return_dict:
            return_dict_2 = []
            for items in answerobj_a.answers:
                server = items['data']
                query_2 = "www." + query
                answerobj_c = reqobj.req(name=query_2, qtype=DNS.Type.CNAME, server=server)
                return_dict_2 = return_dict + answerobj_c.answers
            if not return_dict_2:
                return ("","")
            else:
                return (return_ns,return_dict_2)
        else:
            return (return_ns,return_dict)


def mongo_handle_1():
    connection=pymongo.MongoClient('172.29.152.152',27017)
    db=connection.domain_cdn_analysis
    collection=db.domain_ttl
    for data in collection.find({'flag':0,'id_count':{'$gt':0,'$lt':250000}}):
        domain = data['domain']
        try:
            ttl_record = query_ttl(domain)
            collection.update({'_id':data['_id']},{'$set':{'NS_record':ttl_record[0],'TTL_record':ttl_record[1],'flag':1}})
        except:
            collection.update({'_id':data['_id']},{'$set':{'NS_record':"",'TTL_record':"",'flag':1}})


def mongo_handle_2():
    connection=pymongo.MongoClient('172.29.152.152',27017)
    db=connection.domain_cdn_analysis
    collection=db.domain_ttl
    for data in collection.find({'flag':0,'id_count':{'$gt':249999,'$lt':500000}}):
        domain = data['domain']
        try:
            ttl_record = query_ttl(domain)
            collection.update({'_id':data['_id']},{'$set':{'NS_record':ttl_record[0],'TTL_record':ttl_record[1],'flag':1}})
        except:
            collection.update({'_id':data['_id']},{'$set':{'NS_record':"",'TTL_record':"",'flag':1}})


def mongo_handle_3():
    connection=pymongo.MongoClient('172.29.152.152',27017)
    db=connection.domain_cdn_analysis
    collection=db.domain_ttl
    for data in collection.find({'flag':0,'id_count':{'$gt':499999,'$lt':750000}}):
        domain = data['domain']
        try:
            ttl_record = query_ttl(domain)
            collection.update({'_id':data['_id']},{'$set':{'NS_record':ttl_record[0],'TTL_record':ttl_record[1],'flag':1}})
        except:
            collection.update({'_id':data['_id']},{'$set':{'NS_record':"",'TTL_record':"",'flag':1}})


def mongo_handle_4():
    connection=pymongo.MongoClient('172.29.152.152',27017)
    db=connection.domain_cdn_analysis
    collection=db.domain_ttl
    for data in collection.find({'flag':0,'id_count':{'$gt':749999,'$lt':1000000}}):
        domain = data['domain']
        try:
            ttl_record = query_ttl(domain)
            collection.update({'_id':data['_id']},{'$set':{'NS_record':ttl_record[0],'TTL_record':ttl_record[1],'flag':1}})
        except:
            collection.update({'_id':data['_id']},{'$set':{'NS_record':"",'TTL_record':"",'flag':1}})




threads = []
t1 = threading.Thread(target=mongo_handle_1)
threads.append(t1)
t2 = threading.Thread(target=mongo_handle_2)
threads.append(t2)
t3 = threading.Thread(target=mongo_handle_3)
threads.append(t3)
t4 = threading.Thread(target=mongo_handle_4)
threads.append(t4)


if __name__ == "__main__":
    for t in threads:
        t.setDaemon(True)
        t.start()
    for t in threads:
        t.join()





