#!/usr/bin/python3
# update_conoha_dns_record.py
# -*- coding: utf-8 -*-
import json
import requests
import settings
import sys

def get_global_ip():
	# Get my global IP
	url = "http://inet-ip.info/ip"
	r = requests.get(url)
	#print(r.text)
	if r.status_code != requests.codes.ok:
		raise Exception("request failed {}".format(r.url))
	my_ip = r.text
	return my_ip


def get_access_token(uname, passwd, tenant_id):
	url = "https://identity.tyo2.conoha.io/v2.0/tokens"
	payload = {
		"auth": {
			"passwordCredentials": {
				"username": uname,
				"password": passwd,
			},
			"tenantId": tenant_id
		}
	}
	headers = {
		"Accept": "application/json"
	}
	r = requests.post(url, data=json.dumps(payload), headers=headers)
	if r.status_code != requests.codes.ok:
		print(r)
		raise Exception("request failed {}".format(r.url))
	resp = r.json()
	token_id = resp["access"]["token"]["id"]
	return token_id

def get_domain_id(token_id, domain_name):
	url = "https://dns-service.tyo2.conoha.io/v1/domains"
	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"X-Auth-Token": token_id,
	}
	r = requests.get(url, headers=headers)
	if r.status_code != requests.codes.ok:
		raise Exception("request failed {}".format(r.status_code))
	resp = r.json()
	domain_id = None
	for domain in resp["domains"]:
		if domain["name"] == domain_name:
			domain_id = domain["id"]
			print(domain["name"])
			print("domain ID: {}".format(domain_id))
			break
	if domain_id == None:
		raise Exception("{} is not found".format(domain_name))
	return domain_id

def get_record_id(token_id, domain_id, record_name):
	url = "https://dns-service.tyo2.conoha.io/v1/domains/{domainId}/records".format(domainId=domain_id)
	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"X-Auth-Token": token_id,
	}
	r = requests.get(url, headers=headers)
	if r.status_code != requests.codes.ok:
		raise Exception("request failed {}".format(r.url))
	resp = r.json()
	record_id = None
	for record in resp["records"]:
		if record["name"] == record_name and record["type"] == "A":
			record_id = record["id"]
			break
	if record_id == None:
		raise Exception("{} is not found".format(record_name))
	return record_id

def update_recode(token_id,domain_id,record_name, record_id, ipaddr):	
	url = "https://dns-service.tyo2.conoha.io/v1/domains/{domainId}/records/{recordId}".format(domainId=domain_id, recordId=record_id)
	payload ={
		"name": record_name,
		"type": "A",
		"data": ipaddr,
	}
	headers = {
		"Accept": "application/json",
		"Content-Type": "application/json",
		"X-Auth-Token": token_id
	}
	r = requests.put(url, data=json.dumps(payload), headers=headers)
	if r.status_code != requests.codes.ok:
		raise Exception("request failed {}".format(r.url))

def main():
	USERNAME = settings.USERNAME
	PASSWORD = settings.PASSWORD
	TENANT_ID = settings.TENANT_ID
	TARGET_DOMAIN = settings.TARGET_DOMAIN
	record_name = sys.argv
	ipaddr = get_global_ip()
	token_id = get_access_token(USERNAME, PASSWORD, TENANT_ID)
	domain_id = get_domain_id(token_id, TARGET_DOMAIN)

	print(ipaddr)
	for name in record_name[1:]:
		print(name)
		record_id = get_record_id(token_id, domain_id, name)
		update_recode(token_id, domain_id, name, record_id, ipaddr)
		print("dns record is updated.")

if __name__ == '__main__':
	main()
