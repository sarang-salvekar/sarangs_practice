import json
import http.client
import urllib.parse
import sys, os, base64, datetime, hashlib, hmac

def verify_request(method, url, post_data=None, headers={}):
    parsed_url = urllib.parse.urlparse(url)

    print("Making request with Method: '%s' URL: %s: Data: %s Headers: %s" % (method, url, json.dumps(post_data), json.dumps(headers)))

    if parsed_url.scheme == "https":
        conn = http.client.HTTPSConnection(parsed_url.hostname, parsed_url.port)
    else:
        conn = http.client.HTTPConnection(parsed_url.hostname, parsed_url.port)

    conn.request(method, url, str(post_data), headers)
    response = conn.getresponse()
    print("Status Code: %s " % response.status)
    print("Response Headers: %s" % json.dumps(response.headers.as_string()))
    
    if response.status == 200 or response.status == 406:
        print("Response: %s" % response.read().decode())
        print("HTTP request successfully executed")
        conn.close()
    else:
        try:
            print("Response: %s" % response.read().decode())
        finally:
            if response.reason:
                conn.close()
                raise Exception("Failed: %s" % response.reason)
            else:
                conn.close()
                raise Exception("Failed with status code: %s" % response.status)


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def main():
    url1 = 'https://{{api_ud}}.execute-api.{{region}}.amazonaws.com/{{environment}}/{{resource}}/{{list of url params}}/{{method name}}'
    method1 = 'POST'
    postData1 = "{\"data\": [] }"

    method = 'POST'
    service = 'execute-api'
    host = '{{api_ud}}.execute-api.{{region}}.amazonaws.com'
    region = '{{region}}'
    content_type = 'application/json'
    algorithm = 'AWS4-HMAC-SHA256'

    access_key = ''
    secret_key = ''
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d')

    canonical_uri = '/dev/{{resource}}/{{list of url params}}/{{method name}}'
    parsed_url = urllib.parse.urlparse(url1)
    print(parsed_url)
    canonical_querystring = ''
    canonical_headers = ('host:' + host + '\n' +
                             'x-amz-date:' + amz_date + '\n')

    signed_headers = 'host;x-amz-date'
    body = postData1.encode('utf-8')
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = method1 + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'

    string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    signing_key = getSignatureKey(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'x-amz-content-sha256': payload_hash,
               'x-amz-date': amz_date,
               'Authorization': authorization_header}

    verify_request(method1, url1, postData1, headers)

    print("successfully executed")


def handler(event, context):
    main()