#!/usr/bin/env python
import urllib, urllib2, base64, json, hmac, hashlib, time, random, urlparse

req_token_endpoint = 'https://twitter.com/oauth/request_token'
auth_endpoint = 'https://twitter.com/oauth/authorize'
access_endpoint = 'https://twitter.com/oauth/access_token'

random.seed()

def hmac_sha1(key, content):
   return base64.b64encode(hmac.new(key, content, hashlib.sha1).digest())

def build_signature_base_str(queryParam, method, url_endpoint):
   queryString = "&".join(["%s=%s" % (p, urllib.quote_plus(str(queryParam[p]))) for p in sorted(queryParam)])
   return "&".join([method, urllib.quote_plus(url_endpoint), urllib.quote_plus(queryString)])
   
try:
   cKey = raw_input('Your application consumer key: ')
   cSecret = raw_input('Your application consumer secret: ')
   
except KeyboardInterrupt:
   print "\n"
   
else:
   data = {'oauth_callback': 'oob',
           'oauth_consumer_key': cKey, 
           'oauth_nonce': hashlib.md5("%s%s" % (time.time(), random.randint(1,10000))).hexdigest(),
           'oauth_signature_method': 'HMAC-SHA1', 
           'oauth_timestamp': int(time.time()),
           'oauth_version': '1.0a'
           }
   
   baseString = build_signature_base_str(data, 'POST', req_token_endpoint)
   # print baseString
   data['oauth_signature'] = hmac_sha1(cSecret +'&', baseString)
   # print urllib.urlencode(data)
   try:
      req = urllib2.Request(req_token_endpoint, urllib.urlencode(data))
      f = urllib2.urlopen(req)
      token = f.read()
   except urllib2.HTTPError as e:
      print e, "\n", e.read()
   else:
      qs = urlparse.parse_qs(token)

      print "Please visit the following link and accept the application:\n%s?%s=%s" % (auth_endpoint , 'oauth_token', qs['oauth_token'][0])

      verifier = raw_input('The ID displayed on the screen: ')
      data['oauth_nonce'] = hashlib.md5("%s%s" % (time.time(), random.randint(1,10000))).hexdigest();
      data['oauth_timestamp'] = int(time.time())
      data['oauth_token'] = qs['oauth_token'][0]
      data['oauth_verifier'] = verifier

      baseString = build_signature_base_str(data, 'POST', access_endpoint)

      # data['oauth_signature'] = hmac_sha1('&'.join([cSecret, token]), baseString)
      data['oauth_signature'] = hmac_sha1('&'.join([cSecret, qs['oauth_token_secret'][0]]), baseString)
      try:
         req = urllib2.Request(access_endpoint, urllib.urlencode(data))
         f = urllib2.urlopen(req)
         res = urlparse.parse_qs(f.read())
      except urllib2.HTTPError as e:
         print e, "\n", e.read()
      else:
         print "Your access token: ", res['oauth_token'][0]
         print "Token secret: ", res['oauth_token_secret'][0]
         
         print res
