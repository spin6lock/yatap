# -*- coding: utf-8 -*-
# Copyright under  the latest Apache License 2.0

import wsgiref.handlers, urlparse, base64, logging
from cgi import parse_qsl
from google.appengine.ext import webapp
from google.appengine.api import urlfetch, urlfetch_errors
from wsgiref.util import is_hop_by_hop
from uuid import uuid4
import oauth
from django.utils import simplejson
import re
import string

yatap_version = '0.01'

CONSUMER_KEY = 'B6Wv2V2OC9HY1VxRELCwg'
CONSUMER_SECRET = '8pge4afqr6H2pfpkv7kbLS5PIatEgl06fMqk8Tstes'

ENFORCE_GZIP = True

unwanted_status=['truncated','contributors','in_reply_to_user_id','in_reply_to_status_id',
'coordinates','place','retweet_count','geo','retweeted','in_reply_to_screen_name']

unwanted_user=['description','followers_count','protected',
'location','profile_use_background_image','utc_offset',
'profile_sidebar_fill_color','profile_text_color','follow_request_sent',
'friends_count','created_at','time_zone','notifications','favourites_count','following','listed_count',
'profile_background_color','profile_link_color',
'profile_image_url','geo_enabled','profile_background_image_url',
'lang','profile_background_tile','profile_sidebar_border_color',
'statuses_count','url','contributors_enabled','verified','show_all_inline_media','id']

unwanted_dm = ['sender', 'recipient']

banClient=['Google2Tweet']
        
yatap_message = """
    <html>
        <head>
        <title>GAE Twitter API Proxy</title>
        <link href='https://appengine.google.com/favicon.ico' rel='shortcut icon' type='image/x-icon' />
        <style>body { padding: 20px 40px; font-family: Verdana, Helvetica, Sans-Serif; font-size: medium; }</style>
        </head>
        <body><h2>yatap v#yatap_version# is running!</h2></p>
        <p><a href='/oauth/session'><img src='/static/sign-in-with-twitter.png' border='0'></a> <== Need Fuck GFW First!! 
        or <a href='/oauth/change'>change your key here</a></p>
        <p>This is a simple solution on Google App Engine which can proxy the HTTP request to twitter's official REST API url.</p>
        <p><font color='red'><b>Don't forget the \"/\" at the end of your api proxy address!!!.</b></font></p>
    </body></html>
    """

def success_output(handler, content, content_type='text/html'):
    handler.response.status = '200 OK'
    handler.response.headers.add_header('yatap-Version', yatap_version)
    handler.response.headers.add_header('Content-Type', content_type)
    handler.response.out.write(content)

def error_output(handler, content, content_type='text/html', status=503):
    handler.response.set_status(503)
    handler.response.headers.add_header('yatap-Version', yatap_version)
    handler.response.headers.add_header('Content-Type', content_type)
    handler.response.out.write("yatap Server Error:<br />")
    return handler.response.out.write(content)

def compress_buf(buf):
    zbuf = StringIO.StringIO()
    zfile = gzip.GzipFile(None, 'wb', 9, zbuf)
    zfile.write(buf)
    zfile.close()
    return zbuf.getvalue()

def remove_html_tags(data):
    p=re.compile('<.*?>')
    return p.sub('',data)
    
class TextOnly(webapp.RequestHandler):

    def statuse_filter(self,content):
        statuses=simplejson.loads(content)
        global unwanted_status
        global unwanted_user
        global banClient
        for statuse in statuses:
            statuse['source']=remove_html_tags(statuse['source'])
            for key in unwanted_status:
                if key in statuse:
                    del statuse[key]
            for key in unwanted_user:
                if key in statuse['user']:
                    del statuse['user'][key]
        statuses=filter(lambda x:x['source'] not in banClient,statuses)
        return statuses
        
    def directMsg_filter(self,content):
        global unwanted_dm
        directmessages = simplejson.loads(content)
        for dm in directmessages:
            for key in unwanted_dm:
                del dm[key]
        return directmessages

    
    def conver_url(self, orig_url):
        (scm, netloc, path, params, query, _) = urlparse.urlparse(orig_url)
        
        path_parts = path.split('/')
        
        if path_parts[1] == 'api' or path_parts[1] == 'search':
            sub_head = path_parts[1]
            path_parts = path_parts[2:]
            path_parts.insert(0,'')
            new_path = '/'.join(path_parts).replace('//','/')
            new_netloc = sub_head + '.twitter.com'
        else:
            new_path = path
            new_netloc = 'twitter.com'
    
        new_url = urlparse.urlunparse(('https', new_netloc, new_path.replace('//','/'), params, query, ''))
        return new_url, new_path

    def parse_auth_header(self, headers):
        username = None
        password = None
        
        if 'Authorization' in headers :
            auth_header = headers['Authorization']
            auth_parts = auth_header.split(' ')
            user_pass_parts = base64.b64decode(auth_parts[1]).split(':')
            username = user_pass_parts[0]
            password = user_pass_parts[1]
    
        return username, password

    def do_proxy(self, method):
        orig_url = self.request.url.replace('/text','',1)
        orig_body = self.request.body

        new_url,new_path = self.conver_url(orig_url)

        if new_path == '/' or new_path == '':
            global yatap_message
            yatap_message = yatap_message.replace('#yatap_version#', yatap_version)
            return success_output(self, yatap_message )
        
        username, password = self.parse_auth_header(self.request.headers)
        user_access_token = None
        
        callback_url = "%s/oauth/verify" % self.request.host_url
        client = oauth.TwitterClient(CONSUMER_KEY, CONSUMER_SECRET, callback_url)

        if username is None :
            protected=False
            user_access_token, user_access_secret = '', ''
        else:
            protected=True
            user_access_token, user_access_secret  = client.get_access_from_db(username, password)
            if user_access_token is None :
                return error_output(self, 'Can not find this user from db')
        
        additional_params = dict([(k,v) for k,v in parse_qsl(orig_body)])

        use_method = urlfetch.GET if method=='GET' else urlfetch.POST

        try :
            data = client.make_request(url=new_url, token=user_access_token, secret=user_access_secret, 
                                   method=use_method, protected=protected, 
                                   additional_params = additional_params)
        except Exception,error_message:
            logging.debug( error_message )
            error_output(self, content=error_message)
        else :
            #logging.debug(data.headers)
            self.response.headers.add_header('yatap-Version', yatap_version)
            for res_name, res_value in data.headers.items():
                if is_hop_by_hop(res_name) is False and res_name!='status':
                    self.response.headers.add_header(res_name, res_value)
            if method=='POST':
                content=simplejson.loads(data.content)
                content=content['text']
                self.response.out.write(simplejson.dumps(content))
            else:
                #filter here
                if string.find(orig_url,"direct")!=-1:
                    content=self.directMsg_filter(data.content)
                else:
                    content=self.statuse_filter(data.content)
                self.response.out.write(simplejson.dumps(content))

    def post(self):
        self.do_proxy('POST')
    
    def get(self):
        self.do_proxy('GET')

class MainPage(webapp.RequestHandler):

    def conver_url(self, orig_url):
        (scm, netloc, path, params, query, _) = urlparse.urlparse(orig_url)
        
        path_parts = path.split('/')
        
        if path_parts[1] == 'api' or path_parts[1] == 'search':
            sub_head = path_parts[1]
            path_parts = path_parts[2:]
            path_parts.insert(0,'')
            new_path = '/'.join(path_parts).replace('//','/')
            new_netloc = sub_head + '.twitter.com'
        else:
            new_path = path
            new_netloc = 'twitter.com'
    
        new_url = urlparse.urlunparse(('https', new_netloc, new_path.replace('//','/'), params, query, ''))
        return new_url, new_path

    def parse_auth_header(self, headers):
        username = None
        password = None
        
        if 'Authorization' in headers :
            auth_header = headers['Authorization']
            auth_parts = auth_header.split(' ')
            user_pass_parts = base64.b64decode(auth_parts[1]).split(':')
            username = user_pass_parts[0]
            password = user_pass_parts[1]
    
        return username, password

    def do_proxy(self, method):
        orig_url = self.request.url
        orig_body = self.request.body

        new_url,new_path = self.conver_url(orig_url)

        if new_path == '/' or new_path == '':
            global yatap_message
            yatap_message = yatap_message.replace('#yatap_version#', yatap_version)
            return success_output(self, yatap_message )
        
        username, password = self.parse_auth_header(self.request.headers)
        user_access_token = None
        
        callback_url = "%s/oauth/verify" % self.request.host_url
        client = oauth.TwitterClient(CONSUMER_KEY, CONSUMER_SECRET, callback_url)

        if username is None :
            protected=False
            user_access_token, user_access_secret = '', ''
        else:
            protected=True
            user_access_token, user_access_secret  = client.get_access_from_db(username, password)
            if user_access_token is None :
                return error_output(self, 'Can not find this user from db')
        
        additional_params = dict([(k,v) for k,v in parse_qsl(orig_body)])

        use_method = urlfetch.GET if method=='GET' else urlfetch.POST

        try :
            data = client.make_request(url=new_url, token=user_access_token, secret=user_access_secret, 
                                   method=use_method, protected=protected, 
                                   additional_params = additional_params)
        except Exception,error_message:
            logging.debug( error_message )
            error_output(self, content=error_message)
        else :
            #logging.debug(data.headers)
            self.response.headers.add_header('yatap-Version', yatap_version)
            for res_name, res_value in data.headers.items():
                if is_hop_by_hop(res_name) is False and res_name!='status':
                    self.response.headers.add_header(res_name, res_value)
            self.response.out.write(data.content)

    def post(self):
        self.do_proxy('POST')
    
    def get(self):
        self.do_proxy('GET')


class OauthPage(webapp.RequestHandler):

    def get(self, mode=""):
        callback_url = "%s/oauth/verify" % self.request.host_url
        client = oauth.TwitterClient(CONSUMER_KEY, CONSUMER_SECRET, callback_url)

        if mode=='session':
            # step C Consumer Direct User to Service Provider
            try:
                url = client.get_authorization_url()
                self.redirect(url)
            except Exception,error_message:
                self.response.out.write( error_message )


        if mode=='verify':
            # step D Service Provider Directs User to Consumer
            auth_token = self.request.get("oauth_token")
            auth_verifier = self.request.get("oauth_verifier")

            # step E Consumer Request Access Token 
            # step F Service Provider Grants Access Token
            try:
                access_token, access_secret, screen_name = client.get_access_token(auth_token, auth_verifier)
                self_key = '%s' % uuid4()
                # Save the auth token and secret in our database.
                client.save_user_info_into_db(username=screen_name, password=self_key, 
                                              token=access_token, secret=access_secret)
                show_key_url = '%s/oauth/showkey?name=%s&key=%s' % (
                                                                       self.request.host_url, 
                                                                       screen_name, self_key)
                self.redirect(show_key_url)
            except Exception,error_message:
                logging.debug("oauth_token:" + auth_token)
                logging.debug("oauth_verifier:" + auth_verifier)
                logging.debug( error_message )
                self.response.out.write( error_message )
        
        if mode=='showkey' or mode=='change':
            screen_name = self.request.get("name")
            self_key = self.request.get("key")
            out_message = """
                <html><head><title>yatap</title>
                <style>body { padding: 20px 40px; font-family: Courier New; font-size: medium; }</style>
                </head><body><p><form method="post" action="%s/oauth/changekey">
                screen name : <input type="text" name="name" size="20" value="%s"> <br /><br />
                current key : <input type="text" name="old_key" size="50" value="%s"> <br /><br />
                the new key : <input type="text" name="new_key" size="50" value=""> <br /><br />
                <input type="submit" name="_submit" value="Change the Key">
                </form></p></body></html>
                """ % (self.request.host_url, screen_name, self_key)
            self.response.out.write( out_message )
        
        if mode=='test':
            screen_name = self.request.get("name")
            self_key = self.request.get("key")
            user_access_token, user_access_secret  = client.get_access_from_db(screen_name, self_key)
            self.response.out.write( '%s<---->%s' % (user_access_token, user_access_secret) )
            
    def post(self, mode=''):
        
        callback_url = "%s/oauth/verify" % self.request.host_url
        client = oauth.TwitterClient(CONSUMER_KEY, CONSUMER_SECRET, callback_url)
        
        if mode=='changekey':
            screen_name = self.request.get("name")
            old_key = self.request.get("old_key")
            new_key = self.request.get("new_key")
            user_access_token, user_access_secret  = client.get_access_from_db(screen_name, old_key)
            
            if user_access_token is None or user_access_secret is None:
                logging.debug("screen_name:" + screen_name)
                logging.debug("old_key:" + old_key)
                logging.debug("new_key:" + new_key)
                self.response.out.write( 'Can not find user from db, or invalid old_key.' )
            else:
                try:
                    client.save_user_info_into_db(username=screen_name, password=new_key, 
                                                  token=user_access_token, secret=user_access_secret)
                    show_key_url = '%s/oauth/showkey?name=%s&key=%s' % (
                                                                        self.request.host_url, 
                                                                        screen_name, new_key)
                    self.redirect(show_key_url)
                except Exception,error_message:
                    logging.debug("screen_name:" + screen_name)
                    logging.debug("old_key:" + old_key)
                    logging.debug("new_key:" + new_key)
                    logging.debug( error_message )
                    self.response.out.write( error_message )

def main():
    application = webapp.WSGIApplication( [
        (r'/oauth/(.*)', OauthPage),
        (r'/text/.*',    TextOnly),
        (r'/.*',         MainPage)        
        ], debug=True)
    wsgiref.handlers.CGIHandler().run(application)
    
if __name__ == "__main__":
  main()
