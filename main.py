#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import string
import random
import hashlib
import re
import json
import datetime
import time

from google.appengine.ext import db
from collections import namedtuple


template_dir = os.path.join(os.path.dirname(__file__), 'templates')    # __file__ is *this* file
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

CACHE = {}

### MODELS ###

class BlogPosts(db.Model):
    """Create datastore with subject, content, and created date."""
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):
    username = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)


### HELPER FUNCTIONS ###

user_re = re.compile("^[a-zA-Z0-9_-]{3,20}$")
pass_re = re.compile("^.{3,20}$")
email_re = re.compile("^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return user_re.match(username)

def valid_password(password):
    return pass_re.match(password)

def valid_email(email):
    return email_re.match(email)

def make_salt():
    """Generate a random 5-character string to use as a password salt"""
    salt = ''
    for i in xrange(5):
        salt += random.choice(string.ascii_letters)
    return salt

def make_pw_hash(name, pw, salt=None):
    """Use sha256 hash function to create or validate a username/password hash combination"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return (salt, h)

def valid_pw(name, pw, h):
    """Validate a username/password combination"""
    hash,salt = h.split(',')
    if make_pw_hash(name,pw,salt) == h:
        return True

def cache_get(key):
    global CACHE
    return CACHE.get(key)

def cache_update(key, value):
    global CACHE
    CACHE.update({key: value})

def cache_clear():
    global CACHE
    CACHE.clear()

def get_top10():
    global CACHE
    stmt = "SELECT * FROM BlogPosts ORDER BY created DESC LIMIT 10"
    key = stmt
    if key not in CACHE:
        posts_from_db = db.GqlQuery(stmt)
        posts_list = list(posts_from_db)    
        cache_update(key, tuple([posts_list, time.time()]))
    v, t = cache_get(key)
    return v, int(time.time()-t)

def get_perm(entry_id):
    global CACHE
    key = db.Key.from_path('BlogPosts', int(entry_id))    # Look for a post by entry_id
    if key not in CACHE:
        bp = db.get(key)
        cache_update(key, tuple([bp, time.time()]))
    v,t = cache_get(key)
    return v, int(time.time()-t)

### HELPER CLASSES ###

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        """Helper function for render()"""
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        """Helper function for render()"""
        jinja_template = jinja_env.get_template(template)
        return jinja_template.render(params)

    def render(self, template, **kw):
        """Helper function combining self.write and self.redner_str that is exposed to dependent classes"""
        kw['signedIn'] = self.request.cookies.get('user_id', None)
        self.write(self.render_str(template,**kw))

    def json(self, **kw):
        self.response.content_type = 'application/json'
        res = []
        for bp in kw['posts']:
            res.append({"subject": bp.subject, 
                        "created": bp.created.strftime("%a %B %d %H:%M:%S %Y"),
                        "content": bp.content})
        if len(res) > 1:
            self.write(json.dumps(res))
        else:
            self.write(json.dumps(res[0]))


### PAGE HANDLERS ###

class BaseRedirect(webapp2.RequestHandler):
    """Redirect to blog homepage"""
    def get(self):
        self.redirect('/blog')


class MainPage(Handler):
    """Basic landing page"""
    def get(self, json):
        posts_list, update_time = get_top10()
        
        if json:
            self.json(posts=posts_list)
        else:
            self.render("main.html",posts=posts_list, time=update_time)


class NewPost(Handler):
    """Add a new post to the blog"""
    def get(self,**params):
        self.render("form.html",**params)
    
    def post(self):
        entry_data = {}
        entry_data['subject'] = self.request.get('subject')
        entry_data['content'] = self.request.get('content')
        

        if entry_data['subject'] and entry_data['content']:
            bp = BlogPosts(**entry_data)
            post_key = bp.put()    # Write the values to the model
        
            self.redirect('/blog/%d' % int(post_key.id()))
            
        else:
            entry_data['error'] = "You need both a valid subject and content."
            self.get(**entry_data)    # redirect to the same page and re-render with error messages

        cache_clear()

class Permalink(Handler):
    """Links to each individual post"""
    def get(self, entry_id, json):
        bp, update_time = get_perm(entry_id)
        
        if not bp:
            self.redirect('/404')    # Kludge way to use the built-in 404 handler (for consistency)
            return
        
        if json:
            self.json(posts=[bp])
        else:
            self.render("main.html", posts=[bp], menu="home", time=update_time)


class Signup(Handler):
    def get(self):
        self.render("signup.html",error={})

    def post(self):
        error = {}
        username = self.request.get('username')
        password = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')

        user_from_db = db.GqlQuery("SELECT * FROM Users where username=:1", username).get()

        if not username or not valid_username(username): # username is required and must be valid
            error['username'] = 'Invalid username.'
        elif user_from_db and username == user_from_db.username: # user should not exist in the db
            error['username'] = 'User already exists.'
        elif not password or not valid_password(password): # password is required and must be valid
            error['password'] = 'Invalid password.'
        elif not password2 or password != password2: # make sure password matches
            error['verify'] = 'Passwords do not match.'
        elif email and not valid_email(email): # validate email if given
            error['email'] = 'Invalid email address.'

        if error:
            self.render("signup.html",error=error)
        else:
            salt,h = make_pw_hash(username,password)
            user = Users(username = username,
                         pw_hash = h,
                         salt = salt)
            user.put()
            user_id = user.key().id()
            self.response.headers.add_header('Set-Cookie', 'user_id=%d|%s' % (user_id,h))
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        error = {}
        username = self.request.get('username')
        password = self.request.get('password')

        user_from_db = db.GqlQuery("SELECT * FROM Users where username=:1", username).get()

        if (not username or not password or
            not valid_username(username) or
            not valid_password(password) or
            not user_from_db or
            username != user_from_db.username):
            error = 'Invalid login'

        if error:
            self.render("login.html",error=error)
        else:
            salt,h = make_pw_hash(username,password)
            user = Users(username = username,
                         pw_hash = h,
                         salt = salt)
            user.put()
            user_id = user.key().id()
            self.response.headers.add_header('Set-Cookie', 'user_id=%d|%s; Path=/' % (user_id,h))
            self.redirect('/blog/welcome')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/blog/signup')


class Welcome(Handler):
    def get(self):
        user_cookie = self.request.cookies.get('user_id', None)
        if not user_cookie:
            self.redirect('/blog/signup')
        cookie_user_id,cookie_h = tuple(user_cookie.split('|'))
        user = Users.get_by_id(int(cookie_user_id))
        if not cookie_h == user.pw_hash:
            self.redirect('/blog/signup')
        else:
            self.render("welcome.html",username=user.username)

class Flush(Handler):
    """Redirect to blog homepage"""
    def get(self):
        cache_clear()
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/', BaseRedirect),
    ('/blog(/.json)?', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)(.json)?', Permalink),
    ('/blog/signup', Signup),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/welcome', Welcome),
    ('/blog/flush', Flush)
   ], debug=True)
