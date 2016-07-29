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
import cgi
import re
import random
import string
import hashlib
import json
from google.appengine.ext import db
from google.appengine.api import memcache
from datetime import datetime

#set variable for directory location of your templates. 
#Concatenate current filename (python file) with 'templates'
template_directory = os.path.join(os.path.dirname(__file__), 'templates')
#create new jinja2 Environment. Get it from template_directory.
#so when we render(), it knows where to find the template file to render
jinja_environ = jinja2.Environment(loader = jinja2.FileSystemLoader(template_directory), 
                                   autoescape=True)


lastUpdate = datetime.now()

#def blog_key(name = "default"):
    
 #   return db.Key.from_path('blogs', name)

class BlogPost(db.Model):
    """
    an entity/table/class for blog posts. 
    3 fields that make up a post
    the primary key is made auto by google
    a blog post will be an object just like OOP
    """
   
    subject = db.StringProperty(required = True)
    
    blogText = db.TextProperty(required = True)
    
    #timeCreated is created auto by google
    timeCreated = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    """
    an entity/table/class for Users. 
    3 fields that make up a User, emailnot required
    the primary key is made auto by google
    a User will be an object just like OOP
        ex: user13.email 
    """
   
    userName = db.StringProperty(required = True)

    password = db.StringProperty(required = True)

    email = db.StringProperty(required = False)



#base handler. Other handlers will inherit from it.
class Handler(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **parameters):
        #inputs:
            #template = file location of the template you want
            #**parameters = keyword arguments (name = value), any number of them. Used to assign
                #values to the variables in the html template.
        #create a template, t, with all variables filled in.
        #returns this template.
        t = jinja_environ.get_template(template)
        #function render() on t, is a jinja2.Environment object method
        #render() expects keyword parameters! **kargs
        return t.render(parameters)
    
    
    def renderHtml(self, template, **kw):
        #inputs:
            #template = file location of the template you want
            #**kw = keyword arguments (name = value), any number of them. Used to assign
                #values to the variables in the html template.
        #takes inputs, calls render_str with them. render_str takes i your temlate location and variable values,
            #and returns back the html string, all filled in. Then self.write() will display html on broswer.
        #will send it to write(), where it gets displayed in browser
        self.write(self.render_str(template, **kw))

    def render_Json(self, aCollection):
        #renders a json page.No templates.
        #aCollection must be a python type that json understands (ex: dict,list, int,float, string)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(aCollection)


class FrontHandler(Handler):
    """
    When url is at Front Page.
    """
    def get(self):
        #blogs is a list of Blog objects stored in Blog table in cacheBlogs
        #to prevent repeated queries, keep blogs in a python list        
        blogs = getTopBlogs()
        global lastUpdate
        #subtract time of redering front page,now, from time the cache of top 10
        #blog posts was last updated. Show in # seconds. Round it by converting float to int.
        timeSinceLastUpdate = int((datetime.now() - lastUpdate).total_seconds())
        
        #----------------------------------------------------------
        #get the cookie from user with cookie name of "username"
        #so we can let user know if they are logged in or ask to login, signup
        UNCookieVal = self.request.cookies.get("username", "")
        #the cookie value is in format "username|hashcode"
        #take users cookie val and check to make sure it is valid.
        userName = check_secure_val(UNCookieVal)
        #if valid username hash: (cookie is authentic)
        #---------------------------------------------------------------
        self.renderHtml("frontPage.html", blogPosts = blogs, 
                        timeSinceUpdate = timeSinceLastUpdate,
                        username = userName)
        
    def post(self):
        #if user submits form (clicks the new post button) --> redirect to /newpost url
        self.redirect("/newpost")
    


class FormHandler(Handler):
    """
    page for user filling out a new blog post
    """
    def get(self):
        
        #if user is logged in, let him/her post, otherwise redirect to /login
         #----------------------------------------------------------
        #get the cookie from user with cookie name of "username"
        #so we can personalize the welcome page for each inividual user
        UNCookieVal = self.request.cookies.get("username", "")
        #the cookie value is in format "username|hashcode"
        #take users cookie val and check to make sure it is valid.
        userName = check_secure_val(UNCookieVal)
        
        #if valid username hash: (cookie is authentic)
        if userName:
            #render an empty form
            self.renderHtml("formPage.html", subject="", blogtext="", error="")

        #if user has not logged in or if cookie is cheated:
        else:
            self.redirect('/login')
        #-------------------------------------------------------------
            
    def post(self):
        
        #put user input into python vars
        inpSubj = self.request.get("subject")
        inpBlogPost = self.request.get("content")
        
        #if blog post content was empty but was just a blank space, set it to empty string
        #so that we can say inpBlogPost is False if empty
        if inpBlogPost == " ":
            inpBlogPost = ""
        
        #if there was actual user input in subject & content text areas
        if inpSubj and inpBlogPost:
            #make a new BlogPost object
            blogRecord = BlogPost(subject = inpSubj, blogText = inpBlogPost)
            #store it in the google db
            blogRecord.put()
            #update top 10 blogs value in memcache. 
            getTopBlogs(True)
            #make a str var for the primary key that google db gave to new blog post
            postKey = str(blogRecord.key())
            #redirect user to new url with "/permalink/" + primary key added to url
            self.redirect("http://rhine-blog2.appspot.com/permalink/" + postKey)
        
        #if either or both subject & content was left empty, there will be an error messag back to usere:
        else:
            error1=""
            #if subject was left blank:
            if not inpSubj:
                error1 = "Please enter a Subject. "
            #if content was left blank:
            if not inpBlogPost:
                error1 = error1 + " Please Enter a Blog Post."
            #render the blog post form back to user, with the error message & cache input values
            self.renderHtml("formPage.html", subject = inpSubj, blogtext = inpBlogPost, error = error1)
            


class AfterPostHandler(Handler):
    """
    for after a user posts a new blog.
    """
    def get(self):
        
        #get the cookie from user with cookie name of "username"
        #so we can let user know if they are logged in or ask to login, signup
        UNCookieVal = self.request.cookies.get("username", "")
        #the cookie value is in format "username|hashcode"
        #take users cookie val and check to make sure it is valid.
        userName = check_secure_val(UNCookieVal)        

        
        #ag1zfnJoaW5lLWJsb2cychULEghCbG9nUG9zdBiAgICAvMuKCgw
        #get the url that you are at. Will be unique because the blog post primary key is part of url
        url = self.request.url
        #slit the url string via '/'
        urlList = url.split('/')
        #theblog post primary key is after last '/' so will be last element in list
        postKey =  urlList[-1]
        #convert it to a string, it might be unicode
        postKey = str(postKey)
        #retreive the blog post tuple from memcache based on primary key
        postInfo = getPermalink(postKey)
        #the blogost object is element 0
        thePost = postInfo[0]
        #time memecache for this exact blogpost was last updated is element 1.
        lastUpdatePerm = postInfo[1]
        timeSinceLastCache = int((datetime.now() - lastUpdatePerm).total_seconds())
        #render the blog post to user, sending blog post attributes to template
        self.renderHtml("individPost.html", subject = thePost.subject, blogtext = thePost.blogText, 
                        time = thePost.timeCreated, timeSinceUpdate = timeSinceLastCache,
                        username = userName)
    
    def post(self):
        
        #if user submits form (clicks the 'go to home page' button) --> redirect to front page url
        self.redirect("http://rhine-blog2.appspot.com/")
        


class SignUpHandler(Handler):
    """
    for signing up a NEW user
    """
    
    def get(self):
        #render empty form
        self.renderHtml("signUp.html", cacheUN = "", cacheEmail = "",
                        userNameError="", passwrdError="", 
                        confirmPWError ="", emailError="")
    
    def post(self):
        #when user submits the form
        #put all user inputs into python vars
        inpUserName = self.request.get("username")
        inpPassword = self.request.get("password")
        inpConfirmPW = self.request.get("verify")
        inpEmail = self.request.get("email")
        
        #create boolean vars after testing each input for validity. These functions are global functions.
        isValInpUN = validUserName(inpUserName)
        isValInpPW = validPassword(inpPassword)
        isValInpConPW = inpPassword == inpConfirmPW
        isValInpEmail = validEmail(inpEmail)
        
        #if all inputs are valid:
        if (isValInpUN and isValInpPW and isValInpConPW and isValInpEmail):
           
           #test to see if the username is already in use by someone else
            #get a list of existing user objects
            allUsers = getRegisteredUsers()

            #alreadyUser set to False for now
            alreadyUser = False
            
            #if at least one registered user in system
            if allUsers:
                #Iterate through users:
                for x in allUsers:
                    #if the input username matches an existing user's username:
                    if inpUserName == x.userName:
                        #alreadyUser is True
                        alreadyUser = True
                
            #if username is not yet in use:
            if not alreadyUser:
                #make a password hash string out of inputted password.
                pw_hash = make_pw_hash(inpUserName, inpPassword)
                #create a User object based on username, hashed password, & email
                aUser = User(userName = inpUserName, password = pw_hash, email = inpEmail)
                #store new user in google db
                aUser.put()
                #update memcache for updated list of users
                getRegisteredUsers(True)
                #hash the username so we can send it to user's browser in a cookie
                hashUser = make_secure_val(inpUserName)
                #send the cookie
                self.response.set_cookie("username", hashUser, path='/')
                #redirect user to the welcome page                
                self.redirect("/welcome")
            
            #if username is already taken:
            else:
                #render the signup form back to the user with an error message
                self.renderHtml("signUp.html", cacheUN = inpUserName,
                    cacheEmail = inpEmail,
                    userNameError = "User Name already exists.",
                    passwrdError = "",
                    confirmPWError = "",
                    emailError = "")
        
        #if any of the form inputs are invalid:
        else:
            
            #error messages default to empty:
            userNameError1 = ""
            passwrdError1 = ""
            confirmPWError1 = ""
            emailError1 = ""
            
            #if the input is invalid, set error msg values
            if not isValInpUN:
                userNameError1 = "User Name not valid."
            if not isValInpPW:
                passwrdError1 = "Password is not valid."
            if not isValInpConPW:
                confirmPWError1 = "Passwords do not match."
            if not isValInpEmail:
                emailError1 = "Email address is not valid."
            
            #render form back to user with error messages
            self.renderHtml("signUp.html", cacheUN = inpUserName, 
                            cacheEmail = inpEmail,
                            userNameError = userNameError1, 
                            passwrdError = passwrdError1, 
                            confirmPWError = confirmPWError1, 
                            emailError = emailError1)
 

class LoginHandler(Handler):
    """
    For when a registered user is trying to log into site.
    """
    def get(self):
        #render empty form
        self.renderHtml("login.html", username = "", errorMsg = "")
    
    def post(self):
        #put all user inputs into python vars
        inpUserN = self.request.get("userNM")
        inpPW = self.request.get("passWrd")
        
        #establish a boolean var for login being valid or not
        isValidLogin = False
        
        #retreive a list of user objects from cache or db
        usersList = getRegisteredUsers()
        
        #If there are any users in our db:   (if no users, then isValidLogin must be False)
        if usersList:
            #iterate through all existing users
            for u in usersList:
                #if login attempt username matches a username of an existing user:
                if inpUserN == u.userName:
                    #compare password of login attempt and that store for the user
                    #u.password is in pw_hash format ("hashcode,salt")
                    #calls isCorrectPassword()
                    #if True --> set isValidLogin to True bc username & password match
                    if isCorrectPassword(u.userName, inpPW, u.password):
                        isValidLogin = True
        
        #if login attempt is valid:    
        if isValidLogin:
            #hash the username so we can send it to user's browser in a cookie
            hashUserNm = make_secure_val(inpUserN)
            #send the cookie
            self.response.set_cookie("username", hashUserNm)
            #redirect user to welcome page
            self.redirect("/welcome")
        
        #if login was not valid:
        else:
            #render login form bak to user with error message and cache username
            self.renderHtml("login.html", username = inpUserN, errorMsg = "Invalid Login")
            
            

           
class WelcomeHandler(Handler):
    """
    Welcome Page after a user logs in or just signs up.
    """
    def get(self):
        #get the cookie from user with cookie name of "username"
        #so we can personalize the welcome page for each inividual user
        UNCookieVal = self.request.cookies.get("username", "")
        #the cookie value is in format "username|hashcode"
        #take users cookie val and check to make sure it is valid.
        userName = check_secure_val(UNCookieVal)
        #if valid username hash: (cookie is authentic)
        if userName:
            #render welcome page with their username
            self.renderHtml("welcome.html", username = userName)
        #if cookie is cheated:
        else:
            #redirect user to login
            self.redirect("/login")


class LogoutHandler(Handler):
    """
    For logging a user out
    """
    def get(self):
        #get the username cookie from user's browser
        cookie = self.request.cookies.get("username")
        #if there is one:
        if cookie:
            #delete it by setting value to None. 
            #self.response.delete_cookie("username") --> this works too
            self.response.set_cookie("username", None, path="/")
        #redirect user to signup page regardless of cookie
        self.redirect("/login")


class FlushHandler(Handler):
    """
    When url is requested, it clears the websits memcache completely.
    Does NOT affect the database at all!
    """
    def get(self):
        
        memcache.flush_all()
        self.redirect("http://rhine-blog2.appspot.com/")



class FrontPageJsonHandler(Handler):
    """
    for when someone wants your front page in JSON format
    """
    def get(self):
        #blogs is a list of Blog objects stored in Blog table in db
        blogs = db.GqlQuery("select * from BlogPost order by timeCreated Desc")
        #to prevent repeated queries, keep blogs in a python list        
        blogs = list(blogs)
	   #convert python object (blogPost) into key: value pairs in a dict, so can convert to JSON
        #output is python object, list of dictionaries, one dict per blog
        outputblogs = []
        for b in blogs:
            blogDict = {}
            blogDict["content"] = b.blogText
            blogDict["subject"] = b.subject
            #there's no time datatype in json, need to convert to string first
            blogDict["created"] = b.timeCreated.strftime("%b %d, %Y  %H:%M:%S")
            blogDict["last_modified"] = b.timeCreated.strftime("%b %d, %Y  %H:%M:%S")
            outputblogs.append(blogDict)
        
        #json.dumps only takes a dict, list, int, float, string
        #jsonOut is a python string of valid json
        jsonOut = json.dumps(outputblogs)
        #calls render_Json() that we inherit from Handler class (we created it)
        self.render_Json(jsonOut)
        
        
        
class AfterPostJsonHandler(Handler):
    
    def get(self):
        
        #get the url that you are at. Will be unique because the blog post primary key is part of url
        url = self.request.url
        #slit the url string via '/'
        urlList = url.split('/')
        #theblog post primary key is after last '/' so will be last element in list
        postKey =  urlList[-1]
        #convert it to a string, it might be unicode
        postKey = str(postKey)
        
        #remove .json from url, 5 chars from right
        postKey = postKey.replace(".json", "")
        #retreive the blog post object from google db based on primary key
        thePost = db.get(postKey)
        
		#convert python object (blogPost) into key: value pairs in a dict, so can convert to JSON
        blogDict = {}
        blogDict["content"] = thePost.blogText
        blogDict["subject"] = thePost.subject
        #there's no time datatype in json, need to convert to string first
        blogDict["created"] = thePost.timeCreated.strftime("%b %d, %Y  %H:%M:%S")
        blogDict["last_modified"] = thePost.timeCreated.strftime("%b %d, %Y  %H:%M:%S")

        #json.dumps only takes a dict, list, int, float, string
        #jsonOut is a python string of valid json
        jsonOut = json.dumps(blogDict)
        #calls render_Json() that we inherit from Handler class (we created it)
        self.render_Json(jsonOut)
        
    
def getTopBlogs(update = False):

    myKey = 'top'
    #if update = False and cache has the key (always have key, except 1st post), then
    #we ust return cached value, because it is current.
    #if we are updating cache, after new blog post, update argument of True will
    #be passed in, so we re-query db for top 10 blogs.
    #retrieve value stored in memcache. If key not found, returns None:
    blogs = memcache.get(myKey)
    #if key not in memcache or if update = True (need to update memcache)
    if blogs is None or update == True:
        
        #blogs is a list of Blog objects stored in Blog table in db
        blogs = db.GqlQuery("select * from BlogPost order by timeCreated Desc Limit 10")
        #to prevent repeated queries, keep blogs in a python list        
        blogs = list(blogs)
        #set memcache with key and new blog posts as value
        memcache.set(myKey, blogs)
        global lastUpdate
        #update time variable for latest cache update to be displayed on front page.
        lastUpdate = datetime.now()
        
    return blogs


def getPermalink(blogPostKey):
    #retreives the blog post that has that specific key
    #also retreives the time that the blog was added to cache
    #returns pot object and time in a tuple
    #blogpost & time are added to memcache indepently, so have separate keys
    key1 = blogPostKey
    key2 = blogPostKey + "last"
    
    #Get the post and time out of cache. Will = None if not in cache.
    thePost = memcache.get(key1)
    lastUpdatePerm = memcache.get(key2)
    
    #if the blog post is not in cache:
    if thePost == None:
        #retreive blog post from the database
        thePost = db.get(blogPostKey)
        #add blog post to the cache
        memcache.set(key1, thePost)
        #refresh time of last update since you just updated cache
        lastUpdatePerm = datetime.now()
    
    #if time since last update for the specific blog post is not in cache:
    if lastUpdatePerm == None:
        #set current time to now
        lastUpdatePerm = datetime.now()
        #dd it to cache
        memcache.set(key2, lastUpdatePerm)
    #return tuple of (blogpost object, time of last update)
    return (thePost, lastUpdatePerm)

def getRegisteredUsers(toUpdate = False):
    
    aKey = 'all'
    #only 1 key in memcache, value is the entire list of users. So users are not added
    #to cache separately. 
    #toUpdate will only be True when we added new user to site so need to update cache
    #so when user logs in, won't hit database, just cache.
    #try to get userList out of memcache:
    usersList = memcache.get(aKey)
    
    #if we just updated users in db, or usrsList not stored yet, update the cache
    if toUpdate or usersList == None:
        #retreive a updated list of user objects fromUser table in google db
        usersList = db.GqlQuery("select * from User")
        #to prevent repeated queries while iterating, store in a list
        usersList = list(usersList)
        #add list to cache
        memcache.set(aKey, usersList)
    #return usersList
    return usersList
    
def validUserName(username):
    
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def validPassword(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)
    
def validEmail(emailAddress):
    #since email was optional, if left blank, it is still valid
    if emailAddress == "":
        return True
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIL_RE.match(emailAddress)


def escape_html(s):
    return cgi.escape(s, quote= True)



def make_salt():
    #for use in password hashing
    #salt is a random, 5 letter string
    salt = ""
    for x in range(5):
        z = random.choice(string.letters)
        salt = salt + z
    return salt

def make_pw_hash(username, pw, salt=""):
    """
    returns a string in format of "hashcode,salt".
    The pw are may or may not be valid. Irrelevant here.
    used when creating a pw_hash for a new user AND used when trying to 
    authenticate a registered users password.
    #if salt = "", then we are creating a new pw_hash
    #if salt is not empty, then we are creating a pw_hash to authenticate a
    #users pw_hash already in db."""
    if not salt:
        #make a new salt for the new user
        salt = make_salt()
    
    #input to hash function is a string combining username, password, and salt
    hInp = "" + username + pw + salt
    #get hash function output of the input
    hout = hashlib.sha256(hInp)
    hout = hout.hexdigest()
    #return a string that fuses the hash function output with the salt used
    #ex: pw_hash = "536b474ac010,fkwdm"
    pw_hash = "%s,%s" % (hout, salt)
    return pw_hash
    
def getSalt(pw_hash):
    #returns salt from a password hashes (#ex: pw_hash = "536b474ac010,fkwdm")
    x = pw_hash.split(",")
    salt = x[1]
    return salt

def isCorrectPassword(username, inputPassword, userPW_hash):
    
    """boolean, returns True if the pw_hash string we create based on
    a password entered in during a login MATCHES the pw_hash string that we
    have in db for that user.
    """
    #extract out the salt from the PW_hash we have in db for that user ('password' attribute of User object)
    userPWSalt = getSalt(userPW_hash)
    #using the login username (is valid, the login password (testing for validity,
    #and the user's salt(valid)), create a pw_hash
    inputPWHash = make_pw_hash(username, inputPassword, userPWSalt)
    
    #if the pw_hash we created mathes pw_hash we have in db for the user:
    if inputPWHash == userPW_hash:
        return True
    #else:
    else:
        return False

    
    
    
def hash_str(s):
    
    #hash input = "grindstone" + s
    #returns hash output in hexadecimal output
    
    a = "grindstone" + s
    return hashlib.sha256(a).hexdigest()

def make_secure_val(s):
    #for cookies
    # returns a string of “actual value|hashoutput”
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(cookieValue):
    #checks validity of a user's cookie
    ###checks to see if the actual cookie value is valid
    #cookieValue is a string in format "actualValue|hashOutput"
    #the actual value was the input into hash function to get hashOutput
    if cookieValue == "":
        return None
    y = cookieValue.split("|")
    actualVal = y[0]
    hashOutput = y[1]
    #we take the actual value from users cookie and put it through our 
    #hash function via hash_str().
    #if HashOutput from users cookie MATCHES the hash_str we get from 
    #putting users cookie actual value into our hash function, we know it is valid. 
    if hash_str(actualVal) == hashOutput:
        return actualVal
    else:
        return None

        
app = webapp2.WSGIApplication(
[
    (r'/', FrontHandler), 
    (r'/newpost', FormHandler), 
    (r'/permalink/.*\.json$', AfterPostJsonHandler),
    (r'/permalink/.*', AfterPostHandler),
    (r'/signup', SignUpHandler),
    (r'/welcome', WelcomeHandler),
    (r'/login', LoginHandler),
    (r'/logout', LogoutHandler),
    (r'/flush', FlushHandler),
    (r'/.json', FrontPageJsonHandler),
    (r'/permalink/.*\.json$', AfterPostJsonHandler)
], debug=True)
#app = webapp2.WSGIApplication([
#    ('/', MainHandler)
#], debug=True)
