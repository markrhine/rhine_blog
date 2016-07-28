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

from google.appengine.ext import db
#set variable for directory location of your templates. 
#Concatenate current filename (python file) with 'templates'
template_directory = os.path.join(os.path.dirname(__file__), 'templates')
#create new jinja2 Environment. Get it from template_directory.
#so when we render(), it knows where to find the template file to render
jinja_environ = jinja2.Environment(loader = jinja2.FileSystemLoader(template_directory), 
                                   autoescape=True)


#def blog_key(name = "default"):
    
 #   return db.Key.from_path('blogs', name)

class BlogPost(db.Model):
   
    subject = db.StringProperty(required = True)
    
    blogText = db.TextProperty(required = True)
    
    timeCreated = db.DateTimeProperty(auto_now_add = True)


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



class FrontHandler(Handler):
    def get(self):
        
        blogs = db.GqlQuery("select * from BlogPost order by timeCreated Desc")

        self.renderHtml("frontPage.html", blogPosts = blogs)
        
    def post(self):
        
        self.redirect("/newpost")
    
class FormHandler(Handler):
    def get(self):
            self.renderHtml("formPage.html", subject="", blogtext="", error="")
            
            
    def post(self):
        
        inpSubj = self.request.get("subject")
        inpBlogPost = self.request.get("content")
        if inpBlogPost == " ":
            inpBlogPost = ""
        if inpSubj and inpBlogPost:
            blogRecord = BlogPost(subject = inpSubj, blogText = inpBlogPost)
            blogRecord.put()
            postKey = str(blogRecord.key())
            self.redirect("http://rhine-blog2.appspot.com/permalink/" + postKey)
        
        else:
            error1=""
            if not inpSubj:
                error1 = "Please enter a Subject. "
            if not inpBlogPost:
                error1 = error1 + " Please Enter a Blog Post."
            self.renderHtml("formPage.html", subject = inpSubj, blogtext = inpBlogPost, error = error1)
            
class AfterPostHandler(Handler):
    
    def get(self):
        #ag1zfnJoaW5lLWJsb2cychULEghCbG9nUG9zdBiAgICAvMuKCgw
        url = self.request.url
        postKey = url.split('/')
        postKey =  postKey[-1]
        postKey = str(postKey)
        thePost = db.get(postKey)
        self.renderHtml("individPost.html", subject = thePost.subject, blogtext = thePost.blogText, time = thePost.timeCreated)
    
    
    def post(self):
        
        self.redirect("http://rhine-blog2.appspot.com/")
        
app = webapp2.WSGIApplication(
[
    (r'/', FrontHandler), 
    (r'/newpost', FormHandler), 
    (r'/permalink/.*', AfterPostHandler)
], debug=True)
#app = webapp2.WSGIApplication([
#    ('/', MainHandler)
#], debug=True)
