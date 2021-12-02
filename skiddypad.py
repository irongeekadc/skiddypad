#!/usr/bin/python3
#Skiddypas 2.0
# Purpose:      A simple notepad with usefully transforms for pentesters
# Modifier/Maintainer:   Adrian Crenshaw (Irongeek) 
#Based on J.A.T.E by AlMikFox3
#https://github.com/AlMikFox3/J.AT.E.-Just-Another-Text-Editor/blob/master/algo.py
from tkinter import *
import tkinter.filedialog as tk
import tkinter.messagebox as tk2
import tkinter.simpledialog as tk3
from tkinter import simpledialog
from time import sleep
import threading
import string
import base64
import urllib
import binascii
import codecs
import re
import sys
import os.path
import copy
import os
import socket
import threading
import time 
import logging
import struct
from ipwhois import IPWhois
from pprint import pprint
from netaddr import IPNetwork, IPAddress
eol=os.linesep 
class Thread(threading.Thread):
        def __init__(self, iporname, whattodo, result, pool):
                self.iporname = iporname
                self.whattodo = whattodo
                self.result = result
                self.pool = pool
                threading.Thread.__init__(self)

        def run(self):
                self.pool.acquire()
                try:
                        logging.debug('Starting')
                        self.lookup(self.iporname, self.whattodo)
                finally:
                        self.pool.release()
                        logging.debug('Exiting')

        def lookup(self, iporname, whattodo):
                try:
                        if whattodo=="resolveip":
                                host, aliases, _ = socket.gethostbyaddr(iporname)
                                self.result[iporname] = {
                                        'host': host,
                                        'aliases': aliases if aliases else ''
                                }
                        if whattodo=="resolvename":
                                host = socket.getaddrinfo(iporname,0)
                                self.result[iporname] = {
                                        'host': host[1][4][0],
                                        'aliases': ''
                                }
                except socket.herror:
                        self.result[iporname] = {'host': 'No host found', 'aliases': ''}
                except socket.gaierror:
                        self.result[iporname] = {'host': 'No IP found', 'aliases': ''}


#from http://www.peterbe.com/plog/uniqifiers-benchmark
def uniquelist(seq):
        seen = set()
        seen_add = seen.add
        return [ x for x in seq if not (x in seen or seen_add(x))]
        
#http://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python

donecidr={}
def IPInCIDRList(ip):
        global donecidr
        localdonecidr=copy.deepcopy(donecidr)
        temp=False
        for cidr in localdonecidr:
                if IPAddress(ip) in IPNetwork(cidr):
                        temp=localdonecidr[cidr]
                        break
        #print "temp"
        #print temp
        return temp


def WhoisText(ip):
        tmptext=""
        CheckIfIPAlreadyDone=IPInCIDRList(ip)
        if CheckIfIPAlreadyDone:
                tmptext=CheckIfIPAlreadyDone
        else:
                if not IPAddress(ip).is_private() and not IPAddress(ip).is_loopback():
                        ipwhois = IPWhois(ip)
                        whotemp=ipwhois.lookup()
                        for net in whotemp['nets']:
                                tmptext=tmptext+str(net['cidr'])+eol
                                tmptext=tmptext+str(net['name'])+eol
                                tmptext=tmptext+str(net['description'])+eol
                                tmptext=tmptext+str(net['address'])+eol
                                tmptext=tmptext+str(net['city'])+" "+str(net['postal_code'])+" "+str(net['country'])+eol+eol
                                cidrtemp=[x.strip() for x in str(net['cidr']).split(',')]
                                donecidr[cidrtemp[0]]=tmptext
                else:
                        tmptext=tmptext+ip+" is a private address or loopback"+eol+eol

        return tmptext

class LookupThread(threading.Thread):
        def __init__(self, iporname, whattodo, result, pool):
                self.iporname = iporname
                self.whattodo = whattodo
                self.result = result
                self.pool = pool
                threading.Thread.__init__(self)

        def run(self):
                self.pool.acquire()
                try:
                        logging.debug('Starting')
                        self.lookup(self.iporname, self.whattodo)
                finally:
                        self.pool.release()
                        logging.debug('Exiting')

        def lookup(self, iporname, whattodo):
                try:
                        if whattodo=="resolveip":
                                host, aliases, _ = socket.gethostbyaddr(iporname)
                                self.result[iporname] = {
                                        'host': host,
                                        'aliases': aliases if aliases else ''
                                }
                        if whattodo=="resolvename":
                                host = socket.getaddrinfo(iporname,0)
                                self.result[iporname] = {
                                        'host': host[1][4][0],
                                        'aliases': ''
                                }
                        if whattodo=="whois":
                                whotmp = WhoisText(iporname)
                                self.result[iporname] = {
                                        'host': whotmp
                                }
                except socket.herror:
                        self.result[iporname] = {'host': 'No host found', 'aliases': ''}
                except socket.gaierror:
                        self.result[iporname] = {'host': 'No IP found', 'aliases': ''}



def GetIPSet(text):
                patern=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
                ipset = re.findall(patern , text)
                ipset = sorted(ipset, key=lambda ip: struct.unpack("!L", socket.inet_aton(ip))[0])
                return ipset
#http://code.activestate.com/lists/python-list/374819/
def ishexdigit(char):
        return char in string.hexdigits

def LineOp(self, text, prependstring, appendstring):
        temp=text.split('\n')
        text=""
        for line in temp:
            text=text+prependstring+line+appendstring+eol
        return text

#def TackOn(self, text):
        #frame=self.GetDocumentManager().FindSuitableParent()
        #prependstring=self.InputDialog(frame,"Prepend?" )
        #appendstring=self.InputDialog(frame,"Append?" )
        #text=self.LineOp(text, prependstring, appendstring)
        #return text

def parse_text(text, whattodo):
        #def parse_text(self, textcontrol, whattodo):
        #text = textcontrol._textCtrl.GetValue()
        #text=text.encode()
        global donecidr
        result={}
        if whattodo =="resolve" or whattodo =="getuniqueips" or whattodo =="gethostnames" or whattodo =="gethostnameswithip" or whattodo=="whoisipranges" or whattodo=="whohosts" or whattodo=="commaspaceip": 
                ipset=GetIPSet(text)
        if whattodo =="resolve": 
                # Limit the number of concurrent threads to 40
                pool = threading.BoundedSemaphore(40)
                lookup_threads = [LookupThread(ip, "resolveip", result, pool) for ip in ipset]
                # Start the threads
                for t in lookup_threads:
                        t.start()
                # Tell main to wait for all of them
                main_thread = threading.currentThread()
                for thread in threading.enumerate():
                        if thread is main_thread:
                                continue
                        thread.join()
                #print result
                for ip in ipset:
                        print(ip)
                        iptoreplace=ip+" ("+result[ip]['host']+")"
                        if iptoreplace not in text and result[ip]['host'] != "No host found":
                                text=text.replace(ip, iptoreplace, 1)
        if whattodo =="getuniqueips":
                text=""
                for ip in uniquelist(ipset):
                        text=text+ip+eol
        if whattodo=="commaspaceip":
                text=""
                for ip in uniquelist(ipset):
                        text=text+ip+", "
                text=text[0:len(text)-2]
        if whattodo =="whoisipranges":
                text=""
                #donecidr={}
                for ip in uniquelist(ipset):
                        result={}
                        # Limit the number of concurrent threads to 40
                        pool = threading.BoundedSemaphore(40)
                        lookup_threads = [LookupThread(ip, "whois", result, pool) for ip in ipset]
                        # Start the threads
                        for t in lookup_threads:
                                t.start()
                        # Tell main to wait for all of them
                        main_thread = threading.currentThread()
                        for thread in threading.enumerate():
                                if thread is main_thread:
                                        continue
                                thread.join()
                        print("test",result)
                coveredrange=[]
                for ip in ipset:
                        #print(ipset)
                        #print(result)
                        booltemp = result[ip]['host'] not in coveredrange
                        print(booltemp)
                        print(coveredrange)
                        if booltemp:
                                coveredrange.append(result[ip]['host'])
                                text=text+result[ip]['host']+"\r\n"
                                print(text)
                                print("ran")
                                        

        if whattodo == "gethostnames" or whattodo =="gethostnameswithip" or whattodo=="whohosts": 
                result={}
                # Limit the number of concurrent threads to 40
                pool = threading.BoundedSemaphore(1)

                if whattodo =="whohosts":
                        text = os.linesep.join([s for s in text.splitlines() if s])
                        hostnames=text.split('\n')
                        for x in hostnames:
                                print(x)
                else:
                        for ip in ipset:
                                text=text.replace(ip, "", 1)
                        #http://stackoverflow.com/questions/3939361/remove-specific-characters-from-a-string-in-python
                        #hostnames=str.rsplit(str(text).translate(" ", '()*`!@#$,\''))
                        temp=str(re.sub(r'[~`!@#$%^&*())={\[}\]\|\\:;"\'<,>\?\/]', ' ', text))
                        hostnames=str.rsplit(temp)

                lookup_threads = [LookupThread(hostname, "resolvename", result, pool) for hostname in hostnames]
                # Start the threads
                for t in lookup_threads:
                        t.start()
                # Tell main to wait for all of them
                main_thread = threading.currentThread()

                for thread in threading.enumerate():
                        if thread is main_thread:
                                continue
                        thread.join()
                oldtext=text
                text=""
                hostresult=result
                for host in uniquelist(result):
                        if result[host]['host'] != "No IP found":
                                if whattodo =="gethostnameswithip":
                                        text=text+host+" ("+result[host]['host']+")"+eol
                                if whattodo =="gethostnames":
                                        text=text+host+eol
                                

                                        
        if whattodo =="whohosts":
                #donecidr={}
                for host in hostresult:
                        if host in ipset:
                                text=text+host+eol
                        else:
                                text=text+host+", "+result[host]['host']+eol
                        if result[host]['host'] == "No IP found":
                                text=text+eol
                ipset=GetIPSet(text)
                result={}
                # Limit the number of concurrent threads to 40
                pool = threading.BoundedSemaphore(20)
                lookup_threads = [LookupThread(ip, "whois", result, pool) for ip in ipset]
                # Start the threads
                for t in lookup_threads:
                        t.start()
                # Tell main to wait for all of them
                main_thread = threading.currentThread()
                for thread in threading.enumerate():
                        if thread is main_thread:
                                continue
                        thread.join()
                #print "Both results"
                #pprint(hostresult)
                #pprint(result)
                text=""
                for host in hostresult:
                        tmphostip=hostresult[host]['host']
                        #print result[hostresult[host]['host']]['host']
                        if hostresult[host]['host'] in result:                                
                                tempsplit=result[tmphostip]['host'].split(eol)
                                hostline=host+","+tmphostip
                                if len(tempsplit)>3:
                                        hostline=hostline+",\""+tempsplit[1]+"\",\""+tempsplit[2]+"\""
                                hostline=hostline.replace(eol, ",")
                        else:
                                if tmphostip in ipset:
                                        tempsplit=WhoisText(tmphostip).split(eol)
                                        if len(tempsplit)>3:
                                                hostline=hostline+",\""+tempsplit[1]+"\",\""+tempsplit[2]+"\""
                                        hostline=hostline.replace(eol, ",")
                                else:
                                        hostline=host+", "+tmphostip+",\"Whois Not Found\""
                        text=text+hostline+eol #replace(host, hosttoreplace,1)



        if whattodo =="extractemails":
                emailaddresses=sorted(re.findall( r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b', text, re.IGNORECASE))
                text=""                
                for emailaddress in uniquelist(emailaddresses):
                        text=text+emailaddress+eol

        if whattodo =="extracttwitters":
                #From https://stackoverflow.com/questions/38861170/regular-expressions-in-python-to-match-twitter-handles
                #/(^|[^@\w])@(\w{1,15})\b/g;
                emailaddresses=sorted(re.findall( r'\B(@[\w\d_]+)', text, re.IGNORECASE))
                text=""                
                for emailaddress in uniquelist(emailaddresses):
                        text=text+emailaddress+eol

        if whattodo =="extracturls": 
                #http://daringfireball.net/2010/07/improved_regex_for_matching_urls
                #patern=r'(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
                #http://stackoverflow.com/questions/10475027/extracting-url-link-using-regular-expression-re-string-matching-python./ski	
                patern= r'https?://[^\s<>,"]+|www\.[^\s<>,"]+'
                urls = re.findall(patern , text)
                text=""
                for url in uniquelist(urls):
                        text=text+url+eol
        if whattodo =="unixeol":
                text=text.replace("\r\n","\n");

        if whattodo =="wineol":
                text=text.replace("\n","\r\n");

        if whattodo =="base64e":
                text=base64.b64encode(text.encode())

        if whattodo =="base64d":
                text=base64.b64decode(text.encode())

        if whattodo =="urlencode":
                text=urllib.parse.quote(text).encode('utf8')

        if whattodo =="urldecode":
                text=urllib.parse.unquote(text) #.decode('utf8')

        if whattodo =="rot13":
                text=codecs.encode(text, 'rot_13')

        if whattodo =="hexe":
                text=binascii.hexlify(text.encode().strip())

        if whattodo =="hexd":        
                #text=binascii.unhexlify(filter(ishexdigit, text.encode()))
                text=binascii.unhexlify(text.strip())
                print("sss", text)
        #textcontrol._textCtrl.SetValue(text)
        return text.strip()
        #######################################################################################      



#from algo import *
def bmp1(m,s,f,p):
    i=m
    j=m+1
    f[i]=j
    while i>0:
        while (j<=m and p[i-1]!=p[j-1]):
            if(s[j]==0):
                s[j]=j-i
            j=f[j]

        i=i-1
        j=j-1
        f[i]=j
    return s,f

def bmp2(m,s,f):
    j=f[0]
    for i in range(0,m+1):
        if (s[i]==0):
            s[i]=j
        if(i==j):
            j=f[j]
    return s,f
def bmbad(p,m):
    occ=[-1]*256
    for i in range(0,m):
        occ[ord(p[i])]=i
    return occ    
def bmsearch(p,t,s,occ,m,res):
    i=0
    n=len(t)
    while i<=n-m:
        j=m-1
        while (j>=0 and p[j]==t[i+j]):
            j=j-1
        if(j<0):
            res.append(i)
            i=i+s[0]
        else:
            i+=max(s[j+1],j-occ[ord(t[i+j])])
    return res       
def Boyer_Moore(t,p):
    m=len(p)
    s=[0]*(m+1)
    f=[0]*(m+1)
    s,f=bmp1(m,s,f,p)

            
    s,f=bmp2(m,s,f)


    occ=(bmbad(p,m))
    res=[]
    res=bmsearch(p,t,s,occ,m,res)
    return res
    


def operate(res,text):
        res2=[]
        res3=[]
        for i in range(0,len(text)):
                if(text[i]=='\n'):
                      res2.append(i)            
        if len(res2)==1:
               for val in res:
                       res3.append("1."+str(val))
               return res3
        else:
                
                res2.append(len(text)+10)
                k=0
                res2[k-1]=-1
                for val in res:
                        while val>res2[k]:
                                k+=1
                        count=val-res2[k-1]-1
                        res3.append(str(k+1) + '.'+str(count))       
                return res3                             
                
        
class SKIDDYPAD(Frame):
	def __init__(self,master):
		super(SKIDDYPAD,self).__init__(master)
		self.create_widgets()
		self.set_keyboard_shortcuts()

	def create_widgets(self):
		self.text1 = Text(width = 20, height = 20, undo = True, font = ("Georgia","12"))
		self.text1.pack(expand = YES, fill = BOTH)

		
		
		menubar = Menu(self)
		fmenu = Menu(menubar)
		emenu = Menu(menubar)
		tmenu = Menu(menubar)
		fontmenu = Menu(menubar)
		transmenu = Menu(menubar)
		encodemenu = Menu(menubar)
		#fsizemenu = Menu(menubar)
		hcmenu = Menu(menubar)
		#fsizemenu = Menu(menubar)
		hcmenu.add_command(label = 'Red', command = self.red)
		hcmenu.add_command(label = 'Blue', command = self.blue)
		hcmenu.add_command(label = 'Green', command = self.green)
		hcmenu.add_command(label = 'Black', command = self.black)
		hcmenu.add_command(label = 'Highlight', command = self.hyellow)
		hcmenu.add_command(label = 'Remove Highlight', command = self.remh)
		fontmenu.add_command(label = 'Georgia + 12 + Normal', command = self.f1)
		fontmenu.add_command(label = 'Georgia + 8 + Normal', command = self.f2)
		fontmenu.add_command(label = 'Georgia + 16 + Normal', command = self.f3)
		fontmenu.add_command(label = 'Georgia + 12 + Bold', command = self.f4)
		fontmenu.add_command(label = 'Georgia + 8 + Bold', command = self.f5)
		fontmenu.add_command(label = 'Georgia + 16 + Bold', command = self.f6)
		fontmenu.add_command(label = 'Georgia + 12 + Italic', command = self.f7)
		fontmenu.add_command(label = 'Georgia + 8 + Italic', command = self.f8)
		fontmenu.add_command(label = 'Georgia + 16 +Italic', command = self.f9)
		fontmenu.add_command(label = 'Georgia + 12 + Bold Italic', command = self.f10)
		fontmenu.add_command(label = 'Georgia + 8 + Bold Italic', command = self.f11)
		fontmenu.add_command(label = 'Georgia + 16 + Bold Italic', command = self.f12)
		fmenu.add_command(label = 'New', command = self.newDoc)
		fmenu.add_command(label = 'Open', command = self.openDoc)
		fmenu.add_command(label = 'Save', command = self.saveDoc)
		emenu.add_command(label = 'Select All', command = self.select_all)
		emenu.add_command(label = 'Copy', command = self.copy)
		emenu.add_command(label = 'Paste', command = self.paste)
		emenu.add_command(label = 'Clear', command = self.clear)
		tmenu.add_command(label = 'Word Count', command = self.wordCount)
		tmenu.add_command(label = 'Search', command = self.searchText)


		transmenu.add_command(label = 'Resolve IPs', command = lambda: self.dostuff("resolve"))
		transmenu.add_command(label = 'Extract Unique Sorted IPs From Text Blob', command = lambda: self.dostuff("getuniqueips"))
		transmenu.add_command(label = 'Extract Likely Host Names From Text Blob (crude)', command = lambda: self.dostuff("gethostnames"))
		transmenu.add_command(label = 'Extract Likely Host Names From Text Blob With IP Resolve (crude)', command = lambda: self.dostuff("gethostnameswithip"))
		transmenu.add_command(label = 'Extract Unique Email Addresses', command = lambda: self.dostuff("extractemails"))
		transmenu.add_command(label = 'Extract Unique Twitters', command = lambda: self.dostuff("extracttwitters"))
		transmenu.add_command(label = 'Extract URLs', command = lambda: self.dostuff("extracturls"))
		transmenu.add_command(label = 'Whois IP Ranges', command = lambda: self.dostuff("whoisipranges"))
		transmenu.add_command(label = 'Unix EOL (\\r\\n to \\n)', command = lambda: self.dostuff("unixeol"))
		transmenu.add_command(label = 'Windows EOL (\\n to \\r\\n)', command = lambda: self.dostuff("wineol"))
		transmenu.add_command(label = 'Who Hosts?', command = lambda: self.dostuff("whohosts"))
		transmenu.add_command(label = 'Comma+Space IP List', command = lambda: self.dostuff("commaspaceip"))
		transmenu.add_command(label = 'Prepend/Append', command = self.TackOn)
		encodemenu.add_command(label = 'Base 64 Encode', command = lambda: self.dostuff("base64e"))
		encodemenu.add_command(label = 'Base 64 Decode', command = lambda: self.dostuff("base64d"))
		encodemenu.add_command(label = 'URL Encode', command = lambda: self.dostuff("urlencode"))
		encodemenu.add_command(label = 'URL Decode', command = lambda: self.dostuff("urldecode"))
		encodemenu.add_command(label = 'Rot13 Encode', command = lambda: self.dostuff("rot13"))
		encodemenu.add_command(label = 'HEX Encode', command = lambda: self.dostuff("hexe"))
		encodemenu.add_command(label = 'HEX Decode', command = lambda: self.dostuff("hexd"))

		
		menubar.add_cascade(label ='File', menu = fmenu)
		menubar.add_cascade(label ='Edit', menu = emenu)
		menubar.add_cascade(label ='Tools', menu = tmenu)
		tmenu.add_command(label = 'Search and Replace', command = self.searchRep)
		menubar.add_cascade(label ='Font Themes', menu = fontmenu)
		menubar.add_cascade(label ='Colour & Highlight', menu = hcmenu)
		menubar.add_cascade(label ='Transform', menu = transmenu)
		menubar.add_cascade(label ='Encode', menu = encodemenu)
		
		root.config(menu = menubar)

	def dostuff(self, whattodo):
		userText = self.text1.get("1.0", END)
		self.text1.delete("1.0", END)
		self.text1.insert("1.0",parse_text(userText, whattodo))
		
	def newDoc(self):
		if(tk2.askyesno("Message","Continue without saving ? All the unsaved data will be lost....")):
			self.text1.delete("1.0",END)

	def saveDoc(self):		
		savefile = tk.asksaveasfile(mode = 'w', defaultextension = '.txt')
		text2save = str(self.text1.get("1.0", END))
		savefile.write(text2save)
		savefile.close()

	def openDoc(self):
		openfile = tk.askopenfile(mode = 'r')
		text = openfile.read()
		self.text1.insert(END, text)
		openfile.close()

	def copy(self):
		var = str(self.text1.get(SEL_FIRST,SEL_LAST))
		self.clipboard_clear()
		self.clipboard_append(var)
	

	def paste(self):
		result = self.selection_get(selection = "CLIPBOARD")   #get text from clipboard
		self.text1.insert("1.0", result)


	def clear(self):
		self.text1.delete("1.0", END)

	def wordCount(self):
		userText = self.text1.get("1.0", END)
		wordList = userText.split()
		number_of_words = len(wordList)
		tk2.showinfo('Word Count', 'Words:  ' + str(number_of_words))

	def f1(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","12","normal"))

	def f2(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","8","normal"))

	def f3(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","16","normal"))

	def f4(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","12","bold"))

	def f5(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","8","bold"))

	def f6(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","16","bold"))

	def f7(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","12","italic"))

	def f8(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","8","italic"))

	def f9(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","16","italic"))

	def f10(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georiga","12","bold italic"))

	def f12(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","16","bold italic"))

	def f11(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',font = ("Georgia","8","bold italic"))

	def red(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',foreground = 'red')

	def yellow(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',foreground = 'yellow')

	def green(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',foreground = 'green')

	def black(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',foreground = 'black')

	def blue(self):
		self.text1.tag_remove('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_add('f1',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f1',foreground = 'blue')

	def hyellow(self):
		self.text1.tag_add('f17',SEL_FIRST,SEL_LAST)
		self.text1.tag_config('f17',background = 'yellow')

	def remh(self):
		self.text1.tag_remove('match','1.0',END)
		self.text1.tag_remove('f17',SEL_FIRST,SEL_LAST)


	def searchRep(self):
		
		x = tk3.askstring('Search','Enter the word to be searched')
		userText = self.text1.get("1.0", END)
		res=Boyer_Moore(userText.lower() ,x)
		res=operate(res,userText)
		for val in res:
			pos = val
			if not pos: 
				break
			lastpos = '%s+%dc' % (pos, len(x))
			self.text1.tag_add('match', pos, lastpos)
			self.text1.tag_config('match', foreground='blue',background='yellow')
			if(tk2.askyesno("Message","Replace the highlighted word ?")):
				y = tk3.askstring('Search','Enter the new word')
				self.text1.delete(pos,lastpos)
				self.text1.insert(pos,y)
			pos = lastpos
		self.text1.tag_remove('match', '1.0', END)
		
	def TackOn(self):
		
		prependtxt = tk3.askstring('Prepend/Append','Enter text to prepend:')
		appendtxt = tk3.askstring('Prepend/Append','Enter text to append:')
		userText = self.text1.get("1.0", END).strip()
		userText = LineOp(self, userText, prependtxt, appendtxt)
		self.text1.delete("1.0", END)
		self.text1.insert("1.0", userText)

	def select_all(self):
		print("swsssss")
		self.text1.tag_add(SEL, "1.0", END)
		self.text1.mark_set(INSERT, "1.0")
		self.text1.see(INSERT)


	def searchText(self):
		
		x = tk3.askstring('Search','Enter the word to be searched')
		userText = self.text1.get("1.0", END)
		res=Boyer_Moore(userText.lower() ,x)
		res=operate(res,userText)
		for val in res:
			pos = val
			if not pos: 
				break
			lastpos = '%s+%dc' % (pos, len(x))
			self.text1.tag_add('match', pos, lastpos)
			pos = lastpos
			self.text1.tag_config('match', foreground='blue',background='yellow')

		
		if(tk2.askyesno("Message",str(len(res)) +" matches found\nCancel Highlight ?")):self.text1.tag_remove('match', '1.0', END)


	def set_keyboard_shortcuts(self):
		self.bind('<Control-o>', self.openDoc)
		self.bind('<Control-s>', self.saveDoc)
		self.bind('<Control-f>', self.searchText)
		self.bind("<Control-a>", self.select_all)


root = Tk()
root.title("SkiddyPad 2.0")
root.geometry('1028x720')
app = SKIDDYPAD(root)
app.mainloop()
