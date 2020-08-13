# -*- coding: utf-8 -*-
"""
Created on Mon Jun 29 14:38:20 2020

@author: Abderrahmen Amich
"""
from __future__ import print_function
import json
import sys
import glob, os
import re
import mosspy
import urllib2
import jsbeautifier as jsb
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import time




base_path=os.getcwd()

referers={'search engine':['google','yahoo','bing'],
          'email':['gmail','mail.google','hotmail','outlook','live'],
          'social media':['facebook','twitter','instagram']}



chains=[] # List of all possible redirection chains
checked_files=[] # a list to keep track of processed files

def server_replay(pcap):
    
    res = pcap.split('.')
    name=res[0]
    print(name)
    print('\n-- Analyzing pcap file using replay server\n')
    
    parent_dir = base_path+"\\dumps\\"
    path = os.path.join(parent_dir, name) 
    os.mkdir(path)
    cmd=base_path+"\\CapTipper-master\\CapTipper.py "+ base_path+"\\" +pcap+"  -gd "+base_path+"\\dumps\\"+name+"\\"
    os.system(cmd)
    
    parent_dir = base_path+"\\reports\\"
    path = os.path.join(parent_dir, name) 
    os.mkdir(path)
    cmd1=base_path+"\\CapTipper-master\\CapTipper.py "+ base_path+"\\" +pcap+" -gr "+base_path+"\\reports\\"+name+"\\"
    os.system(cmd1)
    return name

def read_report(name):
    
    os.chdir(base_path+"/dumps/"+name)
    files=glob.glob("*") # All dumped files
    path=base_path+"\\reports\\"+name
    with open(path+"\\"+name+".json",'rb') as f:
        for i, line in enumerate(f):
            try:
                line_=line.decode("utf-8")
                with open(path+'/new-'+name+".json",'a') as f:
                    f.write(line_)
            except UnicodeDecodeError:
                #print("decoding error captured and removed" )
                continue
          
    with open(path+'/new-'+name+".json",'r') as f:
        file = json.load(f)
    

    return file,files
        
def Enticement_source(file):
    conversations=file["conversations"]
    conversation=conversations[0]["uris"]
    referer=conversation[0]["referer"]
    found=0
    for source in referers.keys():
        for src in referers[source]:
            if referer.find(src) != -1:
                print('The enticement source is a '+source)
                found=1
                break
        if found == 1:
            break
    if found == 0:
        print('The type of enticement source is unrecognized')
    return referer

def RedChain_gadget(conversations,files,name):
    for conv_Id in range(len(conversations)):
        chain=find_chain(conv_Id,conversations,files,name)
        if conv_Id==0:
            if chain != {}:
                chains.append(chain)
        else:
            if chain != {}:
                if chains != []:
                    if check_dup(chains,chain)==0:
                        chains.append(chain)
        
    
    return chains

def find_chain(conv_Id,conversations,files,name):
    conversation=conversations[conv_Id]["uris"]
    chain={}
    chain=first(chain,conversation,files,name)
    if chain != {}:
        lenght=len(chain)
        chain=follow(chain,files,name)
        while lenght<len(chain):
            lenght=len(chain)
            chain=follow(chain,files,name)
        
        
    return chain

def first(chain,conversation,files,name):
    
    for Id in range(len(conversation)):
        
        head=conversation[Id]["res_head"]
        # HTTP Redirect
        #print("-- Checking for HTTP Redirect in ",conversation[Id]["filename"])
        if re.search('3\d\d', conversation[Id]["res_num"]) != None:
            red_found=0
            #print('-- HTTP Redirection: ',conversation[Id]["res_num"])
            red_found=1
            if head != "":
                if head.find('Location') != -1:
                    if chain == {}:
                        chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="HTTP Redirect"
                        chain[head[head.find('Location')+len('location')+2:]]="null"
                        for file in files:
                            if file.find(conversation[Id]["filename"]) != -1:
                                checked_files.append(file)
                                break
                        continue
                    else:
                        print("Warning: Found more than one redirection in the same conversation")
                    
            else:
                for file in files:
                    if file.find(conversation[Id]["filename"]) != -1:
                        f = open(base_path+"/dumps/"+name+"/"+file, "r")
                        html=f.read()
                        if file not in checked_files:
                            checked_files.append(file)
                        if html.find('<a') != -1:
                            html=html[html.find('<a'):]
                            if html.find('href=') != -1:
                                if chain == {}:
                                    target=html[html.find('href=')+6:]
                                    target=target[:target.find('"')]
                                    chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="HTTP Redirect"
                                    chain[target]="null"
                                    break
                                
                                else:
                                    print("Warning: Found more than one redirection in the same conversation")
                if red_found==1:
                    continue
    
        # js-based redirect
        
        elif re.search('.*.js', conversation[Id]["filename"]) != None:
            #print("-- Checking for js-based redirection in ",conversation[Id]["filename"])
            for file in files:
                if file.find(conversation[Id]["filename"]) != -1:
                    f = open(base_path+"/dumps/"+name+"/"+file, "r")
                    js=f.read()
                    if file not in checked_files:
                        checked_files.append(file)
                    if js.find('<iframe') != -1: # iframe based
                        fp=js.find('</iframe') 
                        js=js[js.find('<iframe'):fp]
                        if js.find('src=') != -1:
                            target=js[js.find('src=')+5:fp]
                            target=target[:target.find('"')]
                            if chain == {}:
                                chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]= "First-redirection = Js-redirect using iframe tag"
                                chain[target]="null"
                                break
                            else:
                                print("Warning: Found more than one redirection in the same conversation")
                    
                    
        elif re.search('.*.html', conversation[Id]["filename"]) != None:
            #print("-- Checking for js-based redirection in ",conversation[Id]["filename"])
            for file in files:
                if file.find(conversation[Id]["filename"]) != -1:
                    js=extract_js(file)
                    if file not in checked_files:
                        checked_files.append(file)
                    if js != []:
                        for script in js:
                            if script.find('<iframe') != -1: # iframe based
                                fp=script.find('</iframe') 
                                script=script[script.find('<iframe'):fp]
                                if script.find('src=') != -1:
                                    target=script[script.find('src=')+5:fp]
                                    target=target[:target.find('"')]
                                    if chain == {}:
                                        chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]= "Js-redirect using iframe tag"
                                        chain[target]="null"
                                        break
                                    else:
                                        print("Warning: Found more than one redirection in the same conversation")
                    
        
                    
        # meta refresh based                     
        elif head != "":
            #print("-- Checking for meta Refresh redirection in ",conversation[Id]["filename"])
            if head.find('<meta') != -1:
                head=head[head.find('<meta'):]
                fp=head.find('/>')
                head=head[:fp]
                if head.find('"Refresh"') != -1:
                    if head.find('url') != -1:
                        target=head[head.find('url'):]
                        if chain == {}:
                            chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="Meta-refresh redirect"
                            chain[target]="null"
                            for file in files:
                                if file.find(conversation[Id]["filename"]) != -1:
                                    checked_files.append(file)
                                    break
                        else:
                            print("Warning: Found more than one redirection in the same conversation")
                            
                       
        else:
            #print("-- Checking for meta Refresh redirection in ",conversation[Id]["filename"])
            for filee in files:
                if file.find(conversation[Id]["filename"]) != -1:
                    f = open(base_path+"/dumps/"+name+"/"+filee, "r")
                    head=f.read()
                    if head.find('<meta') != -1:
                        head=head[head.find('<meta'):]
                        fp=head.find('/>')
                        head=head[:fp]
                        if head.find('"Refresh"') != -1:
                            if head.find('url') != -1:
                                target=head[head.find('url'):]
                                if chain == {}:
                                    chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="Meta-refresh redirect"
                                    chain[target]="null"
                                    checked_files.append(filee)
                                    break
                                else:
                                    print("Warning: Found more than one redirection in the same conversation")
    
    return chain

def follow(chain,files,name):
    
    lookup=0
    nb=len(chain)
    keys=list(chain.keys())
    for key in keys:
        if chain[key]=="null":
            lookup=key
            file_name=extract_name(lookup)
            break
    if lookup==0:
        print("Warning: a node might be missing from the chain (couldn't follow up to the next node)")
        return -1
    for file in files:
        if file.find(file_name) != -1:
            f = open(base_path+"/dumps/"+name+"/"+file, "r")
            if file not in checked_files:
                checked_files.append(file)
            if re.search('.*.html', file) != None:
                
                html=f.read()
                #print("-- Checking for HTTP Redirect in ",file)
                if re.search('3\d\d Found', html) != None:
                    
                    if html.find('<a') != -1:
                        
                        #fp=html.find('>') 
                        html=html[html.find('<a'):]
                        if html.find('href=') != -1:
                            target=html[html.find('href=')+6:]
                            target=target[:target.find('"')]
                            chain[lookup]="Redirection "+str(nb)+": HTTP Redirect"
                            chain[target]="null"
                            break
                elif html.find('<meta') != -1:
                    #print("-- Checking for meta Refresh redirection in ",file)
                    html=html[html.find('<meta'):]
                    fp=html.find('/>')
                    html=html[:fp]
                    if html.find('"Refresh"') != -1:
                        if html.find('url') != -1:
                            target=html[html.find('url'):]
                            chain[lookup]="Redirection "+str(nb)+": Meta-refresh redirect"
                            chain[target]="null"
                            break
                else:
                    #print("-- Checking for js-based Redirect in ",file)
                    scripts=extract_js(file)
                    if scripts != []:
                        for js in scripts:
                            if js.find('<iframe') != -1: # iframe based
                                fp=js.find('</iframe') 
                                js=js[js.find('<iframe'):fp]
                                if js.find('src=') != -1:
                                    target=js[js.find('src=')+5:fp]
                                    target=target[:target.find('"')]
                                    chain[lookup]= "Redirection "+str(nb)+": Js-redirect using iframe tag"
                                    chain[target]="null"
                                    break
            elif re.search('.*.js', file) != None:
                #print("-- Checking for js-based Redirect in ",file)
                js=f.read()
                if js.find('<iframe') != -1: # iframe based
                    fp=js.find('</iframe') 
                    js=js[js.find('<iframe'):fp]
                    if js.find('src=') != -1:
                        target=js[js.find('src=')+5:fp]
                        target=target[:target.find('"')]
                        chain[lookup]= "Redirection "+str(nb)+": Js-redirect using iframe tag"
                        chain[target]="null"
                        break
            
    return chain



def Vuln_probing(chains,files,name):
    for chain in chains:
        keys=list(chain.keys())
        for key in keys:
            if chain[key]=="null":
                file_name=extract_name(key)
                print("--Looking for fingerprinting js script in the final node of the chain :",file_name)
                break
        found=0
        if re.search('.*.js', file_name) != None:
            for file in files:
                if file.find(file_name) != -1:
                    print("--Checking one js-script")
                    rate=find_sim("dumps/"+name+"/"+file)
                    if rate != -1:
                        if float(rate[:-1]) > 30:
                            print("Attacker have used JS script for vulnerability probing")
                            found=1
                    else:
                        print("--Trying deobfiscation")
                        js=deobfiscate(file)
                        if js != []:
                            print("Found {} potential scripts".format(len(js)))
                            for script in js:
                                
                                new_file=save_js(script)
                                rate=find_sim(new_file)
                                if rate != -1:
                                    print("Similarity rate = ",rate)
                                    if float(rate[:-1]) > 30:
                                        print("Attacker have used JS script for vulnerability probing")
                                        found=1
                break
        elif re.search('.*.html', file_name) != None:
            for file in files:
                if file.find(file_name) != -1:
                    scripts=extract_js(file)
                    if scripts != []:
                        for js in scripts:
                            new_file=save_js(js)
                            rate=find_sim(new_file)
                            if rate != -1:
                                if float(rate[:-1]) > 30:
                                    print("Attacker have used JS script for vulnerability probing")
                                    found=1
                                
                                    
                            else:
                                print("--Trying deobfiscation")
                                js=deobfiscate(file)
                                if js != []:
                                    print("Found {} potential scripts".format(len(js)))
                                    for script in js:
                                        
                                        new_file=save_js(script)
                                        rate=find_sim(new_file)
                                        if rate != -1:
                                            print("Similarity rate = ",rate)
                                            if float(rate[:-1]) > 30:
                                                print("Attacker have used JS script for vulnerability probing")
                                                found=1
                                            
                           
                    break 
        if found==0:
            print("Attacker has probably not used JS script for vulnerability probing") 
                
    return 0

def find_sim(file1):
    
    userid = 812874760

    m = mosspy.Moss(userid, "javascript")
    
    
    # Submission Files
    m.addFile(base_path+"/"+file1)
    m.addFilesByWildcard(base_path+"/js-detect.js")
    
    url = m.send() # Submission Report URL
    
    response = urllib2.urlopen(url)
    html = response.read()
    match = re.findall(r'<TR><TD><A .*</A>', html)
    if match != []:
        res = match[0].split('/')
        rate=re.findall(r'[0-9]+\%', res[-2])
        if rate != []:
            return rate[0]
        else:
            print("Couldn't extract similarity rate from ",res[-2])
    return -1
    
    
def exploitation(chains,conversations,files,name):
    
    scores={}
    suspec_obj=[]
    for chain in chains:
        keys=list(chain.keys())
        for key in keys:
            if chain[key]=="null":
                domain=extract_domain(key)
                print("--Looking for malicious files in :",domain)
                break
    for conv_id in range(len(conversations)):
        conversation=conversations[conv_id]["uris"]
        for Id in range(len(conversation)):
            host=conversation[Id]["host"]
            if domain.find(host) != -1:
                if re.search('.*.(exe|swf|png|jpg|pdf)', conversation[Id]["filename"]) != None:
                    suspec_obj.append(conversation[Id]["filename"])
    print('Checking the behavior of ',len(suspec_obj),' suspicious files')
    for obj in suspec_obj:
        for file in files:
            if file.find(obj) != -1 and file not in checked_files:
                scores[obj]=VirusTot_Api(base_path+'/dumps/'+name+"/"+file)
                if scores[obj]>0.5:
                    print(host+'/'+obj+' is '+str(scores[obj]*100)+'% malicious')
                checked_files.append(file)
                break
    
        
    return 0

def VirusTot_Api(file):
    
    API_KEY = '06b072bb4ef036512a233ac40a7df7e316f10c4fd471e339f1dec03979ed8160'
    
    try:
        f = open(file, "r")
        txt=f.read()
        EICAR = txt.encode('utf-8')
    except UnicodeDecodeError,e:
        f = open(file, "rb")
        EICAR=f.read()
        
    EICAR_MD5 = hashlib.md5(EICAR).hexdigest()
    time.sleep(3)
    vt = VirusTotalPublicApi(API_KEY)
    
    response = vt.get_file_report(EICAR_MD5)
    time.sleep(3)
    report= json.loads(json.dumps(response, sort_keys=False, indent=4))
    
    try:
        score=float(report["results"]["positives"])/float(report["results"]["total"])
    except KeyError,e:
        print("Couldn't analyze the behavior of ",extract_name(file))
        return -1
    return score
   
def extract_js(file):
    f = open(file, "r")
    html=f.read()
    js=[]
    l=len(js)
    if html.find('<script>') != -1:
        fp=html.find('</script>')
        sp=html.find('<script>')+len('<script>')
        js.append(html[sp:fp])
        html=html[fp+len('</script>'):]
        while(l<len(js)):
            l=len(js)
            if html.find('<script>') != -1:
                fp=html.find('</script>')
                sp=html.find('<script>')+len('<script>')
                js.append(html[sp:fp])
                html=html[fp+len('</script>'):]
                
        return js
    
def check_dup(chains,chain):
    check=0
    for elt in chains:
        for key in elt.keys():
            lookup=extract_name(key)
            for key2 in chain.keys():
                if key2.find(lookup) != -1:
                    check=1
    return check
                
def extract_name(path):
    res = path.split('/')
    return res[-1]

def extract_domain(path):
    res = path.split('/')
    strg="/"
    return strg.join(res[:-1])

def deobfiscate(file):
    
    deobf=[]
    f = open(file, "r")
    filename, file_extension = os.path.splitext(file)
    if file_extension=='.html':
        js=extract_js(file)
        if js != []:
            for script in js:
                deobf.append(jsb.beautify(script))
    elif file_extension=='.js':
        js=f.read()
        deobf.append(jsb.beautify(js))
    return deobf

def save_js(js):
    f = open(base_path+"/new.js", "w")
    f.write(js)
    f.close()
    file="new.js"
    return file
       

    
    
if __name__ == '__main__':

    
    if len(sys.argv) == 2:
        
        name=server_replay(sys.argv[1])
        
        file,files=read_report(name)
        
        print('\n-- Running Enticement source detection gadget\n')
        print("Enticement source= ",Enticement_source(file))
        print('\n-- Running Redirection chain gadget\n')
        conversations=file["conversations"] # all conversations from pcap file
        chains=RedChain_gadget(conversations,files,name)
        if chains != []:
            for chain in chains:
                print(chain)
                print("\n")
            print('\n-- Running finger printing gadget\n')
            Vuln_probing(chains,files,name)
            print('\n-- Running Exploitation gadget\n')
            exploitation(chains,conversations,files,name)
        else:
            print("No redirection chain were found")
        #print("Checked files are: ",checked_files)
        
        
        
    else:
        print("infection analysis: pcap file missing")
        
        
