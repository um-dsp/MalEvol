


import os,glob
import json
import sys
import re
import mosspy
import urllib.request, urllib.error, urllib.parse
import jsbeautifier as jsb
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import time
#from igraph import *
import pandas as pd
import subprocess
import hashlib
import time
from adblockparser import AdblockRules
from user_agents import parse
from datetime import date
from countryinfo import CountryInfo
import socket
from py_mini_racer import py_mini_racer


referers={'search engine':['google','yahoo','bing'],
          'email':['gmail','mail.google','hotmail','outlook','live'],
          'social media':['facebook','twitter','instagram']}

base_path = os.getcwd()
chains=[] # List of all possible redirection chains
ip_chains=[]
checked_files=[] # a list to keep track of processed files
objects={} # List of objects found in each visited host


def handle_uploaded_file(name):

    '''Use our Gadgets to perform advanced analysis on the user's pcap file'''

    name0=""
    label='benign'
    ent=""
    prob=""
    scores={}
    scores2={}
    edges=[]
    nodes=[]
    ip_chains=[]
    ent_type="" 
    mac=""
    browser=[]
    geo_data=[] 
    geo_line=[]
    date=""
    matches={}
    format='Unknown format'
    msg=''
    OS=[]
    device=[]
    tot=0
    
    
    name0,hash_value,passit=server_replay(name)
    #if passit ==0:
    file,files=read_report(hash_value,name0)
    if file != '':# and (hash_value,) not in list(AllPcaps.objects.values_list('hash_vlue')):
        format='valid'
        mac,browser,OS,device=get_info(file)
        
        print("\n--The victim's host: \n MAC : {} \n Browser : {} \n OS : {} \n Device : {} \n".format(mac,browser,OS,device))
        
        for elt in device:
            if elt in [None,'na']:
                msg='no device'
                break
        #print(All_browser,All_OS,All_device)

        print('\n-- Running Enticement source detection gadget\n')
        ent,ent_type=Enticement_source(file)
        
        if len(ent)==0:
            ent='The type of enticement source is unrecognized'


        print("Enticement source= ",ent)
        print("The Enticement source type is = ",ent_type)
    

        print('\n-- Running Redirection chain gadget\n')
        conversations=file["conversations"] # all conversations from pcap file
        if len(conversations) != 0:
            for conv in conversations:
                objects[conv["name"]]=[]
                if len(conv["uris"]) != 0:
                    for obj in conv["uris"]:
                        objects[conv["name"]].append(obj["filename"])
    
        chains,ip_chains=RedChain_gadget(conversations,files,hash_value)
        
        if chains != []:
            for chain in chains:
                print("\n The Extracted redirection chain: ", chain)
                print("\n")
            for ip_chain in ip_chains:
                print("\n The Extracted redirection chain IPs: ",ip_chain)
                print("\n")
            
            edges,nodes=generate_graph(ip_chains)
            if nodes != []:
                tot+=1
            print('\n-- Running finger printing gadget\n')
            prob=Vuln_probing(chains,files,hash_value)
            
            print('\n-- Running Exploitation gadget\n')
            label,scores,scores2,VT_scandate=exploitation_chain(chains,conversations,files,hash_value)
            if scores == {}:
                label,scores,scores2,VT_scandate=exploitation(conversations,files,hash_value)
            if label != 'benign':
                tot+=1
                print("No malicious files were detected with Virus Total API\n")
            else:
                print("VirusTotal Api detected some malicious files\n")
            print('Maliciousness likelihood of detected suspicious files: ',scores)
            

        else:
            print("No redirection chain were found")
            print('\n-- Running Exploitation gadget\n')
            label,scores,scores2,VT_scandate=exploitation(conversations,files,hash_value)
            edges=[]
            nodes=[]

    
        print('\n-- Looking for APT matches \n')
        matches,hashes,matches2=APT_matches(hash_value,file,chains,VT_scandate,files)
        if matches2 != {}:
            tot+=1
            print('Detected IOC matches with public APTNotes are:',matches['APTs'])
        else:
            print('No IOC matches were found with public APTNotes')
        print('\n-- running geo analysis \n')
        geo_data, geo_line,date=get_loc(file,hashes)
        if geo_data != []:
            tot+=1
        #print(geo_data)
       
        
        print("\n--traffic date = ", date)
        #print('VT_dates =', VT_scandate)

    
    
    else:
        print('file format is invalid')   

    return msg,format,name0,label,ent,prob,scores2,edges,nodes,ent_type, mac,browser,OS,device,geo_data, geo_line,date,matches,ip_chains

def hash(file):

    hasher = hashlib.md5()
    with open(file, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
 
    return hasher.hexdigest()

def server_replay(name):

    ''' Analyze PCAP file; dump all objects of all involved hosts; return a json analysis report'''

    pcap_path = os.path.join(base_path, 'pcaps',name)
    #pcap_path="E:/MalEvol-Dataset/threatglass-pcaps/"+name
    hash_value=hash(pcap_path)
    res = name.split('.')
    name0=''.join(res[:-1])
    ##print(name0)
    ##print("hash_value = ",hash_value)
    #print("All hash_values : ", len(list(AllPcaps.objects.values_list('hash_vlue'))))
    passit=0
    #if (hash_value,) not in list(AllPcaps.objects.values_list('hash_vlue')):
    print('\n-- Analyzing pcap file using replay server\n')

    # dump objects
    path0 = os.path.join(base_path, 'dumps',hash_value)

    if not(os.path.exists(path0)):
        os.mkdir(path0)
    if len([n for n in os.listdir(path0) if os.path.isfile(os.path.join(path0, name))]) == 0:
        cmd ='python2 '+ os.path.join(base_path, 'CapTipper-master','CapTipper.py')+' '+pcap_path+' '+'-gd'+' '+ path0
        os.system(cmd)


    # create a json report
    path1 = os.path.join(base_path, 'reports',hash_value)
    if not(os.path.exists(path1)):
        os.mkdir(path1)

    if len([n for n in os.listdir(path1) if os.path.isfile(os.path.join(path1, name))]) == 0:
        cmd1 ='python2 '+ os.path.join(base_path, 'CapTipper-master','CapTipper.py')+' '+pcap_path+' '+'-gr'+' '+ path1
        os.system(cmd1)

        
    #else:
        #print('server replay analysis already done')
        #passit=1
    return name0,hash_value,passit


    


def read_report(hash_value,name0):
    
    
    '''Read the created JSON report '''
    file=''
    os.chdir(os.path.join(base_path,"dumps",hash_value))
    files=glob.glob("*") # All dumped files
    path=os.path.join(base_path,"reports",hash_value)
    json_name=name0+".json"
    if os.path.exists(os.path.join(path,'new-'+json_name)):
        try:
            with open(os.path.join(path,'new-'+json_name),'r') as f:
                file = json.load(f)
        except:
            pass
    else:
        if os.path.exists(os.path.join(path,json_name)):
            with open(os.path.join(path,json_name),'rb') as f:
                for i, line in enumerate(f):
                    try:
                        line_=line.decode("utf-8")
                        with open(os.path.join(path,'new-'+json_name),'a') as f:
                            f.write(line_)
                    except (UnicodeDecodeError, UnicodeEncodeError):
                       ##print("decoding error captured and removed")
                        continue
            try:
                with open(os.path.join(path,'new-'+json_name),'r') as f:
                    file = json.load(f)
            except:
                pass
    

    return file,files

def get_info(file):
    try:
        mac=file['client']['MAC']
    except:
        mac=""
    try:
        ua_string=file['client']['USER-AGENT']
    except:
        ua_string=""
    if ua_string != '':
        user_agent = parse(ua_string)
    else:
        return mac,[],[],[]

    browser =[]
    if user_agent.browser.family =='IE':
        browser.append('Internet Explorer')
    else:
        browser.append(user_agent.browser.family)
    browser.append(user_agent.browser.version_string)

    OS = []
    OS.append(user_agent.os.family)
    OS.append(user_agent.os.version_string)

    device = []
    if user_agent.device.family not in ['Other',None]:
        device.append(user_agent.device.brand)
    print(user_agent.device.family,user_agent.device.model)
    if user_agent.device.model != None:
        device.append(user_agent.device.family+' '+user_agent.device.model)
    else:
        device.append('na')


    return mac,browser,OS,device

def Enticement_source(file):
    try:
        conversations=file["conversations"]
        conversation=conversations[0]["uris"]
        referer=conversation[0]["referer"]
    except:
        return "",""
    found=0
    ent_type='Unrecognized'
    if referer != '':
        for source in list(referers.keys()):
            for src in referers[source]:
                if referer.find(src) != -1:
                    #print('The enticement source is a '+source)
                    ent_type=source
                    found=1
                    break
            if found == 1:
                break
        if found == 0:
            print('checking for ad server source')
            req = urllib.request.Request("https://easylist.to/easylist/easylist.txt",headers = {"User-Agent": "Mozilla/5.0"})    
            f = urllib.request.urlopen(req)
            try:
                data = f.read().decode('utf-8')
            except:
                data=f.read().decode()
    
            data=data[data.find('! *** easylist:easylist/easylist_general_block.txt ***')+len('! *** easylist:easylist/easylist_general_block.txt ***')+1:]
            data=data.split('\n')
            rules=data[:-1]
            f.close()
            rules=AdblockRules(data)#,supported_options=['script', 'domain'],skip_unsupported_rules=False
            if rules.should_block("referer") == True:
                ent_type='Ad-Server'
                found=1
        if found == 0:
            print('The type of enticement source is unrecognized')

    return referer,ent_type

def RedChain_gadget(conversations,files,hash_value):
    if len(conversations) != 0:
        for conv_Id in range(len(conversations)):
            chain,ip_chain=find_chain(conv_Id,conversations,files,hash_value)
            if conv_Id==0:
                if chain != {}:
                    chains.append(chain)
                if ip_chain != {}:
                    ip_chains.append(ip_chain)
            else:
                if ip_chain != {}:
                    if ip_chains != []:
                        if check_dup(chains,chain)==0:
                            chains.append(chain)
                            ip_chains.append(ip_chain)
                    else:
                        chains.append(chain)
                        ip_chains.append(ip_chain)
        
    
    return chains,ip_chains

def adv_open(path,filee):
    
    ##print('trying adv open')
    try:
        f= open(os.path.join(path,filee),'r',encoding = 'utf-8')
        res=f.read()
        f.close()
        return res
    except (UnicodeDecodeError, UnicodeEncodeError):
        with open(os.path.join(path,filee),'rb') as f:
            for i, line in enumerate(f):
                try:
                    line_=line.decode("utf-8")
                    with open(os.path.join(path,'new-'+filee),'a') as f:
                        f.write(line_)
                        ##print("a readable line is stored")
                except:
                    ##print("decoding error captured and removed")
                    continue
        try:     
            f= open(os.path.join(path,'new-'+filee),'r')
            res=f.read()
            f.close()
            return res
        except :
            return '-1'

def find_chain(conv_Id,conversations,files,hash_value):
    try:
        conversation=conversations[conv_Id]["uris"]
    except:
        return []
    if len(conversation) != 0:
        chain={}
        ip_chain={}
        #print('running first')
        chain,ip_chain=first(chain,ip_chain,conversation,files,hash_value,conversations)
        if chain != {}:
            lenght=len(chain)
            #print('running follow')
            chain,ip_chain=follow(chain,ip_chain,files,hash_value,conversations)
            while lenght<len(chain):
                lenght=len(chain)
                #print('running follow')
                chain,ip_chain=follow(chain,ip_chain,files,hash_value,conversations)
        
        
    return chain,ip_chain
def map_to_ip(filename,conversations):

    temp=str(filename)
    
    
    found=0
    if temp.find('http') == -1:
        for car in ['javascript',';','(',')','+','|']:
            if temp.find(car) != -1:
                
                file1 = open(os.path.join(base_path,"obfiscatedURL.txt"),"a")
                
                file1.write('\n\n'+temp)
                file1.close() 
                print('js code stored')
                ctx = py_mini_racer.MiniRacer()
                try:
                    temp=ctx.eval(temp.replace("document.write", "return "))
                    print('deobfiscated url is :',temp)
                    temp=str(temp)
                except:
                    pass
                if temp.find('http') == -1:
                    hash_object = hashlib.md5(temp.encode())

                    return hash_object.hexdigest()
    #while filename.find('http') != -1:
    if temp.find('https://') != -1:
        temp=temp[temp.find('https://')+8:]
        if temp.find('/') != -1:
            temp=temp[:temp.find('/')]
    if temp.find('http://') != -1:
        temp=temp[temp.find('http://')+7:]
        if temp.find('/') != -1:
            temp=temp[:temp.find('/')]

    if temp.find('/') != -1:
        if temp.find('.') < temp.find('/'):
            if temp.find('.') != -1:
                temp=temp[:temp.find('/')]

    for conv_Id in range(len(conversations)):
        conversation=conversations[conv_Id]["uris"]
        for Id in range(len(conversation)):
            if temp.find(conversation[Id]["host"]) != -1 or conversation[Id]["host"].find(temp) != -1:
                ip=conversation[Id]["server_ip_port"]
                found=1
                #print('{} and {} matched for ip'.format(temp,conversation[Id]["host"]))
                return ip[:ip.find(':')]
            #if filename.find(conversation[Id]["filename"]) or conversation[Id]["filename"].find(filename):
            #    ip=conversation[Id]["server_ip_port"]
            #    found=1
            #    print('{} and {} matched for ip'.format(filename,conversation[Id]["host"]))
            #    return ip[:ip.find(':')]

    if found ==0:
        try:
            ips = socket.gethostbyname_ex(temp)
        except :#socket.gaierror:
            ips=[]
        if ips != []:
            return ips[-1][0]
        else:
            print("IP chain is missing one ip for {} , please improve the ip extraction method".format(filename))
            if len(temp)>10:
                for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                    if temp.find(car) != -1:
                        temp=temp[:temp.find(car)]
            return temp
    
        
    

def first(chain,ip_chain,conversation,files,hash_value,conversations):


    len0=len(chain)

    for Id in range(len(conversation)):
        try:
            head=conversation[Id]["res_head"]
            ip=conversation[Id]["server_ip_port"]
            ip=ip[:ip.find(':')]
        except:
            head=""
            ip=""
        #print(ip)
        red_found=0
        # HTTP Redirect
        ##print("-- Checking for HTTP Redirect in ",conversation[Id]["filename"])
        m=re.search('3\d\d', conversation[Id]["res_num"])
        if  m != None:
            
            ##print('-- HTTP Redirection: ',conversation[Id]["res_num"])
            
            if head != "":
                if head.find('Location') != -1:
                    if chain == {}:
                        red_found=1
                        chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="first : HTTP "+m.group(0)
                        ip_chain[ip]="first : HTTP "+m.group(0)
                        to_add=head[head.find('Location')+len('location')+2:]
                        ip_to=map_to_ip(to_add,conversations)
                        
                        

                        chain[to_add]="null"
                        if ip_to != '':
                            ip_chain[ip_to]="null"
                        else:
                            if len(to_add)>10:
                                for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                    if to_add.find(car) != -1:
                                        to_add=to_add[:to_add.find(car)]
                            ip_chain[to_add]="null"
                        
                        for filee in files:
                            if filee.find(conversation[Id]["filename"]) != -1:
                                checked_files.append(filee)
                                break
                        continue
                    else:
                        print("Warning: Found more than one redirection in the same conversation")
                    
            else:
                for filee in files:
                    if filee.find(conversation[Id]["filename"]) != -1:
                        try:
                            #print("reading file",filee)
                            f = open(os.path.join(base_path,"dumps",hash_value,filee), "r")
                            html=f.read()
                            f.close()
                        except:# (UnicodeDecodeError, UnicodeEncodeError):
                            #print('decode error is raised')
                            f=adv_open(os.path.join(base_path,"dumps",hash_value),filee)
                            html=f.read()
                            if html == '-1':
                                continue
                            
                            
                        if filee not in checked_files:
                            checked_files.append(filee)
                        if html.find('<a') != -1:
                            html=html[html.find('<a'):]
                            if html.find('href=') != -1:
                                if chain == {}:
                                    red_found=1
                                    target=html[html.find('href=')+6:]
                                    target=target[:target.find('"')]
                                    
                                    chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="first: HTTP "+m.group(0)
                                    ip_chain[ip]="first: HTTP "+m.group(0)

                                    chain[target]="null"
                                    ip_to=map_to_ip(target,conversations)
                                    if ip_to != '':
                                        ip_chain[ip_to]="null"
                                    else:
                                        if len(target)>10:
                                            for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                                if target.find(car) != -1:
                                                    target=target[:target.find(car)]
                                        ip_chain[target]="null"
                                    break
                                
                                else:
                                    print("Warning: Found more than one redirection in the same conversation")
                if red_found==1:
                    continue
    
        # js-based redirect
        
        elif re.search('.*.js', conversation[Id]["filename"]) != None:
            ##print("-- Checking for js-based redirection in ",conversation[Id]["filename"])
            for filee in files:
                if filee.find(conversation[Id]["filename"]) != -1:
                    try:
                        #print("reading file",filee)
                        f = open(os.path.join(base_path,"dumps",hash_value,filee), "r")
                        js=f.read()
                        f.close()
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        ##print('decode error is raised')
                        js=adv_open(os.path.join(base_path,"dumps",hash_value),filee)
                        if js == '-1':
                            continue
                        
                        
                    if filee not in checked_files:
                        checked_files.append(filee)
                    if js.find('<iframe') != -1: # iframe based
                        fp=js.find('</iframe') 
                        js=js[js.find('<iframe'):fp]
                        if js.find('src=') != -1:
                            target=js[js.find('src=')+5:fp]
                            target=target[:target.find('"')]
                            if chain == {}:
                                red_found=1
                                chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]= "first: Js with iframe tag"
                                ip_chain[ip]="first: Js with iframe tag"
                                

                                chain[target]="null"
                                ip_to=map_to_ip(target,conversations)
                                if ip_to != '':
                                    ip_chain[ip_to]="null"
                                else:
                                    if len(target)>10:
                                        for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                            if target.find(car) != -1:
                                                target=target[:target.find(car)]
                                    ip_chain[target]="null"
                                break
                            else:
                                print("Warning: Found more than one redirection in the same conversation")
                    
                    
        elif re.search('.*.html', conversation[Id]["filename"]) != None:
            ##print("-- Checking for js-based redirection in ",conversation[Id]["filename"])
            for filee in files:
                if filee.find(conversation[Id]["filename"]) != -1:
                    js=extract_js(os.path.join(base_path,"dumps",hash_value,filee))
                    #print(js)
                    if filee not in checked_files:
                        checked_files.append(filee)
                    if js != [] and js != None:
                        
                        for script in js:
                            if script.find('<iframe') != -1: # iframe based
                                fp=script.find('</iframe') 
                                script=script[script.find('<iframe'):fp]
                                if script.find('src=') != -1:
                                    target=script[script.find('src=')+5:fp]
                                    target=target[:target.find('"')]
                                    if chain == {}:
                                        red_found=1
                                        chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]= "first: Js with iframe tag"
                                        ip_chain[ip]="first: Js with iframe tag"
                                        
                                        chain[target]="null"
                                        ip_to=map_to_ip(target,conversations)
                                        if ip_to != '':
                                            ip_chain[ip_to]="null"
                                        else:
                                            if len(target)>10:
                                                for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                                    if target.find(car) != -1:
                                                        target=target[:target.find(car)]

                                            ip_chain[target]="null"
                                        break
                                    else:
                                        print("Warning: Found more than one redirection in the same conversation")
                    
        
                    
        # meta refresh based                     
        else:
            if head != "":
                ##print("-- Checking for meta Refresh redirection in ",conversation[Id]["filename"])
                if head.find('<meta') != -1:
                    head=head[head.find('<meta'):]
                    fp=head.find('/>')
                    head=head[:fp]
                    if head.find('"Refresh"') != -1:
                        if head.find('url') != -1:
                            target=head[head.find('url'):]
                            found=1
                            if chain == {}:
                                chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="first: Meta-refresh"
                                ip_chain[ip]="first: Meta-refresh"
                                

                                chain[target]="null"
                                ip_to=map_to_ip(target,conversations)
                                if ip_to != '':
                                    ip_chain[ip_to]="null"
                                else:
                                    if len(target)>10:
                                        for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                            if target.find(car) != -1:
                                                target=target[:target.find(car)]
                                    ip_chain[target]="null"
                                for filee in files:
                                    if filee.find(conversation[Id]["filename"]) != -1:
                                        checked_files.append(filee)
                                        break
                            else:
                                print("Warning: Found more than one redirection in the same conversation")
                            
                       
            else:
                ##print("-- Checking for meta Refresh redirection in ",conversation[Id]["filename"])
                for filee in files:
                    if filee.find(conversation[Id]["filename"]) != -1:
                   
                        try:
                            #print("reading file",filee)
                            f = open(os.path.join(base_path,"dumps",hash_value,filee), "r")
                            head=f.read()
                            f.close()
                        except:# (UnicodeDecodeError, UnicodeEncodeError):
                            #print('decode error is raised')
                            head=adv_open(os.path.join(base_path,"dumps",hash_value),filee)
                            if head == '-1':
                                continue
                            #head=f.read()
                        
                        if head.find('<meta') != -1:
                            head=head[head.find('<meta'):]
                            fp=head.find('/>')
                            head=head[:fp]
                            if head.find('"Refresh"') != -1:
                                if head.find('url') != -1:
                                    target=head[head.find('url'):]
                                    if chain == {}:
                                        chain[conversation[Id]["host"]+'/'+conversation[Id]["filename"]]="Meta-refresh"
                                        ip_chain[ip]="Meta-refresh"
                                        

                                        chain[target]="null"
                                        ip_to=map_to_ip(target,conversations)
                                        if ip_to != '':
                                            ip_chain[ip_to]="null"
                                        else:
                                            if len(target)>10:
                                                for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                                    if target.find(car) != -1:
                                                        target=target[:target.find(car)]
                                            ip_chain[target]="null"
                                        checked_files.append(filee)
                                        break
                                    else:
                                        print("Warning: Found more than one redirection in the same conversation")
        
    
    return chain,ip_chain

def follow(chain,ip_chain,files,hash_value,conversations):
    
    lookup=0
    ip=0
    nb=len(chain)
    keys=list(chain.keys())
    ips=list(ip_chain.keys())
    for key in keys:
        if chain[key]=="null":
            lookup=key
            
            file_name=extract_name(lookup)
            break

    for ipp in ips:
        if ip_chain[ipp]=="null":
            ip=ipp
            break
    if lookup==0:
        #print("Warning: a node might be missing from the chain (couldn't follow up to the next node)")
        return -1
    if ip==0:
        ip=lookup
    
    for filee in files:
        if filee.find(file_name) != -1:
            try:

                ##print("reading file",filee)
                f = open(os.path.join(base_path,"dumps",hash_value,filee), "r")
                html=f.read()
                f.close()
            except:# (UnicodeDecodeError, UnicodeEncodeError):
                ##print('decode error is raised')
                html=adv_open(os.path.join(base_path,"dumps",hash_value),filee)
                if html == '-1':
                    continue
            
            if filee not in checked_files:
                checked_files.append(filee)
            if re.search('.*.html', filee) != None:
                
                ##print("-- Checking for HTTP Redirect in ",file)
                m=re.search('3\d\d Found', html)
                if m != None:
                    #print('http redirect')
                    if html.find('<a') != -1:
                        
                        #fp=html.find('>') 
                        html=html[html.find('<a'):]
                        if html.find('href=') != -1:
                            target=html[html.find('href=')+6:]
                            target=target[:target.find('"')]
                            
                            chain[lookup]="Redirection "+str(nb)+": HTTP "+m.group(0)[:m.group(0).find('Found')-1]
                            ip_chain[ip]="Redirection "+str(nb)+": HTTP "+m.group(0)[:m.group(0).find('Found')-1]
                            
                            

                            chain[target]="null"
                            ip_to=map_to_ip(target,conversations)
                            if ip_to != '':
                                ip_chain[ip_to]="null"
                            else:
                                if len(target)>10:
                                    for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                        if target.find(car) != -1:
                                            target=target[:target.find(car)]
                                ip_chain[target]="null"
                            
                            break
                            
                elif html.find('<meta') != -1:
                    ##print("-- Checking for meta Refresh redirection in ",file)
                    html=html[html.find('<meta'):]
                    fp=html.find('/>')
                    html=html[:fp]
                    if html.find('"Refresh"') != -1:
                        if html.find('url') != -1:
                            target=html[html.find('url'):]
                            chain[lookup]="Redirection "+str(nb)+": Meta-refresh"
                            ip_chain[ip]="Redirection "+str(nb)+": Meta-refresh"
                            

                            chain[target]="null"
                            ip_to=map_to_ip(target,conversations)
                            if ip_to != '':
                                ip_chain[ip_to]="null"
                            else:
                                if len(target)>10:
                                    for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                        if target.find(car) != -1:
                                            target=target[:target.find(car)]
                                ip_chain[target]="null"
                            
                            break
                else:
                    ##print("-- Checking for js-based Redirect in ",file)
                    scripts=extract_js(os.path.join(base_path,"dumps",hash_value,filee))
                    ##print(scripts)
                    if scripts != []:
                        for js in scripts:
                            if js.find('<iframe') != -1: # iframe based
                                fp=js.find('</iframe') 
                                js=js[js.find('<iframe'):fp]
                                if js.find('src=') != -1:
                                    target=js[js.find('src=')+5:fp]
                                    target=target[:target.find('"')]
                                    chain[lookup]= "Redirection "+str(nb)+": Js with iframe tag"
                                    ip_chain[ip]="Redirection "+str(nb)+": Js with iframe tag"
                                    

                                    chain[target]="null"
                                    ip_to=map_to_ip(target,conversations)
                                    if ip_to != '':
                                        ip_chain[ip_to]="null"
                                    else:
                                        if len(target)>10:
                                            for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                                if target.find(car) != -1:
                                                    target=target[:target.find(car)]
                                        ip_chain[target]="null"
                                    
                                    break
            elif re.search('.*.js', filee) != None:
                ##print("-- Checking for js-based Redirect in ",file)
                js=html
                if js.find('<iframe') != -1: # iframe based
                    fp=js.find('</iframe') 
                    js=js[js.find('<iframe'):fp]
                    if js.find('src=') != -1:
                        target=js[js.find('src=')+5:fp]
                        target=target[:target.find('"')]
                        chain[lookup]= "Redirection "+str(nb)+": Js with iframe tag"
                        ip_chain[ip]="Redirection "+str(nb)+": Js with iframe tag"
                        

                        chain[target]="null"
                        ip_to=map_to_ip(target,conversations)
                        if ip_to != '':
                            ip_chain[ip_to]="null"
                        else:
                            if len(target)>10:
                                for car in ['\\','?','*',"~",';','\\n','Content-Encoding','Content-Length','none']:
                                    if target.find(car) != -1:
                                        target=target[:target.find(car)]
                            ip_chain[target]="null"
                        #print(ip)
                        break
            
    
    return chain,ip_chain



def Vuln_probing(chains,files,hash_value):
    
    result="Attacker have probably not used JS script for vulnerability probing"
    for chain in chains:
        keys=list(chain.keys())
        for key in keys:
            if chain[key]=="null":
                file_name=extract_name(key)
                ##print("--Looking for finger#printing js script in the final node of the chain :",file_name)
                break
        found=0
        if re.search('.*.js', file_name) != None:
            for filee in files:
                if filee.find(file_name) != -1:
                    ##print("--Checking one js-script")
                    rate=find_sim(os.path.join("dumps",hash_value,filee))
                    if rate != -1:
                        if float(rate[:-1]) > 30:
                            #print("Attacker have used JS script for vulnerability probing")
                            result="Attacker have used JS script for vulnerability probing"
                            found=1
                    else:
                        #print("--Trying deobfiscation")
                        js=deobfiscate(filee)
                        if js != []:
                            #print("Found {} potential scripts".format(len(js)))
                            for script in js:
                                if script != '':
                                    new_file=save_js(script)
                                    rate=find_sim(new_file)
                                    if rate != -1:
                                        #print("Similarity rate = ",rate)
                                        if float(rate[:-1]) > 30:
                                            #print("Attacker have used JS script for vulnerability probing")
                                            result="Attacker have used JS script for vulnerability probing"
                                            found=1
                        if found==0:
                            #print("Trying XorBruteForcer for deobfiscation")
                            out=deobfiscate2(filee,hash_value)
                            if str(out).find('Pattern found using the following keys:') != -1:
                                #print("Attacker have used JS script for vulnerability probing")
                                result="Attacker have used JS script for vulnerability probing"
                                found=1
                            #if stderr != None:
                            #    #print("XorBrute forcer exited with error: "+str(stderr))
                break
        elif re.search('.*.html', file_name) != None:
            for filee in files:
                if filee.find(file_name) != -1:
                    scripts=extract_js(os.path.join(base_path,"dumps",hash_value,filee))
                    ##print(scripts)
                    if scripts != []:
                        for js in scripts:
                            if js != '':
                                new_file=save_js(js)
                                rate=find_sim(new_file)
                                if rate != -1:
                                    if float(rate[:-1]) > 30:
                                        #print("Attacker have used JS script for vulnerability probing")
                                        result="Attacker have used JS script for vulnerability probing"
                                        found=1
                                
                                    
                            else:
                                #print("--Trying deobfiscation")
                                js=deobfiscate(filee)
                                
                                if js != []:
                                    #print("Found {} potential scripts".format(len(js)))
                                    for script in js:
                                        if script != '':
                                            new_file=save_js(script)
                                            rate=find_sim(new_file)
                                            if rate != -1:
                                                #print("Similarity rate = ",rate)
                                                if float(rate[:-1]) > 30:
                                                    #print("Attacker have used JS script for vulnerability probing")
                                                    result="Attacker have used JS script for vulnerability probing"
                                                    found=1
                                if found==0:
                                    #print("Trying XorBruteForcer for deobfiscation")
                                    out=deobfiscate2(filee,hash_value)
                                    if out.find('Pattern found using the following keys:') != -1:
                                        #print("Attacker have used JS script for vulnerability probing")
                                        result="Attacker have used JS script for vulnerability probing"
                                        found=1
                                    #if stderr != None:
                                    #    #print("XorBrute forcer exited with error: "+str(stderr))
                                            
                           
                    break 
        if found==0:
            print("vulnerability probing was not performed using JS script") 
                
    return result

def find_sim(file1):
    
    userid = 812874760

    m = mosspy.Moss(userid, "javascript")
    
    
    # Submission Files
    try:
        m.addFile(os.path.join(base_path,file1))
        m.addFilesByWildcard(os.path.join(base_path,"js-detect.js"))
    
        url = m.send() # Submission Report URL
    
        response = urllib.request.urlopen(url)
        html = response.read().decode('utf-8')
        match = re.findall(r'<TR><TD><A .*</A>', html)
        if match != []:
            res = match[0].split('/')
            rate=re.findall(r'[0-9]+\%', res[-2])
            if rate != []:
                return rate[0]
            else:
                print("Couldn't extract similarity rate from ",res[-2])
        return -1
    except:
        return -1
    
    
def exploitation_chain(chains,conversations,files,hash_value):
    
    scores={}
    VT_scandate = {}
    label='benign'
    if chains==[]:
        return label,scores,VT_scandate
    suspec_obj=[]
    
    for chain in chains:
        if chain != {}:
            keys=list(chain.keys())
            for key in keys:
                if chain[key]=="null":
                    domain=extract_domain(key)
                    break
    host_search=0
    print("--Looking for malicious files in :"+domain)
    for conv_id in range(len(conversations)):
        try:
            conversation=conversations[conv_id]["uris"]
        except:
            continue
        
        for Id in range(len(conversation)):
            try:
                host=conversation[Id]["host"]
            except:
                continue
            if domain.find(host) != -1:
                host_search=1
                if re.search('.*.(exe|swf|pdf|txt|doc|docs|ppt|xls|zip)', conversation[Id]["filename"]) != None:
                    if conversation[Id]["filename"] not in suspec_obj:
                        suspec_obj.append(conversation[Id]["filename"])
        if host_search==1:
            break


    
    if suspec_obj != []:
        print(suspec_obj)
        print('Checking the behavior of ',len(suspec_obj),' suspicious files')
        for obj in suspec_obj:
            for filee in files:
                if filee.find(obj) != -1:
                    scores[obj],VT_scandate[obj]=VirusTot_Api(os.path.join(base_path,'dumps',hash_value,filee))
                    # Wait for 5 seconds
                    
                    if scores[obj]!= -1:
                        print(host+'/'+obj+' is '+str(scores[obj]*100)+'% malicious')
                    checked_files.append(filee)
                    if scores[obj]>0:
                        label='malicious'
                    break
                
    
    #print(label)
    #print(scores)
    #print(VT_scandate)
    scores2={}
    if scores != {}:
        for obj in scores.keys():
            if obj.find('.') != -1:
                ext=obj.split('.')[-1]
            else:
                ext=''
            if len(VT_scandate[obj])==2:
                scores2[VT_scandate[obj][1]+'.'+ext]=scores[obj]
            else:
               print('hash value not found')


    return label,scores,scores2,VT_scandate

def exploitation(conversations,files,hash_value):
    
    VT_scandate={}
    scores={}
    scores2={}
    suspec_obj=[]
    label='benign'
    
    try:
        conversation1=conversations[-1]["uris"]
        conversation2=conversations[-2]["uris"]
    except:
        return label,scores,scores2,VT_scandate

    for conversation in [conversation1,conversation2]:
   
        for Id in range(len(conversation)):
            try:
                host=conversation[Id]["host"]
            except:
                continue
            #print("--Looking for malicious files in :",host)
            if re.search('.*.(exe|swf|pdf|txt|doc|docs|ppt|xls|zip)', conversation[Id]["filename"]) != None:
                if conversation[Id]["filename"] not in suspec_obj:
                    suspec_obj.append(conversation[Id]["filename"])
    if suspec_obj != []:
        print(suspec_obj)
        print('Checking the behavior of ',len(suspec_obj),' suspicious files')
        for obj in suspec_obj:
            for filee in files:
                if filee.find(obj) != -1:
                    scores[obj],VT_scandate[obj]=VirusTot_Api(os.path.join(base_path,'dumps',hash_value,filee))
                    
                    if scores[obj]!= -1:
                        print(host+'/'+obj+' is '+str(scores[obj]*100)+'% malicious')
                    checked_files.append(filee)
                    if scores[obj]>0:
                        label='malicious'
                    break
                    
       
    #print(label)
    #print(scores)
    #print(VT_scandate)
    
    if scores != {}:
        for obj in scores.keys():
            if obj.find('.') != -1:
                ext=obj.split('.')[-1]
            else:
                ext=''
            if len(VT_scandate[obj])==2:
                scores2[VT_scandate[obj][1]+'.'+ext]=scores[obj]
            else:
               print('hash value not found')

    return label,scores,scores2,VT_scandate

def VirusTot_Api(filee):
    
    API_KEY = '06b072bb4ef036512a233ac40a7df7e316f10c4fd471e339f1dec03979ed8160'
    
    try:
        ##print("reading file",filee)
        f = open(filee, "r")
        txt=f.read()
        EICAR = txt.encode('utf-8')
        f.close()
    except UnicodeDecodeError as e:
        ##print("reading file",filee)
        f = open(filee, "rb")
        EICAR=f.read()
        f.close()
        
    EICAR_MD5 = hashlib.md5(EICAR).hexdigest()
    
    vt = VirusTotalPublicApi(API_KEY)
    
    response = vt.get_file_report(EICAR_MD5)
    time.sleep(5)
    report= json.loads(json.dumps(response, sort_keys=False, indent=4))
    
    scan_date=""
    md5=""
    if "results" in report.keys():
        if "scan_date" in report["results"].keys():
            ##print("extracting scan date")
            scan_date=report["results"]["scan_date"]
        if "md5" in report["results"].keys():
            ##print("extracting md5")
            md5=report["results"]["md5"]
    else:
        if "scan_date" in report.keys():
            ##print("extracting scan date")
            scan_date=report["scan_date"]
        if "md5" in report.keys():
            ##print("extracting md5")
            md5=report["md5"]
    
    if scan_date != "" and md5 != "":
        date_hash=[scan_date,md5]
    else:
        date_hash=[]

    ##print("extracting score")
    try:
        score=abs(float(report["results"]["positives"])/float(report["results"]["total"]))
    except KeyError as e:
        try:
            score=abs(float(report["positives"])/float(report["total"]))
        except KeyError as e:
            print("Couldn't analyze the behavior of ",extract_name(filee))
            return -1,date_hash
    return score,date_hash
   
def extract_js(filee):
    ##print("extracting js from path: ",filee)

    try:
        ##print('reading file')
        f = open(filee, "r")
        html=f.read()
        f.close()
        ##print('reading scceeded')
    except:# (UnicodeDecodeError, UnicodeEncodeError):
        ##print('decode error is raised')
        split=os.path.split(filee)
        ##print(split)
        path= split[0]
        name= split[-1]
        ##print(path)
        ##print(name)
        html=adv_open(path,name)
        
        if html == '-1':
            ##print("adv #print failed")
            return []
    
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
        for key in list(elt.keys()):
            lookup=extract_name(key)
            for key2 in list(chain.keys()):
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

def deobfiscate(filee):
    
    deobf=[]
    
    
    filename, file_extension = os.path.splitext(filee)
    if file_extension=='.html':
        js=extract_js(filee)
        if js != []:
            for script in js:
                deobf.append(jsb.beautify(script))
    elif file_extension=='.js':
        try:
            ##print("reading file",filee)
            f = open(filee, "r")
            js=f.read()
            f.close()
        except:# (UnicodeDecodeError, UnicodeEncodeError):
            ##print('decode error is raised')
            js=adv_open("",filee)
            if js == '-1':
                return []
        
        deobf.append(jsb.beautify(js))

    return deobf

def deobfiscate2(filee,hash_value):
    
    '''XorBruteForcer'''
    #os.system("python2 "+os.path.join(base_path,"xorBruteForcer.py")+" "+os.path.join(base_path,"dumps",name,file)+" PluginDetect")
    out=os.popen("python2 "+os.path.join(base_path,"xorBruteForcer.py")+" "+os.path.join(base_path,"dumps",hash_value,filee)+" PluginDetect").read()
    #out = subprocess.Popen(["python2", os.path.join(base_path,"xorBruteForcer.py"), os.path.join(base_path,"dumps",name,file), "PluginDetect"], 
    #       stdout=subprocess.PIPE, 
    #       stderr=subprocess.STDOUT)
    #stdout,stderr = out.communicate()
    ##print(out)
    return out

def save_js(js):
    f = open(os.path.join(base_path,"new.js"), "w")
    f.write(js)
    f.close()
    filee="new.js"
    return filee



def generate_graph(chains):
    nodes = []
    edges= []
    if chains != []:
        for chain in chains:
            # first node
            
            redirect=''
            #print('looking for node number : 1')
            first_found=0
            ind=0
            for node in chain.keys():
                for car in ['javascript',';','(',')','+','|']:
                    if node.find(car) != -1:
                        chain[hash(node)]=chain[node]
                        del chain[node]
                        break
                if chain[node].find('first') != -1:
                    first_found=1
                    nodes.append({'id': node, 'label':node, 'group':'first'})
                    redirect=chain[node]
                    redirect=redirect[redirect.find(':')+1:]
                    break

            # remaining nodes
            
            if first_found==1:
                if len(chain.keys())>=3:
                    for ind in range(1,len(chain.keys())-1):
                        #print('looking for node number :',ind+1)
                        
                        for node in chain.keys():
                            if chain[node].find('Redirection '+str(ind+1)+':') != -1:
                                
                                #print(node)
                                nodes.append({'id': node, 'label':node, 'group':'inter'})
                            
                                edges.append({'from': nodes[-2]['id'], 'to': nodes[-1]['id'], 'label':redirect, 'arrows':"to"})
                           
                                redirect=chain[node]
                                if redirect != 'null':
                                    redirect=redirect[redirect.find(':')+1:]
                                break
                                
                                
                            
                        

            

            # last node
            #print('looking for last node')
           
            if redirect not in ['null',''] :
                for node in chain.keys():
                    if chain[node] == 'null':     
                        nodes.append({'id': node, 'label':node, 'group':'final'})
                        if len(nodes)>1:
                            if redirect.find(':') != -1:
                                redirect=redirect[redirect.find(':')+1:]
                            edges.append({'from': nodes[-2]['id'], 'to': nodes[-1]['id'], 'label':redirect, 'arrows':"to"})
                        break
                        
                
                
    #print(nodes)
    #print(edges)
    return edges,nodes

def IP_extract(file):
    
    try:
        client=get_ip(file["client"]["IP"])
    except:
        client=''
    
    try:
        infected_host=get_ip(file["conversations"][0]["ip"])
    except:
        infected_host=''
    
    
    transition=[]
    for Id in range(1,len(file["conversations"])-1):
        try:
            transition.append(get_ip(file["conversations"][Id]["ip"]))
        except:
            continue
    #transition= ';'.join(transition)
    try:
        infecting_host=get_ip(file["conversations"][len(file["conversations"])-1]["ip"])
    except:
        infecting_host=''  
    
    try:
        date = get_date(file["info"]["traffic_time"])
    except:
        date=""
    #year=get_year(file["info"]["traffic_time"])
    
    #data.loc[data.index[-1]+1] = pd.Series({'Year':year, 'Client':client, 'Infected_host':infected_host, 'transitions':transition, 'infecting_host':infecting_host})
    #data.to_csv(base_path+'/webInf.csv', index=False)
    
    return client, infected_host, transition, infecting_host, date

def get_ip(IP):
    
    ip=IP
    if IP.find(':') != -1:
        ip=IP[0: IP.find(':')]
        
    
    return ip

def get_year(time):
    
    year=time
    splt=year.split('/')
    if len(splt)==3:
        year=splt[-1]
        year=year[0: year.find(' ')]
        year='20'+year
    else:
        print('the traffic time'+ year + 'is not precise')
        
    return year

def get_date(time):
    
    splt=time.split(' ')
    if len(splt)==2:
        splt1=splt[0].split('/')
        if len(splt1) == 3:
            date= '20'+splt1[-1]+'-'+splt1[0]+'-'+splt1[1]+' '+splt[-1]
        else:
            #print('the traffic time'+ year + 'is not precise')
            date=""
    elif len(splt)==1 :
        #print('the traffic time'+ year + 'is not precise')
        if len(splt) == 3:
            date= '20'+splt[-1]+'-'+splt[0]+'-'+splt[1]
        else:
            date=""
    else:
        #print('the traffic time'+ year + 'is not precise')
        date=""
        
    return date

def get_loc(file,hashes):
    geo_data=[]
    geo_line=[]
    
    client, infected_host, transition, infecting_host,date=IP_extract(file)
    
    print('/**Locating infected host\n')
    infected_host=check_ip(infected_host)
    City,lat,longi,Country=ip_lookup(infected_host)
    if lat!='' and Country!='(Unknown Country?) (XX)':
        geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color": 'blue' ,"title": City,"host": infected_host,'hashes':''})#"chart.colors.getIndex(0)"
        geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
        print(City+' '+Country)
    else:
        if Country not in ['(Unknown Country?) (XX)','']:
            if Country.find('(') != -1:
                Country=Country[0:Country.find('(')]
                print('Country is: ',Country)
            while Country[-1] == ' ':
                Country=Country[0:-1]
            print('located only country:', Country)
            try:
                info = CountryInfo(Country)
                cap=info.capital()
                lat,longi=info.capital_latlng()
                
                geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color": 'blue' ,"title": cap,"host": infected_host,'hashes':''})#"chart.colors.getIndex(0)"
                geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
            except:
                pass
        else:
            print('Host is not located')

    index=0
    added=[]
    print('/**Locating transitions hosts\n')
    for host in transition:
        if host not in added:
            ip=check_ip(host)
            City,lat,longi,Country=ip_lookup(ip)
            
            if lat!='' and Country!='(Unknown Country?) (XX)':
                geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color":'purple' ,"title": City,"host": ip,'hashes':''})#"chart.colors.getIndex(1)"
                
                geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
                print(City+' '+Country)
                added.append(host)
                index+=1
            else:
                if Country not in ['(Unknown Country?) (XX)','']:
                    if Country.find('(') != -1:
                        Country=Country[0:Country.find('(')]
                        print('Country is: ',Country)
                    while Country[-1] == ' ':
                        Country=Country[0:-1]
                    print('located only country:', Country)
                    try:
                        info = CountryInfo(Country)
                        cap=info.capital()
                        lat,longi=info.capital_latlng()

                        geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color":'purple' ,"title": cap,"host": ip,'hashes':''})#"chart.colors.getIndex(0)"
                        geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
                    except:
                        pass
                    index+=1
    print('/**Locating Infecting host\n')
    infecting_host=check_ip(infecting_host)
    City,lat,longi,Country=ip_lookup(infected_host)
    
    if lat!='' and Country!='(Unknown Country?) (XX)':
        geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color":'red' ,"title": City,"host": infecting_host,'hashes':list(hashes.keys())})#"chart.colors.getIndex(4)"
        geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
        print(City+' '+Country)
    else:
        if Country not in ['(Unknown Country?) (XX)','']:
            if Country.find('(') != -1:
                Country=Country[0:Country.find('(')]
                print('Country is: ',Country)
            while Country[-1] == ' ':
                Country=Country[0:-1]
            print('located only country:', Country)
            try:
                info = CountryInfo(Country)
                cap=info.capital()
                lat,longi=info.capital_latlng()
            

                geo_data.append({"latitude": float(lat),"longitude": float(longi),"value": 1,"color":'red' ,"title": cap,"host": infecting_host,'hashes':list(hashes.keys())})#"chart.colors.getIndex(0)"
                geo_line.append({ "latitude": float(lat), "longitude": float(longi) })
            except:
                pass
        else:
            print('Host is not located')
    
    

    return geo_data, geo_line,date

    
def ip_lookup(ip):
    try:
        req = urllib.request.Request("http://api.hostip.info/get_html.php?ip="+ip+"&position=true",headers = {"User-Agent": "Mozilla/5.0"})
    
        f = urllib.request.urlopen(req)
        try:
            data = f.read().decode('utf-8')
        except:
            data=f.read().decode()
        
        f.close()
        if data.find('Private Address') != -1:
            print('Cannot lookup a private ip')
            return '','','',''
        else:
            #find Country
            Country=data[data.find('Country')+len('Country')+2:data.find('\n')]
            #print("Country is: " + Country)
            #find city
            data1=data[data.find('\n')+1:]
            City = data1[data1.find('City')+len('City')+2:data1.find('\n')]
            #City=City[0: City.find(',')]
            #print("City is: " +City)
            #find Latitude
            data1=data1[data1.find('\n')+2:]
            lat=data1[data1.find('Latitude')+len('Latitude')+2:data1.find('\n')]
            #print("lat is: " +lat)
            #find Longitude
            data1=data1[data1.find('\n')+1:]
            longi=data1[data1.find('Longitude')+len('Longitude')+2:data1.find('\n')]
            #print("longi is: " +longi)
            return City,lat,longi,Country
    except urllib.error.HTTPError as e:
        if e.code == 502:
            print('ip lookup service is down')
            return '','','',''

def check_ip(ip):
    if ip.find(':') != -1:
        ip=ip[:ip.find(':')]
    if ip.find(' ')==0:
        ip=ip[1:]
    if ip.find(' ')==len(ip)-1:
        ip=ip[:-1]

    ##print(ip)
    return ip


def APT_matches(hash_value,file,chains,VT_scandate,files):

    matches={"hosts":[],
             "URL":[],
             "md5":{},  #md5: VT_date
             "ips":[],
             "APTs":[]}
    matches2={}

    #filenames={}
    hosts=[]
    hashes={hash_value:""}
    URLs=[]

    client, infected_host, transition, infecting_host,date=IP_extract(file)
    IPs=[client, infected_host, transition, infecting_host]

    #print("extracting data")
    for elt in VT_scandate.keys():
        #if len(VT_scandate[elt]) != 0:
        #    filenames[(extract_name(elt))]= VT_scandate[elt][0]
        #else:
        #    filenames[(extract_name(elt))]= VT_scandate[elt]
        URLs.append(elt)
    if chains != []:
        for chain in chains:
            for node in chain.keys():
                if node not in URLs:
                    URLs.append(node)
                filename=extract_name(node)
                for filee in files:
                    if filee.find(filename) != -1:
                        hash_value1=hash(os.path.join(base_path,"dumps",hash_value,filee))
                        hashes[hash_value1]=""
                        break
                #if filename not in filenames.keys():
                #    filenames[filename]=""
                host = extract_domain(node)
                if host not in hosts:
                    hosts.append(host)

    for value in VT_scandate.values():
        if len(value) == 2:
            hashes[value[-1]]=value[0]

    #print(filenames,hosts,hashes,URLs,IPs)

    with open(os.path.join(base_path,"APTNotes1.json"),'r') as f:
        APTs = json.load(f)

    #print("extracting matches")
    for apt in APTs:

        # Host matches
        if apt["type"] == "Host":
            target = apt["match"]
            if target in hosts:
                if target not in matches["hosts"]:
                    matches["hosts"].append(target)
                if apt["file"] not in matches["APTs"]:
                    matches["APTs"].append(apt["file"])

                if apt["file"] not in matches2.keys():
                    matches2[apt["file"]]={'hosts':[target]}
                else:
                    if 'hosts' not in matches2[apt["file"]].keys():
                        matches2[apt["file"]]['hosts'] = [target]
                    else:
                        matches2[apt["file"]]['hosts'].append(target)
        
        # MD5 matches
        elif apt["type"] == "MD5":
            target = apt["match"]
            if target in hashes.keys():
                if target not in matches["md5"].keys():
                    matches["md5"][target] = hashes[target]
                if apt["file"] not in matches["APTs"]:
                    matches["APTs"].append(apt["file"])

                if apt["file"] not in matches2.keys():
                    matches2[apt["file"]]={'MD5':[target]}
                else:
                    if 'MD5' not in matches2[apt["file"]].keys():
                        matches2[apt["file"]]['MD5'] = [target]
                    else:
                        matches2[apt["file"]]['MD5'].append(target)
        # URL matches
        elif apt["type"] == "URL":
            target = apt["match"]
            if target in URLs:
                if target not in matches["URL"]:
                    matches["URL"].append(target)
                if apt["file"] not in matches["APTs"]:
                    matches["APTs"].append(apt["file"])

                if apt["file"] not in matches2.keys():
                    matches2[apt["file"]]={'URLs':[target]}
                else:
                    if 'URLs' not in matches2[apt["file"]].keys():
                        matches2[apt["file"]]['URLs'] = [target]
                    else:
                        matches2[apt["file"]]['URLs'].append(target)


        # IPs matches
        elif apt["type"] == "IP":
            target = apt["match"]
            if target in IPs:
                if target not in matches["ips"]:
                    matches["ips"].append(target)
                if apt["file"] not in matches["APTs"]:
                    matches["APTs"].append(apt["file"])

                if apt["file"] not in matches2.keys():
                    matches2[apt["file"]]={'IP':[target]}
                else:
                    if 'IP' not in matches2[apt["file"]].keys():
                        matches2[apt["file"]]['IP'] = [target]
                    else:
                        matches2[apt["file"]]['IP'].append(target)


       

    #print(matches)
    


    return matches,hashes,matches2



def get_year(traffic_date):
    
    #print('getting year from',traffic_date)
    return traffic_date.split('-')[0]

def find_edge_id(target,edgess):

    ind=0
    for edge in edgess:
        if edge['from']==target['from'] and edge['to']==target['to']:
            #print(node['id'])
            return ind
        ind+=1
    return -1

def find_node_id(target,nodess):

    ind=0
    for node in nodess:
        if node['id']==target['id']:
            #print(node['id'])
            return ind
        ind+=1
    return -1




def extract_apt_date(apt):

    date=''
    if type(apt) == str:
        if apt.find('(') != -1:
            date=apt[apt.find('(')+1:]
            if date.find(')') != -1:
                date=date[:date.find(')')]
    
                res=date.split('-')
                if len(res)==3:
                    return '-'.join([res[-1],res[0],res[1]])
                else:
                    return ''
        else:
            return ''
    else:
        return ''


if __name__ == '__main__':

    
    if len(sys.argv) == 2:
        
        
        print(type(base_path))
        handle_uploaded_file(sys.argv[1])
        
    else:
        print("infection analysis: pcap file missing")
