# -*- coding: utf-8 -*-
"""
Created on Mon Jun 29 14:38:20 2020

@author: abder
"""
import json
import sys
import glob, os
import re




referers={'search engine':['google','yahoo','bing'],
          'email':['gmail','mail.google','hotmail','outlook','live'],
          'social meida':['facebook','twitter','instagram']}



def read_report(path):
    res = path.split('/')
    filename=res[-1]
    folder=res[0]
    for elt in res[1:-1]:
        folder=folder+'/'+elt
        
    with open(path,'rb') as f:
        for i, line in enumerate(f):
            try:
                line_=line.decode("utf-8")
                with open(folder+'/new-'+filename,'a') as f:
                    f.write(line_)
            except UnicodeDecodeError:
                #print("decoding error captured and removed" )
                continue
          
    with open(folder+'/new-'+filename,'r') as f:
        file = json.load(f)
    
    
    os.chdir("D:/research/infection-analysis/dumps/")#"+name+"/")
    files=glob.glob("*")
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

def check_redirect(chain,conversation,Id,conv_Id,files):
    
    head=conversation[Id]["res_head"]
    # HTTP Redirect
    if re.search('3\d\d', conversation[Id]["res_num"]) != None:
        print('-- HTTP Redirection: ',conversation[Id]["res_num"])
        if head != "":
            if head.find('Location') != -1:
                if conv_Id==0:
                    chain[-1]=chain[-1]+'/'+conversation[Id]["filename"]
                chain.append(head[head.find('Location')+len('location')+2:])
        else:
            print('Checking the response head in the file ',conversation[Id]["filename"])

    # js-based redirect
    elif re.search('.*.js', conversation[Id]["filename"]) != None:
        print("-- Checking for js-based redirection in ",conversation[Id]["filename"])
        for file in files:
            if file.find(conversation[Id]["filename"]) != -1:
                f = open("D:/research/infection-analysis/dumps/"+file, "r")
                js=f.read()
                if js.find('<iframe') != -1: # iframe based
                    fp=js.find('</iframe') 
                    js=js[js.find('<iframe'):fp]
                    if js.find('src=') != -1:
                        target=js[js.find('src=')+5:fp]
                        target=target[:target.find('"')]
                        if conv_Id==0:
                            chain[-1]=chain[-1]+'/'+conversation[Id]["filename"]
                        chain.append(target)
                        break

    # meta refresh based                     
    else:
        if head != "":
            if head.find('<meta') != -1:
                head=head[head.find('<meta'):]
                fp=head.find('/>')
                head=head[:fp]
                if head.find('"Refresh"') != -1:
                    if head.find('url') != -1:
                        target=head[head.find('url'):]
                        if conv_Id==0:
                            chain[-1]=chain[-1]+'/'+conversation[Id]["filename"]
                        chain.append(target)
        else:
            print('Checking the response head in the file ',conversation[Id]["filename"])
    return chain

def find_next(chain,conv_Id,conversations,files):
    conversation=conversations[conv_Id]["uris"]
    for Id in range(len(conversation)):
        if conv_Id==0:
            chain=check_redirect(chain,conversation,Id,conv_Id,files)
        elif chain[-1].find(conversation[Id]["filename"]) != -1: 
            chain=check_redirect(chain,conversation,Id,conv_Id,files)
    return chain

def RedCain(chain,conversations,files):
    for conv_Id in range(len(conversations)):
        chain=find_next(chain,conv_Id,conversations,files)
    return chain
    

if __name__ == '__main__':

    
    if len(sys.argv) == 2:
        file,files=read_report(sys.argv[1])
        print('\n-- Running Enticement source detection gadget\n')
        print("Enticement source= ",Enticement_source(file))
        print('\n-- Running Redirection chain gadget\n')
        chain=[]
        conversations=file["conversations"]
        chain.append(conversations[0]["uris"][0]['host'])
        
        print("Redirection chain = ",RedCain(chain,conversations,files))
        
    else:
        print("infection analysis: pcap file missing")
        
        
