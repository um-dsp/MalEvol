# -*- coding: utf-8 -*-
"""
Created on Tue Aug 11 09:45:43 2020

@author: abder
"""

from urllib2 import Request,urlopen
import pandas as pd
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import os
import warnings 

base_path=os.getcwd()
warnings.filterwarnings("ignore")

# import analyzed web traffic
data=pd.read_csv(base_path+'/webInf.csv')

# locate positions
def locate(data):
    
    column_names = ['year','Country','City','Latitude','Longitude','type']
    coord = pd.DataFrame(columns = column_names)
    for ind in range(len(data)):
        for col in data.columns.tolist()[1:]:
            if col != 'transitions':
                ip=data.at[ind, col]
                if ip.find(' ')==0:
                    ip=ip[1:]
                if ip.find(' ')==len(ip)-1:
                    ip=ip[:-1]
                #print('locating :', ip)
                City,lat,longi,Country=ip_lookup(ip)
                if col == 'Client':
                    typee='client'
                if col == 'Infected_host':
                    typee='infected'
                if col == 'infecting_host':
                    typee='infecting'
                if lat!='':
                    coord=coord.append({'year':data.at[ind,'Year'],'Country':Country, 'City':City, 'Latitude':lat, 'Longitude':longi, 'type':typee},ignore_index=True)
                else:
                    continue
            else:
                trans=data.at[0,'transitions']
                if trans != '[]':
                    trans=trans[trans.find('[')+1:trans.find(']')]
                    trans=trans.split(';')
                    for ip in trans:
                        if ip.find(' ')==0:
                            ip=ip[1:]
                        if ip.find(' ')==len(ip)-1:
                            ip=ip[:-1]
                        #print('locating :', ip)
                        City,lat,longi,Country=ip_lookup(ip)
                        typee='trans'
                        if lat!='':
                            coord=coord.append({'year':data.at[ind,'Year'],'Country':Country, 'City':City, 'Latitude':lat, 'Longitude':longi, 'type':typee},ignore_index=True)
                        else:
                            continue
    return coord
        
def ip_lookup(ip):
    req = Request("http://api.hostip.info/get_html.php?ip="+ip+"&position=true",headers = {"User-Agent": "Mozilla/5.0"})
    f=urlopen(req)
    #f = urllib2.urlopen()
    data = f.read()
    f.close()
    if data.find('Private Address') != -1:
        #print('Cannot lookup a private ip')
        return '','','',''
    else:
        #find Country
        Country=data[data.find('Country')+len('Country')+2:data.find('\n')]
        
        #find city
        data1=data[data.find('\n')+1:]
        City = data1[data1.find('City')+len('City')+2:data1.find('\n')]
        City=City[0: City.find(',')]
        
        #find Latitude
        data1=data1[data1.find('\n')+2:]
        lat=data1[data1.find('Latitude')+len('Latitude')+2:data1.find('\n')]
        
        #find Longitude
        data1=data1[data1.find('\n')+1:]
        longi=data1[data1.find('Longitude')+len('Longitude')+2:data1.find('\n')]
        return City,lat,longi,Country

def locatePerYear(coord):
    
    time_line=coord['year'].unique().tolist()
    colors_map={0:'red',1:'blue',2:'black'}
    coord=coord[coord['Country'] != '(Unknown Country?) (XX)']
    # prepare a color for each point depending on the type.
    colors=[]
    for enc in pd.factorize(coord['type'])[0].tolist():
        colors.append(colors_map[enc])
    coord['labels_enc'] = colors
    coord=coord.sort_values(['year','City','type'])
    
    coord_per_year={}
    for year in time_line:
        coord_per_year[year] = coord[coord['year'] == year]
        coord_per_year[year]=coord_per_year[year].sort_values(['year','City','type'])
        count = coord_per_year[year].pivot_table(index=['year', 'Country', 'City', 'Latitude', 'Longitude', 'type','labels_enc'], aggfunc='size')
        #print(count)
        counts=[]
        for index in range(len(count)):
            counts.append(count[index])
        coord_per_year[year].drop_duplicates(subset=['year', 'Country', 'City', 'Latitude', 'Longitude', 'type','labels_enc'],inplace=True)
        #print(coord_per_year[year])
        coord_per_year[year]['occ']=counts
        
    return coord_per_year

def plot_map(coord_per_year):
    
    for year in coord_per_year.keys():
    
        # Set the dimension of the figure
        my_dpi=96
        plt.figure(figsize=(2600/my_dpi, 1800/my_dpi), dpi=my_dpi)
    
        # read the data (on the web)
        data = coord_per_year[year]
    
        # Make the background map
        m=Basemap(llcrnrlon=-180, llcrnrlat=-65,urcrnrlon=180,urcrnrlat=80)
        m.drawmapboundary(fill_color='#A6CAE0', linewidth=0)
        m.fillcontinents(color='grey', alpha=0.3)
        m.drawcoastlines(linewidth=0.1, color="white")
        
        # preparing positions
        longg=[]
        for i in range(len(data['Longitude'])):
            longg.append(float(data['Longitude'].tolist()[i]))
        lat=[]               
        for i in range(len(data['Latitude'])):
            lat.append(float(data['Latitude'].tolist()[i]))
        
        
        # Add a point per position
        m.scatter(longg, lat, s=data['occ']*100, alpha=0.4, c=data['labels_enc'], cmap="Set1")
        
        #set legend
        '''legend=[]
        label_map={'red':'infected host','white':'transition server','black':'infecting host'}
        for color in data['labels_enc']:
            legend.append(label_map[color])
        print(legend)'''
        
        l1 = plt.scatter([],[], s=50, c='red', edgecolors='none')
        l2 = plt.scatter([],[], s=50, c='blue', edgecolors='none')
        l3 = plt.scatter([],[], s=50, c='black',edgecolors='none')
        plt.legend([l1,l2,l3], ['infected host', 'transition server','infecting host'], ncol=4, frameon=True, fontsize=14,
        handlelength=2, loc = 8, borderpad = 1.8,
        handletextpad=1, title='Lebels', scatterpoints = 1)
        
        # Add a connection between new york and London
        '''startlat = 40.78; startlon = -73.98
        arrlat = 51.53; arrlon = 0.08
        m.drawgreatcircle(startlon,startlat,arrlon,arrlat, linewidth=2, color='orange')'''
    
        # copyright and source data info
        plt.text( -170, -58,'Web-Borne Malware Infections Geographical Analysis\n\nData of '+str(year), ha='left', va='bottom', size=13, color='#555555' )
    
        # Save as png
        plt.savefig('Web-Borne Malware Infections geo-analysis of the year '+str(year), bbox_inches='tight')

    return 0

def main():
    
    print('/** Locating all hosts involved in web traffic ...')
    coord=locate(data)
    coord_per_year=locatePerYear(coord)
    plot_map(coord_per_year)
    print('/** Geographical Analysis Per year figures are stored in the main directory')
    
main()    