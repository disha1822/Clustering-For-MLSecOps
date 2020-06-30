#!/usr/bin/env python
# coding: utf-8



# Converting the access_log to csv File 

from datetime import datetime
import pytz

def parse_str(x):
    """
    Returns the string delimited by two characters.

    Example:
        `>>> parse_str('[my string]')`
        `'my string'`
    """
    return x[1:-1]

def parse_datetime(x):
    '''
    Parses datetime with timezone formatted as:
        `[day/month/year:hour:minute:second zone]`

    Example:
        `>>> parse_datetime('13/Nov/2015:11:45:42 +0000')`
        `datetime.datetime(2015, 11, 3, 11, 45, 4, tzinfo=<UTC>)`

    Due to problems parsing the timezone (`%z`) with `datetime.strptime`, the
    timezone will be obtained using the `pytz` library.
    '''
    dt = datetime.strptime(x[1:-7], '%d/%b/%Y:%H:%M:%S')
    dt_tz = int(x[-6:-3])*60+int(x[-3:-1])
    return dt.replace(tzinfo=pytz.FixedOffset(dt_tz))


import re
import pandas as pd

dataset = pd.read_csv(
    'log_data/access_log',
    sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
    engine='python',
    na_values='-',
    header=None,
    usecols=[0, 3, 4, 5, 6, 7, 8],
    names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
    converters={'time': parse_datetime,
                'request': parse_str,
                'status': int,
                'size': int,
                'referer': parse_str,
                'user_agent': parse_str})


print(dataset.info())

#Data Pre-processing 

from sklearn.preprocessing import LabelEncoder, StandardScaler
label = LabelEncoder()
sc = StandardScaler()

x =dataset
X = x.to_numpy()

ip = label.fit_transform(X[:,0])
date = label.fit_transform(X[:,1])
url = label.fit_transform(X[:,2])

df_ip = pd.DataFrame(ip, columns = ['IP'])
df_date = pd.DataFrame(date, columns = ['Date'])
df_url = pd.DataFrame(url, columns = ['URL'])

result = pd.concat([df_ip,df_date,df_url], axis = 1)

data_scaled = sc.fit_transform(result)
print(data_scaled)


################## Finding Right No of Clusters. ########################

##################### Using WCSS #######################

from sklearn.cluster import KMeans
import matplotlib.pyplot as plt

wcss =[]

for i in range(1,11):
    model = KMeans(n_clusters = i)
    model.fit(data_scaled)
    print('model with ',i,' clusters created....')
    w = model.inertia_
    wcss.append(w)


############ WCSS V/s No of Clusters : Effect of Elbow #########################

plt.plot(range(1,11), wcss, marker = 'o')


############## Model Train & Predict #################

from sklearn.cluster import KMeans

model = KMeans(n_clusters = 6)
model.fit(data_scaled)
pred = model.fit_predict(data_scaled)


######################### Visualizing the Cluster #########################

dataset = pd.DataFrame(data_scaled, columns = ['IP','Date','URL'])
dataset['Cluster No'] = pred
plt.scatter(dataset['IP'], dataset['Date'], c = dataset['Cluster No'])


map_ip = pd.concat([dataset['IP'], x['ip']], axis = 1)

#################### Function to find Suspicious IP #####################

def Freq_Counter(mylist, iplabel):
    freq = {}
    for item in mylist:
        if item in freq:
            freq[item] += 1
        else:
            freq[item] = 1
    max_freq = 0
    max_key = 0
    for key,value in freq.items():
        if value > max_freq:
            max_freq = value
            max_key = key
    return iplabel[mylist.index(max_key)]

################## Finding Suspicious IP #######################

res = Freq_Counter(map_ip['IP'].tolist(), map_ip['ip'].tolist())


######################## Storing Suspicious IP in a File ########################

file1 = open('suspicious_ip.txt', 'w')
file1.write(res)
file1.close()
