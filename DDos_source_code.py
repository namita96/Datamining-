#!/usr/bin/env python
# coding: utf-8

# In[5]:


import pandas as pd 
import numpy as np
import pickle
import math
import sklearn.ensemble
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split 
from sklearn.metrics import classification_report, confusion_matrix  
from sklearn.model_selection import KFold, cross_val_score
from sklearn import model_selection, preprocessing
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC, LinearSVC
get_ipython().run_line_magic('matplotlib', 'inline')
from matplotlib import pyplot as plt
from matplotlib import style


# In[6]:


# Reading the  csv file and converting it into a dataframe

data = pd.read_csv(r'C:\Users\Namita\Desktop\DDOS\CSV-03-11\03-11\LDAP.csv',low_memory = False)

labels = data.values[:,-1]
data1 = data.values[:,:-1]
#data1.insert(0, data.columns.to_list())
Lables = [x for x in labels if str(x) != 'nan']

newlist = []
for item in Lables:
    if item == 'BENIGN':
        item = 0
    else:
        item = 1
    newlist.append(item)
Lables = newlist
Data = [row for row in data1 if not pd.isnull(row).all()]
len(Data)

df3 = pd.DataFrame(Data)

df3.columns = ['Unnamed','Flow ID','Source IP','Source Port','Destination IP','Destination Port','Protocol','Timestamp','Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std','Bwd Packet Length Max','Bwd Packet Length Min','Bwd Packet Length Mean','Bwd Packet Length Std','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Header Length','Bwd Header Length','Fwd Packets/s','Bwd Packets/s','Min Packet Length','Max Packet Length','Packet Length Mean','Packet Length Std','Packet Length Variance','FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count','ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count','Down/Up Ratio','Average Packet Size','Avg Fwd Segment Size','Avg Bwd Segment Size','Fwd Header Length.1','Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate','Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate','Subflow Fwd Packets','Subflow Fwd Bytes','Subflow Bwd Packets','Subflow Bwd Bytes','Init_Win_bytes_forward','Init_Win_bytes_backward','act_data_pkt_fwd','min_seg_size_forward','Active Mean','Active Std','Active Max','Active Min','Idle Min','Idle Std','Idle Max','Idle Min','SimillarHTTP','Inbound'
]

df3['Label'] = Lables

df3.shape

df3.head(10)


# In[7]:


# dropping the columns with constant value and removing of nan values

df3 = df3.loc[:, (df3 != 0).any()] 
 # dropping out columns which have contsant value = 0
df3 = df3.drop(['Unnamed','Flow ID','Source IP','Destination IP','Protocol','Timestamp','Source Port','Destination Port'], axis = 1) 

df3 = df3.dropna()
df3.shape


# In[8]:


df3.head(5)


# In[9]:


# Apply label encoding to columns to convert strings to numeric values
for column in df3.columns:
    
        le = LabelEncoder()
        
        df3['Flow Bytes/s'] = le.fit_transform(df3['Flow Bytes/s'])
        df3['Flow Packets/s'] = le.fit_transform(df3['Flow Packets/s'])
        df3['SimillarHTTP'] = le.fit_transform(df3['SimillarHTTP'])
        
        
     
df3.head(5)


# In[11]:


#plot the correlation matrix

import seaborn as sns

corr = df3.corr()
ax = sns.heatmap(
    corr, 
    vmin=-1, vmax=1, center=0,
    cmap=sns.diverging_palette(40, 250, n=250),
    square=True
)
ax.set_xticklabels(
    ax.get_xticklabels(),
    rotation=80,
    horizontalalignment='right'
);


# In[12]:


#K fold precprocessing - unbalanced dataset

X = df3.drop('Label',axis=1)
#print(X)
y = df3['Label']

scaler = StandardScaler()
X = scaler.fit_transform(X)

kf = KFold(n_splits=5)
    
KFold(n_splits=5, random_state=None, shuffle=False)
for train_index, test_index in kf.split(X):
     print("TRAIN:", train_index, "TEST:", test_index)
     X_train, X_valid = X[train_index], X[test_index]
     y_train, y_valid = y.iloc[train_index], y.iloc[test_index]
        

encoder = preprocessing.LabelEncoder()
y_train = encoder.fit_transform(y_train)
y_valid = encoder.fit_transform(y_valid)
y_valid = y_valid.reshape(-1, 1)
 
#random forest
random_forest = RandomForestClassifier(n_estimators= 20, max_depth=30, max_features='sqrt',
                                       min_samples_leaf=5, min_samples_split=25, 
                                       random_state=1, verbose=1, n_jobs=2)


random_forest.fit(X_train, y_train)
pred_probs = random_forest.predict(X_valid)
print("For Random forest:", pred_probs)

accuracy =  model_selection.cross_val_score(random_forest,y_valid,pred_probs, scoring='accuracy', cv= 5)
print ("Accuracy: " +'%.4f' % (np.mean(accuracy)))
print(confusion_matrix(y_valid,pred_probs)) 
print(classification_report(y_valid,pred_probs))


# In[ ]:


#Converting an unbalanced dataset to balanced dataset


# In[13]:


from imblearn import under_sampling, over_sampling
from imblearn.under_sampling import RandomUnderSampler

rus = RandomUnderSampler(random_state=42)
X_res, y_res = rus.fit_resample(X, y)
y_res.value_counts()


# In[ ]:


#Use train and test method to split the data as traing and test data


# In[52]:


from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize
from sklearn.metrics import roc_auc_score
from sklearn.metrics import roc_curve, auc
import sklearn.metrics as metrics
scaler = StandardScaler()
X_res = scaler.fit_transform(X_res)

X_train, X_valid, y_train, y_valid = train_test_split(X_res, y_res, test_size=0.33, random_state=42)
        

encoder = preprocessing.LabelEncoder()
y_train = encoder.fit_transform(y_train)
y_valid = encoder.fit_transform(y_valid)
y_valid = y_valid.reshape(-1, 1)
 
#random forest model 
random_forest = RandomForestClassifier(n_estimators=5, max_depth= 20, max_features='sqrt',
                                       min_samples_leaf=5, min_samples_split= 10, 
                                       random_state=1, verbose=1, n_jobs=2)


random_forest.fit(X_train, y_train)
pred_probs = random_forest.predict(X_valid)
print("For Random forest:", pred_probs)
#Test data accuracy value
accuracy =  model_selection.cross_val_score(random_forest,y_valid,pred_probs, scoring='accuracy')
print ("Accuracy: " +'%.4f' % (np.mean(accuracy)))
print(confusion_matrix(y_valid,pred_probs)) 
print(classification_report(y_valid,pred_probs))
f1 = model_selection.cross_val_score(random_forest,y_valid,pred_probs, scoring='f1_weighted')
print ("F1: " +'%.4f' % (np.mean(f1)))
precision = model_selection.cross_val_score(random_forest,y_valid,pred_probs, scoring='precision_weighted')
print ("Precision: " +'%.4f' % (np.mean(precision)))
recall = model_selection.cross_val_score(random_forest,y_valid,pred_probs, scoring='recall_weighted')
print ("Recall: " +'%.4f' % (np.mean(recall))  )


#Plot the roc graph
fpr, tpr, threshold = metrics.roc_curve(y_valid, pred_probs)
roc_auc = metrics.auc(fpr, tpr)

plt.title('Receiver Operating Characteristic')
plt.plot(fpr, tpr, 'b', label = 'ROC = %0.2f' % roc_auc)
plt.legend(loc = 'lower right')
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0, 1])
plt.ylim([0, 1])
plt.ylabel('True Positive Rate')
plt.xlabel('False Positive Rate')
plt.show()


# In[53]:



#KNN classifier
knn = KNeighborsClassifier(n_neighbors = 5)
knn.fit(X_train, y_train)
pred_kprobs = knn.predict(X_valid)
print("For KNN:", pred_kprobs)

#test accuracy
accuracy =  model_selection.cross_val_score(knn,y_valid,pred_kprobs, scoring='accuracy')
print (" Accuracy for KNN: " +'%.4f' % (np.mean(accuracy)))
print(confusion_matrix(y_valid,pred_kprobs)) 
print(classification_report(y_valid,pred_kprobs))
f1 = model_selection.cross_val_score(knn,y_valid,pred_kprobs, scoring='f1_weighted')
print ("F1: " +'%.4f' % (np.mean(f1)))
precision = model_selection.cross_val_score(knn,y_valid,pred_kprobs, scoring='precision_weighted')
print ("Precision: " +'%.4f' % (np.mean(precision)))
recall = model_selection.cross_val_score(knn,y_valid,pred_kprobs, scoring='recall_weighted')


#plot the ROC graph
fpr, tpr, threshold = metrics.roc_curve(y_valid, pred_kprobs)
roc_auc = metrics.auc(fpr, tpr)

plt.title('Receiver Operating Characteristic')
plt.plot(fpr, tpr, 'b', label = 'ROC= %0.2f' % roc_auc)
plt.legend(loc = 'lower right')
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0, 1])
plt.ylim([0, 1])
plt.ylabel('True Positive Rate')
plt.xlabel('False Positive Rate')
plt.show()


# In[54]:



#svm classifier
svclassifier = SVC(gamma='auto', C=100, kernel='poly')  
model = svclassifier.fit(X_train, y_train)
y_pred = svclassifier.predict(X_valid) 

print("For SVM :", y_pred)

#Test accurcay
accuracy =  model_selection.cross_val_score(svclassifier,y_valid,y_pred, scoring='accuracy')
print ("Accuracy: " +'%.4f' % (np.mean(accuracy)))
print(confusion_matrix(y_valid,y_pred)) 
print(classification_report(y_valid,y_pred))
f1 = model_selection.cross_val_score(svclassifier,y_valid,y_pred, scoring='f1_weighted')
print ("F1: " +'%.4f' % (np.mean(f1)))
precision = model_selection.cross_val_score(svclassifier, y_valid,y_pred, scoring='precision_weighted')
print ("Precision: " +'%.4f' % (np.mean(precision)))
recall = model_selection.cross_val_score(svclassifier, y_valid,y_pred, scoring='recall_weighted')
print ("Recall: " +'%.4f' % (np.mean(recall))  )


#plot the roc graph

fpr, tpr, threshold = metrics.roc_curve(y_valid, y_pred)
roc_auc = metrics.auc(fpr, tpr)

plt.title('Receiver Operating Characteristic')
plt.plot(fpr, tpr, 'b', label = 'ROC= %0.2f' % roc_auc)
plt.legend(loc = 'lower right')
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0, 1])
plt.ylim([0, 1])
plt.ylabel('True Positive Rate')
plt.xlabel('False Positive Rate')
plt.show()


# In[55]:


#Naive Bayes

from sklearn.naive_bayes import GaussianNB
nb = GaussianNB()
nb.fit(X_train, y_train)

y_pred_class = nb.predict(X_valid)
print( "For Navies Bayes:",y_pred_class)


# Test the accuracy
accuracy =  model_selection.cross_val_score(nb,y_valid,y_pred_class, scoring='accuracy')
print ("Accuracy: " +'%.4f' % (np.mean(accuracy)))
print(confusion_matrix(y_valid,y_pred_class)) 
print(classification_report(y_valid,y_pred_class))
f1 = model_selection.cross_val_score(nb,y_valid,y_pred_class, scoring='f1_weighted')
print ("F1: " +'%.4f' % (np.mean(f1)))
precision = model_selection.cross_val_score(nb,y_valid,y_pred_class,scoring='precision_weighted')
print ("Precision: " +'%.4f' % (np.mean(precision)))
recall =model_selection.cross_val_score(nb,y_valid,y_pred_class,scoring='recall_weighted')
print ("Recall: " +'%.4f' % (np.mean(recall))  )

#Plot the roc graph
fpr, tpr, threshold = metrics.roc_curve(y_valid, y_pred_class)
roc_auc = metrics.auc(fpr, tpr)

plt.title('Receiver Operating Characteristic')
plt.plot(fpr, tpr, 'b', label = 'ROC= %0.2f' % roc_auc)
plt.legend(loc = 'lower right')
plt.plot([0, 1], [0, 1],'r--')
plt.xlim([0, 1])
plt.ylim([0, 1])
plt.ylabel('True Positive Rate')
plt.xlabel('False Positive Rate')
plt.show()


# In[ ]:




