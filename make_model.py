import numpy as np
import pandas as pd
from sklearn.svm import SVC
import pickle
from sklearn.feature_selection import SelectFromModel
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2

x = pd.read_csv('data_training.csv')
a = np.array(x)
y = a[:,16]

x = np.column_stack((x.having_IP_Address, x.URL_Length, x.Shortining_Service, x.having_At_Symbol, x.double_slash_redirecting, x.Prefix_Suffix, x.having_Sub_Domain, x.Domain_registeration_length, x.HTTPS_token, x.Submitting_to_email, x.RightClick, x.Iframe, x.age_of_domain, x.DNSRecord, x.web_traffic, x.Statistical_report))

cSVMl = SVC(kernel='linear')
cSVMl.fit(x, y)
model_namel = 'model_l.sav'
pickle.dump(cSVMl, open(model_namel, 'wb'))
print(' Model SVM Linear Successful')

cSVMp = SVC(kernel='poly', gamma='scale', degree=7, C=5.0)
cSVMp.fit(x, y)
model_namep = 'model_p.sav'
pickle.dump(cSVMp, open(model_namep, 'wb'))
print(' Model SVM Polynomial Successful')

cSVMr = SVC(kernel='rbf', gamma=0.3, C=5.0)
cSVMr.fit(x, y)
model_namer = 'model_r.sav'
pickle.dump(cSVMr, open(model_namer, 'wb'))
print(' Model SVM RBF Successful')


