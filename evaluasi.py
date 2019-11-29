import pandas as pd
import numpy as np
from sklearn.model_selection import KFold
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report
from termcolor import colored


dataset = pd.read_csv('data_training.csv')

x = dataset.drop('Result', axis=1)
y = dataset['Result']

scaler = MinMaxScaler(feature_range=(-1, 1))
x = scaler.fit_transform(x)

scoresl = []
scoresp = []
scoresr = []
scoresDT = []
scoresKNN = []

cv = KFold(n_splits=10, random_state=42, shuffle=True)

print(colored('\n SUPPORT VECTOR MACHINE (SVM)', attrs=['bold']))
print(colored(' Linear:', attrs=['bold']))
cl = input(' C  : ')
cl_input = float(cl)
cSVMl = SVC(kernel='linear', C=cl_input)
print(colored(' ---------------------------------------------------', attrs=['bold']))
for train_index, test_index in cv.split(x):
    print(" Train 	: ", train_index)
    print(" Test 	: ", test_index)

    x_train, x_test, y_train, y_test = x[train_index], x[test_index], y[train_index], y[test_index]
    cSVMl.fit(x_train, y_train)
    Y_SVMl = cSVMl.predict(x_test)
    skorl = cSVMl.score(x_test, y_test)*100
    print(" Score 	:  [%.2f" % skorl, "%]")
    scoresl.append(skorl)
    cmlinear = confusion_matrix(y_test, Y_SVMl)
    print('', cmlinear)

akurasi_SVMl = np.mean(scoresl)
print(" Akurasi:  [%.2f" % akurasi_SVMl, "%]")

print(colored('\n Polynomial:', attrs=['bold']))
degree = input(' Degree : ')
degree_input = float(degree)
cp = input(' C 	: ')
cp_input = float(cp)
cSVMp = SVC(kernel='poly', gamma='scale', degree=degree_input, C=cp_input)
print(colored(' ---------------------------------------------------', attrs=['bold']))
for train_index, test_index in cv.split(x):
    print(" Train 	: ", train_index)
    print(" Test 	: ", test_index)

    x_train, x_test, y_train, y_test = x[train_index], x[test_index], y[train_index], y[test_index]
    cSVMp.fit(x_train, y_train)
    Y_SVMp = cSVMp.predict(x_test)
    skorp = cSVMp.score(x_test, y_test)*100
    print(" Score 	:  [%.2f" % skorp, "%]")
    scoresp.append(skorp)
    cmpoly = confusion_matrix(y_test, Y_SVMp)
    print('', cmpoly)

akurasi_SVMp = np.mean(scoresp)
print(" Akurasi:  [%.2f" % akurasi_SVMp, "%]")

print(colored('\n RBF:', attrs=['bold']))
gamma = input(' Gamma 	: ')
gamma_input = float(gamma)
cr = input(' C 	: ')
cr_input = float(cr)
cSVMr = SVC(kernel='rbf', gamma=gamma_input, C=cr_input)
print(colored(' ---------------------------------------------------', attrs=['bold']))
for train_index, test_index in cv.split(x):
    print(" Train 	: ", train_index)
    print(" Test 	: ", test_index)

    x_train, x_test, y_train, y_test = x[train_index], x[test_index], y[train_index], y[test_index]
    cSVMr.fit(x_train, y_train)
    Y_SVMr = cSVMr.predict(x_test)
    skorr = cSVMr.score(x_test, y_test)*100
    print(" Score 	:  [%.2f" % skorr, "%]")
    scoresr.append(skorr)
    cmrbf = confusion_matrix(y_test, Y_SVMr)
    print('', cmrbf)

akurasi_SVMr = np.mean(scoresr)
print(" Akurasi:  [%.2f" % akurasi_SVMr, "%]")

print(colored('\n DECISION TREE', attrs=['bold']))
print(colored(' *criterion = gini / entropy', 'grey'))
print(colored(' *max depth = integer', 'grey'))
criterion = input(' Criterion   : ')
criterion_input = str(criterion)
max_depth = input(' Max Depth   : ')
max_depth_input = int(max_depth)
cDT = DecisionTreeClassifier(criterion=criterion_input, max_depth=max_depth_input)
print(colored(' ---------------------------------------------------', attrs=['bold']))
for train_index, test_index in cv.split(x):
    print(" Train   : ", train_index)
    print(" Test    : ", test_index)

    x_train, x_test, y_train, y_test = x[train_index], x[test_index], y[train_index], y[test_index]
    cDT.fit(x_train, y_train)
    Y_DT = cDT.predict(x_test)
    skorDT = cDT.score(x_test, y_test)*100
    print(" Score   :  [%.2f" % skorDT, "%]")
    scoresDT.append(skorDT)
    cmDT = confusion_matrix(y_test, Y_DT)
    print('', cmDT)

akurasi_DT = np.mean(scoresDT)
print(" Akurasi:  [%.2f" % akurasi_DT, "%]")

print(colored('\n K-NEAREST NEIGHBORS', attrs=['bold']))
print(colored(' *weights     = uniform / distance', 'grey'))
print(colored(' *n_neighbors = integer', 'grey'))
weights = input(' Weights       : ')
weights_input = str(weights)
n_neighbors = input(' N Neighbors   : ')
n_neighbors_input = int(n_neighbors)
cKNN = KNeighborsClassifier(weights=weights_input, n_neighbors=n_neighbors_input)
print(colored(' ---------------------------------------------------', attrs=['bold']))
for train_index, test_index in cv.split(x):
    print(" Train   : ", train_index)
    print(" Test    : ", test_index)

    x_train, x_test, y_train, y_test = x[train_index], x[test_index], y[train_index], y[test_index]
    cKNN.fit(x_train, y_train)
    Y_KNN = cKNN.predict(x_test)
    skorKNN = cKNN.score(x_test, y_test)*100
    print(" Score   :  [%.2f" % skorKNN, "%]")
    scoresKNN.append(skorKNN)
    cmKNN = confusion_matrix(y_test, Y_KNN)
    print('', cmKNN)

akurasi_KNN = np.mean(scoresKNN)
print(" Akurasi:  [%.2f" % akurasi_KNN, "%]")

print(colored('\n AKURASI :', attrs=['bold']))
print(" Akurasi SVM : %.2f, %.2f, %.2f" %(akurasi_SVMl,akurasi_SVMp,akurasi_SVMr), "%")
print(" Akurasi DT  : %.2f" % akurasi_DT, "%")
print(" Akurasi KNN : %.2f" % akurasi_KNN, "%")