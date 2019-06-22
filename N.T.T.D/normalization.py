import base64
import os
import json
from tabulate import tabulate
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn import preprocessing
from scipy.stats.stats import pearsonr

# from featureSelection import *


'''
Global save Boolean Value, if true will save 'mean' and 'ds' values to file
change to "True" if new data set is trained on the model.
'''
SAVE_zscore = False

'''
Global save Boolean Value, if true will save the label encoder
change to "True" if new data set is trained on the model.
'''
SAVE_test_index = False
'''

Global save Boolean value, if true will update feature file
change to "True" if new feature added to the training set
'''
SAVE_features = False

'''
List of Features to extract from the data set
'''
Features = ['sport', 'dport', 'proto', 'dur', 'dbytes', 'sttl', 'dttl',
            'dloss', 'sloss', 'service', 'Spkts', 'Dpkts', 'swin', 'dwin',
            'smeansz', 'dmeansz', 'synack', 'ackdat', 'is_sm_ips_ports', 'Label']

'''
test without: 
'stcpb', 'dtcpb',
'''


# Plot a confusion matrix.
# cm is the confusion matrix, names are the names of the classes.
def plot_confusion_matrix(cm, names, title='Confusion matrix', cmap=plt.cm.Blues):
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(names))
    plt.xticks(tick_marks, names, rotation=45)
    plt.yticks(tick_marks, names)
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')


# Encode text values to dummy variables(i.e. [1,0,0],[0,1,0],[0,0,1] for red,green,blue)
def encode_text_dummy(df, name):
    dummies = pd.get_dummies(df[name])
    for x in dummies.columns:
        dummy_name = f"{name}-{x}"
        df[dummy_name] = dummies[x]
    df.drop(name, axis=1, inplace=True)


# Encode text values to a single dummy variable.  The new columns (which do not replace the old) will have a 1
# at every location where the original column (name) matches each of the target_values.  One column is added for
# each target value.
def encode_text_single_dummy(df, name, target_values):
    for tv in target_values:
        l = list(df[name].astype(str))
        l = [1 if str(x) == str(tv) else 0 for x in l]
        name2 = f"{name}-{tv}"
        df[name2] = l


# Encode text values to indexes(i.e. [1],[2],[3] for red,green,blue).
def encode_text_index(df, name, main=None):
    newOutcome = []
    if main is not None:
        for other in df[name]:
            if other != main:
                newOutcome.append("other")
            else:
                newOutcome.append(main)
        df[name] = newOutcome
    le = preprocessing.LabelEncoder()
    le.fit(df[name])

    if SAVE_test_index:
        with open('text_index.json', 'r+') as read:
            try:
                load = json.load(read)
            except:
                load = {}
        with open('text_index.json', 'w+') as text_index:
            load[name] = {'le': le.classes_.tolist()}
            json.dump(load,text_index)

    df[name] = le.transform(df[name])
    return le.classes_


# Encode a numeric column as zscores
def encode_numeric_zscore(df, name, mean=None, sd=None):
    if mean is None:
        df[name] = df[name].map(lambda x: int(x, 16) if type(x) == str else x)
        mean = df[name].mean()

    if sd is None:
        sd = df[name].std()

    df[name] = (df[name] - mean) / sd
    if SAVE_zscore:
        with open('zscore.json', 'r+') as read:
            try:
                load = json.load(read)
            except:
                load = {}
        with open('zscore.json', 'w+') as zscore:
            load[name] = {'mean': mean, 'sd': sd}
            json.dump(load, zscore)


# Convert all missing values in the specified column to the median
def missing_median(df, name):
    med = df[name].median()
    df[name] = df[name].fillna(med)


# Convert all missing values in the specified column to the default
def missing_default(df, name, default_value):
    df[name] = df[name].fillna(default_value)


# Convert a Pandas dataframe to the x,y inputs that TensorFlow needs
def to_xy(df, target):
    result = []
    for x in df.columns:
        if x != target:
            result.append(x)
    # find out the type of the target column.
    target_type = df[target].dtypes
    target_type = target_type[0] if hasattr(
        target_type, '__iter__') else target_type
    # Encode to int for classification, float otherwise. TensorFlow likes 32 bits.
    if target_type in (np.int64, np.int32):
        # Classification
        dummies = pd.get_dummies(df[target])
        return df[result].values.astype(np.float32), dummies.values.astype(np.float32)
    # Regression
    return df[result].values.astype(np.float32), df[[target]].values.astype(np.float32)


# Nicely formatted time string
def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60
    return f"{h}:{m:>02}:{s:>05.2f}"


# Regression chart.
def chart_regression(pred, y, sort=True):
    t = pd.DataFrame({'pred': pred, 'y': y.flatten()})
    if sort:
        t.sort_values(by=['y'], inplace=True)
    plt.plot(t['y'].tolist(), label='expected')
    plt.plot(t['pred'].tolist(), label='prediction')
    plt.ylabel('output')
    plt.legend()
    plt.show()


# Remove all rows where the specified column is +/- sd standard deviations
def remove_outliers(df, name, sd):
    drop_rows = df.index[(np.abs(df[name] - df[name].mean())
                          >= (sd * df[name].std()))]
    df.drop(drop_rows, axis=0, inplace=True)


# Encode a column to a range between normalized_low and normalized_high.
def encode_numeric_range(df, name, normalized_low=-1, normalized_high=1,
                         data_low=None, data_high=None):
    if data_low is None:
        data_low = min(df[name])
        data_high = max(df[name])

    df[name] = ((df[name] - data_low) / (data_high - data_low)) \
               * (normalized_high - normalized_low) + normalized_low


##################################################################################################################################################
##################################################################################################################################################
##################################################################################################################################################
##################################################################################################################################################



class NormalizedDF:
    dfGlobal = pd.read_csv(
        "D:/training set/UNSW-NB15/UNSW-NB15_1.csv",
        header=None)
    dfGlobal.columns = ['srcip',
                        'sport',
                        'dstip',
                        'dport',
                        'proto',
                        'state',
                        'dur',
                        'sbytes',
                        'dbytes',
                        'sttl',
                        'dttl',
                        'sloss',
                        'dloss',
                        'service',
                        'Sload',
                        'Dload',
                        'Spkts',
                        'Dpkts',
                        'swin',
                        'dwin',
                        'stcpb',
                        'dtcpb',
                        'smeansz',
                        'dmeansz',
                        'trans_depth',
                        'res_bdy_len',
                        'Sjit',
                        'Djit',
                        'Stime',
                        'Ltime',
                        'Sintpkt',
                        'Dintpkt',
                        'tcprtt',
                        'synack',
                        'ackdat',
                        'is_sm_ips_ports',
                        'ct_state_ttl',
                        'ct_flw_http_mthd',
                        'is_ftp_login',
                        'ct_ftp_cmd',
                        'ct_srv_src',
                        'ct_srv_dst',
                        'ct_dst_ltm',
                        'ct_src_ ltm',
                        'ct_src_dport_ltm',
                        'ct_dst_sport_ltm',
                        'ct_dst_src_ltm',
                        'attack_cat',
                        'Label']

    '''
    df.drop(['srcip','dstip','state','Sload','Dload','trans_depth','res_bdy_len','Sjit','Djit'
             ,'Stime','Ltime','Sintpkt','Dintpkt'], axis = 1)
    '''

    dfGlobal.drop(dfGlobal.columns.difference(Features), 1,
                  inplace=True)
    if SAVE_features:
        with open('feature_set.json', 'w+') as update:
            load = Features
            json.dump(load, update)

    dfGlobal = dfGlobal.drop(
        dfGlobal[~((dfGlobal.proto == 'udp') | (dfGlobal.proto == 'tcp') | (dfGlobal.proto == 'icmp'))].index)
    dfGlobal = dfGlobal.drop(dfGlobal[(dfGlobal.sport == '-') | (dfGlobal.sport == '') | (dfGlobal.dport == '-') | (
                dfGlobal.dport == '')].index)
    dfGlobal.drop_duplicates()

    def __init__(self):
        self.df = NormalizedDF.dfGlobal.copy()
        self.normolize = False

    def getNormalizeDF(self):
        if not self.normolize:
            self._normalize()
        return self.df

    def _normalize(self):
        if not self.normolize:
            encode_numeric_zscore(self.df, 'sport')
            encode_numeric_zscore(self.df, 'dport')
            encode_text_dummy(self.df, 'proto')
            encode_numeric_zscore(self.df, 'dur')
            encode_numeric_zscore(self.df, 'sttl')
            encode_numeric_zscore(self.df, 'dttl')
            encode_numeric_zscore(self.df, 'dloss')
            encode_numeric_zscore(self.df, 'sloss')
            encode_text_index(self.df, 'service')
            encode_numeric_zscore(self.df, 'Spkts')
            encode_numeric_zscore(self.df, 'Dpkts')
            encode_numeric_zscore(self.df, 'dbytes')

            # ---- ##
            encode_numeric_zscore(self.df, 'swin')
            encode_numeric_zscore(self.df, 'dwin')
           # encode_numeric_zscore(self.df, 'stcpb')
           # encode_numeric_zscore(self.df, 'dtcpb')

            encode_numeric_zscore(self.df, 'smeansz')
            encode_numeric_zscore(self.df, 'dmeansz')

            encode_numeric_zscore(self.df, 'synack')
            encode_numeric_zscore(self.df, 'ackdat')

            self.normolize = True

    def getNormalizeXY(self, prc=0):
        if not self.normolize:
            self.getNormalizeDF()
        if prc:
            return to_xy(self.df.sample(frac=prc, replace=True, random_state=1), 'Label')
        return to_xy(self.df, 'Label')

    @staticmethod
    def updateDataSet(path="D:/training set/UNSW-NB15/UNSW-NB15_1.csv"):

        dfGlobal = pd.read_csv(path, header=None)
        dfGlobal.columns = ['srcip',
                            'sport',
                            'dstip',
                            'dport',
                            'proto',
                            'state',
                            'dur',
                            'sbytes',
                            'dbytes',
                            'sttl',
                            'dttl',
                            'sloss',
                            'dloss',
                            'service',
                            'Sload',
                            'Dload',
                            'Spkts',
                            'Dpkts',
                            'swin',
                            'dwin',
                            'stcpb',
                            'dtcpb',
                            'smeansz',
                            'dmeansz',
                            'trans_depth',
                            'res_bdy_len',
                            'Sjit',
                            'Djit',
                            'Stime',
                            'Ltime',
                            'Sintpkt',
                            'Dintpkt',
                            'tcprtt',
                            'synack',
                            'ackdat',
                            'is_sm_ips_ports',
                            'ct_state_ttl',
                            'ct_flw_http_mthd',
                            'is_ftp_login',
                            'ct_ftp_cmd',
                            'ct_srv_src',
                            'ct_srv_dst',
                            'ct_dst_ltm',
                            'ct_src_ ltm',
                            'ct_src_dport_ltm',
                            'ct_dst_sport_ltm',
                            'ct_dst_src_ltm',
                            'attack_cat',
                            'Label']

        '''
        df.drop(['srcip','dstip','state','Sload','Dload','trans_depth','res_bdy_len','Sjit','Djit'
                 ,'Stime','Ltime','Sintpkt','Dintpkt'], axis = 1)
        '''

        dfGlobal.drop(dfGlobal.columns.difference(Features), 1, inplace=True)

        dfGlobal = dfGlobal.drop(
            dfGlobal[~((dfGlobal.proto == 'udp') | (dfGlobal.proto == 'tcp') | (dfGlobal.proto == 'icmp'))].index)
        try:
            dfGlobal = dfGlobal.drop(dfGlobal[
                                         (dfGlobal.sport == '-') | (dfGlobal.sport == '') | (dfGlobal.dport == '-') | (
                                                     dfGlobal.dport == '')].index)
        except TypeError as e:
            print(e)
        dfGlobal.drop_duplicates()

        NormalizedDF.dfGlobal = pd.concat([NormalizedDF.dfGlobal, dfGlobal])


def main():
    # test = NormalizedDF()
    # print(tabulate(test.df[:30], headers='keys', tablefmt='psql'))
    # test.getNormalizeDF()
    # print(tabulate(test.df[:30], headers='keys', tablefmt='psql'))
    NormalizedDF.updateDataSet("D:/training set/UNSW-NB15/UNSW-NB15_2.csv")
    # test2 = NormalizedDF()
    # print(tabulate(test2.df[:30], headers='keys', tablefmt='psql'))
    # test2.getNormalizeDF()
    # print(tabulate(test2.df[:30], headers='keys', tablefmt='psql'))
    NormalizedDF.updateDataSet("D:/training set/UNSW-NB15/UNSW-NB15_3.csv")
    # test3 = NormalizedDF()
    # print(tabulate(test2.df[:30], headers='keys', tablefmt='psql'))
    # test3.getNormalizeDF()
    # print(tabulate(test2.df[:30], headers='keys', tablefmt='psql'))
    NormalizedDF.updateDataSet("D:/training set/UNSW-NB15/UNSW-NB15_4.csv")
    test4 = NormalizedDF()
    # print(tabulate(test2.df[:30], headers='keys', tablefmt='psql'))
    test4.getNormalizeDF()
    print(tabulate(test4.df[:30], headers='keys', tablefmt='psql'))
    return test4


if __name__ == '__main__':
    main()
