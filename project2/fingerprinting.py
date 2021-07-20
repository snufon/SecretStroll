import numpy as np
import pandas as pd
from scapy.all import *
from statistics import mean, stdev

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold


def classify(train_features, train_labels, test_features, test_labels, n_estimators = 100):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier(n_estimators, criterion = "entropy")
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

def perform_crossval(features, labels, folds=10, nb_estimators = 100):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    accurcacies = []

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test, nb_estimators)
        accuracy = (y_test == predictions)
        accuracy = accuracy.sum()/len(accuracy)

        accurcacies.append(accuracy)

    return mean(accurcacies)


directory = r'captured_traffic_full/'

def excract_features(cell,capture):
    file_name = directory + 'captured_' + str(cell) + '_' + str(capture)
    f = rdpcap(file_name)
    
    bytes_sent = 0
    start_time = f[0].time
    end_time = f[len(f) - 1].time
    
    prev_time = start_time

    time_between_packets = []
    
    for pkt in f:
            if pkt['Ethernet'].type == 2048:
                if pkt['IP'].len > 54:
                    next_time = pkt.time
                    bytes_sent += pkt['IP'].len
                    time_between_packets.append(next_time-prev_time)
                    prev_time = next_time
    
    #returns all the features: number of packets, time taken for the query, bytes sent by the server, mean and std time between packets
    return len(f), float(end_time-start_time), float(bytes_sent), float(mean(time_between_packets)), float(stdev(time_between_packets)), cell

def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    ###############################################
    # TODO: Complete this function. 
    ###############################################

    data_set = pd.DataFrame(columns = ["Number packets", "Total time", "Bytes Sent by Server", "Average Time Between Packets", "Std Time Between Packets", "Cell"])

    i = 0
    for cell in range(1,101):
        for capture in range(1,21):
            data_set.loc[i] = list(excract_features(cell,capture))
            i += 1


    return data_set
        
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    try:
        data_set = pd.read_csv("fingerprinting.csv", index_col = "Unnamed: 0")
    except Exception as e:
        data_set = load_data()
        data_set.to_csv("fingerprinting.csv")

    features = data_set[["Number packets", "Total time", "Bytes Sent by Server", "Average Time Between Packets", "Std Time Between Packets"]].to_numpy()
    labels = data_set["Cell"].to_numpy()

    nb_estimators = [10,20,50,80,100,200,300]
    mean_accuracy = []
    for n in nb_estimators:
        print("---Random Forest using ", n, " estimators---")
        accuracy = perform_crossval(features, labels, folds=10, nb_estimators = n)
        mean_accuracy.append(accuracy)
        print("Accuracy of model: ", accuracy*100,"%")
    max_accuracy = max(mean_accuracy)
    best_nb_estimators_index = mean_accuracy.index(max_accuracy)
    best_nb_estimators = nb_estimators[best_nb_estimators_index]
    print("---Best number of estimators: ", best_nb_estimators, " estimators")


    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)