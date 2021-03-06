from flows import PriorityFlows, Packet

import pyshark
import os
from keras.models import Sequential
from keras.layers.core import Dense, Activation, Dropout
from keras.callbacks import EarlyStopping
from keras.callbacks import ModelCheckpoint
import numpy as np

'''
Global var to switch test and real time use mode
'''
test_on = True


class Machine:
    def __init__(self, inputShape={'x': 0, 'y': 0}):
        self.inputShape = inputShape
        self.model = Sequential()
        self.model.add(Dense(10, input_dim=inputShape['x'], kernel_initializer='normal', activation='elu'))
        self.model.add(Dropout(0.1))
        self.model.add(Dense(50, kernel_initializer='normal', activation='elu'))
        self.model.add(Dropout(0.3))
        self.model.add(Dense(10, kernel_initializer='normal', activation='relu'))
        self.model.add(Dropout(0.1))
        self.model.add(Dense(1, kernel_initializer='normal'))
        self.model.compile(loss='categorical_crossentropy', optimizer='adam')
        self.model.add(Dense(inputShape['y'], activation='softmax'))
        self.load_weights('best_weights.hdf5')

    def load_weights(self, weights):
        self.model.load_weights(weights)

    def predict(self, packetAttribute):
        x = packetAttribute
        return self.model.predict(packetAttribute)


def main():
    flowList = PriorityFlows()
    model = Machine({'x': flowList.input_shape, 'y': flowList.output_shape})

    cap = pyshark.LiveCapture(bpf_filter="(ip || icmp) and (udp || tcp)")

    # counter = 0
    print("Starting")
    if cap is not None:
        for capPacket in cap:
            badpacket = flowList + Packet(capPacket)
            predict = model.predict(flowList.getFeatures(badpacket[1]))
            predict_max = np.argmax(predict, axis=1)
            # print(badpacket[1],' predect: ',predict)
            if (badpacket[0]):
                # run through the machine no in suspect list
                if predict_max[0] == 1 and predict[0][1] >= 0.63 and flowList.getFlow(badpacket[1]).count > 20:
                    flowList.switchList(badpacket[1])
                    print("Warning suspiciuse activaty found: ", badpacket[1], ', predict: ', predict)

            else:
                if predict_max[0] == 0:
                    flowList.switchList(badpacket[1], True)  # << mabye will switch back to main flows
                    print("activaty : ", badpacket[1], " no longer suspiciuse, predict: ", predict)
    else:
        print("none")


def testpcap():
    flowList = PriorityFlows()
    model = Machine({'x': flowList.input_shape, 'y': flowList.output_shape})

    files = [os.path.join('D:\\training set\\UNSW-NB15\\PCAP\\pcap 17-2-2015', f) for f in
             os.listdir('D:\\training set\\UNSW-NB15\\PCAP\\pcap 17-2-2015') if
             os.path.isfile(os.path.join('D:\\training set\\UNSW-NB15\\PCAP\\pcap 17-2-2015', f))]
    for file in files:
        cap = pyshark.FileCapture(file, display_filter="(ip || icmp) and (udp || tcp)")

        if cap is not None:
            for capPacket in cap:
                badpacket = flowList + Packet(capPacket)
                predict = model.predict(flowList.getFeatures(badpacket[1]))
                predict_max = np.argmax(predict, axis=1)
                # print(badpacket[1],' predect: ',predict)
                if (badpacket[0]):
                    # run through the machine no in suspect list
                    if predict_max[0] == 1 and predict[0][1] >= 0.63:
                        flowList.switchList(badpacket[1])
                        print("Warning suspiciuse activaty found: ", badpacket[1], ', predict: ', predict)
                else:
                    if predict_max[0] == 0:
                        flowList.switchList(badpacket[1], True)  # << mabye will switch back to main flows
                        print("activaty : ", badpacket[1], " no longer suspiciuse, predict: ", predict)
        else:
            print("none")

    print('done')


if __name__ == "__main__":
    if test_on:
        testpcap()
    else:
        main()
