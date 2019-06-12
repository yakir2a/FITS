from flows import PriorityFlows, Packet

import pyshark
import os
from keras.models import Sequential
from keras.layers.core import Dense, Activation
from keras.callbacks import EarlyStopping
from keras.callbacks import ModelCheckpoint

'''
Global var to switch test and real time use mode
'''
test_on = True


class Machine:
    def __init__(self, inputShape={'x': 0, 'y': 0}):
        self.inputShape = inputShape
        self.model = Sequential()
        self.model.add(Dense(10, input_dim=inputShape['x'], kernel_initializer='normal', activation='relu'))
        self.model.add(Dense(50, kernel_initializer='normal', activation='relu'))
        self.model.add(Dense(10, kernel_initializer='normal', activation='relu'))
        self.model.add(Dense(1, kernel_initializer='normal'))
        self.model.add(Dense(inputShape['y'], activation='softmax'))

    def load_weights(self, weights):
        self.model.load_weights(weights)

    def predict(self, packetAttribute):
        return self.model.predict(packetAttribute)


def main():
    model = Machine()

    cap = pyshark.LiveCapture(bpf_filter="(ip || icmp) and (udp || tcp)")

    flowList = PriorityFlows()

    # counter = 0

    if cap is not None:
        for capPacket in cap:
            badpacket = flowList + Packet(capPacket)
            if (badpacket):
                # run through the machine no in suspect list
                if model.predict(flowList.getFeatures(badpacket[1])):
                    flowList.switchList(badpacket[1])
                    print("Warning suspiciuse activaty found: ", badpacket[1])
            else:
                if not model.predict(flowList.getFeatures(badpacket[1])):
                    flowList.switchList(badpacket[1])  # << mabye will switch back to main flows
                    print("activaty : ", badpacket[1], " no longer suspiciuse")
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
                if (badpacket):
                    # run through the machine no in suspect list
                    if model.predict(flowList.getFeatures(badpacket[1])):
                        flowList.switchList(badpacket[1])
                        print("Warning suspiciuse activaty found: ", badpacket[1])
                else:
                    if not model.predict(flowList.getFeatures(badpacket[1])):
                        flowList.switchList(badpacket[1])  # << mabye will switch back to main flows
                        print("activaty : ", badpacket[1], " no longer suspiciuse")
        else:
            print("none")


if __name__ == "__main__":
    if test_on:
        testpcap()
    else:
        main()
