import pyshark
from heapq import heapify, heappush, heappop
from collections import deque



class Packet():
    def __init__(self, packet):
        self.transport_protocol = packet.transport_layer
        self.time_delta = packet[self.transport_protocol].time_delta
        self.timestamp = packet.sniff_timestamp
        self.flowKey = ["{} {} {} {} {}".format(self.transport_protocol,packet.ip.src,packet.ip.dst,packet[self.transport_protocol].srcport,packet[self.transport_protocol].dstport),
                        "{} {} {} {} {}".format(self.transport_protocol,packet.ip.dst,packet.ip.src,packet[self.transport_protocol].dstport,packet[self.transport_protocol].srcport)]
        self.ip_layer = {'totalLength' : packet.ip.len, 'srcIp' : packet.ip.src, 'dstIp' : packet.ip.dst}
        self.transport_layer = {'srcPort' : packet[self.transport_protocol].srcport, 'dstPort' : packet[self.transport_protocol].dstport}
    '''
    
    need to add function for the ML input
    '''


class Flow:
    maxSize = 5000
    def __init__(self,packet):
        self.count = 1
        self.flow = deque([packet])
        self.lastPacket = packet
        self.average_delta = float(packet.time_delta)
        self.session_start = float(packet.timestamp)

    def getDelta(self):
        return self.flow[0].time_delta

    def addPacket(self,packet):
        self.flow.appendleft(packet)
        self.count = self.count + 1
        self.average_delta = self.calculateDetla(packet.time_delta)
        if self.count > Flow.maxSize:
            self.flow.pop()

    def calculateDetla(self,newDelta):
        return ((self.count * self.average_delta) + float(newDelta)) / self.count

    def sessionDuration(self):
        return float(self.flow[0].timestamp) - self.session_start


    def getTimestamp(self):
        return float(self.flow[0].timestamp)

    '''
    
    need to add statistic function for the ML input 
    '''

'''

hold all flows and organize them by priority
'''
class PriorityFlows:
    maxSize = 5000
    def __init__ (self, packet=None):
        self.count = 0
        if packet:
            flow = Flow(packet)
            self._flows = {packet.flowKey[0]: flow}
            self.count = 1
            self._rebuild_heap()
        else:
            self._flows = dict()
        self._suspiciousFlows = dict()

    def _rebuild_heap(self):
        self._heap = [(v.getTimestamp(), k) for k, v in self._flows.items()]
        heapify(self._heap)

    def _pop(self):
        v, k = heappop(self._heap)
        del self._flows[k]

    def __add__(self, other):
        '''
        check if packet in suspicious list already if so add it to its flow and return False + flowKey
        '''
        if other.flowKey[0] in self._suspiciousFlows:
            self._suspiciousFlows[other.flowKey[0]].addPacket(other)
            return (False,other.flowKey[0])
        elif other.flowKey[1] in self._suspiciousFlows:
            self._suspiciousFlows[other.flowKey[1]].addPacket(other)
            return (False,other.flowKey[1])

        '''
        check if flow exist if so add packet to it else create new flow with it, pop lowers priorty flow if list full
        '''
        if other.flowKey[0] in self._flows:
            self._flows[other.flowKey[0]].addPacket(other)
        elif other.flowKey[1] in self._flows:
            self._flows[other.flowKey[1]].addPacket(other)
        else:
            self.count += 1
            if self.count > PriorityFlows.maxSize:
                self._pop()
            flow = Flow(other)
            self._flows.update({other.flowKey[0]: flow})
            self._rebuild_heap()

        '''
        return True + flowKey
        '''
        return (True,other.flowKey[0])

    '''
    
    if flow found to be suspicious switch from normal flow to suspicious flow likewise in reverse if 'switchBack' flag is True
    '''
    def switchList(self,flowKey,switchBack = False):
        if self._flows[flowKey] in self._flows:
            self._suspiciousFlows.update({flowKey: self._flows[flowKey]})
            del self._flows[flowKey]
        elif switchBack:
            self._flows.update({flowKey: self._suspiciousFlows[flowKey]})
            del self._suspiciousFlows[flowKey]

        self._rebuild_heap()


    def __str__(self):
        print(self.count)
        heap = self._heap.copy()
        try:
            while heap:
                v, k = heappop(heap)
                v = self._flows[k]
                print("{}, duration: {}, Packets: {}".format(k,v.sessionDuration(),v.count))
            return "\n-----------------------------------------------------------------------------------"
        except:
            return "end of heap"

    '''
    
    place holder this function will return the featurse the machine need for her prediction
    '''
    def getFeatures(self,flowKey):
        return 'will return flow features for the machine'


if __name__ == "__main__":
    cap = pyshark.LiveCapture(bpf_filter= "(ip || icmp) and (udp || tcp)")
    #cap.sniff(timeout=10)
    print(cap)
    counter = 0
    flows = PriorityFlows()
    if cap is not None:
        for capPacket in cap:
            counter += 1
            badpacket = flows + Packet(capPacket)

            '''
            if(badpacket):
                # run through the machine no in suspect list
                continue
            else:
                # run through the machine to check if Flow still bad
                continue
            '''

            if counter == 200:
                print(flows)
                counter = 0
    else:
        print("none")



