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

    def getFlowKey(self):
        return self.flow[0].flowKey[0]

    def getTimestamp(self):
        return float(self.flow[0].timestamp)


class PriorityFlows:
    maxSize = 5000
    def __init__ (self, packet=None):
        self.count = 0
        if packet:
            flow = Flow(packet)
            self._dict = {flow.getFlowKey(): flow}
            self.count = 1
            self._rebuild_heap()
        else:
            self._dict = dict()

    def _rebuild_heap(self):
        self._heap = [(v.getTimestamp(), k) for k, v in self._dict.items()]
        heapify(self._heap)

    def _pop(self):
        v, k = heappop(self._heap)
        del self._dict[k]

    def __add__(self, other):
        if other.flowKey[0] in self._dict:
            self._dict[other.flowKey[0]].addPacket(other)
        elif other.flowKey[1] in self._dict:
            self._dict[other.flowKey[1]].addPacket(other)
        else:
            self.count += 1
            if self.count > PriorityFlows.maxSize:
                self._pop()
            flow = Flow(other)
            self._dict.update({flow.getFlowKey(): flow})
            self._rebuild_heap()

    def __str__(self):
        print(self.count)
        heap = self._heap.copy()
        try:
            while heap:
                v, k = heappop(heap)
                v = self._dict[k]
                print("{}, duration: {}, Packets: {}".format(k,v.sessionDuration(),v.count))
            return "\n-----------------------------------------------------------------------------------"
        except:
            return "end of heap"











if __name__ == "__main__":
    cap = pyshark.LiveCapture(bpf_filter= "(ip || icmp) and (udp || tcp)")
    #cap.sniff(timeout=10)
    print(cap)
    counter = 0
    flows = PriorityFlows()
    if cap is not None:
        for capPacket in cap:
            counter += 1
            flows + Packet(capPacket)
            if counter == 10000:
                print(flows)
                counter = 0
    else:
        print("none")



