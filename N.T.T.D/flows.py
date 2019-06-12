import pyshark
import json
from heapq import heapify, heappush, heappop
from collections import deque
import socket


class Packet():
    def __init__(self, packet):
        self.transport_protocol = packet.transport_layer
        self.time_delta = packet[self.transport_protocol].time_delta
        self.timestamp = packet.sniff_timestamp
        self.flowKey = ["{} {} {} {} {}".format(self.transport_protocol, packet.ip.src, packet.ip.dst,
                                                packet[self.transport_protocol].srcport,
                                                packet[self.transport_protocol].dstport),
                        "{} {} {} {} {}".format(self.transport_protocol, packet.ip.dst, packet.ip.src,
                                                packet[self.transport_protocol].dstport,
                                                packet[self.transport_protocol].srcport)]
        self.ip_layer = {'totalLength': packet.ip.len, 'srcIp': packet.ip.src, 'dstIp': packet.ip.dst}
        self.transport_layer = {'srcPort': packet[self.transport_protocol].srcport,
                                'dstPort': packet[self.transport_protocol].dstport}
        self.bytes = int(packet.length)
        # self.bits = 8 * self.bytes
        # self.delta_seconds = self.time_delta.seconds

        self.srcip = packet.ip.src
        self.srcport = packet[self.transport_protocol].srcport
        self.dstip = packet.ip.dst
        self.dstport = packet[self.transport_protocol].dstport

        try:
            self.next_seq = int(packet.tcp.nxtseq)
            self.seq = int(packet.tcp.seq)
            self.window_size = int(packet.tcp.window_size)
            # print(dir(packet))
        except:
            pass
        '''
        #Time to live
        self.ttl
        
        self.state
        #tcp try and catch boolean var
        self.loss
        '''

    '''
    
    need to add function for the ML input
    '''


class Flow:
    maxSize = 5000

    def __init__(self, packet):
        self.count = 1
        self.flow = deque([packet])
        self.lastPacket = packet
        self.average_delta = float(packet.time_delta)
        self.session_start = float(packet.timestamp)

        # packet count for dst and src
        self.sCount = 1
        self.dCount = 0

        # service -> http, ftp, ssh, dns ..,else None
        try:
            self.service = socket.getservbyport(int(packet.dstport))
        except:
            self.service = 'other'

        # average packet size for dst and src
        self.smeansz = packet.bytes
        self.dmeansz = 0

        # Destination to source bytes
        self.dbytes = 0

        # Source bits per second and Destination bits per second
        # self.src_bit = packet.bits
        # self.dst_bit = 0
        # self.src_delte = packet.delta_seconds
        # self.dst_delta = 0

        # if
        if packet.srcip == packet.dstip and packet.srcport == packet.dstport:
            self.is_sm_ips_ports = 1
        else:
            self.is_sm_ips_ports = 0

        # if tcp
        try:
            self.sNext_seq = packet.next_seq
            self.dNext_seq = 0
            self.swin = packet.window_size
            self.dwin = 0
        except:
            self.sNext_seq = 0
            self.dNext_seq = 0
            self.swin = 0
            self.dwin = 0

        self.sloss = 0
        self.dloss = 0
        '''
        
        self.sbytes
        self.dbytes
        self.sttl
        self.dttl
        
        self.sloss
        self.dloss
        '''

    def getDelta(self):
        return self.flow[0].time_delta

    def addPacket(self, packet, sender='src'):
        self.flow.appendleft(packet)
        self.count = self.count + 1

        # if tcp
        try:
            if sender == 'src':
                self.swin = packet.window_size
                if self.sNext_seq > packet.seq:
                    self.sloss += 1
                else:
                    self.sNext_seq = packet.next_seq
            else:
                self.dwin = packet.window_size
                if self.dNext_seq > packet.seq:
                    self.dloss += 1
                else:
                    self.dNext_seq = packet.next_seq
        except:
            pass

        # average packet size
        self.packetSizeAverage(packet, sender)

        # Spkts and Dpkts counts
        if sender == 'src':
            self.sCount += 1
        else:
            self.dCount += 1

        # average delta time
        self.average_delta = self.calculateDetla(packet.time_delta)

        if self.count > Flow.maxSize:
            self.flow.pop()

        # Destination to source bytes
        if sender == 'dst':
            self.dbytes += packet.bytes

    def calculateDetla(self, newDelta):
        return ((self.count * self.average_delta) + float(newDelta)) / self.count

    # 'dur' attribute
    def sessionDuration(self):
        return float(self.flow[0].timestamp) - self.session_start

    # do average before increasing packet count
    def packetSizeAverage(self, packet, sender='src'):
        if sender == 'src':
            self.smeansz = ((self.smeansz * self.sCount) + packet.bytes) / (self.sCount + 1)
        else:
            self.dmeansz = ((self.dmeansz * self.dCount) + packet.bytes) / (self.dCount + 1)

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
    '''
    IMPORTENT if adding or removing features from the real time need to Update input_shape to the current value,
                        same for output_shape, i case of updating the model to predict more cases
    '''
    input_shape = 20
    output_shape = 2

    def __init__(self, packet=None):
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
            self._suspiciousFlows[other.flowKey[0]].addPacket(other, 'src')
            return (False, other.flowKey[0])
        elif other.flowKey[1] in self._suspiciousFlows:
            self._suspiciousFlows[other.flowKey[1]].addPacket(other, 'dst')
            return (False, other.flowKey[1])

        '''
        check if flow exist, if so add packet to it else create new flow with it, pop lowers priorty flow if list full
        '''
        if other.flowKey[0] in self._flows:
            self._flows[other.flowKey[0]].addPacket(other, 'src')
        elif other.flowKey[1] in self._flows:
            self._flows[other.flowKey[1]].addPacket(other, 'dst')
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
        return (True, other.flowKey[0])

    ''' 
    if flow found to be suspicious switch from normal flow to suspicious flow likewise in reverse if 'switchBack' flag is True
    '''

    def switchList(self, flowKey, switchBack=False):
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
                print(f"\n-- {k}, delta:{v.average_delta}, duration: {v.sessionDuration()}, "
                      f"Packets: {v.count}, sloss: {v.sloss}, dloss: {v.dloss}\n"
                      f"   smeansz: {v.smeansz}, dmeansz: {v.dmeansz}\n"
                      f" service: {v.service}, dbytes: {v.dbytes}, is_sm_ips_ports: {v.is_sm_ips_ports}")
            return "\n-----------------------------------------------------------------------------------"
        except:
            return "end of heap"

    '''
    
    place holder this function will return the featurse the machine need for her prediction
    '''

    def getFeatures(self, flowKey):

        '''
        features order to fill:
        sport, dport, dur, sttl, dttl, sloss, dloss, Spkts, Dpkts, swin, dwin, stcpb, dtcpb, smeansz, dmeansz,
        synack, ackdat, proto-icmp, proto-tcp, proto-udp
        '''

        with open('zscore.json', 'r') as zscore:
            load_z = json.load(zscore)
        with open('feature_set.json', 'r') as features:
            load_fs = json.load(features)
        for k, v in load_z.items():
            continue
        return 'will return flow features for the machine'


if __name__ == "__main__":
    cap = pyshark.LiveCapture(bpf_filter="(ip || icmp) and (udp || tcp)")
    # cap.sniff(timeout=10)
    print(cap)
    counter = 0
    flows = PriorityFlows()
    if cap is not None:
        for capPacket in cap:
            counter += 1
            badpacket = flows + Packet(capPacket)
            # print(capPacket.highest_layer)
            '''
            if(badpacket):
                # run through the machine no in suspect list
                continue
            else:
                # run through the machine to check if Flow still bad
                continue
            '''

            if counter == 50:
                print(flows)
                counter = 0
    else:
        print("none")
