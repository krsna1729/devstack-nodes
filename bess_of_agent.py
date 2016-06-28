#!/usr/bin/python
from struct import *
import twink
from twink.ofp4 import *
import twink.ofp4.build as b
import twink.ofp4.parse as p
import twink.ofp4.oxm as oxm
import threading
import binascii
import argparse
import logging
import zerorpc
import signal
import socket
import select
import errno
import time
import sys
import os
import os.path
import cStringIO
import pprint
from collections import namedtuple
#TODO: Remove this along with the hack of iterating to find the rule causing PACKET_IN
from scapy.all import *
logging.basicConfig(level=logging.ERROR)

def aton_ip(ip):
    return socket.inet_aton(ip)

def aton_mac(mac):
    return struct.pack('6B', *(int(x,base=16) for x in mac.split(':')))

def set_val(field, val):
    output = field.copy()
    output.update({'value' : val})
    return output

HWSRC  ={'offset' :  0,
         'size'   :  6}
HWDST  ={'offset' :  6,
         'size'   :  6}
ETHTYPE={'offset' : 12,
         'size'   :  2}
VLANID ={'offset' : 14,
         'size'   :  2}
IPSRC  ={'offset' : 26,
         'size'   :  4}
IPDST  ={'offset' : 30,
         'size'   :  4}

INPORT ={'name'   : 'in_port',
         'size'   :  1}
TUNID  ={'name'   : 'tun_id',
         'size'   :  4}
TUNSRC ={'name'   : 'tun_ip_src',
         'size'   :  4}
TUNDST ={'name'   : 'tun_ip_dst',
         'size'   :  4} 

TYPE_QINQ=0x88A8
TYPE_VLAN=0x8100







_EPOLL_BLOCK_DURATION_S = 1
PKT_IN_BYTES = 4096
PHY_NAME = "eth2"
dpid = 0xffff
n_tables = 254

dp = None

epl = 'epoll'

_CONNECTIONS = {}

_EVENT_LOOKUP = {
    select.POLLIN: 'POLLIN',
    select.POLLPRI: 'POLLPRI',
    select.POLLOUT: 'POLLOUT',
    select.POLLERR: 'POLLERR',
    select.POLLHUP: 'POLLHUP',
    select.POLLNVAL: 'POLLNVAL',
}

ofp_port_stats_names = '''port_no rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped,
                          rx_errors tx_errors rx_frame_err rx_over_err rx_crc_err
                          collisions duration_sec duration_nsec'''
of_port_stats = namedtuple('of_port_stats', ofp_port_stats_names)
default_port_stats = of_port_stats('<port no>', 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0,
                                   0, 1, 1)
'''
of_ports_stats = {
    OFPP_LOCAL: default_port._replace(port_no=OFPP_LOCAL),
    1: default_port._replace(port_no=1, hw_addr=binascii.a2b_hex("0000deaddead"), name='vxlan', curr=0),
    2: default_port._replace(port_no=2, hw_addr=binascii.a2b_hex("000000000001"), name=PHY_NAME, curr=0),
}
'''

ofp_port_names = '''port_no hw_addr name config state
                    curr advertised supported peer curr_speed max_speed
                    pkt_inout_socket stats'''
of_port = namedtuple('of_port', ofp_port_names)
default_port = of_port('<port no>', '<mac address>', '<port name>', 0, 0,
                       0x802, 0, 0, 0, 0, 0,
                       None, default_port_stats)
of_ports = {
    OFPP_LOCAL: default_port._replace(port_no=OFPP_LOCAL, hw_addr=binascii.a2b_hex("0000deadbeef"), name='br-int', curr=0,
                                      stats=default_port_stats._replace(port_no=OFPP_LOCAL)),
    1: default_port._replace(port_no=1, hw_addr=binascii.a2b_hex("0000deaddead"), name='vxlan', curr=0,
                             stats=default_port_stats._replace(port_no=1)),
    2: default_port._replace(port_no=2, hw_addr=binascii.a2b_hex("000000000001"), name=PHY_NAME, curr=0,
                             stats=default_port_stats._replace(port_no=2)),
}

flows = {}
channel = 0

try:
    BESS_PATH = os.getenv('BESSDK', '/opt/bess')
    sys.path.insert(1, '%s/libbess-python' % BESS_PATH)
    from bess import *
except ImportError as e:
    print >> sys.stderr, 'Cannot import the API module (libbess-python)', e.message
    sys.exit()


def _get_flag_names(flags):
    names = []
    for bit, name in _EVENT_LOOKUP.items():
        if flags & bit:
            names.append(name)
            flags -= bit

            if flags == 0:
                break

    assert flags == 0,\
        "We couldn't account for all flags: (%d)" % (flags,)

    return names


def _handle_inotify_event(fd, event_type):
    # Common, but we're not interested.
    if (event_type & select.POLLOUT) == 0:
        flag_list = _get_flag_names(event_type)
        print flag_list

    try:
        s = _CONNECTIONS[fd]
    except KeyError as e:
        print >> sys.stderr, 'KeyError in epoll. Race-condition?', e.message
        return
    if event_type & select.EPOLLIN:
        data = s.recv(PKT_IN_BYTES)
        # TODO: Formalise this. Assumption - DP to prepend cookie before sending PACKET_IN. Reason also? For now ACTION
        # cookie = unpack('Q', data[:8])[0]
        cookie = None
        #print 'Received data: ', data, 'bytearray: ', binascii.hexlify(bytearray(data))
        if len(data) < 14:
            return
        eth = Ether(bytearray(data))
        #eth.show()
        if Ether not in eth:
#            print 'Got a PKT_IN that is not Ethernet 2'
            return
        eth_type = eth['Ethernet'].type
        for c, f in flows.iteritems():
            oxm_list = oxm.parse_list(f.match.oxm_fields)
            for i in oxm_list:
                if i.oxm_value == eth_type:
                    cookie = c
                    break
            if cookie is not None:
                break

#        print 'PACKET_IN Cookie:', cookie
        if cookie is None:
            return
        #print flows[cookie]
        f = flows[cookie]
        port = 0xffffffff
        for p, stuff in of_ports.iteritems():
            if stuff.pkt_inout_socket == s:
                    port = p
                    print 'Found matching port for PKT_IN: ', port
        match = b.ofp_match(None, None, oxm.build(None, oxm.OXM_OF_IN_PORT, False, None, 2))
        # Get cookie from DP. Use it to lookup table_id, match. Append Data
        '''channel.send(b.ofp_packet_in(b.ofp_header(4, OFPT_PACKET_IN, 0, 0),
                     0xffffffff, len(data[8:]), OFPR_ACTION, f.table_id, cookie, f.match, data[8:]))'''
        channel.send(b.ofp_packet_in(b.ofp_header(4, OFPT_PACKET_IN, 0, 0),
                                     0xffffffff, len(data), OFPR_ACTION, f.table_id, cookie, match, data))


def run_epoll():

    while True:
        events = epl.poll(_EPOLL_BLOCK_DURATION_S)
        for fd, event_type in events:
            _handle_inotify_event(fd, event_type)


def connect_bess():

    s = BESS()
    try:
        s.connect()
    except s.APIError as e:
        print >> sys.stderr, e.message
        return None
    else:
        return s


def init_phy_port(bess, name, port_id):

    try:
        result = bess.create_port('PMD', name, {'port_id': port_id})
        bess.resume_all()
    except (bess.APIError, bess.Error)as err:
        print err.message
        return {'name': None}
    else:
        return result


PKTINOUT_NAME = 'pktinout_%s'
SOCKET_PATH = '/tmp/bess/unix_' + PKTINOUT_NAME


def init_pktinout_port(bess, name):

    # br-int alone or vxlan too?
    if name == 'br-int':
        return None, None

    try:
        bess.pause_all()
        result = bess.create_port('UnixSocket', PKTINOUT_NAME % name, {'path': '@' + SOCKET_PATH % name})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect('\0' + SOCKET_PATH % name)
        s.setblocking(0)
        epl.register(s.fileno())
        _CONNECTIONS[s.fileno()] = s
    except (bess.APIError, bess.Error, socket.error) as err:
        print err
        bess.resume_all()
        return {'name': None}, None
    else:
        # TODO: Handle VxLAN PacketOut if Correct/&Reqd. Create PI connect PI_pktinout_vxlan-->Encap()-->PO_dpif
        if name == 'vxlan':
            pass
        elif name == 'eth2':
            # bess.create_module('PortInc', 'CTL_INC2', {'port': PKTINOUT_NAME % name})
            # bess.create_module('PortOut', 'CTL_0UT2', {'port': PKTINOUT_NAME % name})

            bess.create_module('PortInc', 'INC2'    , {'port': name})
            bess.create_module('PortOut', 'OUT2'    , {'port': name})
        else:
            # UNIX_port [PACKET_OUT]--> DP port
            bess.create_module('PortInc', 'PI_' + PKTINOUT_NAME % name, {'port': PKTINOUT_NAME % name})
            bess.create_module('PortOut', 'PO_' + name, {'port': name})
            bess.connect_modules('PI_' + PKTINOUT_NAME % name, 'PO_' + name)

            bess.create_module('PortOut', 'PO_' + PKTINOUT_NAME % name, {'port': PKTINOUT_NAME % name})
            bess.create_module('PortInc', 'PI_' + name, {'port': name})
            # TODO: Below connection is temporary. Bypass flow processing.
            # DP port --> [PACKET_IN] UNIX_port
            bess.connect_modules('PI_' + name, 'PO_' + PKTINOUT_NAME % name)
        bess.resume_all()
        return result, s


def deinit_pktinout_port(bess, name):

    # br-int alone or vxlan too?
    if name == 'br-int':
        return

    try:
        bess.pause_all()
        # TODO: Handle VxLAN PacketOut if Correct/&Reqd. Create PI connect PI_pktinout_vxlan-->Encap()-->PO_dpif
        if name != 'vxlan':
            bess.disconnect_modules('PI_' + PKTINOUT_NAME % name, 0)
            bess.destroy_module('PI_' + PKTINOUT_NAME % name)
            bess.destroy_module('PO_' + name)
            bess.destroy_port(PKTINOUT_NAME % name)
        bess.resume_all()
        return
    except (bess.APIError, bess.Error)as err:
        bess.resume_all()
        print err.message


def handle_inport():
    print 'IN_PORT'
    
def handle_eth_type():
    print 'ETH_TYPE'
        
handle_match_on = {oxm.OXM_OF_IN_PORT : handle_inport,
                   oxm.OXM_OF_ETH_TYPE : handle_eth_type,
                   #           OXM_OF_ : ,
}

#dpdkIntelDPE#006
def switch_proc(message, ofchannel):

    msg = p.parse(message)

    # TODO: Acquire lock

    if msg.header.type == OFPT_FEATURES_REQUEST:
        channel.send(b.ofp_switch_features(b.ofp_header(4, OFPT_FEATURES_REPLY, 0, msg.header.xid), dpid, 0, n_tables, 0, 0xF))

    elif msg.header.type == OFPT_GET_CONFIG_REQUEST:
        channel.send(b.ofp_switch_config(b.ofp_header(4, OFPT_GET_CONFIG_REPLY, 0, msg.header.xid), 0, 0xffff))

    elif msg.header.type == OFPT_ROLE_REQUEST:
        channel.send(b.ofp_role_request(b.ofp_header(4, OFPT_ROLE_REPLY, 0, msg.header.xid), msg.role, msg.generation_id))

    elif msg.header.type == OFPT_FLOW_MOD:
        if msg.cookie in flows:
            print "I already have this FlowMod: Cookie", msg.cookie
        print msg.cookie, oxm.parse_list(msg.match.oxm_fields), (msg.instructions)

        print "------------------------"
        print "OFPT_FLOW_MOD"
        print "table_id:\t", msg.table_id
        print "priority:\t", msg.priority
        print "match"
        for f in oxm.parse_list(msg.match.oxm_fields):
            try:
                handle_match_on[f.oxm_field]()
            except:
                print 'unhandled match type'
            print "\tfield\t", f.oxm_field,
            print "\tvalue\t", f.oxm_value
            if f.oxm_hasmask:
                print "\tmask\t", f.oxm_mask
        for i in msg.instructions:
            print "\t", i.type
            print "\t", i
            
        flows[msg.cookie] = msg

    elif msg.header.type == OFPT_MULTIPART_REQUEST:
        if msg.type == OFPMP_FLOW:
            channel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_flow_stats(None, f.table_id, 1, 2, f.priority,
                                                                f.idle_timeout, f.hard_timeout, f.flags, f.cookie, 0, 0,
                                                                f.match, f.instructions)
                                               for f in flows.itervalues())]))
        elif msg.type == OFPMP_PORT_STATS:
            channel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_port_stats(ofp.stats.port_no, ofp.stats.rx_packets, ofp.stats.tx_packets, ofp.stats.rx_bytes, ofp.stats.tx_bytes, ofp.stats.rx_dropped, ofp.stats.tx_dropped,
                                                                ofp.stats.rx_errors, ofp.stats.tx_errors, ofp.stats.rx_frame_err, ofp.stats.rx_over_err, ofp.stats.rx_crc_err,
                                                                ofp.stats.collisions, ofp.stats.duration_sec, ofp.stats.duration_nsec)
                                               for ofp in of_ports.itervalues())]))
        elif msg.type == OFPMP_PORT_DESC:
            channel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_port(ofp.port_no, ofp.hw_addr, ofp.name, ofp.config, ofp.state,
                                                          ofp.curr, ofp.advertised, ofp.supported, ofp.peer, ofp.curr_speed, ofp.max_speed)
                                               for ofp in of_ports.itervalues())]))
        elif msg.type == OFPMP_DESC:
            channel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0,
                         b.ofp_desc("Nicira, Inc.", "Open vSwitch", "2.4.0", None, None)))

#        else:
#            print 'Unhandled message OFPT_MULTIPART_REQUEST type:\n', msg

    elif msg.header.type == OFPT_PACKET_OUT:
        index = msg.actions[0].port
        sock = of_ports[index].pkt_inout_socket
        if sock is not None:
            try:
                sent = sock.send(msg.data)
            except socket.error as e:
                print >> sys.stderr, e.message
            else:
                if sent != len(msg.data):
                    print "Incomplete Transmission Sent:%d, Len:%d" % (sent, len(msg.data))
        else:
            print "Packet out OF Port %d, Len:%d. Failed - Null socket" % (index, len(msg.data))

    elif msg.header.type == OFPT_HELLO:
        pass

    elif msg.header.type == OFPT_SET_CONFIG:
        pass

    elif msg.header.type == OFPT_BARRIER_REQUEST:
        pass

#    else:
#        print 'Unhandled message type:\n', msg
        #assert 0

    # TODO: Release lock


def of_agent_start(ctl_ip='127.0.0.1', port=6653):

    global channel
    socket = twink.sched.socket
    try:
        s = socket.create_connection((ctl_ip, port),)
    except socket.error as err:
        if err.errno != errno.ECONNREFUSED:
            raise err
        print 'Is the controller running at %s:%d' % (ctl_ip, port)
        return errno.ECONNREFUSED

    ch = type("Switch", (
        twink.AutoEchoChannel,
        twink.LoggingChannel,), {
                  "accept_versions": [4, ],
                  "handle": staticmethod(switch_proc)
              })()
    ch.attach(s)
    channel = ch

    t1 = threading.Thread(name="Switch Loop", target=ch.loop)
    t1.setDaemon(True)
    t1.start()


class PortManager(object):
    def __init__(self):
        self.of_port_num = 2

    def add_port(self, dev, mac):
        if (self.of_port_num + 1) == OFPP_LOCAL:
            raise ValueError("Unable to add dev. Reached max OF port_num")

        elif dev is None:
            raise ValueError("dev cannot be None")

        elif mac is None:
            raise ValueError("mac cannot be None")

        self.of_port_num += 1
        mac = mac.replace(":","")
        # Create vhost-user port
        ret = dp.create_port('vhost_user', dev, {'mac': mac})
        # Create corresponding pkt_in_out port
        ret, sock = init_pktinout_port(dp, dev)
        of_ports[self.of_port_num] = default_port._replace(
            port_no=self.of_port_num, hw_addr=binascii.a2b_hex(mac[:12]), name=dev, pkt_inout_socket=sock,
            stats=default_port_stats._replace(port_no=self.of_port_num))

        ofp = of_ports[self.of_port_num]
        channel.send(b.ofp_port_status(b.ofp_header(4, OFPT_PORT_STATUS, 0, 0), OFPPR_ADD,
                                       b.ofp_port(ofp.port_no, ofp.hw_addr, ofp.name, ofp.config, ofp.state,
                                                  ofp.curr, ofp.advertised, ofp.supported, ofp.peer, ofp.curr_speed, ofp.max_speed
                                                  )))

        print 'Current OF ports:\n', of_ports
        return "Successfully added dev: %s with MAC: %s as ofport:%d" % (dev, mac, self.of_port_num)

    def del_port(self, dev):
        if dev is None:
            raise ValueError("dev cannot be None")

        for port_no, port_details in of_ports.iteritems():
            if port_details.name == dev:
                ofp = of_ports[port_no]
                channel.send(b.ofp_port_status(b.ofp_header(4, OFPT_PORT_STATUS, 0, 0), OFPPR_DELETE,
                                               b.ofp_port(ofp.port_no, ofp.hw_addr, ofp.name, ofp.config, ofp.state,
                                                          ofp.curr, ofp.advertised, ofp.supported, ofp.peer,
                                                          ofp.curr_speed, ofp.max_speed
                                                          )))
                deinit_pktinout_port(dp, port_details.name)
                dp.destroy_port(dev)
                del of_ports[port_no]
                print 'Current OF ports:\n', of_ports
                return "Successfully deleted dev: %s which was ofport: %d" % (dev, port_no)

        return "Unable to locate dev: %s" % dev


def nova_agent_start():
    s = zerorpc.Server(PortManager())
    s.bind("tcp://0.0.0.0:10515")
    print "Port Manager listening on 10515"

    #blocks?
    s.run()


def print_stupid():
    while 1:
        channel.send(ofp_header_only(2, version=4))
        time.sleep(2)
    pass


def init_modules(B):

    B.pause_all()
    try:
        ### DROP ###
        B.create_module('Sink', name='DROP', arg=None)
        # for i in range(1,6):
        #     B.create_module('Sink', name='DRP' + str(i), arg=None)

        ### PLACEHOLDERS FOR ACTUAL PORT_INC/PORT_OUT ###
        B.create_module('Merge', name='INC1', arg=None)
        B.create_module('Sink' , name='OUT1', arg=None)
        # for i in range(3,5):
        #     B.create_module('Sink', name='OUT' + str(i), arg=None)
        B.create_module('Sink', name='LCL', arg=None)
        B.create_module('Sink', name='CTL', arg=None)

        ### PHY PORT_INC/PORT_OUT ###
#        B.create_module('PortInc', name='IN2', arg=None)
#        B.create_module('PortOut', name='OUT2', arg={'port' : PHY_NAME})
        
        ### Table 0 ###
        B.create_module('WildcardMatch',
                        name='t0_start',
                        arg={'fields' : [ETHTYPE,VLANID],
                             'size' : 4096})
        B.create_module('ExactMatch',
                        name='t0_inport',
                        arg={'fields' : [INPORT],
                             'size' : 4096})
        B.create_module('BPF', name='t0_p2')
        B.create_module('BPF', name='t0_default')
        
        ### Table 1 ###
        B.create_module('WildcardMatch',
                        name='t1_start',
                        arg={'fields' : [INPORT,IPSRC],
                             'size' : 4096})
        
        ### Table 2 ###
        B.create_module('WildcardMatch',
                        name='t2_start',
                        arg={'fields' : [IPSRC,IPDST],
                             'size' : 4096})
                
        ### Table 3 ###
        B.create_module('ExactMatch',
                        name='t3_start',
                        arg={'fields' : [INPORT],
                             'size' : 4096})
        
        ### Table 4 ###
        B.create_module('ExactMatch',
                        name='t4_start',
                        arg={'fields' : [IPDST],
                             'size' : 4096})
        # B.create_module('Update',
        #                 name='t4u1',
        #                 arg=[set_val(HWDST,'fa:16:3e:cf:f2:56')])
        # B.create_module('Update',
        #                 name='t4u2',
        #                 arg=[set_val(HWDST,'fa:16:3e:f3:5e:82')])
        # B.create_module('SetMetadata',
        #                 name='t4s2',
        #                 arg=[set_val(TUNID, 0x40c),
        #                      set_val(TUNDST,aton_ip('1.1.1.2'))])
        # B.create_module('Update',
        #                 name='t4u3',
        #                 arg=[set_val(HWDST,'fa:16:3e:da:05:ed')])
        # B.create_module('SetMetadata',
        #                 name='t4s3',
        #                 arg=[set_val(TUNID, 0x406),
        #                      set_val(TUNDST, aton_ip('1.1.1.2'))])
        # B.create_module('Update',
        #                 name='t4u4',
        #                 arg=[set_val(HWDST, 'fa:16:3e:3e:82:e8')])
        
        ### Table 5 ###
        B.create_module('ExactMatch',
                        name='t5_start',
                        arg={'fields' : [TUNID,HWSRC],
                             'size' : 4096})
        
        ### Table 6 ###
        B.create_module('BPF', name='t6_start')
        B.create_module('VLANPop', name='vlan_pop')
        
        ### Group Table ###
        B.create_module('HashLB',
                        name='grp_start',
                        arg=2)
        # B.create_module('Update',
        #                 name='gru1',
        #                 arg=[set_val(HWDST, 'fa:16:3e:f3:5e:82')])
        # B.create_module('SetMetadata',
        #                 name='grs1',
        #                 arg=[set_val(TUNID, 0x40c),
        #                      set_val(TUNDST, aton_ip('1.1.1.2'))])
        # B.create_module('Update',
        #                 name='gru2',
        #                 arg=[set_val(HWDST, 'fa:16:3e:cf:f2:56')])
        
        ### VXLAN Encapsulation ###
        B.create_module('VXLANEncap',
                        name='vxlan_out')
        B.create_module('IPEncap',
                        name='ip_encap')
        B.create_module('EtherEncap',
                        name='ether_encap')  


        
    #### CONNECT MODULES ####
        B.connect_modules('vxlan_out','ip_encap'   , 0, 0)
        B.connect_modules('ip_encap','ether_encap' , 0, 0)
        B.connect_modules('ether_encap','OUT1'     , 0, 0)

        
        B.connect_modules('INC1'    ,'t0_start'    , 0, 0)
        B.connect_modules('INC2'    ,'t0_start'    , 0, 0)
        
        B.connect_modules('t0_start', 't6_start'   , 1, 0)
        B.connect_modules('t0_start', 't0_inport'  , 0, 0)
        
        B.connect_modules('t0_inport', 't0_p2'     , 1, 0)
        B.connect_modules('t0_inport', 'OUT2'      , 2, 0)
        B.connect_modules('t0_inport', 't0_default', 0, 0)
    
        B.connect_modules('t0_p2'    , 'LCL'       , 1, 0)
        B.connect_modules('t0_p2'    , 't0_default', 0, 0)

        B.connect_modules('t0_default', 'CTL'      , 1, 0)
        B.connect_modules('t0_default', 't1_start' , 0, 0)

        B.connect_modules('t1_start'  , 't5_start' , 0, 0)
        B.connect_modules('t1_start'  , 't4_start' , 1, 0)
        B.connect_modules('t1_start'  , 't2_start' , 2, 0)
        B.connect_modules('t1_start'  , 't3_start' , 3, 0)
        B.connect_modules('t1_start'  , 'DROP'     , 4, 0)

        B.connect_modules('t2_start'  , 'grp_start', 1, 0)
        B.connect_modules('t2_start'  , 't4_start' , 2, 0)
        B.connect_modules('t2_start'  , 'DROP'     , 3, 0)
        B.connect_modules('t2_start'  , 'OUT2'     , 0, 0)

        B.connect_modules('t3_start'  , 'grp_start', 1, 0)
        B.connect_modules('t3_start'  , 'DROP'     , 0, 0)

        # B.connect_modules('t4_start'  , 't4u1'     , 1, 0)
        # B.connect_modules('t4u1'      , 'OUT4'     , 0, 0)
        # B.connect_modules('t4_start'  , 't4u2'     , 2, 0)
        # B.connect_modules('t4u2'      , 't4s2'     , 0, 0)
        # B.connect_modules('t4s2'      , 'vxlan_out', 0, 0)
        # B.connect_modules('t4_start'  , 't4u3'     , 3, 0)
        # B.connect_modules('t4u3'      , 't4s3'     , 0, 0)
        # B.connect_modules('t4s3'      , 'vxlan_out', 0, 0)
        # B.connect_modules('t4_start'  , 't4u4'     , 4, 0)
        # B.connect_modules('t4u4'      , 'OUT3'     , 0, 0)

        # B.connect_modules('t5_start'  , 'OUT3'     , 1, 0)
        # B.connect_modules('t5_start'  , 'OUT4'     , 2, 0)
        B.connect_modules('t5_start'  , 'DROP'     , 0, 0)

        B.connect_modules('t6_start'  , 'CTL'      , 1, 0)
        B.connect_modules('t6_start'  , 'vlan_pop' , 2, 0)
        B.connect_modules('vlan_pop'  , 'OUT2'     , 0, 0)
        B.connect_modules('t6_start'  , 'DROP'     , 0, 0)

        # B.connect_modules('grp_start' , 'gru1'     , 0, 0)
        # B.connect_modules('gru1'      , 'grs1'     , 0, 0)
        # B.connect_modules('grs1'      , 'vxlan_out', 0, 0)
        # B.connect_modules('grp_start' , 'gru2'     , 1, 0)
        # B.connect_modules('gru2'      , 'OUT4'     , 0, 0)

        
    finally:
        B.resume_all()


        
if __name__ == "__main__":

    while dp is None:
        dp = connect_bess()
        time.sleep(2)
    dp.resume_all()
    epl = select.epoll()

    def cleanup(*args):
        dp.pause_all()
        for sfd, s in _CONNECTIONS.iteritems():
            epl.unregister(sfd)
            s.close()
        epl.close()
        dp.reset_all()
        sys.exit()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dpid', default=1, type=int, help='Datapath ID default=1')
    parser.add_argument('-c', '--ctl', default=None, help='Controller IP. default=None')
    args = parser.parse_args()

    dpid = args.dpid

    if init_phy_port(dp, PHY_NAME, 0)['name'] == PHY_NAME:
        print "Successfully created PMD port : %s" % PHY_NAME
    else:
        print 'Failed to create PMD port. Check if it exists already'

    print 'Initial list of Openflow ports', of_ports

    for port_num, port in of_ports.iteritems():
        ret, sock = init_pktinout_port(dp, port.name)
        of_ports[port_num] = of_ports[port_num]._replace(pkt_inout_socket=sock)
        print ret, ' ', of_ports[port_num].pkt_inout_socket

    while of_agent_start(ctl_ip=args.ctl) == errno.ECONNREFUSED:
        pass

    init_modules(dp)
        
    # TODO: Start a thread that will select poll on all of those UNIX sockets
    t2 = threading.Thread(name="PACKET_IN thread", target=run_epoll)
    t2.setDaemon(True)
    t2.start()

    nova_agent_start()

    signal.pause()

