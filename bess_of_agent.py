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

IN_PORT ={'name'   : 'in_port',  #0
          'size'   :  4}
ETH_DST  ={'offset' :  6,  #3
           'size'   :  6}
ETH_SRC  ={'offset' :  0,  #4
           'size'   :  6}
ETH_TYPE={'offset' : 12,  #5
         'size'   :  2}
VLAN_VID ={'offset' : 14,  #6
           'size'   :  2}
IP_PROTO={'offset' :  9, #10
          'size'   :  1}
IPV4_SRC  ={'offset' : 26,  #11
            'size'   :  4}
IPV4_DST  ={'offset' : 30,  #12
            'size'   :  4}
UDP_SRC   ={'offset' : 34,  #15
            'size'   :  2}
UDP_DST   ={'offset' : 36,  #16
            'size'   :  2}
ARP_TPA ={'offset' : 24,
          'size'   :  4}  #23

FIELD = {
    0: IN_PORT,
    3: ETH_DST,
    4: ETH_SRC,
    5: ETH_TYPE,
    6: VLAN_VID,
    10: IP_PROTO,
    11: IPV4_SRC,
    12: IPV4_DST,
    15: UDP_SRC,
    16: UDP_DST,
    23: ARP_TPA
}


TUNID  ={'name'   : 'tun_id',
         'size'   :  4}
TUNSRC ={'name'   : 'tun_ip_src',
         'size'   :  4}
TUNDST ={'name'   : 'tun_ip_dst',
         'size'   :  4} 

WILDCARD_MATCH='WildcardMatch'
EXACT_MATCH='ExactMatch'

TABLE_TYPE = {
    0 : WILDCARD_MATCH,
    1 : WILDCARD_MATCH,
    2 : WILDCARD_MATCH,
    3 : EXACT_MATCH,
    4 : EXACT_MATCH,
    5 : EXACT_MATCH,
    6 : WILDCARD_MATCH
}

TABLE_FIELDS = {
    0 : [IN_PORT, ETH_TYPE, VLAN_VID, IP_PROTO, IPV4_DST, UDP_SRC, UDP_DST, ARP_TPA],
    1 : [IN_PORT,IPV4_SRC],
    2 : [IPV4_SRC,IPV4_DST],
    3 : [IN_PORT],
    4 : [IPV4_DST],
    5 : [TUNID,ETH_SRC],
    6 : [ETH_TYPE, VLAN_VID]
}





_EPOLL_BLOCK_DURATION_S = 1
PKT_IN_BYTES = 4096
PHY_NAME = "eth2"
LCL_NAME = "br-int"
dpid = 0xffff
n_tables = 254

dp = None
flows = {}
channel = 0

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


def init_phy_port(dp, name, port_id):
    dp.pause_all()
    try:
        result = dp.create_port('PMD', name, {'port_id': port_id})
        dp.resume_all()
    except (dp.APIError, dp.Error)as err:
        print err.message
        return {'name': None}
    else:
        return result


def init_lcl_port(dp, name, port_id):
    dp.pause_all()
    try:
        result = dp.create_port('VPort', name, {'port_id': port_id})
        dp.create_module('PortInc', 'INC_LCL', {'port': name})
        dp.create_module('PortOut', 'OUT_LCL', {'port': name})
        dp.resume_all()
    except (dp.APIError, dp.Error)as err:
        print err.message
        return {'name': None}
    else:
        return result



    
PKTINOUT_NAME = 'pktinout_%s'
SOCKET_PATH = '/tmp/bess/unix_' + PKTINOUT_NAME


def init_pktinout_port(dp, name):

    # br-int alone or vxlan too?
    if name == 'br-int':
        return None, None

    try:
        dp.pause_all()
        result = dp.create_port('UnixSocket', PKTINOUT_NAME % name, {'path': '@' + SOCKET_PATH % name})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect('\0' + SOCKET_PATH % name)
        s.setblocking(0)
        epl.register(s.fileno())
        _CONNECTIONS[s.fileno()] = s
    except (dp.APIError, dp.Error, socket.error) as err:
        print err
        dp.resume_all()
        return {'name': None}, None
    else:
        # TODO: Handle VxLAN PacketOut if Correct/&Reqd. Create PI connect PI_pktinout_vxlan-->Encap()-->PO_dpif
        if name == 'vxlan':
            pass
        elif name == 'eth2':
            # dp.create_module('PortInc', 'CTL_INC_PHY', {'port': PKTINOUT_NAME % name})
            # dp.create_module('PortOut', 'CTL_0UT2', {'port': PKTINOUT_NAME % name})
            dp.create_module('PortInc', 'INC_PHY'    , {'port': name})
            dp.create_module('PortOut', 'OUT_PHY'    , {'port': name})
        else:
            # UNIX_port [PACKET_OUT]--> DP port
            dp.create_module('PortInc', 'PI_' + PKTINOUT_NAME % name, {'port': PKTINOUT_NAME % name})
            dp.create_module('PortOut', 'PO_' + name, {'port': name})
            dp.connect_modules('PI_' + PKTINOUT_NAME % name, 'PO_' + name)

            dp.create_module('PortOut', 'PO_' + PKTINOUT_NAME % name, {'port': PKTINOUT_NAME % name})
            dp.create_module('PortInc', 'PI_' + name, {'port': name})
            # TODO: Below connection is temporary. Bypass flow processing.
            # DP port --> [PACKET_IN] UNIX_port
            dp.connect_modules('PI_' + name, 'PO_' + PKTINOUT_NAME % name)
        dp.resume_all()
        return result, s


def deinit_pktinout_port(dp, name):

    # br-int alone or vxlan too?
    if name == 'br-int':
        return

    try:
        dp.pause_all()
        # TODO: Handle VxLAN PacketOut if Correct/&Reqd. Create PI connect PI_pktinout_vxlan-->Encap()-->PO_dpif
        if name != 'vxlan':
            dp.disconnect_modules('PI_' + PKTINOUT_NAME % name, 0)
            dp.destroy_module('PI_' + PKTINOUT_NAME % name)
            dp.destroy_module('PO_' + name)
            dp.destroy_port(PKTINOUT_NAME % name)
        dp.resume_all()
        return
    except (dp.APIError, dp.Error)as err:
        dp.resume_all()
        print err.message


########## HANDLE DP MODIFICATIONS ###        

VLAN_POP_NUM=0
def create_new_vlan_pop():
    global VLAN_POP_NUM
    dp.pause_all()
    name='vlan_pop'+str(VLAN_POP_NUM)
    try:
        dp.create_module('VLANPop', name=name)
        VLAN_POP_NUM+=1
    except Exception, err:
            print 'PROBLEM CREATING NEW VLAN_POP'
            print err
    finally:
        dp.resume_all()
    return name     


MASK_OF_SIZE = {
    1 : 0xff,
    2 : 0xffff,
    4 : 0xffffffff,
    6 : 0xffffffffffff
}
def table_match(tid, match):
    global TABLE_FIELDS
    global MASK_OF_SIZE
    fields = TABLE_FIELDS[tid]
    value  = [0 for f in fields]
    mask   = [0 for f in fields]
    for m in match:
        i = fields.index(FIELD[m.oxm_field])
        value[i] = m.oxm_value
        if TABLE_TYPE[tid] == WILDCARD_MATCH:
            if m.oxm_hasmask:
                mask[i] = m.oxm_mask
            else:
                mask[i] = MASK_OF_SIZE[fields[i]['size']]
    return (value,mask)


# ASSUMING 8 TABLES
OGATE_MAPS = [dict() for i in range(0,8)]
def handle_flow_mod(table_id,priority,match,instr):
    global dp
    global OGATE_MAPS
    for f in match:
        print "field\t", f.oxm_field
        print "value\t", f.oxm_value
        if f.oxm_hasmask:
            print "mask\t", f.oxm_mask

    def connect_modules(from_table,to_table, ogate):
        print 'CONNECTING: ', from_table, ':', ogate, ' --> ', to_table
        dp.pause_all()
        try:
            dp.connect_modules(from_table, to_table, ogate, 0)
        except Exception, err:
            print 'PROBLEM CONNECTING MODULES'
            print err
        finally:
            dp.resume_all()

            
    ### CODE BELOW UNTESTED ON GRP TABLE
            
    new_connection = False
    table_name = 't'+str(table_id)
    print '~~~~~~~~~~~~~~~~~~~'
    values, masks = table_match(table_id,match)
    ogate_map = OGATE_MAPS[table_id]
    print table_name, ' add'
    print '\tpriority : ',priority
    print '\tvalues   : ',values
    if TABLE_TYPE[table_id] == WILDCARD_MATCH:
        print '\tmasks    : ',masks


    ### GOTO_TABLE
    if instr.type == OFPIT_GOTO_TABLE:
        goto_str = 't'+str(instr.table_id)
        print '\tto_table : ',goto_str
        if not goto_str in ogate_map:
            ogate_map[goto_str] = len(ogate_map)
            new_connection = True
        ogate = ogate_map[goto_str]
        print '\tgate     : ', ogate
        if new_connection:
            connect_modules(table_name,goto_str,ogate)

    ### APPLY_ACTIONS
    elif instr.type == OFPIT_APPLY_ACTIONS:
        print 'APPLY_ACTIONS'
        initial_action = True
        predecessor = table_name
        
        for action in instr.actions:

            if action.type == OFPAT_OUTPUT:
                # MAP OF PORTS TO MODULES
                if action.port == OFPP_CONTROLLER:
                    goto_str = 'OUT_CTL'
                elif action.port == OFPP_LOCAL:
                    goto_str = 'OUT_LCL'
                elif action.port == 2:
                    goto_str = 'OUT_PHY'
                else:
                    print 'UNHANDLED PORT # ', action.port
                    return

                # DETERMINE OUTPUT GATE
                print '\tto_port : ',goto_str
                if initial_action:
                    if not goto_str in ogate_map:
                        ogate_map[goto_str] = len(ogate_map)
                        new_connection = True
                    ogate = ogate_map[goto_str]
                else:
                    new_connection = True
                    ogate = 0
                print '\tgate     : ', ogate

                # CREATE CONNECTION, IF NECESSARY
                if new_connection:
                    connect_modules(predecessor,goto_str,ogate)

            elif action.type == OFPAT_POP_VLAN:
                # WE WILL RUN THE LOOP ONCE FOR EACH UNIQUE INSTRS STRING
                k = str(instr.actions)
                if not k in ogate_map:
                    ogate_map[k] = len(ogate_map)
                    new_connection = True
                ogate = ogate_map[k]
                print '\tgate     : ', ogate

                # CREATE CONNECTION AND CONTINUE LOOP, IF NECESSARY
                if new_connection:
                    goto_str = create_new_vlan_pop()
                    connect_modules(predecessor,goto_str,ogate)
                    predecessor=goto_str
                    initial_action=False
                else:
                    break

            # UNHANDLED ACTION
            else:
                print 'UNHANDLED ACTION'
                return


    # UNHANDLED INSTRUCTION TYPE
    else:
        print 'UNHANDLED INSTRUCTION TYPE'
        return

    try:
        dp.pause_all()
        if TABLE_TYPE[table_id] == WILDCARD_MATCH:
            dp.run_module_command(table_name, 'add',
                                  {'priority': priority,
                                   'values'  : values,
                                   'masks'   : masks,
                                   'gate'    : ogate    })
            print 'update SUCCESS'
        elif TABLE_TYPE(table_id) == EXACT_MATCH:
            ### UNTESTED !!!
            dp.run_module_command(table_name, 'add',
                                  {'fields'  : values,
                                   'gate'    : ogate    })
            print 'update SUCCESS'
        else:
            print 'UNHANDLED TABLE TYPE ', TABLE_TYPE(table_id)

    except Exception, err:
        print 'update FAIL'
        print err
    finally:
        dp.resume_all()
                    


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
        print "========================"
        if msg.cookie in flows:
            print "I already have this FlowMod: Cookie", msg.cookie
        print msg.cookie, oxm.parse_list(msg.match.oxm_fields), (msg.instructions)

        print "------------------------"
        print "OFPT_FLOW_MOD"
        print "table_id:\t", msg.table_id
        print "priority:\t", msg.priority
        match = oxm.parse_list(msg.match.oxm_fields)
        print "match", 
        print match
        if len(msg.instructions) != 1:
            print len(msg.instructions), ' INSTRUCTIONS: NOT HANDLED'
            return
        i = msg.instructions[0]
        print "instr", i
        handle_flow_mod(msg.table_id, msg.priority, match, i)
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


    
def init_modules(dp):
    global TABLE_FIELDS
    dp.pause_all()
    try:
        ### PLACEHOLDER ###
        dp.create_module('Sink', name='CTL', arg=None)

        
        ### Tables 0-6 ###
        for i in range(0,7):
            dp.create_module(TABLE_TYPE[i],
                             name='t'+str(i),
                             arg={'fields' : TABLE_FIELDS[i],
                                  'size' : 4096})

        ### Group Table ###
            
            
        ### Incoming Static Pipeline ###
        dp.create_module('BPF'          ,name='is_vxlan')
        dp.create_module('VXLANDecap'   , name='IN_VXLAN')
        dp.connect_modules('INC_PHY'    ,'is_vxlan'    , 0, 0)
        dp.connect_modules('is_vxlan'   ,'t0'          , 0, 0)
        dp.run_module_command('is_vxlan',
                              'add',
                              arg=[{'filter':'ip and udp dst port 4789',
                                    'gate':1}])
        dp.connect_modules('is_vxlan'   ,'IN_VXLAN'    , 1, 0)
        dp.connect_modules('IN_VXLAN'   ,'t0'          , 0, 0)
                                                      

        ### Outgoing Static Pipeline ###
        dp.create_module('VXLANEncap'   , name='OUT_VXLAN')
        dp.create_module('IPEncap'      , name='ip_encap')
        dp.create_module('EtherEncap'   , name='ether_encap')  
        dp.connect_modules('OUT_VXLAN'  , 'ip_encap'   , 0, 0)
        dp.connect_modules('ip_encap'   , 'ether_encap', 0, 0)
        dp.connect_modules('ether_encap', 'OUT_PHY'    , 0, 0)
            
    finally:
        dp.resume_all()


        
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


    if init_lcl_port(dp, LCL_NAME, 0)['name'] == LCL_NAME:
        print "Successfully created VPort port : %s" % LCL_NAME
    else:
        print 'Failed to create VPort port.'


    for port_num, port in of_ports.iteritems():
        ret, sock = init_pktinout_port(dp, port.name)
        of_ports[port_num] = of_ports[port_num]._replace(pkt_inout_socket=sock)
        print ret, ' ', of_ports[port_num].pkt_inout_socket

    init_modules(dp)
        
    while of_agent_start(ctl_ip=args.ctl) == errno.ECONNREFUSED:
        pass
        
    # TODO: Start a thread that will select poll on all of those UNIX sockets
    t2 = threading.Thread(name="PACKET_IN thread", target=run_epoll)
    t2.setDaemon(True)
    t2.start()

    nova_agent_start()

    signal.pause()

