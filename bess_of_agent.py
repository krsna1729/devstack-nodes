#!/usr/bin/python
from struct import *
from scapy.all import *
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
import errno
import time
import sys
import os
import os.path
import cStringIO
import pprint
from collections import namedtuple
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
TUNNEL_ID={'name'   : 'tun_id',      #38
           'size'   :  4}


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
    23: ARP_TPA,
    38: TUNNEL_ID
}

TUNSRC   ={'name'   : 'tun_ip_src',
           'size'   :  4}
TUNDST   ={'name'   : 'tun_ip_dst',
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
    0 : [IN_PORT,ETH_TYPE,VLAN_VID,IP_PROTO,IPV4_DST,UDP_SRC,UDP_DST,ARP_TPA],
    1 : [ETH_TYPE,IN_PORT,IPV4_SRC],
    2 : [ETH_TYPE,IPV4_SRC,IPV4_DST],
    3 : [IN_PORT],
    4 : [ETH_TYPE,IPV4_DST],
    5 : [ETH_DST,ETH_SRC,TUNNEL_ID],
    6 : [ETH_TYPE, VLAN_VID]
}

PKT_IN_BYTES = 4096
PHY_NAME = "eth2"
LCL_NAME = "br-int"
CTL_NAME = "ctl"
SOCKET_PATH = '/tmp/bess/unix_' + CTL_NAME
dpid = 0xffff
n_tables = 254

dp = None
flows = {}
groups = {}
group_stats = {}
channel = 0

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
    OFPP_LOCAL:
        default_port._replace(port_no=OFPP_LOCAL, hw_addr=binascii.a2b_hex("0000deadbeef"), name='br-int', curr=0,
                              stats=default_port_stats._replace(port_no=OFPP_LOCAL)),
    1:  default_port._replace(port_no=1, hw_addr=binascii.a2b_hex("0000deaddead"), name='vxlan', curr=0,
                              stats=default_port_stats._replace(port_no=1)),
    2:  default_port._replace(port_no=2, hw_addr=binascii.a2b_hex("000000000001"), name=PHY_NAME, curr=0,
                              stats=default_port_stats._replace(port_no=2)),
}

try:
    BESS_PATH = os.getenv('BESSDK', '/opt/bess')
    sys.path.insert(1, '%s/libbess-python' % BESS_PATH)
    from bess import *
except ImportError as e:
    print >> sys.stderr, 'Cannot import the API module (libbess-python)', e.message
    sys.exit()


def run_pktin_recv():

    s = of_ports[OFPP_LOCAL].pkt_inout_socket
    while True:
        try:
            data = s.recv(PKT_IN_BYTES)
            if len(data) == 0:
                continue
            print len(data), type(data), data
            # TODO: Formalise this. DP to prepend cookie before sending PACKET_IN. Reason also? For now ACTION
            # Format is cookie(8)(Q)+inport(4)(I)
            fmt = "!QI"
            split = calcsize(fmt)
            (cookie, inport) = unpack(fmt, data)

            f = flows[cookie]
            match = b.ofp_match(None, None, oxm.build(None, oxm.OXM_OF_IN_PORT, False, None, inport))
            channel.send(b.ofp_packet_in(b.ofp_header(4, OFPT_PACKET_IN, 0, 0),
                                         0xffffffff, len(data[split:]), OFPR_ACTION, f.table_id, cookie, match, data[split:]))
        except Exception as e:
            print(e)
            break 
 
    # s.close()
    print 'Exiting thread run_pktin_recv'
    return


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
        dp.create_module('PortInc', 'INC_PHY'    , {'port': name})
        dp.create_module('PortOut', 'OUT_PHY'    , {'port': name})
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

    
def init_pktinout_port(dp):

    try:
        dp.pause_all()
        result = dp.create_port('UnixSocket', CTL_NAME, {'path': '@' + SOCKET_PATH})
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect('\0' + SOCKET_PATH)
    except (dp.APIError, dp.Error, socket.error) as err:
        print err
        dp.resume_all()
        return {'name': None}, None
    else:
        dp.create_module('PortInc', 'INC_CTL', {'port': CTL_NAME})
        dp.create_module('PortOut', 'OUT_CTL', {'port': CTL_NAME})
        print 'Created INC_CTL and OUT_CTL'

        dp.resume_all()
        return result, s


def deinit_pktinout_port(dp, s):

    try:
        s.close()
        dp.pause_all()
        dp.destroy_module('INC_CTL')
        dp.destroy_module('OUT_CTL')
        dp.destroy_port(CTL_NAME)
        dp.resume_all()
        return
    except (dp.APIError, dp.Error) as err:
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

    ### UPDATE TABLE ENTRIES
    try:
        dp.pause_all()
        if TABLE_TYPE[table_id] == WILDCARD_MATCH:
            dp.run_module_command(table_name, 'add',
                                  {'priority': priority,
                                   'values'  : values,
                                   'masks'   : masks,
                                   'gate'    : ogate    })
            print 'update SUCCESS'
        elif TABLE_TYPE[table_id] == EXACT_MATCH:
            dp.run_module_command(table_name, 'add',
                                  {'fields'  : values,
                                   'gate'    : ogate    })
            print 'update SUCCESS'
        else:
            print 'UNHANDLED TABLE TYPE ', TABLE_TYPE[table_id]

    except Exception, err:
        print 'update FAIL'
        print err
    finally:
        dp.resume_all()


def case_flow_mod(msg):
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
        case_flow_mod(msg)
    elif msg.header.type == OFPT_GROUP_MOD:
        if msg.group_id in groups:
            print "I already have this GroupMod: ID ", msg.group_id
        print msg.group_id, msg.type, msg.buckets
        groups[msg.group_id] = msg
        # Initializing list of bucket stats with 0s
        group_stats[msg.group_id] = [0]*len(msg.buckets)

    elif msg.header.type == OFPT_MULTIPART_REQUEST:
        # TODO: Collect real FLOW stats and report them. Create a named tuple
        if msg.type == OFPMP_FLOW:
            channel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_flow_stats(None, f.table_id, 1, 2, f.priority,
                                                                f.idle_timeout, f.hard_timeout, f.flags, f.cookie, 0, 0,
                                                                f.match, f.instructions)
                                               for f in flows.itervalues())]))
        # TODO: Collect real GROUP stats and report them. Create a named tuple
        elif msg.type == OFPMP_GROUP:
            ofchannel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_group_stats(None, gid, 0, 0, 0,
                                                                 1, 2, group_stats[gid])
                                               for gid in groups.iterkeys())]))
        elif msg.type == OFPMP_GROUP_DESC:
            ofchannel.send(b.ofp_multipart_reply(b.ofp_header(4, OFPT_MULTIPART_REPLY, 0, msg.header.xid),
                         msg.type, 0, ["".join(b.ofp_group_desc(None, g.type, g.group_id, g.buckets)
                                               for g in groups.itervalues())]))
        # TODO: Collect real PORT stats and report them. We have a namedtuple
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

        fmt = "!I"
        sock = of_ports[OFPP_LOCAL].pkt_inout_socket
        if sock is not None:
            try:
                sent = sock.send(pack(fmt, msg.actions[0].port)+msg.data)
            except socket.error as e:
                print >> sys.stderr, e.message
            else:
                if sent != calcsize(fmt)+len(msg.data):
                    print "Incomplete Transmission Sent:%d, Len:%d" % (sent, calcsize(fmt)+len(msg.data))
        else:
            print "Packet out OF Port %d, Len:%d. Failed - Null socket" % (msg.actions[0].port, len(msg.data))

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
        mac = mac.replace(":", "")
        # Create vhost-user port
        ret = dp.create_port('vhost_user', dev, {'mac': mac})


        of_ports[self.of_port_num] = default_port._replace(
            port_no=self.of_port_num, hw_addr=binascii.a2b_hex(mac[:12]), name=dev,
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

                dp.destroy_port(dev)
                del of_ports[port_no]
                print 'Current OF ports:\n', of_ports
                return "Successfully deleted dev: %s which was ofport: %d" % (dev, port_no)

        return "Unable to locate dev: %s" % dev


def nova_agent_start():
    s = zerorpc.Server(PortManager())
    s.bind("tcp://0.0.0.0:10515")
    print "Port Manager listening on 10515"

    # blocks?
    s.run()

    
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
        dp.create_module('VXLANDecap'   ,name='IN_VXLAN')
        dp.connect_modules('INC_PHY'    ,'is_vxlan'    , 0, 0)
        dp.connect_modules('is_vxlan'   ,'t0'          , 0, 0)
        dp.run_module_command('is_vxlan',
                              'add',
                              arg=[{'filter':'ip and udp dst port 4789',
                                    'gate':1}])
        dp.connect_modules('is_vxlan'   ,'IN_VXLAN'    , 1, 0)
        dp.connect_modules('IN_VXLAN'   ,'t0'          , 0, 0)
        dp.connect_modules('INC_CTL'    ,'t0'          , 0, 0)
        dp.connect_modules('INC_LCL'    ,'t0'          , 0, 0)
        

        ### Outgoing Static Pipeline ###
        dp.create_module('VXLANEncap'   , name='OUT_VXLAN')
        dp.create_module('IPEncap'      , name='ip_encap')
        dp.create_module('EtherEncap'   , name='ether_encap')  
        dp.connect_modules('OUT_VXLAN'  , 'ip_encap'   , 0, 0)
        dp.connect_modules('ip_encap'   , 'ether_encap', 0, 0)
        dp.connect_modules('ether_encap', 'OUT_PHY'    , 0, 0)
            
    finally:
        dp.resume_all()


def trace_test(trace,dbg):
    pkts = rdpcap(trace)
    num_pkts = int(os.environ.get('PKTS', len(pkts)))
    print 'Replaying ', num_pkts, 'packets'
    for i in range(num_pkts):
        if pkts[i]['IP'].dst == '192.168.50.21':
            of_msgs = pkts[i].getlayer(Raw).load
            if dbg: print 'PktNo.', i, binascii.hexlify(of_msgs)
            of_len = 0
            of_len_end = 0
            while len(pkts[i]['Raw']) > of_len:
                of_len_end += unpack_from("!H", of_msgs, 2+of_len)[0]
                if dbg: print '\tOF-Payload range:', of_len, of_len_end, binascii.hexlify(of_msgs)[of_len*2:of_len_end*2]
                msg = p.parse(of_msgs, of_len)
                if msg.header.type == OFPT_FLOW_MOD:
                    if dbg: print '\tTwink Parse out :', msg
                    case_flow_mod(msg)
                of_len = of_len_end   
        
        
if __name__ == "__main__":

    while dp is None:
        dp = connect_bess()
        time.sleep(2)
    dp.resume_all()


    def cleanup(*args):
        dp.pause_all()
        deinit_pktinout_port(dp, of_ports[OFPP_LOCAL].pkt_inout_socket)
        dp.reset_all()
        sys.exit()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dpid', default=1, type=int, help='Datapath ID default=1')
    parser.add_argument('-c', '--ctl', default=None, help='Controller IP. default=None')
    parser.add_argument('-i', '--phy', default="eth2", help='Interface name. default=eth2')
    args = parser.parse_args()

    dpid = args.dpid
    PHY_NAME = args.phy

    if init_phy_port(dp, PHY_NAME, 0)['name'] == PHY_NAME:
        print "Successfully created PMD port : %s" % PHY_NAME
    else:
        print 'Failed to create PMD port. Check if it exists already'

    print 'Initial list of Openflow ports', of_ports

    ret, sock = init_pktinout_port(dp)
    of_ports[OFPP_LOCAL] = of_ports[OFPP_LOCAL]._replace(pkt_inout_socket=sock)
    print ret, ' ', of_ports[OFPP_LOCAL].pkt_inout_socket

    if init_lcl_port(dp, LCL_NAME, 0)['name'] == LCL_NAME:
        print "Successfully created VPort port : %s" % LCL_NAME
    else:
        print 'Failed to create VPort port.'

    init_modules(dp)
        
    while of_agent_start(ctl_ip=args.ctl) == errno.ECONNREFUSED:
        pass
        
    # TODO: Start a thread that will select poll on all of those UNIX sockets
    t2 = threading.Thread(name="PACKET_IN thread", target=run_pktin_recv)
    t2.setDaemon(True)
    t2.start()

    nova_agent_start()

    signal.pause()
