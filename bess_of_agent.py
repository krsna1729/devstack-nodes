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
LCL_NAME = "brint"
CTL_NAME = "ctl"
SOCKET_PATH = '/tmp/bess/unix_' + CTL_NAME
dpid = 0xffff
n_tables = 254

dp = None
pm = None
flows = {}
groups = {}
group_stats = {}
channel = None

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
    fmt = "QI"
    split = calcsize(fmt)
    while True:
        try:
            data = s.recv(PKT_IN_BYTES)
            if len(data) < split+64:
                print 'Frame less than minimum possible size. Skipping..'
                continue
            print len(data), type(data), binascii.hexlify(data)
            # TODO: Formalise this. DP to prepend cookie before sending PACKET_IN. Reason also? For now ACTION
            # Format is cookie(8)(Q)+inport(4)(I)
            #fmt = "QI"
            split = calcsize(fmt)
            cookie, inport, = unpack(fmt, data[:split])
        except Exception as e:
            print 'Exception in run_pktin_recv', e
        else:
            print hex(cookie), inport
            f = flows.get(cookie, None)
            if f is None:
                print 'Cannot find cookie, dropping PKT_IN'
                continue
            match = b.ofp_match(None, None, oxm.build(None, oxm.OXM_OF_IN_PORT, False, None, inport))
            channel.send(b.ofp_packet_in(b.ofp_header(4, OFPT_PACKET_IN, 0, 0),
                                         0xffffffff, len(data[split:]), OFPR_ACTION, f.table_id, cookie, match, data[split:]))
 
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


def port_provision(dp, port, name):
    dp.pause_all()
    try:
        dp.create_module('PortInc', 'INC_' + str(port), {'port': name})
        dp.create_module('PortOut', 'OUT_' + str(port), {'port': name})
        dp.create_module('SetMetadata',
                         name='INC_' + str(port) + '_MARK',
                         arg={'name' : 'in_port',
                         'value' : port,
                         'size' : 4})
        dp.connect_modules('INC_' + str(port),
                           'INC_' + str(port) + '_MARK',
                           0, 0)
        dp.connect_modules('INC_' + str(port) + '_MARK',
                           't0',
                           0, 0)
    except Exception as err:
            print 'ERROR: setting up port'
            print err

    dp.resume_all()


def init_phy_port(dp, name, port_id):
    dp.pause_all()
    try:
        result = dp.create_port('PMD', name, {'port_id': port_id})
        dp.create_module('PortInc', 'INC_PHY'    , {'port': name})
        dp.create_module('PortOut', 'OUT_PHY'    , {'port': name})
        dp.create_module('SetMetadata',
                         name='INC_PHY_MARK',
                         arg={'name' : 'in_port',
                              'value' : 2,
                              'size' : 4})
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
        dp.create_module('SetMetadata',
                         name='INC_LCL_MARK',
                         arg={'name' : 'in_port',
                              'value' : OFPP_LOCAL,
                              'size' : 4})
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
        dp.create_module('SetMetadata',
                         name='INC_CTL_MARK',
                         arg={'name' : 'in_port',
                              'value' : OFPP_CONTROLLER,
                              'size' : 4})
        dp.create_module('GenericEncap',
                         name='OUT_CTL_GENCAP',
                         arg={'fields':[{'name' : 'cookie',  'size' : 8},
                                      {'name' : 'in_port', 'size' : 4}]})
        dp.connect_modules('OUT_CTL_GENCAP', 'OUT_CTL' , 0, 0)
        print 'Created INC_CTL and OUT_CTL'

        dp.resume_all()
        return result, s


def deinit_pktinout_port(dp, s):

    try:
        s.close()
        dp.pause_all()
        dp.destroy_module('INC_CTL')
        dp.destroy_module('OUT_CTL')
        dp.destroy_module('INC_CTL_MARK')
        dp.destroy_module('OUT_CTL_GENCAP')
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
            print 'ERROR: failed to create new VLANPop'
            print err
    finally:
        dp.resume_all()
    return name     


update_cntr=0
def update_field(arg=None):
    global dp
    global update_cntr
    update_tag = None

    if arg is not None:
        update_tag = 'update_' + str(update_cntr)
        update_cntr += 1
        dp.pause_all()
        try:
            dp.create_module('Update',
                             name=update_tag,
                             arg=arg)
        except Exception, err:
            print 'ERROR: failed to update_field'
            print err
        finally:
            dp.resume_all()
        return update_tag


metadata_cntr=0
def set_metadata(arg=None):
    global dp
    global metadata_cntr
    metadata_tag = None

    if arg is not None:
        metadata_tag = 'meta_' + str(metadata_cntr)
        metadata_cntr += 1
        dp.pause_all()
        try:
            dp.create_module('SetMetadata',
                             name=metadata_tag,
                             arg=arg)
        except Exception, err:
            print 'ERROR: failed to set_metadata'
            print err
        finally:
            dp.resume_all()
        return metadata_tag


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



def connect_modules(from_table,to_table, ogate):
    global dp
    print 'CONNECTING: ', from_table, ':', ogate, ' --> ', to_table
    dp.pause_all()
    try:
        dp.connect_modules(from_table, to_table, ogate, 0)
    except Exception, err:
        print 'ERROR: failed to connect modules'
        print err
    finally:
        dp.resume_all()

    
cookie_cntr=0
def output_action(cookie,port,prev_module,next_gate):
    global OGATE_MAPS
    global dp
    global cookie_cntr
    
    if port == OFPP_CONTROLLER:
        ### TAG COOKIE METADATA
        ### AND ENCAPSULATE
        metadata_tag = 'cookie_' + str(cookie_cntr)
        cookie_cntr += 1
        dp.pause_all()
        try:
            dp.create_module('SetMetadata',
                             name=metadata_tag,
                             arg={'name' : 'cookie',
                                  'value' : cookie,
                                  'size' : 8})
        except Exception, err:
            print 'ERROR: failed to setup metadata'
            print err
        finally:
            dp.resume_all()

        connect_modules(prev_module,metadata_tag,next_gate)
        prev_module = metadata_tag
        next_gate = 0

        goto_str = 'OUT_CTL_GENCAP'
    elif port == OFPP_LOCAL:
        goto_str = 'OUT_LCL'
    elif port == 1:
        goto_str = 'OUT_VXLAN'
    elif port == 2:
        goto_str = 'OUT_PHY'
    else:
        goto_str = 'OUT_' + str(port)
        if not port in of_ports:
            print 'ERROR: NONEXISTENT PORT ', goto_str
            return

    connect_modules(prev_module,goto_str,next_gate)


def apply_actions(cookie,actions,prev_module,next_gate):

    for action in actions:

        if action.type == OFPAT_OUTPUT:
            output_action(cookie,
                          action.port,
                          prev_module,
                          next_gate)
            # TERMINAL ACTION

        elif action.type == OFPAT_GROUP:
            goto_str = 'GRP_' + str(action.group_id)
            print '\tto : ',goto_str
            connect_modules(prev_module,goto_str,next_gate)
            # TERMINAL ACTION

        elif action.type == OFPAT_POP_VLAN:
            goto_str = create_new_vlan_pop()
            connect_modules(prev_module,goto_str,next_gate)
            prev_module=goto_str
            next_gate = 0

        elif action.type == OFPAT_SET_FIELD:
            print 'TBD: for now, skip', action, oxm.parse(action.field)
            oparsed = oxm.parse(action.field)
            if oparsed.oxm_class == 32768:
                if oparsed.oxm_field == oxm.OXM_OF_ETH_DST:
                    goto_str = update_field(arg=[{'offset': 6, 'size': 6, 'value': oparsed.oxm_value.encode("hex")}])
                elif oparsed.oxm_field == oxm.OXM_OF_TUNNEL_ID:
                    goto_str = set_metadata(arg={'name': 'tun_id', 'size': 4, 'value': oparsed.oxm_value})

            elif oparsed.oxm_class == 1:
                if oparsed.nxm_field == oxm.NXM_NX_TUN_IPV4_DST:
                    goto_str = set_metadata(arg={'name': 'tun_ip_dst', 'size': 4, 'value': oparsed.nxm_value})
            else:
                print 'ERROR: UNHANDLED OXM_CLASS'
                return
            connect_modules(prev_module,goto_str,next_gate)
            prev_module=goto_str
            next_gate = 0
            
        # UNHANDLED ACTION
        else:
            print 'ERROR: UNHANDLED ACTION'
            return


def handle_group_mod(group_id,command,command_type,buckets):
    global dp

    mod_name = 'GRP_' + str(group_id)
    ### Group Table Entry ###
    dp.pause_all()
    dp.create_module('HashLB',
                      name=mod_name,
                      arg=len(buckets))

    dp.resume_all()
    i = 0
    for bkt in buckets:
        print 'BUCKET ', i
        ### NOTE: uncertain if using group_id in place of cookie is okay
        ### perhaps we should just add cookie metadata to every packet?
        apply_actions(group_id,bkt.actions,mod_name,i)
        i=i+1

        
# ASSUMING 8 TABLES        
OGATE_MAPS = [dict() for i in range(0,8)]
def handle_flow_mod(cookie,table_id,priority,match,instr):
    global dp
    global OGATE_MAPS
    
    for f in match:
        print "field\t", f.oxm_field
        print "value\t", f.oxm_value
        if f.oxm_hasmask:
            print "mask\t", f.oxm_mask
                        
    new_connection = False
    table_name = 't'+str(table_id)
    print '~~~~~~~~~~~~~~~~~~~'
    values, masks = table_match(table_id,match)
    print table_name, ' add'
    print '\tpriority : ',priority
    print '\tvalues   : ',values
    if TABLE_TYPE[table_id] == WILDCARD_MATCH:
        print '\tmasks    : ',masks

    ### Record mapping from this flow_mod to the appropriate outgate
    ogate_map = OGATE_MAPS[table_id]
    ogate = len(ogate_map)
    ogate_map[cookie] = ogate
    print '\tcookie   : ', cookie
    print '\tgate     : ', ogate
        
    if instr is None:
        goto_str = 'DROP'
        print '\tto_table : ',goto_str
        connect_modules(table_name,goto_str,ogate)

    ### GOTO_TABLE
    elif instr.type == OFPIT_GOTO_TABLE:
        goto_str = 't'+str(instr.table_id)
        print '\tto_table : ',goto_str
        connect_modules(table_name,goto_str,ogate)

    ### APPLY_ACTIONS
    elif instr.type == OFPIT_APPLY_ACTIONS:
        print 'APPLY_ACTIONS'
        apply_actions(cookie,instr.actions,table_name,ogate)

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
        print 'ERROR: unable to update table rules'
        print err
    finally:
        dp.resume_all()

        
def case_group_mod(msg):
    print "~~~~~~~~~~~~~~~~~~~~~~~"
    if msg.group_id in groups:
        print "I already have this GroupMod: ID ", msg.group_id
    print msg
    print "------------------------"
    print "GROUP:",
    print msg.group_id
    if msg.command == OFPGC_ADD:
        print "ADD"
    else:
        print "UNHANDLED COMMAND ", msg.command
        return
    if msg.type == OFPGT_SELECT:
        print "SELECT"
    else:
        print "UNHANDLED TYPE ", msg.type
        return
    for b in msg.buckets:
        print "bucket: ",
        print b
    print "!!!!!!!!!!!!!!!!!!!!!!!!"
    handle_group_mod(msg.group_id,msg.command,msg.type,msg.buckets)
    groups[msg.group_id] = msg
    

def case_flow_mod(msg):
    print "========================"
    if msg.cookie in flows:
        msg0 = flows[msg.cookie]
        print "This cookie maps to an existing flow_mod", msg.cookie
        print str(msg0)
        print str(msg)
        if (str(oxm.parse_list(msg.match.oxm_fields)) == str(oxm.parse_list(msg0.match.oxm_fields))
            and str(msg.instructions) == str(msg0.instructions)):
            print "This is a duplicate message, we can safely skip"
            return
        else:
            print "WARNING!!! THIS IS NOT A DUPLICATE MESSAGE!"
            print "THIS CASE IS CURRENTLY UNHANDLED"
            print msg.cookie, oxm.parse_list(msg.match.oxm_fields), (msg.instructions)
            print msg0.cookie, oxm.parse_list(msg0.match.oxm_fields), (msg0.instructions)
            return

    print "------------------------"
    print "OFPT_FLOW_MOD"
    print "table_id:\t", msg.table_id
    print "priority:\t", msg.priority
    match = oxm.parse_list(msg.match.oxm_fields)
    print "match", 
    print match
    if len(msg.instructions) > 1:
        print len(msg.instructions), ' INSTRUCTIONS: NOT HANDLED'
        return
    if len(msg.instructions) == 1:
        i = msg.instructions[0]
        print "instr", i
    else:
        i = None
    handle_flow_mod(msg.cookie, msg.table_id, msg.priority, match, i)
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
        case_group_mod(msg)
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
        port_provision(dp, self.of_port_num, dev)


        of_ports[self.of_port_num] = default_port._replace(
            port_no=self.of_port_num, hw_addr=binascii.a2b_hex(mac[:12]), name=dev,
            stats=default_port_stats._replace(port_no=self.of_port_num))

        ofp = of_ports[self.of_port_num]
        
        if channel:
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
    global pm
    s = zerorpc.Server(pm)
    s.bind("tcp://0.0.0.0:10515")
    print "Port Manager listening on 10515"

    # blocks?
    s.run()

    
def init_modules(dp):
    global TABLE_FIELDS
    dp.pause_all()
    try:
        ### DROP
        dp.create_module('Sink', name='DROP')
        
        ### Tables 0-6 ###
        for i in range(0,7):
            dp.create_module(TABLE_TYPE[i],
                             name='t'+str(i),
                             arg={'fields' : TABLE_FIELDS[i],
                                  'size' : 4096})

        ### Group Table ###
            
        ### Incoming Static Pipeline ###
        dp.create_module('BPF'            , name='is_vxlan')
        dp.create_module('VXLANDecap'     , name='IN_VXLAN')
        dp.create_module('SetMetadata',
                         name='IN_VXLAN_MARK',
                         arg={'name' : 'in_port',
                              'value' : 1,
                              'size' : 4})
        dp.connect_modules('INC_PHY'      , 'INC_PHY_MARK' , 0, 0)
        dp.connect_modules('INC_PHY_MARK' , 'is_vxlan'     , 0, 0)
        dp.connect_modules('is_vxlan'     , 't0'           , 0, 0)
        dp.run_module_command('is_vxlan'  ,
                              'add',
                              arg=[{'filter':'ip and udp dst port 4789',
                                    'gate':1}])
        dp.connect_modules('is_vxlan'     , 'IN_VXLAN'     , 1, 0)
        dp.connect_modules('IN_VXLAN'     , 'IN_VXLAN_MARK', 0, 0)
        dp.connect_modules('IN_VXLAN_MARK', 't0'           , 0, 0)
        #dp.connect_modules('INC_CTL'      , 'INC_CTL_MARK' , 0, 0)
        #dp.connect_modules('INC_CTL_MARK' , 't0'           , 0, 0)
        dp.connect_modules('INC_LCL'      , 'INC_LCL_MARK' , 0, 0)
        dp.connect_modules('INC_LCL_MARK' , 't0'           , 0, 0)
        

        ### Outgoing Static Pipeline ###
        dp.create_module('VXLANEncap'     , name='OUT_VXLAN')
        dp.create_module('IPEncap'        , name='ip_encap')
        dp.create_module('EtherEncap'     , name='ether_encap')  
        dp.connect_modules('OUT_VXLAN'    , 'ip_encap'     , 0, 0)
        dp.connect_modules('ip_encap'     , 'ether_encap'  , 0, 0)
        dp.connect_modules('ether_encap'  , 'OUT_PHY'      , 0, 0)
            
    finally:
        dp.resume_all()


def trace_test(trace, ip, dbg):

    ### CREATE VM PORTS 3 & 4
    for i in range(3,5):
        pname = 'vport_' + str(i)
        pmac  = '{0:012d}'.format(i)
        print 'ADDING NEW PORT ', pname
        print 'w/ mac', pmac
        pm.add_port(pname,pmac)

    pkts = rdpcap(trace)
    num_pkts = int(os.environ.get('PKTS', len(pkts)))
    print 'Replaying ', num_pkts, 'packets'
    for i in range(num_pkts):
        if pkts[i]['IP'].dst == ip:
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
                elif msg.header.type == OFPT_GROUP_MOD:
                    case_group_mod(msg)
                of_len = of_len_end   
        
        
if __name__ == "__main__":

    while dp is None:
        dp = connect_bess()
        time.sleep(2)
    dp.resume_all()


    def cleanup(*args):
        dp.pause_all()
        of_ports[OFPP_LOCAL].pkt_inout_socket.close()
        dp.reset_all()
        sys.exit()

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dpid', default=1, type=int, help='Datapath ID default=1')
    parser.add_argument('-c', '--ctl', default=None, help='Controller IP. default=None')
    parser.add_argument('-p', '--phy', default="eth2", help='Interface name. default=eth2')
    parser.add_argument('-f', '--tracefile', default=None, help='PCAP tracefile path. default=None')
    parser.add_argument('-i', '--traceip', default=None, help='Trace IP to match against. default=None')
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

    pm = PortManager()
        
    init_modules(dp)
    if args.tracefile is not None and args.traceip is not None:
        trace_test(args.tracefile, args.traceip, False)
        print 'Done.'
        of_ports[OFPP_LOCAL].pkt_inout_socket.close()
        sys.exit()
        #cleanup()

    while of_agent_start(ctl_ip=args.ctl) == errno.ECONNREFUSED:
        pass
        
    # TODO: Start a thread that will select poll on all of those UNIX sockets
    t2 = threading.Thread(name="PACKET_IN thread", target=run_pktin_recv)
    t2.setDaemon(True)
    t2.start()

    nova_agent_start()

    signal.pause()

