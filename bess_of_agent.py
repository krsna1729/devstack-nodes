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
from collections import namedtuple
#TODO: Remove this along with the hack of iterating to find the rule causing PACKET_IN
from scapy.all import *
logging.basicConfig(level=logging.ERROR)

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
            print 'Got a PKT_IN that is not Ethernet 2'
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

        print 'PACKET_IN Cookie:', cookie
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
        if name != 'vxlan':
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

        else:
            print 'Unhandled message OFPT_MULTIPART_REQUEST type:\n', msg

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

    else:
        print 'Unhandled message type:\n', msg
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

    # TODO: Start a thread that will select poll on all of those UNIX sockets
    t2 = threading.Thread(name="PACKET_IN thread", target=run_epoll)
    t2.setDaemon(True)
    t2.start()

    nova_agent_start()

    signal.pause()

