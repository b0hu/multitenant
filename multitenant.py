from operator import attrgetter
from ryu.base import app_manager
#from ryu.app.simple_switch_13 import add_flow
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class sdn_vlan(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.vlan_set = {
                '00:00:00:00:00:01':2,
                '00:00:00:00:00:02':3,
                '00:00:00:00:00:03':1,
                '00:00:00:00:00:04':2,
                '00:00:00:00:00:05':3,
                '00:00:00:00:00:06':1,
                '00:00:00:00:00:07':2,
                '00:00:00:00:00:08':3,
                '00:00:00:00:00:09':1,
                '00:00:00:00:00:0a':2,
                '00:00:00:00:00:0b':3,
                '00:00:00:00:00:0c':1,
                '00:00:00:00:00:0d':2,
                '00:00:00:00:00:0e':3,
                '00:00:00:00:00:0f':1,
                '00:00:00:00:00:10':2,
            }
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        #send unkown packets to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if self.vlan_set[dst]==self.vlan_set[src]:

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            
            elif self.vlan_set[dst]==self.vlan_set[src]:
                out_port = ofproto.OFPP_FLOOD
            

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.drop_flow(datapath, 1, match)
            #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            #datapath.send_msg(out)


    def drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        msg = parser.OFPFlowMod(datapath,table_id = OFDPA_FLOW_TABLE_ID_ACL_POLICY,priority = priority,command = ofproto.OFPFC_ADD,match = match,instructions = instruction)
        datapath.send_msg(msg)
                           
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
