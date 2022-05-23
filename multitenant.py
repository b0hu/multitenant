from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

class sdn_vlan(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(sdn_vlan, self).__init__(*args, **kwargs)
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
        self.hosts = {
                '00:00:00:00:00:01',
                '00:00:00:00:00:02',
                '00:00:00:00:00:03',
                '00:00:00:00:00:04',
                '00:00:00:00:00:05',
                '00:00:00:00:00:06',
                '00:00:00:00:00:07',
                '00:00:00:00:00:08',
                '00:00:00:00:00:09',
                '00:00:00:00:00:0a',
                '00:00:00:00:00:0b',
                '00:00:00:00:00:0c',
                '00:00:00:00:00:0d',
                '00:00:00:00:00:0e',
                '00:00:00:00:00:0f',
                '00:00:00:00:00:10',
                'ff:ff:ff:ff:ff:ff'
            }
        self.vlan_group = {
            1:{
                '00:00:00:00:00:03',
                '00:00:00:00:00:06',
                '00:00:00:00:00:09',
                '00:00:00:00:00:0c',
                '00:00:00:00:00:0f'
            },
            2:{
                '00:00:00:00:00:01',
                '00:00:00:00:00:04',
                '00:00:00:00:00:07',
                '00:00:00:00:00:0a',
                '00:00:00:00:00:0d',
                '00:00:00:00:00:10'
            },
            3:{
                '00:00:00:00:00:02',
                '00:00:00:00:00:05',
                '00:00:00:00:00:08',
                '00:00:00:00:00:0b',
                '00:00:00:00:00:0e'
            }
        }
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        
        #self.logger.info("switch features in %s", datapath)
        #send unkown packets to controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("send to controller")
    

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
        
        dpid = format(datapath.id, "d").zfill(16)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        self.logger.info("packet in dpid:%s, src:%s, dst:%s, in_port:%s", dpid, src, dst, in_port)
        
        if dst not in self.hosts or src not in self.hosts:
            self.logger.debug("invalid! src:%s, dst:%s", src, dst)
            return

        elif dst == 'ff:ff:ff:ff:ff:ff' or self.vlan_set[dst]==self.vlan_set[src]:

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            
            elif dst == 'ff:ff:ff:ff:ff:ff':
                all = self.vlan_group[self.vlan_set[src]]-{src}
                self.logger.info("all address:%s",all)
                out_port = []
                for i in all:
                    if i in self.mac_to_port[dpid]:
                        self.logger("i:%s",i)
                        self.logger("mac_to_port[dpid][i]:%s",self.mac_to_port[dpid][i])
                        out_port = out_port.append(self.mac_to_port[dpid][i])
                self.logger.info("ff:ff:ff:ff:ff:ff:%s",out_port)
                if not out_port:
                    return
            
            else:
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



    def drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        msg = parser.OFPFlowMod(datapath,priority = priority,command = ofproto.OFPFC_ADD,match = match,instructions = instruction)
        datapath.send_msg(msg)
                           
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

#address = vlan_group[vlan_set[dst]]-{dst}
#out_port = [mac_to_port[i] for i in address]
#actions = [parser.OFPActionOutput(out_port)]

#not valid -> drop
#the same vlan memorized -> actions, add
#the same vlan not memorized -> actions, add
#fffff -> actions, add
#different -> drop
