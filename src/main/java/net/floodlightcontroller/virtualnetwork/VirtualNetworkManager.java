/**
 *    Copyright 2015, PONTIFICIA UNIVERSIDAD CATOLICA DEL PERU
 *    @author Gabriel Cuba
 *   
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may 
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *    
 *         http://www.apache.org/licenses/LICENSE-2.0 
 *    
 *    Unless required by applicable law or agreed to in writing, software 
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.virtualnetwork;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.ListenableFuture;

public class VirtualNetworkManager implements IFloodlightModule, IVirtualNetworkService, IOFMessageListener {
	protected static Logger log = LoggerFactory.getLogger(VirtualNetworkManager.class);

	private static final short APP_ID = 20;

	static {
		AppCookie.registerApp(APP_ID, "VirtualNetworkManager");

	}

	// Our dependencies
	IFloodlightProviderService floodlightProviderService;
	IRestApiService restApiService;
	IDeviceService deviceService;
	protected IOFSwitchService switchService;

	// Our internal state
	protected Map<String, VirtualNetwork> vNetsByvnid; // List of all created
														// virtual networks
	protected Map<String, String> nameTovnid; // Logical name -> Network ID
	protected Map<MacAddress, String> macTovnid; // Host MAC -> Network ID
	protected Map<String, ArrayList<VlanRule>> apVlanRuleToVnid; // Ap VlanRule
																	// ID ->
																	// Network
																	// ID
	protected Map<String, ArrayList<VlanRule>> ipVlanRuleToVnid; // IP VlanRule
																	// ID ->
																	// Network
																	// ID
	protected Map<String, ArrayList<VlanRule>> macVlanRuleToVnid; // MAC
																	// VlanRule
																	// ID ->
																	// Network
																	// ID
	protected Map<String, Set<DatapathId>> vnidToSwitch;
	protected Map<String, Map<DatapathId, ArrayList<OFPort>>> vnidToSwitch2;
	protected BitSet[] filterTable;

	// Device Listener impl class
	protected DeviceListenerImpl deviceListener;

	// IVirtualNetworkService2

	@Override
	public void createNetwork(String vnid, String network) {
		if (log.isDebugEnabled()) {
			log.debug("Creating network {} with ID", new Object[] { network, vnid });
		}

		if (!nameTovnid.isEmpty()) {
			// We have to iterate all the networks to handle name/gateway
			// changes
			for (Entry<String, String> entry : nameTovnid.entrySet()) {
				if (entry.getValue().equals(vnid)) {
					nameTovnid.remove(entry.getKey());
					break;
				}
			}
		}
		if (network != null)
			nameTovnid.put(network, vnid);
		if (vNetsByvnid.containsKey(vnid))
			vNetsByvnid.get(vnid).setName(network); // network already exists,
													// just updating name
		else
			vNetsByvnid.put(vnid, new VirtualNetwork(network, vnid)); // new
		// network
		apVlanRuleToVnid.put(vnid, new ArrayList<VlanRule>());
		macVlanRuleToVnid.put(vnid, new ArrayList<VlanRule>());
		ipVlanRuleToVnid.put(vnid, new ArrayList<VlanRule>());
		vnidToSwitch.put(vnid, new HashSet<DatapathId>());
		if (filterTable[Integer.parseInt(vnid)] == null) {
			filterTable[Integer.parseInt(vnid)] = new BitSet(4096);
		}
	}

	@Override
	public void deleteNetwork(String vnid) {
		String name = null;
		if (nameTovnid.isEmpty()) {
			log.warn("Could not delete network with ID {}, network doesn't exist", vnid);
			return;
		}
		for (Entry<String, String> entry : nameTovnid.entrySet()) {
			if (entry.getValue().equals(vnid)) {
				name = entry.getKey();
				break;
			}
			log.warn("Could not delete network with ID {}, network doesn't exist", vnid);
		}

		if (log.isDebugEnabled())
			log.debug("Deleting network with name {} ID {}", name, vnid);

		nameTovnid.remove(name);
		if (vNetsByvnid.get(vnid) != null) {
			vNetsByvnid.get(vnid).clearHosts();
			vNetsByvnid.remove(vnid);
			apVlanRuleToVnid.remove(vnid);
			macVlanRuleToVnid.remove(vnid);
			ipVlanRuleToVnid.remove(vnid);
		}

	}

	@SuppressWarnings("unchecked")
	public void blockNetworks(String vnid, String networks, Integer block) {
		Integer from = Integer.parseInt((vnid));
		String nets[] = networks.split(",");
		// if (filterTable[from] == null) {
		// filterTable[from] = new BitSet(4096);
		// }
		for (String net : nets) {
			Integer to = Integer.parseInt(net);
			if (block == 1) {
				if (!filterTable[from].get(to)) {
					filterTable[from].set(to, true);
					if (filterTable[to] == null) {
						filterTable[to] = new BitSet(4096);
						filterTable[to].set(from, true);
					}
				}
			} else {
				if (filterTable[from].get(to)) {
					filterTable[from].set(to, false);
					if (filterTable[to] == null) {
						filterTable[to] = new BitSet(4096);
						filterTable[to].set(from, false);
					}
				}
			}
		}

		/*
		 * in all switches
		 * 
		 * get ports related to vnid 
		 * for each port  in table 0, add flows to redirect packets from those ports to table #1 with timeout 0s 
		 * get DstMAC from all flows that are not from the same vlan 
		 * for each dstMAC: in table 1, add flow to discard packets with dstMAC with timeout 200 s
		 */

		// We need to remove the flows which are now forbidden
		// Better we insert discard flows
		// We get all the switches
		Set<DatapathId> swID = vnidToSwitch.get(vnid);
		//Map<DatapathId, ArrayList<OFPort>> swPorts = vnidToSwitch2.get(vnid);
		if (swID != null) {
			for (DatapathId id : swID) {
				// For every switch
				IOFSwitch sw = switchService.getSwitch(id);
				ListenableFuture<?> future;
				List<OFStatsReply> values = null;
				if (sw != null) {
					OFStatsRequest<?> req = null;
					Match match;
					match = sw.getOFFactory().buildMatch().build();
					req = sw.getOFFactory().buildFlowStatsRequest().setMatch(match).setOutPort(OFPort.ANY)
							.setTableId(TableId.ALL).build();
					try {
						if (req != null) {
							future = sw.writeStatsRequest(req);
							values = (List<OFStatsReply>) future.get(10, TimeUnit.SECONDS);
						}
					} catch (Exception e) {
						log.error("Failure retrieving statistics from switch " + sw, e);
					}
				}
				// List<OFFlowDelete> fmList=new ArrayList<OFFlowDelete>();
				for (OFStatsReply statsReply : values) { // for each flow stats
															// reply
					OFFlowStatsReply flowReply = (OFFlowStatsReply) statsReply;

					for (OFFlowStatsEntry entry : flowReply.getEntries()) {
						//U64 flowCookie = entry.getCookie();
						//U64 compare = AppCookie.makeCookie(2, Integer.parseInt(vnid));
						Match match = entry.getMatch();
						MacAddress dstMac = match.get(MatchField.ETH_DST);
						String dstVnid = null;
						if (dstMac != null)
							dstVnid = macTovnid.get(dstMac);
						if (dstVnid != null && dstVnid.equals(vnid)) {
							OFFlowDelete fm = sw.getOFFactory().buildFlowDelete().setMatch(match).build();
							try {
								sw.write(fm);
							} catch (Exception e) {
								log.error("Failed to clear flows on switch {} - {}", this, e);
							}
						}
					}

				}

			}
		}
	}

	public List<Short> getBlockedNetworks(String vnid) {
		short i;
		List<Short> lista = new ArrayList<Short>();
		if (filterTable[Integer.parseInt(vnid)] != null) {
			for (i = 1; i < 4095; i++) {
				if (filterTable[Integer.parseInt(vnid)].get((int) i)) {
					lista.add(i);
				}
			}
		}
		return lista;
	}

	public Iterator<? extends SwitchPort> getNetworkDevices(String vnid) {
		List<SwitchPort> aps = new ArrayList<SwitchPort>();
		Set<MacAddress> hostList = vNetsByvnid.get(vnid).getHosts();
		Iterator<MacAddress> hostIt = hostList.iterator();
		@SuppressWarnings("unchecked")
		Iterator<IDevice> it = (Iterator<IDevice>) deviceService.getAllDevices();
		while (it.hasNext() && hostIt.hasNext()) {
			IDevice dev = it.next();
			if (dev.getMACAddress().equals(hostIt.next())) {
				aps.add(dev.getAttachmentPoints()[0]);
			}
		}
		return aps.iterator();
	}
	
	public Map<DatapathId,Set<OFPort>> getSwitchPortsFromVlan(String id){
		Map<DatapathId,Set<OFPort>> map= vNetsByvnid.get(id).getAps();
		return map;
	}

	@SuppressWarnings("unchecked")
	public void addVlanRule(Integer type, String match, String vnid) {

		if (vnid != null) {
			VlanRule vlanRule = new VlanRule(type, match, vnid);
			switch (type) {
			case 1:
				apVlanRuleToVnid.get(vnid).add(vlanRule);
				Iterator<IDevice> it = (Iterator<IDevice>) deviceService.queryDevices(MacAddress.NONE, null, IPv4Address.NONE,
						IPv6Address.NONE, DatapathId.of(match.split("-")[0]), OFPort.of(Integer.parseInt(match.split("-")[1])));
				while (it.hasNext()) {
					IDevice dev = it.next();
					if (dev.getAttachmentPoints().length > 0) {
						vNetsByvnid.get(vnid).addHost(dev.getMACAddress(), type,dev.getAttachmentPoints()[0]);
						// Remove host from default vNetwork
						vNetsByvnid.get("1").removeHost(dev.getMACAddress(), 0, dev.getAttachmentPoints()[0]);
						macTovnid.put(dev.getMACAddress(), vnid);
						vnidToSwitch.get(vnid).add(dev.getAttachmentPoints()[0].getSwitchDPID());
						this.setTableMissPerPort(vnid, dev.getAttachmentPoints()[0]);
						log.info("Setting tableMiss in {} for node {}", new Object[] { dev.getAttachmentPoints()[0] },
								new Object[] { dev.getMACAddress() });
					}
				}
				break;
			case 2:
				macVlanRuleToVnid.get(vnid).add(vlanRule);
				Iterator<IDevice> it1 = (Iterator<IDevice>) deviceService.queryDevices(MacAddress.of(match), null, IPv4Address.NONE,
						IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
				while (it1.hasNext()) {
					IDevice dev = it1.next();
					if (dev.getAttachmentPoints().length > 0) {
						vNetsByvnid.get(vnid).addHost(dev.getMACAddress(), type,dev.getAttachmentPoints()[0]);
						vNetsByvnid.get("1").removeHost(dev.getMACAddress(), 0,dev.getAttachmentPoints()[0]);
						macTovnid.put(dev.getMACAddress(), vnid);
						vnidToSwitch.get(vnid).add(dev.getAttachmentPoints()[0].getSwitchDPID());
						this.setTableMissPerPort(vnid, dev.getAttachmentPoints()[0]);
						log.info("Setting tableMiss in {} for node {}", new Object[] { dev.getAttachmentPoints()[0] },
								new Object[] { dev.getMACAddress() });
					}
				}
				break;
			case 3:
				ipVlanRuleToVnid.get(vnid).add(vlanRule);
				Iterator<IDevice> it2 = (Iterator<IDevice>) deviceService.queryDevices(MacAddress.NONE, null,
						IPv4Address.of(match), IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
				while (it2.hasNext()) {
					IDevice dev = it2.next();
					if (dev.getAttachmentPoints().length > 0) {
						vNetsByvnid.get(vnid).addHost(dev.getMACAddress(), type,dev.getAttachmentPoints()[0]);
						vNetsByvnid.get("1").removeHost(dev.getMACAddress(), 0,dev.getAttachmentPoints()[0]);
						macTovnid.put(dev.getMACAddress(), vnid);
						vnidToSwitch.get(vnid).add(dev.getAttachmentPoints()[0].getSwitchDPID());
						this.setTableMissPerPort(vnid, dev.getAttachmentPoints()[0]);
						log.info("Setting tableMiss in {} for node {}", new Object[] { dev.getAttachmentPoints()[0] },
								new Object[] { dev.getMACAddress() });
					}
				}
				break;
			}
		}
	}

	public void deleteVlanRule(String id, String vnid, Integer type) {
		int id2 = Integer.parseInt(id);
		switch (type) {
		case 1:
			apVlanRuleToVnid.get(vnid).remove(id2);
			break;
		case 2:
			macVlanRuleToVnid.get(vnid).remove(id2);
			break;
		case 3:
			ipVlanRuleToVnid.get(vnid).remove(id2);
			break;
		}
	}

	@Override
	public Collection<VirtualNetwork> listNetworks() {
		return vNetsByvnid.values();
	}

	@Override
	public Map<String, VlanRule> listVlanRule() {
		Map<String, VlanRule> map = new HashMap<>();
		Integer i;
		for (Entry<String, ArrayList<VlanRule>> entry : apVlanRuleToVnid.entrySet()) {
			for (i = 0; i < entry.getValue().size(); i++) {
				map.put(1 + "-" + entry.getKey().toString() + "-" + i, entry.getValue().get(i));
			}
		}

		for (Entry<String, ArrayList<VlanRule>> entry : macVlanRuleToVnid.entrySet()) {
			for (i = 0; i < entry.getValue().size(); i++) {
				map.put(2 + "-" + entry.getKey().toString() + "-" + i, entry.getValue().get(i));
			}
		}
		for (Entry<String, ArrayList<VlanRule>> entry : ipVlanRuleToVnid.entrySet()) {
			for (i = 0; i < entry.getValue().size(); i++) {
				map.put(3 + "-" + entry.getKey().toString() + "-" + i, entry.getValue().get(i));
			}
		}
		return map;
	}

	@Override
	public Map<String, VlanRule> listVlanRuleByVnid(String vnid) {
		Map<String, VlanRule> map = new HashMap<>();
		Integer j;
		for (j = 0; j < apVlanRuleToVnid.get(vnid).size(); j++) {
			map.put(1 + "-" + vnid + "-" + j.toString(), apVlanRuleToVnid.get(vnid).get(j));
			map.put(2 + "-" + vnid + "-" + j.toString(), macVlanRuleToVnid.get(vnid).get(j));
			map.put(3 + "-" + vnid + "-" + j.toString(), ipVlanRuleToVnid.get(vnid).get(j));
		}
		return map;
	}

	@Override
	public Map<String, VlanRule> listVlanRuleByVnidAndType(String vnid, Integer type) {
		Map<String, VlanRule> map = new HashMap<>();
		Integer j;
		switch (type) {
		case 1:
			for (j = 0; j < apVlanRuleToVnid.get(vnid).size(); j++) {
				map.put(1 + "-" + vnid + "-" + j.toString(), apVlanRuleToVnid.get(vnid).get(j));
			}
		case 2:
			for (j = 0; j < macVlanRuleToVnid.get(vnid).size(); j++) {
				map.put(2 + "-" + vnid + "-" + j.toString(), macVlanRuleToVnid.get(vnid).get(j));
			}
		case 3:
			for (j = 0; j < ipVlanRuleToVnid.get(vnid).size(); j++) {
				map.put(3 + "-" + vnid + "-" + j.toString(), ipVlanRuleToVnid.get(vnid).get(j));
			}
		}
		return map;
	}

	// IFloodlightModule

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IVirtualNetworkService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(IVirtualNetworkService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IOFSwitchService.class);
		l.add(IRestApiService.class);
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		vNetsByvnid = new ConcurrentHashMap<String, VirtualNetwork>();
		vNetsByvnid.put("1", new VirtualNetwork("default", "1"));
		macTovnid = new ConcurrentHashMap<MacAddress, String>();
		nameTovnid = new ConcurrentHashMap<String, String>();
		apVlanRuleToVnid = new ConcurrentHashMap<String, ArrayList<VlanRule>>();
		ipVlanRuleToVnid = new ConcurrentHashMap<String, ArrayList<VlanRule>>();
		macVlanRuleToVnid = new ConcurrentHashMap<String, ArrayList<VlanRule>>();
		vnidToSwitch = new ConcurrentHashMap<String, Set<DatapathId>>();
		vnidToSwitch.put("1", new HashSet<DatapathId>());
		filterTable = new BitSet[4096];
		filterTable[1] = new BitSet(4096);
		deviceListener = new DeviceListenerImpl();

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		restApiService.addRestletRoutable(new VirtualNetworkWebRoutable());
		deviceService.addListener(this.deviceListener);

	}

	// IOFMessageListener

	@Override
	public String getName() {
		return "virtualizer";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Link discovery should go before us so we don't block LLDPs
		return (type.equals(OFType.PACKET_IN) && (name.equals("linkdiscovery") || (name.equals("devicemanager"))));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// We need to go before forwarding
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding")|| (name.equals("clustering")));
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			return processPacketIn(sw, (OFPacketIn) msg, cntx);
		default:
			break;
		}
		log.warn("Received unexpected message {}", msg);
		return Command.CONTINUE;
	}

	/**
	 * Processes an OFPacketIn message and decides if the OFPacketIn should be
	 * dropped or the processing should continue.
	 * 
	 * @param sw
	 *            The switch the PacketIn came from.
	 * @param msg
	 *            The OFPacketIn message from the switch.
	 * @param cntx
	 *            The FloodlightContext for this message.
	 * @return Command.CONTINUE if processing should be continued, Command.STOP
	 *         otherwise.
	 */
	private Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Command ret = Command.STOP;
		Integer srcNet = AppCookie.extractUser(msg.getCookie());
		// String srcNetwork = macTovnid.get(eth.getSourceMACAddress());
		// If the host is on an unknown network we deny it.
		// We make exceptions for ARP and DHCP.
		if (eth.getEtherType() == EthType.ARP || eth.isBroadcast() || eth.isMulticast()) {
			ret = Command.CONTINUE;
		} else {
			Boolean bool = oneSameNetwork(eth.getSourceMACAddress(), srcNet.toString(), eth.getDestinationMACAddress(), sw.getId().toString(),eth.getEtherType().toString());
			if (bool == null) {
				log.trace("Blocking traffic from host {} because it is not attached to any network.",
						eth.getSourceMACAddress().toString());
				ret = Command.STOP;
			} else if (bool.equals(Boolean.TRUE)) {
				// if they are on the same network continue
				ret = Command.CONTINUE;
				log.trace("Flow {} will be processed by Clustering or Forwarding", new Object[] { eth.getSourceMACAddress() });
			} else {
				IRoutingDecision decision = new RoutingDecision(sw.getId(), msg.getMatch().get(MatchField.IN_PORT),
						IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
						IRoutingDecision.RoutingAction.DROP);
				decision.addToContext(cntx);
				ret = Command.CONTINUE;
			}
		}
		if (log.isTraceEnabled())
			log.trace("Results for flow between {} and {} is {}",
					new Object[] { eth.getSourceMACAddress(), eth.getDestinationMACAddress(), ret });
		/*
		 * TODO - figure out how to still detect gateways while using drop mods
		 * if (ret == Command.STOP) { if (!(eth.getPayload() instanceof ARP))
		 * doDropFlow(sw, msg, cntx); }
		 */
		return ret;
	}

	/**
	 * Checks to see if two MAC Addresses are on the same network.
	 * 
	 * @param m1
	 *            The first MAC.
	 * @param m2
	 *            The second MAC.
	 * @return True if they are on the same virtual network, false otherwise.
	 */
	protected Boolean oneSameNetwork(MacAddress m1, String net, MacAddress m2, String id,String type) {
		String net1 = net;
		String net2 = macTovnid.get(m2);
		log.info("Net1 {} to Net2 {} ", new Object[] { m1 + " " + net1 }, new Object[] { m2 + " " + net2 });
		if (net1 == null || net1.equals("0")) {
			log.debug("Net of H1 {} is {} , device probably was not yet discovered or packet received in a core switch, will drop...",new Object[] {id + " " + type + " " + m1}, new Object[] {net1});
			///return Boolean.TRUE;
			return null;
			}
		if (net2 == null)
			return null;
		return !filterTable[Integer.parseInt(net1)].get(Integer.parseInt(net2));

	}

	// IDeviceListener
	class DeviceListenerImpl implements IDeviceListener {

		@Override
		public void deviceAdded(IDevice device) {
			boolean b = false;
			if (device.getAttachmentPoints().length > 0) {
				if (this.addByAP(device) || this.addByMAC(device)) {
					b = true;
				}
				// IPv4Address[] ips = device.getIPv4Addresses();
				// int len=ips.length;
				// if (len>0) {
				// if(!device.getIPv4Addresses()[0].equals(IPv4Address.of("0.0.0.0"))){
				if (!this.addByIP(device) && !b) {
					vNetsByvnid.get("1").addHost(device.getMACAddress(), 0,device.getAttachmentPoints()[0]);
					macTovnid.put(device.getMACAddress(), "1");
					vnidToSwitch.get("1").add(device.getAttachmentPoints()[0].getSwitchDPID());
					VirtualNetworkManager.this.setTableMissPerPort("1", device.getAttachmentPoints()[0]);
					log.info("Setting tableMiss in {} for node {} for vNID=1", new Object[] { device.getAttachmentPoints() },
							new Object[] { device.getMACAddress() });
				}
				//TODO set tableMiss for non default vNetwork
			}
		}

		@Override
		public void deviceRemoved(IDevice device) {
			for (Entry<String, VirtualNetwork> entry : vNetsByvnid.entrySet()) {
				entry.getValue().removeHost(device.getMACAddress(), 0, device.getAttachmentPoints()[0]);
				VirtualNetworkManager.this.removeTableMissPerPort(entry.getKey(), device.getAttachmentPoints()[0]);
				log.info("Removing tableMiss in {} for node {}", new Object[] { device.getAttachmentPoints()[0] },
						new Object[] { device.getMACAddress() });
			}
		}

		@Override
		public void deviceIPV4AddrChanged(IDevice device) {
			//If device has at least one AP
			if (device.getAttachmentPoints().length > 0
					&& !device.getIPv4Addresses()[0].equals(IPv4Address.of("0.0.0.0"))) {
				boolean b = false;
				// we search through vnid=1
				b = vNetsByvnid.get("1").removeHost(device.getMACAddress(), 0, device.getAttachmentPoints()[0]);
				if (b) {
					/*VirtualNetworkManager.this.removeTableMissPerPort("1", device.getAttachmentPoints()[0]);
					log.info("Removing tableMiss in {} for node {}", new Object[] { device.getAttachmentPoints()[0] },
							new Object[] { device.getMACAddress() });*/
				} else {
					for (Entry<String, VirtualNetwork> entry : vNetsByvnid.entrySet()) {
						b = entry.getValue().removeHost(device.getMACAddress(), 3, device.getAttachmentPoints()[0]);// si
																					// el
																					// tipo
																					// es
																					// 2
						if (b) {
							/*VirtualNetworkManager.this.removeTableMissPerPort(entry.getKey(),
									device.getAttachmentPoints()[0]);
							log.info("Removing tableMiss in {} for node {}",
									new Object[] { device.getAttachmentPoints()[0] },
									new Object[] { device.getMACAddress() });*/
						}
					}
				}
				if (!this.addByIP(device) && b) {
					vNetsByvnid.get("1").addHost(device.getMACAddress(), 0, device.getAttachmentPoints()[0]);
					macTovnid.put(device.getMACAddress(), "1");
					VirtualNetworkManager.this.setTableMissPerPort("1", device.getAttachmentPoints()[0]);
					log.info("Setting tableMiss in {} for node {} for vNID=1", new Object[] { device.getAttachmentPoints()[0] },
							new Object[] { device.getMACAddress() });
				}
			}
		}

		@Override
		public void deviceMoved(IDevice device) {
			if (device.getAttachmentPoints().length > 0) {
				for (Entry<String, VirtualNetwork> entry : vNetsByvnid.entrySet()) {
					entry.getValue().removeHost(device.getMACAddress(), 1, device.getAttachmentPoints()[0]);// si
																			// el
																			// tipo
																			// es
																			// 3
					VirtualNetworkManager.this.removeTableMissPerPort(entry.getKey(), device.getAttachmentPoints()[0]);
					log.info("Removing tableMiss in {} for node {}", new Object[] { device.getAttachmentPoints()[0] },
							new Object[] { device.getMACAddress() });

				}
				///TODO
				if (!this.addByAP(device)&!this.addByIP(device)) {
					vNetsByvnid.get("1").addHost(device.getMACAddress(), 0, device.getAttachmentPoints()[0]);
					macTovnid.put(device.getMACAddress(), "1");
					VirtualNetworkManager.this.setTableMissPerPort("1", device.getAttachmentPoints()[0]);
					log.info("Setting tableMiss in {} for node {}  for vNID=1", new Object[] { device.getAttachmentPoints()[0] },
							new Object[] { device.getMACAddress() });
				}
			}
		}

		@Override
		public void deviceVlanChanged(IDevice device) {
			// ignore
		}

		@Override
		public String getName() {
			// return VirtualNetworkManager.this.getName();
			return "";
		}

		@Override
		public boolean isCallbackOrderingPrereq(String type, String name) {
			return false;
		}

		@Override
		public boolean isCallbackOrderingPostreq(String type, String name) {
			// We need to go before forwarding
			return false;
		}

		public boolean addByAP(IDevice device) {
			String apString;
			boolean b = false;
			for (SwitchPort i : device.getAttachmentPoints()) {
				apString = i.getSwitchDPID().toString() + "-" + i.getPort().toString();
				for (Entry<String, ArrayList<VlanRule>> entry : apVlanRuleToVnid.entrySet()) {
					for (VlanRule rule : entry.getValue()) {
						if (apString.equals(rule.getMatch())) {
							vNetsByvnid.get(entry.getKey()).addHost(device.getMACAddress(), 1, device.getAttachmentPoints()[0]);
							macTovnid.put(device.getMACAddress(), rule.getVnid());

							vnidToSwitch.get(rule.getVnid()).add(device.getAttachmentPoints()[0].getSwitchDPID());
							b = true;
							VirtualNetworkManager.this.setTableMissPerPort(rule.getVnid(),
									device.getAttachmentPoints()[0]);
							break;
						}
					}
				}

			}
			return b;
		}

		public boolean addByMAC(IDevice device) {
			String mac = device.getMACAddressString();
			boolean b = false;
			for (Entry<String, ArrayList<VlanRule>> entry : macVlanRuleToVnid.entrySet()) {
				for (VlanRule rule : entry.getValue()) {
					if (mac.equals(rule.getMatch())) {
						vNetsByvnid.get(entry.getKey()).addHost(device.getMACAddress(), 2, device.getAttachmentPoints()[0]);
						macTovnid.put(device.getMACAddress(), rule.getVnid());
						vnidToSwitch.get(rule.getVnid()).add(device.getAttachmentPoints()[0].getSwitchDPID());
						VirtualNetworkManager.this.setTableMissPerPort(rule.getVnid(), device.getAttachmentPoints()[0]);
						b = true;
						break;
					}
				}
			}
			return b;
		}

		public boolean addByIP(IDevice device) {
			String ipString = null;
			boolean b = false;
			for (IPv4Address i : device.getIPv4Addresses()) {
				ipString = i.toString();
				for (Entry<String, ArrayList<VlanRule>> entry : ipVlanRuleToVnid.entrySet()) {
					for (VlanRule rule : entry.getValue()) {
						if (ipString.equals(rule.getMatch())) {
							vNetsByvnid.get(entry.getKey()).addHost(device.getMACAddress(), 3, device.getAttachmentPoints()[0]);
							macTovnid.put(device.getMACAddress(), rule.getVnid());
							vnidToSwitch.get(rule.getVnid()).add(device.getAttachmentPoints()[0].getSwitchDPID());
							VirtualNetworkManager.this.setTableMissPerPort(rule.getVnid(),
									device.getAttachmentPoints()[0]);
							b = true;
							break;
						}
					}
				}
			}
			return b;
		}

		@Override
		public void deviceIPV6AddrChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}

	}

	protected void setTableMissPerPort(String vnid, SwitchPort sp) {
		IOFSwitch sw = switchService.getSwitch(sp.getSwitchDPID());
		OFFactory factory = sw.getOFFactory();
		Match.Builder mb = factory.buildMatch();
		mb.setExact(MatchField.IN_PORT, sp.getPort());
		// mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		Match match = mb.build();
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		U64 cookie = AppCookie.makeCookie(APP_ID, Integer.parseInt(vnid));
		OFActions actions = factory.actions();
		actionList.add(actions.output(OFPort.CONTROLLER, 0xffFFffFF));
		OFInstructions inst = factory.instructions();
		OFInstructionApplyActions apply = inst.buildApplyActions().setActions(actionList).build();
		// OFInstructionGotoTable goToTable = inst.gotoTable(TableId.ZERO);
		ArrayList<OFInstruction> instList = new ArrayList<OFInstruction>();
		instList.add(apply);
		OFFlowAdd flowAdd = factory.buildFlowAdd().setBufferId(OFBufferId.NO_BUFFER).setPriority(1).setMatch(match)
				.setInstructions(instList).setCookie(cookie).build();
		sw.write(flowAdd);

	}

	protected void removeTableMissPerPort(String vnid, SwitchPort sp) {
		IOFSwitch sw = switchService.getSwitch(sp.getSwitchDPID());
		OFFactory factory = sw.getOFFactory();
		Match.Builder mb = factory.buildMatch();
		U64 cookie = AppCookie.makeCookie(APP_ID, Integer.parseInt(vnid));
		mb.setExact(MatchField.IN_PORT, sp.getPort());
		// mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		Match match = mb.build();
		OFFlowDelete fm = sw.getOFFactory().buildFlowDelete().setMatch(match).setCookie(cookie).build();
		sw.write(fm);

	}
}