package net.floodlightcontroller.circuittree;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.floodlightcontroller.circuittree.web.CircuitTreeWebRoutable;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowMod.Builder;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CircuitTreeManager implements ICircuitTreeService, IFloodlightModule, IDeviceListener{
	
	// service modules needed
		protected IRestApiService restApi;
		protected IDeviceService deviceManager;
		protected IStorageSourceService storageSource;
		protected static Logger logger;
		protected ITopologyService topologyService;
		protected IOFSwitchService switchService;
		protected IStaticFlowEntryPusherService sfp;
		protected IRoutingService routingEngine;
		private OFFactory factory = OFFactories.getFactory(OFVersion.OF_13);
		protected Map<IPv4Address, IDevice> serverList;
		protected Map<DatapathId, Integer> switches;
		protected Integer id;
		// variable used
		static final int CircuitTreePriority = 32768;

		@Override
		public Collection<Class<? extends IFloodlightService>> getModuleServices() {
			Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
			l.add(ICircuitTreeService.class);
			return l;
		}

		@Override
		public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
			Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
			// We are the class that implements the service
			m.put(ICircuitTreeService.class, this);
			return m;
		}

		@Override
		public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
			Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
			l.add(IRestApiService.class);
			l.add(IDeviceService.class);
			l.add(IOFSwitchService.class);
			l.add(IRoutingService.class);
			l.add(ITopologyService.class);
			l.add(IStaticFlowEntryPusherService.class);
			return l;
		}

		@Override
		public void init(FloodlightModuleContext context) throws FloodlightModuleException {
			restApi = context.getServiceImpl(IRestApiService.class);
			deviceManager = context.getServiceImpl(IDeviceService.class);
			logger = LoggerFactory.getLogger(CircuitTreeManager.class);
			sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
			switchService = context.getServiceImpl(IOFSwitchService.class);
			topologyService = context.getServiceImpl(ITopologyService.class);
			routingEngine = context.getServiceImpl(IRoutingService.class);
			serverList = new HashMap<IPv4Address, IDevice>();
			switches = new HashMap<DatapathId, Integer>();
			id = 1;
		}

		@Override
		public void startUp(FloodlightModuleContext context) {
			// register REST interface
			restApi.addRestletRoutable(new CircuitTreeWebRoutable());
			deviceManager.addListener(this);
		}

		/**
		 * listen for new device
		 */
		@Override
		public void deviceAdded(IDevice device) {

			if (device.getAttachmentPoints().length > 0) {
				DatapathId sw = device.getAttachmentPoints()[0].getSwitchDPID();
				if (!switches.containsKey(sw)) {
					switches.put(sw, id);
					// we set default flow
					this.setDefaultFlow(sw, id);
					id++;
				}
				for (Map.Entry<IPv4Address, IDevice> entry : serverList.entrySet()) {
					if (!entry.getValue().equals(device)) {
						handleDeviceFlow(sw, device);
					}
				}
			}

			/*
			 * Not using this for the moment
			 * for (Map.Entry<IPv4Address, IDevice> entry :
			 * serverList.entrySet()) { DatapathId swid =
			 * entry.getValue().getAttachmentPoints()[0] .getSwitchDPID(); if
			 * (swid.equals(sw)) { handleDeviceFlow(swid, device); } }
			 */
		}

		@Override
		public void deviceRemoved(IDevice device) {
			DatapathId switchId = device.getAttachmentPoints()[0].getSwitchDPID();
			IOFSwitch sw = switchService.getSwitch(switchId);
			for (OFPortDesc port : sw.getPorts()) {
				if (topologyService.isAttachmentPointPort(switchId, port.getPortNo())) {
					return;
				}
			}
			switches.remove(switchId);
		}

		@Override
		public void deviceMoved(IDevice device) {

			Integer last = device.getOldAP().length;
			if (last > 0) {
				DatapathId switchId = device.getOldAP()[last - 1].getSwitchDPID();
				IOFSwitch sw = switchService.getSwitch(switchId);
				for (OFPortDesc port : sw.getPorts()) {
					if (topologyService.isAttachmentPointPort(switchId, port.getPortNo())) {
						return;
					}
				}
				switches.remove(switchId);
				SwitchPort[] aPs =device.getAttachmentPoints();
				if (aPs != null && aPs.length>0) {
					DatapathId newSwitchId = aPs[0].getSwitchDPID();
					if (!switches.containsKey(newSwitchId)) {
						switches.put(newSwitchId, id);
						// we set default flow
						this.setDefaultFlow(newSwitchId, id);
						id++;
					}
				}
			}
		}

		@Override
		public void deviceIPV4AddrChanged(IDevice device) {
			// first, we need to delete old flows
			for (Map.Entry<IPv4Address, IDevice> entry : serverList.entrySet()) {
				if (device.getIPv4Addresses()[0].equals(entry.getKey())) {
					serverList.put(device.getIPv4Addresses()[0], device);
					this.handleNewMice(device);
					return;
				}
			}
			sfp.deleteFlow(device.getMACAddressString() + "cktree");
			handleDeviceFlow(null, device);
		}

		@Override
		public void deviceVlanChanged(IDevice device) {

		}

		@Override
		public String getName() {
			return null;
		}

		@Override
		public boolean isCallbackOrderingPrereq(String type, String name) {
			return false;
		}

		@Override
		public boolean isCallbackOrderingPostreq(String type, String name) {
			return false;
		}

		public void addNewMice(String ipadd) {
			IPv4Address ip = IPv4Address.of(ipadd);
			serverList.put(ip, null);
			@SuppressWarnings("unchecked")
			Iterator<Device> diter = (Iterator<Device>) deviceManager.queryDevices(MacAddress.NONE, null, ip,  IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
			// There should be only one MAC address to the given IP address. In any
			// case,
			// we return only the first MAC address found.
			if (diter.hasNext()) {
				Device device = diter.next();
				serverList.put(ip, device);
				handleNewMice(device);
			}
		}

		@Override
		public void handleNewMice(IDevice device) {

			List<Route> routes = new ArrayList<Route>();
			// this.accessSwitches(device.getAttachmentPoints());
			// por favor llene sus datos
			DatapathId srcDpid = device.getAttachmentPoints()[0].getSwitchDPID();
			OFPort srcPort = device.getAttachmentPoints()[0].getPort();
			MacAddress serverMac = device.getMACAddress();
			if (serverList.size() == 1) {
				// this.egressSwitchFlows(srcDpid, serverMac);
			} else {
				sfp.deleteFlow(device.getMACAddressString() + "cktree");
			}
			for (DatapathId sw : switches.keySet()) {
				if (sw.equals(srcDpid))
					continue;
				Route currentRoute = this.findRoute(srcDpid, srcPort, sw, OFPort.of(0));
				routes.add(currentRoute);
				List<NodePortTuple> listaNPT = currentRoute.getPath();
				int i;
				// for (NodePortTuple npt : listaNPT.) {
				NodePortTuple npt = null;
				NodePortTuple nextNpt = null;
				// String alias = new StringBuilder(sw.toString()).reverse()
				// .toString();
				// alias = alias.substring(0, 17);
				String alias = this.buildAlias(sw, OFPort.ZERO);
				Integer nptCount = listaNPT.size();
				for (i = 0; i < nptCount; i = i + 2) {
					npt = listaNPT.get(i);
					nextNpt = listaNPT.get(i + 1);
					if (i == 0) {
						// we are working with the ingress switch
						// first the up (to server)
						String nameUp = sw.toString() + npt.getNodeId().toString() + "up";
						ArrayList<OFAction> actionList = new ArrayList<OFAction>();
						OFActions actions = factory.actions();
						// It should be a masked match, with mask Y*, action should
						// be goto table 4
						// Here we only set the flow to translate alias
						OFActionOutput output = actions.buildOutput().setMaxLen(0xFFffFFff).setPort(srcPort).build();
						actionList.add(output);
						Match match = factory.buildMatch()
								// .setExact(MatchField.IN_PORT, OFPort.of(1))
								.setExact(MatchField.ETH_TYPE, EthType.IPv4)
								// .setExact(MatchField.IPV4_SRC,
								// device.getIPv4Addresses()[0])
								.setExact(MatchField.ETH_DST, serverMac).build();
						OFFlowMod.Builder fmb;
						fmb = factory.buildFlowAdd();
						fmb.setMatch(match);
						fmb.setCookie((U64.of(0)));
						fmb.setIdleTimeout(0);
						fmb.setHardTimeout(0);
						fmb.setPriority(CircuitTreePriority);
						fmb.setActions(actionList);
						sfp.addFlow(nameUp, fmb.build(), npt.getNodeId());

						if (nptCount > 2) {
							// now the 'down'
							String nameDown = sw.toString() + nextNpt.getNodeId().toString() + "down";
							ArrayList<OFAction> actionListdwn = new ArrayList<OFAction>();
							OFActions actionsDwn = factory.actions();
							// Action should be a goto to table 5
							OFActionOutput outputD = actionsDwn.buildOutput().setMaxLen(0xFFffFFff)
									.setPort(nextNpt.getPortId()).build();
							actionListdwn.add(outputD);
							// MAtch should be masked match against alias
							alias = this.buildAlias(sw, OFPort.ZERO);
							Match matchDown = factory.buildMatch().setExact(MatchField.ETH_TYPE, EthType.IPv4)
									.setMasked(MatchField.ETH_DST, MacAddress.of(alias), MacAddress.of("ff:ff:ff:00:00:00"))
									.build();
							OFFlowMod.Builder fmbD;
							fmbD = factory.buildFlowAdd();
							fmbD.setMatch(matchDown);
							fmbD.setCookie((U64.of(0)));
							fmbD.setIdleTimeout(0);
							fmbD.setHardTimeout(0);
							fmbD.setPriority(CircuitTreePriority);
							fmbD.setActions(actionListdwn);
							sfp.addFlow(nameDown, fmbD.build(), nextNpt.getNodeId());
						}
					} else if (i == nptCount - 2) {
						// upstream
						OFFlowMod.Builder fmUp = this.flowMod(EthType.IPv4, device.getMACAddress(),
								device.getIPv4Addresses()[0], npt.getPortId(), serverMac, 1, sw);
						sfp.addFlow(sw.toString() + npt.getNodeId().toString() + "up", fmUp.build(), npt.getNodeId());
					} else {
						// first the 'up'
						String nameUp = sw.toString() + npt.getNodeId().toString() + "up";
						ArrayList<OFAction> actionList = new ArrayList<OFAction>();
						OFActions actions = factory.actions();
						OFActionOutput output = actions.buildOutput().setMaxLen(0xFFffFFff).setPort(npt.getPortId())
								.build();
						actionList.add(output);
						Match match = factory.buildMatch().setExact(MatchField.ETH_TYPE, EthType.IPv4)
								.setExact(MatchField.ETH_DST, serverMac).build();
						OFFlowMod.Builder fmb;
						fmb = factory.buildFlowAdd();
						fmb.setMatch(match);
						fmb.setCookie((U64.of(0)));
						fmb.setIdleTimeout(0);
						fmb.setHardTimeout(0);
						fmb.setPriority(CircuitTreePriority);
						fmb.setActions(actionList);
						sfp.addFlow(nameUp, fmb.build(), npt.getNodeId());
						// now the 'down'
						String nameDown = sw.toString() + nextNpt.getNodeId().toString() + "down";
						ArrayList<OFAction> actionListdwn = new ArrayList<OFAction>();
						OFActions actionsDwn = factory.actions();
						OFActionOutput outputD = actionsDwn.buildOutput().setMaxLen(0xFFffFFff).setPort(nextNpt.getPortId())
								.build();
						actionListdwn.add(outputD);
						Match matchDwn = factory.buildMatch()
								// .setExact(MatchField.IN_PORT, OFPort.of(1))
								.setExact(MatchField.ETH_TYPE, EthType.IPv4)
								.setMasked(MatchField.ETH_DST, MacAddress.of(alias), MacAddress.of("ff:ff:ff:00:00:00"))
								.build();
						OFFlowMod.Builder fmbD;
						fmbD = factory.buildFlowAdd();
						fmbD.setMatch(matchDwn);
						fmbD.setCookie((U64.of(0)));
						fmbD.setIdleTimeout(0);
						fmbD.setHardTimeout(0);
						fmbD.setPriority(CircuitTreePriority);
						fmbD.setActions(actionListdwn);
						sfp.addFlow(nameDown, fmbD.build(), nextNpt.getNodeId());
					}

				}
			}

		}

		@Override
		public void egressSwitchFlows(DatapathId serverSwid, MacAddress serverMac) {
			// We get all devices and insert Flow in each one except for
			// ingress switch
			for (IDevice device : deviceManager.getAllDevices()) {
				if (device.getAttachmentPoints().length != 0) {
					if (device.getMACAddress().equals(serverMac)) {
						continue;
					}
					/*
					 * DatapathId devSwid = device.getAttachmentPoints()[0]
					 * .getSwitchDPID(); if (devSwid.equals(serverSwid)) { continue;
					 * }
					 */
					this.handleDeviceFlow(serverSwid, device);

				}
			}

		}

		// When a 'normal' device 'grows' into a server, we need to delete those flows
		public void deleteDevFlow(Device device) {
			sfp.deleteFlow(device.getMACAddressString() + "cktree");

		}

		public void handleDeviceFlow(DatapathId serverSwid, IDevice device) {

			for (IPv4Address ip : device.getIPv4Addresses()) {
				if (!ip.equals(IPv4Address.of("0.0.0.0"))) {
					OFFlowMod.Builder fmDwn = this.flowMod(EthType.IPv4, device.getMACAddress(), ip,
							device.getAttachmentPoints()[0].getPort(), null, 2,
							device.getAttachmentPoints()[0].getSwitchDPID());
					sfp.addFlow(device.getMACAddressString() + "cktree", fmDwn.build(),
							device.getAttachmentPoints()[0].getSwitchDPID());

					break;
				}
			}
		}

		public String buildAlias(DatapathId dpid, OFPort forPort) {
			Integer identifier = switches.get(dpid);
			if (identifier == null) {
			}
			String idHex = Integer.toHexString(identifier);
			String switchID = "";
			String hostID = "";
			if (idHex.length() == 1) {
				switchID = "00:00:0" + idHex + ":";
			} else if (idHex.length() == 2) {
				switchID = "00:00:" + idHex + ":";
			}
			Integer hostPort = Integer.parseInt(forPort.toString());
			String hostHex = Integer.toHexString(hostPort);
			if (hostHex.length() == 1) {
				hostID = "00:00:0" + hostHex;
			} else if (idHex.length() == 2) {
				hostID = "00:00:" + hostHex;
			}
			return switchID + hostID;
		}

		@Override
		public Builder flowMod(EthType ethType, MacAddress hostMac, IPv4Address ip, OFPort forPort, MacAddress serverMac,
				int matchType, DatapathId dpid) {
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			OFActions actions = factory.actions();
			OFOxms oxms = factory.oxms();
			// If we need to rewrite some header
			OFActionSetField setDlDst = null;
			// We always need to forward to some port
			String alias = buildAlias(dpid, forPort);
			OFFlowMod.Builder fmb;
			fmb = factory.buildFlowAdd();
			Match match = null;
			if (matchType == 1) {
				// ingress
				match = factory.buildMatch().setExact(MatchField.ETH_TYPE, ethType).setExact(MatchField.ETH_DST, serverMac)
						.build();
				setDlDst = actions.buildSetField().setField(oxms.buildEthSrc().setValue(MacAddress.of(alias)).build())
						.build();
			} else if (matchType == 0) {
				// egress-down
				match = factory.buildMatch().setExact(MatchField.ETH_TYPE, ethType)
						.setExact(MatchField.ETH_DST, MacAddress.of(alias)).build();
				setDlDst = actions.buildSetField().setField(oxms.buildEthDst().setValue(hostMac).build()).build();
			} else if (matchType == 2) {
				// ingress-down alias flow
				// we shall use this for OF table 4, it should mask switch id
				match = factory.buildMatch().setExact(MatchField.ETH_TYPE, ethType)
						.setMasked(MatchField.ETH_DST, MacAddress.of(alias), MacAddress.of("00:00:00:ff:ff:ff")).build();
				setDlDst = actions.buildSetField().setField(oxms.buildEthDst().setValue(hostMac).build()).build();
				fmb.setTableId(TableId.of(4));
			}
			OFActionOutput output = actions.buildOutput().setPort(forPort).build();
			actionList.add(setDlDst);
			actionList.add(output);

			fmb.setMatch(match);
			fmb.setCookie((U64.of(0)));
			fmb.setIdleTimeout(0);
			fmb.setHardTimeout(0);
			fmb.setActions(actionList);
			fmb.setPriority(CircuitTreePriority);
			return fmb;
		}

		/*
		 * @Override public void accessSwitches(SwitchPort[] ap) { Integer id=1; for
		 * (DatapathId switchId : switchService.getAllSwitchDpids()) { if
		 * (!switchId.equals(ap[0].getSwitchDPID())) { IOFSwitch sw =
		 * switchService.getSwitch(switchId); loopPorts: for (OFPortDesc port :
		 * sw.getPorts()) { if (topologyService.isAttachmentPointPort(switchId,
		 * port.getPortNo())) { switches.put(sw.getId(),id); id++; break loopPorts;
		 * } }
		 * 
		 * } } }
		 */
		@Override
		public List<DatapathId> accessSwitches(SwitchPort[] ap) {
			List<DatapathId> switches = new ArrayList<DatapathId>();

			for (DatapathId switchId : switchService.getAllSwitchDpids()) {
				if (!switchId.equals(ap[0].getSwitchDPID())) {
					IOFSwitch sw = switchService.getSwitch(switchId);
					loopPorts: for (OFPortDesc port : sw.getPorts()) {
						if (topologyService.isAttachmentPointPort(switchId, port.getPortNo())) {
							switches.add(sw.getId());
							break loopPorts;
						}
					}

				}
			}
			return switches;
		}

		@Override
		public Route findRoute(DatapathId longSrcDpid, OFPort shortSrcPort, DatapathId longDstDpid, OFPort shortDstPort) {
			Route result = routingEngine.getRoute(longSrcDpid, shortSrcPort, longDstDpid, shortDstPort, U64.of(0));

			if (result != null) {
				return result;
			} else {
				logger.debug("ERROR! no route found");
				return null;
			}
		}

		public IPv4Address queryServer(IPv4Address ip) {
			return serverList.get(ip) != null ? serverList.get(ip).getIPv4Addresses()[0] : null;
		}

		private void setDefaultFlow(DatapathId sw, Integer id) {
			// we set default flow to match the alias and send it to table 4

			String alias = buildAlias(sw, OFPort.ZERO);
			OFFlowMod.Builder fmb;
			fmb = factory.buildFlowAdd();
			Match match = null;

			match = factory.buildMatch().setExact(MatchField.ETH_TYPE, EthType.IPv4)
					.setMasked(MatchField.ETH_DST, MacAddress.of(alias), MacAddress.of("ff:ff:ff:00:00:00")).build();

			ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
			instructionList.add(factory.instructions().gotoTable(TableId.of(4)));
			fmb.setMatch(match);
			fmb.setCookie((U64.of(0)));
			fmb.setIdleTimeout(0);
			fmb.setHardTimeout(0);
			fmb.setInstructions(instructionList);
			fmb.setPriority(CircuitTreePriority);
			sfp.addFlow(sw.toString() + "cktree", fmb.build(), sw);

		}

		/*
		 * private void setHomeAliasFlow(DatapathId sw,Integer id, MacAddress mac) {
		 * //we set default flow in table 5 to change our MAC to alias
		 * OFFlowMod.Builder fmDwn = this.flowMod(EthType.IPv4, mac, null,
		 * device.getAttachmentPoints()[0].getPort(), null, 0,
		 * device.getAttachmentPoints()[0].getSwitchDPID());
		 * sfp.addFlow(device.getMACAddressString() + "cktree", fmDwn.build(),
		 * device.getAttachmentPoints()[0].getSwitchDPID());
		 * 
		 * }
		 */
		public Integer getSwID(DatapathId sw) {
			return switches.get(sw);

		}

		@Override
		public void deviceIPV6AddrChanged(IDevice device) {
			// TODO Auto-generated method stub
			
		}
}
