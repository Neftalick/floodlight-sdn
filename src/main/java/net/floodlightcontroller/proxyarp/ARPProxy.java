package net.floodlightcontroller.proxyarp;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.circuittree.ICircuitTreeService;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.topology.ITopologyService;


public class ARPProxy extends TimerTask implements IOFMessageListener, IFloodlightModule {

	/** Broadcast MAC address. */
	protected static final long BROADCAST_MAC = 0xffffffffffffL;
	/** APR timeout in milliseconds. */
	protected static final long ARP_TIMEOUT = 5000L;

	/** Logger to log ProxyARP events. */
	protected static Logger logger;
	/** Required Module: Floodlight Provider Service. */
	protected IFloodlightProviderService floodlightProvider;
	/** Required Module: Floodlight Device Manager Service. */
	protected IDeviceService deviceManager;
	protected IOFSwitchService switchService;
	/**
	 * Required Module: Topology Manager module. We listen to the
	 * topologyManager for changes of the topology.
	 */
	protected ITopologyService topologyManager;
	/** A map that maps: TargetIPAddress -> Set of ARPRequest. */
	protected Map<IPv4Address, HashSet<ARPRequest>> arpRequests;
	/** A timer object to schedule ARP timeouts. */
	protected Timer timer;
	protected ICircuitTreeService circuitService;

	/**
	 * Encapsulates information regarding the ARP request and its state.
	 * 
	 * @author Michael Bredel <michael.bredel@cern.ch>
	 */
	protected class ARPRequest {
		/** The MAC address of the source host */
		MacAddress sourceMACAddress;
		/** The IP address of the source host. */
		IPv4Address sourceIPAddress;
		/** The MAC address of the target (destination) host. */
		MacAddress targetMACAddress;
		/** The IP address of the target (destination) host. */
		IPv4Address targetIPAddress;
		/** The switch ID of the switch where the ARP request is received. */
		DatapathId switchId;
		/** The port ID of the port where the ARP request is received. */
		OFPort inPort;
		/** The time the ARP request started. */
		private long startTime;

		/**
		 * Setter for the IP address of the source host that initialized the ARP
		 * request.
		 * 
		 * @param sourceIPAddress
		 *            The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceMACAddress(MacAddress sourceMACAddress) {
			this.sourceMACAddress = sourceMACAddress;
			return this;
		}

		/**
		 * Setter for the IP address of the source host that initialized the ARP
		 * request.
		 * 
		 * @param sourceIPAddress
		 *            The IP address of the source host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSourceIPAddress(IPv4Address sourceIPAddress) {
			this.sourceIPAddress = sourceIPAddress;
			return this;
		}

		/**
		 * Setter for the MAC address of the target (destination) host.
		 * 
		 * @param targetMACAddress
		 *            The MAC address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetMACAddress(MacAddress targetMACAddress) {
			this.targetMACAddress = targetMACAddress;
			return this;
		}

		/**
		 * Setter for the IP address of the target (destination) host.
		 * 
		 * @param targetIPAddress
		 *            The IP address of the target (destination) host.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setTargetIPAddress(IPv4Address targetIPAddress) {
			this.targetIPAddress = targetIPAddress;
			return this;
		}

		/**
		 * Setter for the SwitchId where the ARP request is received.
		 * 
		 * @param switchId
		 *            Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setSwitchId(DatapathId switchId) {
			this.switchId = switchId;
			return this;
		}

		/**
		 * Setter for the PortId where the ARP request is received.
		 * 
		 * @param portId
		 *            Where the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setInPort(OFPort portId) {
			this.inPort = portId;
			return this;
		}

		/**
		 * Setter for the start time when the ARP request is received.
		 * 
		 * @param startTime
		 *            The time when the ARP request is received.
		 * @return <b>ARPRequest</b> The current ARPRequest object.
		 */
		public ARPRequest setStartTime(long startTime) {
			this.startTime = startTime;
			return this;
		}

		/**
		 * Getter for the source MAC address, i.e from the node that initialized
		 * the ARP request.
		 * 
		 * @return <b>long</b> The MAC address of the source of the ARP request.
		 */
		public MacAddress getSourceMACAddress() {
			return this.sourceMACAddress;
		}

		/**
		 * Getter for the source IP address, i.e. from the node that initialized
		 * the ARP request.
		 * 
		 * @return <b>long</b> The IP address of the source of the ARP request.
		 */
		public IPv4Address getSourceIPAddress() {
			return this.sourceIPAddress;
		}

		/**
		 * Getter for the target (destination) MAC address.
		 * 
		 * @return <b>long</b> The MAC address of the target (destination) of
		 *         the ARP request.
		 */
		public MacAddress getTargetMACAddress() {
			return this.targetMACAddress;
		}

		/**
		 * Getter for the target (destination) IP address.
		 * 
		 * @return <b>long</b> The IP address of the target (destination) of the
		 *         ARP request.
		 */
		public IPv4Address getTargetIPAddress() {
			return this.targetIPAddress;
		}

		/**
		 * Getter for the switch ID of the ARP incoming switch.
		 * 
		 * @return <b>long</b> The switch ID of the switch where the ARP request
		 *         is received.
		 */
		public DatapathId getSwitchId() {
			return this.switchId;
		}

		/**
		 * Getter for the port ID if the ARP incoming port.
		 * 
		 * @return <b>short</b> The port ID of the port where the ARP request is
		 *         received.
		 */
		public OFPort getInPort() {
			return this.inPort;
		}

		/**
		 * Getter for the start time of the ARP request.
		 * 
		 * @return <b>long</b> The start time when the ARP request is received.
		 */
		public long getStartTime() {
			return this.startTime;
		}
	}

	@Override
	public String getName() {
		return "ARPHandler";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && name.equals("clustering"));
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		topologyManager = context.getServiceImpl(ITopologyService.class);
		deviceManager = context.getServiceImpl(IDeviceService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		circuitService = context.getServiceImpl(ICircuitTreeService.class);
		logger = LoggerFactory.getLogger(ARPProxy.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("ARPProxy-Modul started");
		}
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		arpRequests = new HashMap<IPv4Address, HashSet<ARPRequest>>();
		timer = new Timer();
		timer.schedule(this, ARP_TIMEOUT, ARP_TIMEOUT);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			IRoutingDecision decision = null;
			if (cntx != null) {
				decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
			}
			return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
		default:
			break;
		}
		return Command.CONTINUE;
	}

	/**
	 * Handles packetIn messages and decides what to do with it.
	 * 
	 * @param sw
	 *            The switch the packet is received.
	 * @param piMsg
	 *            The OpenFlow PacketIN message from the switch containing all
	 *            relevant information.
	 * @param decision
	 *            A forwarding decision made by a previous module.
	 * @param cntx
	 *            The Floodlight context.
	 * @return <b>Command</b> The command whether another listener should
	 *         proceed or not.
	 */
	protected Command processPacketInMessage(IOFSwitch sw, OFPacketIn piMsg, IRoutingDecision decision,
			FloodlightContext cntx) {
		/* Get the Ethernet frame representation of the PacketIn message. */
		Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// If this is not an ARP message, continue.
		if (ethPacket.getEtherType() != EthType.ARP)
			return Command.CONTINUE;

		/* A new empty ARP packet. */
		ARP arp = new ARP();

		// Get the ARP packet or continue.
		if (ethPacket.getPayload() instanceof ARP) {
			arp = (ARP) ethPacket.getPayload();
		} else {
			return Command.CONTINUE;
		}

		// If a decision has been made already we obey it.
		if (decision != null) {
			if (logger.isTraceEnabled()) {
				logger.trace("Forwaring decision={} was made for PacketIn={}", decision.getRoutingAction().toString(),
						piMsg);
			}

			switch (decision.getRoutingAction()) {
			case NONE:
				// Don't handle the APR message.
				return Command.CONTINUE;
			case DROP:
				// Don't handle the APR message.
				return Command.CONTINUE;
			case FORWARD_OR_FLOOD:
				// Handle the ARP message by the ARP proxy.
				break;
			case FORWARD:
				// Handle the ARP message by the ARP proxy.
				break;
			case MULTICAST:
				// Handle the ARP message by the ARP proxy.
				break;
			default:
				logger.error("Unexpected decision made for this packet-in={}", piMsg, decision.getRoutingAction());
				return Command.CONTINUE;
			}
		}

		// Handle ARP request.
		if (arp.getOpCode() == ARP.OP_REQUEST) {
			// return this.handleARPRequest(arp, sw.getId(), piMsg.getInPort(),
			// cntx);
			return this.handleARPRequest(arp, sw.getId(), (piMsg.getVersion().compareTo(OFVersion.OF_12) < 0
					? piMsg.getInPort() : piMsg.getMatch().get(MatchField.IN_PORT)), cntx);
		}

		// Handle ARP reply.
		if (arp.getOpCode() == ARP.OP_REPLY) {
			// return this.handleARPReply(arp, sw.getId(), piMsg.getInPort(),
			// cntx);
			return this.handleARPReply(arp, sw.getId(), (piMsg.getVersion().compareTo(OFVersion.OF_12) < 0
					? piMsg.getInPort() : piMsg.getMatch().get(MatchField.IN_PORT)), cntx);
		}

		// Handle RARP request. TODO

		// Handle RARP reply. TODO

		// Make a routing decision and forward the ARP message to subsequent
		// modules. (Actually, this should never happen).
		decision = new RoutingDecision(sw.getId(), piMsg.getInPort(),
				IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
				IRoutingDecision.RoutingAction.NONE);
		decision.addToContext(cntx);

		return Command.CONTINUE;
	}

	/**
	 * Handles incoming ARP requests. Reads the relevant information, creates an
	 * ARPRequest object, sends out the ARP request message or, if the
	 * information is already known by the system, sends back an ARP reply
	 * message.
	 * 
	 * @param arp
	 *            The ARP (request) packet received.
	 * @param switchId
	 *            The ID of the incoming switch where the ARP message is
	 *            received.
	 * @param portId
	 *            The Port ID where the ARP message is received.
	 * @param cntx
	 *            The Floodlight context.
	 * @return <b>Command</b> The command whether another listener should
	 *         proceed or not.
	 */
	protected Command handleARPRequest(ARP arp, DatapathId switchId, OFPort portId, FloodlightContext cntx) {
		/* The known IP address of the ARP source. */
		IPv4Address sourceIPAddress = arp.getSenderProtocolAddress();
		/* The known MAC address of the ARP source. */
		MacAddress sourceMACAddress = arp.getSenderHardwareAddress();
		/* The IP address of the (yet unknown) ARP target. */
		IPv4Address targetIPAddress = arp.getTargetProtocolAddress();
		/* The MAC address of the (yet unknown) ARP target. */
		MacAddress targetMACAddress = MacAddress.NONE;
		// logger.info("Received ARP request for" +
		// arp.getTargetProtocolAddress().toString() + " ... ");
		IPv4Address algunServer = circuitService.queryServer(sourceIPAddress);
		int bypass = algunServer != null ? 1 : 0;
		//int bypass=0;
		if (logger.isDebugEnabled()) {
			logger.debug("Received ARP request message from " + arp.getSenderHardwareAddress().toString() + " at "
					+ switchId.toString() + " - " + portId + " for target: "
					+ arp.getTargetProtocolAddress().toString());
		}

		// Check if there is an ongoing ARP process for this packet.
		if (arpRequests.containsKey(targetIPAddress)) {
			// Update start time of current ARPRequest objects

			long startTime = System.currentTimeMillis();
			HashSet<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);

			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				if (iter.next().getSourceMACAddress().equals(sourceMACAddress)) {
					iter.next().setStartTime(startTime);
					return Command.STOP;
				}
			}
			 logger.trace("We are waiting for " +
			 arp.getTargetProtocolAddress().toString() + " ... ");
		}

		@SuppressWarnings("unchecked")
		Iterator<Device> diter = (Iterator<Device>) deviceManager.queryDevices(MacAddress.NONE, null, targetIPAddress, IPv6Address.NONE, DatapathId.NONE,OFPort.ZERO);
		// There should be only one MAC address to the given IP address. In any
		// case,
		// we return only the first MAC address found.
		if (diter.hasNext()) {
			// If we know the destination device, get the corresponding MAC
			// address and send an ARP reply.
			Device device = diter.next();
			targetMACAddress = device.getMACAddress();
			// long age = System.currentTimeMillis() -
			// device.getLastSeen().getTime();

			// if (targetMACAddress > 0 && age < ARP_TIMEOUT) {
			if (!targetMACAddress.toString().equalsIgnoreCase("00:00:00:00:00:00")) {
				if (bypass == 1) {
					
					/*String alias = new StringBuilder(device.getAttachmentPoints()[0].getSwitchDPID().toString())
							.reverse().toString().substring(0, 17);
					*/
					String alias=buildAlias(device.getAttachmentPoints()[0].getSwitchDPID(), device.getAttachmentPoints()[0].getPort());
					targetMACAddress = MacAddress.of(alias);
				}
				ARPRequest arpRequest = new ARPRequest().setSourceMACAddress(sourceMACAddress)
						.setSourceIPAddress(sourceIPAddress).setTargetMACAddress(targetMACAddress)
						.setTargetIPAddress(targetIPAddress).setSwitchId(switchId).setInPort(portId);
				// Send ARP reply.
				this.sendARPReply(arpRequest);
			} else {
				ARPRequest arpRequest = new ARPRequest().setSourceMACAddress(sourceMACAddress)
						.setSourceIPAddress(sourceIPAddress).setTargetIPAddress(targetIPAddress)
						.setTargetMACAddress(targetMACAddress).setSwitchId(switchId).setInPort(portId)
						.setStartTime(System.currentTimeMillis());
				// Put new ARPRequest object to current ARPRequests list.
				this.putArpRequest(targetIPAddress, arpRequest);
				// Send ARP request.
				 logger.trace("Dont know where " +
				 arp.getTargetProtocolAddress().toString() + " is, flooding...");
				this.sendARPReqest(arpRequest);
			}

		} else {
			ARPRequest arpRequest = new ARPRequest().setSourceMACAddress(sourceMACAddress)
					.setSourceIPAddress(sourceIPAddress).setTargetIPAddress(targetIPAddress)
					.setTargetMACAddress(targetMACAddress).setSwitchId(switchId).setInPort(portId)
					.setStartTime(System.currentTimeMillis());
			// Put new ARPRequest object to current ARPRequests list.
			this.putArpRequest(targetIPAddress, arpRequest);
			// Send ARP request
			logger.info("Dont know where " +
			 arp.getTargetProtocolAddress().toString() + " is, flooding... ");
			this.sendARPReqest(arpRequest);

		}
		// Make a routing decision and forward the ARP message
		IRoutingDecision decision = new RoutingDecision(switchId, portId,
				IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
				IRoutingDecision.RoutingAction.NONE);
		decision.addToContext(cntx);

		return Command.STOP;
	}

	/**
	 * Handles incoming ARP replies. Reads the relevant information, get the
	 * corresponding ARPRequest object, and sends back and ARP reply message.
	 * 
	 * @param arp
	 *            The ARP (reply) packet received.
	 * @param switchId
	 *            The ID of the incoming switch where the ARP message is
	 *            received.
	 * @param portId
	 *            The Port ID where the ARP message is received.
	 * @param cntx
	 *            The Floodlight context.
	 * @return
	 * 		<p>
	 *         Command
	 *         </p>
	 *         The command whether another listener should proceed or not.
	 */
	protected Command handleARPReply(ARP arp, DatapathId switchId, OFPort portId, FloodlightContext cntx) {
		/* The IP address of the ARP target. */
		IPv4Address targetIPAddress = arp.getSenderProtocolAddress();
		/* The set of APRRequest objects related to the target IP address. */
		Set<ARPRequest> arpRequestSet = arpRequests.remove(targetIPAddress);
		/* The ARPRequenst object related to the ARP reply message. */
		ARPRequest arpRequest;

		/* El nodo original */
		IPv4Address original = arp.getTargetProtocolAddress();
		boolean bool = false;
		IPv4Address algunServer = circuitService.queryServer(arp.getTargetProtocolAddress());
		int bypass = algunServer != null ? 1 : 0;
		//int bypass=0;

		if (logger.isDebugEnabled()) {
			logger.debug("Received ARP reply message from " + arp.getSenderHardwareAddress().toString() + " at "
					+ switchId.toString() + " - " + portId.toString());
		}
		// logger.info("Received ARP reply message from " +
		// arp.getSenderHardwareAddress().toString() + " at "
		// + switchId.toString() + " - " + portId.toString());
		// If the ARP request has already timed out, consume the message.
		// The sending host should send a new request, actually.
		if (arpRequestSet == null)
			return Command.STOP;

		for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
			arpRequest = iter.next();
			iter.remove();
			MacAddress targetMACAddress;
			if (bypass == 1) {
				//String alias = new StringBuilder(switchId.toString()).reverse().toString().substring(0, 17);
				String alias=buildAlias(switchId, portId);
				targetMACAddress = MacAddress.of(alias);
			} else {
				targetMACAddress = arp.getSenderHardwareAddress();
			}

			if (arpRequest.getSourceIPAddress().equals(original)) {
				// bool=true;
				// continue;
			}
			arpRequest.setTargetMACAddress(targetMACAddress);
			// arpRequest.setTargetMACAddress(arp.getSenderHardwareAddress());
			///

			// Make a routing decision and forward the ARP message
			// IDeviceService.fcStore.put(bc, IDeviceService.CONTEXT_DST_DEVICE,
			// value);
			if (bool) {
				IRoutingDecision decision = new RoutingDecision(switchId, portId,
						IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
						IRoutingDecision.RoutingAction.PREROUTE);
				decision.addToContext(cntx);
			} else {
				sendARPReply(arpRequest);
				IRoutingDecision decision = new RoutingDecision(switchId, portId,
						IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE),
						IRoutingDecision.RoutingAction.FORWARD);
				decision.addToContext(cntx);
			}
		}

		return Command.CONTINUE;
	}

	/**
	 * Creates an ARP request frame, puts it into a packet out message and sends
	 * the packet out message to all switch ports (attachment point ports) that
	 * are not connected to other OpenFlow switches.
	 * 
	 * @param arpRequest
	 *            The ARPRequest object containing information regarding the
	 *            current ARP process.
	 */
	protected void sendARPReqest(ARPRequest arpRequest) {
		// Create an ARP request frame
		IPacket arpReply = new Ethernet().setSourceMACAddress(arpRequest.getSourceMACAddress())
				.setDestinationMACAddress(Ethernet.toByteArray(BROADCAST_MAC)).setEtherType(EthType.ARP)
				.setPayload(new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
						.setOpCode(ARP.OP_REQUEST).setHardwareAddressLength((byte) 6).setProtocolAddressLength((byte) 4)
						.setSenderHardwareAddress(arpRequest.getSourceMACAddress())
						.setSenderProtocolAddress(arpRequest.getSourceIPAddress())
						.setTargetHardwareAddress(arpRequest.getTargetMACAddress())
						.setTargetProtocolAddress(arpRequest.getTargetIPAddress())
						.setPayload(new Data(new byte[] { 0x01 })));

		// Send ARP request to all external ports (i.e. attachment point ports).
		for (DatapathId switchId : switchService.getAllSwitchDpids()) {
			IOFSwitch sw = switchService.getSwitch(switchId);
			List<OFPort> ports = new ArrayList<>();
			for (OFPortDesc port : sw.getPorts()) {
				OFPort portId = port.getPortNo();
				if (switchId.equals(arpRequest.getSwitchId())
						&& portId.getShortPortNumber() == arpRequest.getInPort().getShortPortNumber()) {
					continue;
				}
				if (topologyManager.isAttachmentPointPort(switchId, portId))
					ports.add(portId);
				// this.sendPOMessage(arpReply, sw, portId);
				if (logger.isDebugEnabled()) {
					logger.debug("Send ARP request to " + switchId.toString() + " at all non source ports ");
				}
				/*
				 * logger.info("Send ARP request from " +
				 * arpRequest.getSourceIPAddress().toString() + "to" +
				 * arpRequest.getTargetIPAddress().toString() + " to switch " +
				 * switchId.toString() + " at port " + portId.toString());
				 */
			}
			if (ports.size() > 0) {
				this.floodPOMessage(arpReply, sw, ports);
			}
		}

		logger.info("Flooded ARP request: " + arpReply.toString());
	}

	/**
	 * Creates an ARP reply frame, puts it into a packet out message and sends
	 * the packet out message to the switch that received the ARP request
	 * message.
	 * 
	 * @param arpRequest
	 *            The ARPRequest object containing information regarding the
	 *            current ARP process.
	 */
	protected void sendARPReply(ARPRequest arpRequest) {
		// Create an ARP reply frame (from target (source) to source
		// (destination)).
		IPacket arpReply = new Ethernet().setSourceMACAddress(arpRequest.getTargetMACAddress())
				.setDestinationMACAddress(arpRequest.getSourceMACAddress()).setEtherType(EthType.ARP)
				.setPayload(new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET).setProtocolType(ARP.PROTO_TYPE_IP)
						.setOpCode(ARP.OP_REPLY).setHardwareAddressLength((byte) 6).setProtocolAddressLength((byte) 4)
						.setSenderHardwareAddress(arpRequest.getTargetMACAddress())
						.setSenderProtocolAddress(arpRequest.getTargetIPAddress())
						.setTargetHardwareAddress(arpRequest.getSourceMACAddress())
						.setTargetProtocolAddress(arpRequest.getSourceIPAddress())
						.setPayload(new Data(new byte[] { 0x01 })));
		// Send ARP reply.
		sendPOMessage(arpReply, switchService.getSwitch(arpRequest.getSwitchId()), arpRequest.getInPort());
		///if (logger.isDebugEnabled()) {
		long endTime = System.currentTimeMillis();
		long time=endTime-arpRequest.getStartTime();
		logger.info("Send ARP reply to " + arpRequest.getSwitchId() + " at port " + arpRequest.getInPort() + " " + arpRequest.getTargetIPAddress() + " "+ time);
		///}
	}

	/**
	 * Creates and sends an OpenFlow PacketOut message containing the packet
	 * information to the switch. The packet included on the PacketOut message
	 * is sent out at the given port.
	 * 
	 * @param packet
	 *            The packet that is sent out.
	 * @param sw
	 *            The switch the packet is sent out.
	 * @param port
	 *            The port the packet is sent out.
	 */
	protected void sendPOMessage(IPacket packet, IOFSwitch sw, OFPort port) {
		// Serialize and wrap in a packet out
		byte[] data = packet.serialize();
		OFPacketOut.Builder po = sw.getOFFactory().buildPacketOut().setData(data)
				.setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(port, (short) 0)))
				.setInPort(OFPort.CONTROLLER).setBufferId(OFBufferId.NO_BUFFER);

		sw.write(po.build());
	}

	protected void floodPOMessage(IPacket packet, IOFSwitch sw, List<OFPort> ports) {
		// Serialize and wrap in a packet out
		byte[] data = packet.serialize();
		OFPacketOut.Builder po = sw.getOFFactory().buildPacketOut().setData(data).setInPort(OFPort.CONTROLLER)
				.setBufferId(OFBufferId.NO_BUFFER);
		List<OFAction> actions = new ArrayList<>();
		for (OFPort port : ports) {
			// po.setActions(Collections.singletonList((OFAction)
			// sw.getOFFactory().actions().output(port, (short) 0)));
			OFActionOutput output =sw.getOFFactory().actions().buildOutput().setPort(port).build();
			actions.add((OFAction) output);
		}
		
			po.setActions(actions);
			OFPacketOut po1=po.build();
			sw.write(po1);
	}

	/**
	 * Puts the current ARP request to a list of concurrent ARP requests.
	 * 
	 * @param targetIPAddress
	 *            The IP address of the target (destination) hosts.
	 * @param arpRequest
	 *            The ARP request initialized by the source hosts.
	 */
	private void putArpRequest(IPv4Address targetIPAddress, ARPRequest arpRequest) {
		if (arpRequests.containsKey(targetIPAddress)) {
			arpRequests.get(targetIPAddress).add(arpRequest);
		} else {
			arpRequests.put(targetIPAddress, new HashSet<ARPRequest>());
			arpRequests.get(targetIPAddress).add(arpRequest);
		}
	}

	/**
	 * Check for old ARP request. Remove ARP requests older than ARP_TIMEOUT
	 * from the arpRequests data structure.
	 */
	private void removeOldArpRequests() {
		/* The current time stamp. */
		long currentTime = System.currentTimeMillis();
		for (Iterator<IPv4Address> it = arpRequests.keySet().iterator(); it.hasNext();) {
			// for (IPv4Address targetIPAddress : arpRequests.keySet()) {
			IPv4Address targetIPAddress = it.next();
			HashSet<ARPRequest> arpRequestSet = arpRequests.get(targetIPAddress);
			for (Iterator<ARPRequest> iter = arpRequestSet.iterator(); iter.hasNext();) {
				if ((currentTime - iter.next().getStartTime()) > ARP_TIMEOUT)
					iter.remove();
				if (arpRequestSet.isEmpty())
					it.remove();
			}
		}
	}

	@Override
	public void run() {
		if (!arpRequests.isEmpty()) {
			this.removeOldArpRequests();
		}
	}
	public String buildAlias(DatapathId dpid, OFPort forPort){
		Integer identifier=circuitService.getSwID(dpid);
		//Integer identifier=0;
		if(identifier==null){
			
			
		}
		String idHex=Integer.toHexString(identifier);
		String switchID="";
		String hostID="";
		if(idHex.length()==1){
			switchID="00:00:0"+idHex+":";
		}else if(idHex.length()==2){
			switchID="00:00:"+idHex+":";
		}
		Integer hostPort=Integer.parseInt(forPort.toString());
		String hostHex=Integer.toHexString(hostPort);
		if(hostHex.length()==1){
			hostID="00:00:0"+hostHex;
		}else if(idHex.length()==2){
			hostID="00:00:"+hostHex;
		}
		return switchID+hostID;
	}

}
