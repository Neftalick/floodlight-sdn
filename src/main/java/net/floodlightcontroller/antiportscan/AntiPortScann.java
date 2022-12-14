package net.floodlightcontroller.antiportscan;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.DHCP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.virtualnetwork.IVirtualNetworkService;

public class AntiPortScann implements IFloodlightModule, IOFMessageListener{
	protected static Logger log = LoggerFactory.getLogger(AntiPortScann.class);
    private static final long MILLIS_PER_SEC = 1000;


	private static final short APP_ID = 100;
	static {
		AppCookie.registerApp(APP_ID, "AntiPortScann");
	}

	// Our dependencies
	IFloodlightProviderService floodlightProviderService;
	IRestApiService restApiService;
	IDeviceService deviceService;

	// Our internal state
	protected Map<MacAddress, String> hostToSyn; // map of host MAC to syn flag counter
	protected Map<MacAddress, String> hostToSynAck; // map of host MAC to syn-ack flag counter
	protected Map<MacAddress, Long > hostToTimestamp; // map of host MAC to timestamp
	
	protected Map<IPv4Address, Host> hostsConsultados;
	protected Double thresholdTime;
	protected Integer thresholdCantPorts;
	protected ArrayList<MacAddress> hostBlocked;


	// IFloodlightModule

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IVirtualNetworkService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
	getServiceImpls() {
		Map<Class<? extends IFloodlightService>,
		IFloodlightService> m =
		new HashMap<Class<? extends IFloodlightService>,
		IFloodlightService>();
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRestApiService.class);
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);

		hostToSyn = new ConcurrentHashMap<MacAddress, String>();
		hostToSynAck = new ConcurrentHashMap<MacAddress, String>();

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
	}

	// IOFMessageListener

	@Override
	public String getName() {
		return "anti port scanning";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Link discovery should go before us so we don't block LLDPs
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// We need to go before forwarding
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
		case PACKET_IN:
			return processPacketIn(sw, (OFPacketIn)msg, cntx);
		default:
			break;
		}
		log.warn("Received unexpected message {}", msg);
		return Command.CONTINUE;
	}


	/**
	 * Processes an OFPacketIn message and decides if the OFPacketIn should be dropped
	 * or the processing should continue.
	 * @param sw The switch the PacketIn came from.
	 * @param msg The OFPacketIn message from the switch.
	 * @param cntx The FloodlightContext for this message.
	 * @return Command.CONTINUE if processing should be continued, Command.STOP otherwise.
	 */
	protected Command processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		Command ret = Command.STOP;

		// 1. caso TCP SYN
		
		// Revisar si la MAC origen está en el MAP de contadores SYN
		
		if(!hostBlocked.contains(eth.getSourceMACAddress())) {
			portScanning(eth);
			ret = Command.CONTINUE;
		}

		
		// Si no está, agregarlo al map de contadores SYN, SYN-ACK y al de tiempo (con la hora actual)
		
		// si está, revisar si está dentro de la ventana de analisis, si no está en la ventana de análsis borrarlo del map
		
		// si está en la ventana de análisis, revisar si longitud(SYN)-longitud(SYN-ACK)> THRESHOLD
		
		// si es TRUE, continuear el pipeline, si es FALSE, DROP
		
		// 2. Caso TCP SYN-ACK
		
		// Revisar si la MAC origen están al MAP de contadores SYN
		
		// Si está, incrementar el contador SYN-ACK
		
		if (log.isTraceEnabled())
			log.trace("Anti port scann entre {} y {}",
					new Object[] {eth.getSourceMACAddress(), eth.getDestinationMACAddress()});

		return ret;
	}
	
	 protected void portScanning(Ethernet eth) {
	        if (eth.getEtherType().equals(EthType.IPv4)) {
	            IPv4 ip = (IPv4) eth.getPayload();
	            if (ip.getProtocol().equals(IpProtocol.TCP)) {
	                TCP tcp = (TCP) ip.getPayload();
	                
	                // 1. caso TCP SYN
	                
	                if (tcp.getFlags() == (short) 0x02) {
	                    IPv4Address ipDestino = ip.getDestinationAddress();
	                    if (hostsConsultados.get(ipDestino) == null) {
	                        Host newHost = new Host();
	                        hostsConsultados.put(ipDestino, newHost);
	                    }
	                    Host hostConsultado = hostsConsultados.get(ipDestino);
	                    
	                    // Revisar si la MAC origen está en el MAP de contadores SYN
	        
	                    MacAddress sourceMac = eth.getSourceMACAddress();
	                    if (!(hostConsultado.getMapSynRequests().get(sourceMac) == null)) {
	                    	
	                        // Agregar el puerto consultado
	                    	
	                        hostConsultado.getMapSynRequests().get(sourceMac).add(tcp.getDestinationPort().getPort());
	                        
	                        // Revisar si está dentro de la ventana de analisis
	                        
	                        Long startTime = hostConsultado.getMapMacTime().get(sourceMac);
	                        double timeDifSec = ((System.nanoTime() - startTime) * 1.0 / 1000000) / MILLIS_PER_SEC;
	                        if (timeDifSec < thresholdTime) {
	                        	
	                            // Revisar si longitud(SYN)-longitud(SYN-ACK)> THRESHOLD
	                        	
	                            if (hostConsultado.getMapSynRequests().get(sourceMac).size() > thresholdCantPorts) {
	                                hostBlocked.add(sourceMac);
	                                System.out.println("###### SE DETECTO PORT SCANNING ######");
	                                System.out.println("-- ATACANTE --");
	                                System.out.println("mac source: " + sourceMac);
	                            }
	                        } else {
	                        	
	                            // Si no está en la ventana de análsis borrarlo del MAP
	                        	
	                            hostConsultado.getMapSynRequests().remove(sourceMac);
	                        }
	                    } else {
	                    	
	                        // Si no está, agregarlo al MAP de contadores SYN, SYN-ACK y al de tiempo (con la hora actual)
	                        //TODO: FALTA AL SYN-ACK
	                    	
	                        ArrayList<Integer> lp = new ArrayList<>();
	                        lp.add(tcp.getDestinationPort().getPort());
	                        hostConsultado.getMapSynRequests().put(sourceMac, lp);

	                        hostConsultado.getMapMacTime().put(sourceMac, System.nanoTime());
	                    }
	                }

	           
	                /*
	                
	                //TODO: CONSULTAR
	                
	                // 2. Caso TCP SYN-ACK | RESPUESTA DEL SERVIDOR -> "CONTADOR DE VECES RESPONDE UNA SOLICITUD TCP"
	                
	                MacAddress sourceMac = eth.getSourceMACAddress();
	                
	                if (tcp.getFlags() == (short) 0x12) {
	                	
	                    // Revisar si la MAC origen están al MAP de contadores SYN
	                	
	                    if (hostToSyn.containsKey(sourceMac)) {
	                    	
	                        // Si está, incrementar el contador SYN-ACK
	                    	
	                        String currentCount = hostToSynAck.get(sourceMac);
	                        hostToSynAck.put(sourceMac, currentCount+1);
	                    }
	                }*/

	            }
	        }
	    }
	
	protected class PortScanSuspect{
		MacAddress sourceMACAddress;
		MacAddress destMACAddress;
		Integer ackCounter;
		Integer synAckCounter;
		private long startTime;
		
	}

}
