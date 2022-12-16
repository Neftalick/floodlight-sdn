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
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFFlowMod;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;

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



public class AntiPortScann implements IFloodlightModule, IOFMessageListener {
    protected static Logger log = LoggerFactory.getLogger(AntiPortScann.class);
    private static final long NANOS_PER_SEC = 1000000000;
    private static final short APP_ID = 100;
    static {
        AppCookie.registerApp(APP_ID, "AntiPortScann");
    }

    // Our dependencies
    IFloodlightProviderService floodlightProviderService;
    IRestApiService restApiService;
    IDeviceService deviceService;

    // Our internal state
    protected Map<MacAddress, Integer> hostToSyn; // map of host MAC to syn flag counter
    protected Map<MacAddress, Integer> hostToSynAck; // map of host MAC to syn-ack flag counter
    protected Map<MacAddress, Long > hostToTimestamp; // map of host MAC to timestamp

    protected Double thresholdTime;
    protected Integer thresholdCantPorts;
    protected Map<IPv4Address, PortScanSuspect> hostQueries;


    // IFloodlightModule

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
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

        hostToSyn = new ConcurrentHashMap<MacAddress, Integer>();
        hostToSynAck = new ConcurrentHashMap<MacAddress, Integer>();
        hostToTimestamp = new ConcurrentHashMap<MacAddress, Long >();

        thresholdTime = 3.0;
        thresholdCantPorts = 5;
        hostQueries = new ConcurrentHashMap<IPv4Address, PortScanSuspect >();


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

        //Validacion si es IPv4
        MacAddress sourceMac = eth.getSourceMACAddress();
        if (eth.getEtherType().equals(EthType.IPv4)) {
            IPv4 ip = (IPv4) eth.getPayload();
            IPv4Address ipDestino = ip.getDestinationAddress();
            IPv4Address ipFuente = ip.getSourceAddress();
            //Validacion si es TCP
            if (ip.getProtocol().equals(IpProtocol.TCP)) {
                TCP tcp = (TCP) ip.getPayload();
                int flags=tcp.getFlags();
                System.out.println("De anti Port Scanner "+ipFuente + "to Destn IPaddress:" + ipDestino + "flags " + flags  );
                // 1. caso TCP SYN
                if (tcp.getFlags() == (short) 0x02) {
                    int scannedPort = tcp.getDestinationPort().getPort();



                    if (hostQueries.get(ipDestino) == null) {

                        PortScanSuspect portScanSuspectNew = new PortScanSuspect();
                        portScanSuspectNew.setAckCounter(0);
                        portScanSuspectNew.setDestMACAddress(eth.getDestinationMACAddress());
                        portScanSuspectNew.setSourceMACAddress(eth.getSourceMACAddress());
                        portScanSuspectNew.setSynAckCounter(0);
                        portScanSuspectNew.setStartTime(System.nanoTime());
                        hostQueries.put(ipDestino, portScanSuspectNew);
                    }
                    PortScanSuspect portScanSuspect = hostQueries.get(ipDestino);

                    // Revisar si la MAC origen est� en el MAP de contadores SYN
                    if (hostToSyn.containsKey(sourceMac)) {

                        // si est�, revisar si est� dentro de la ventana de analisis, si no est� en la ventana de an�lsis borrarlo del map

                        Long startTime = portScanSuspect.getStartTime();
                        double timeDifSec = ((System.nanoTime() - startTime) * 1.0 / NANOS_PER_SEC) ;

                        //** revisar si longitud(SYN)-longitud(SYN-ACK)> THRESHOLD

                        if (timeDifSec < thresholdTime) {
                            int thresholdSuspect =  hostToSyn.size()-hostToSynAck.size();
                            if (thresholdSuspect > thresholdCantPorts) ret = Command.CONTINUE;
                            else System.out.println("Anti port scann entre "+eth.getSourceMACAddress()+" y "+eth.getDestinationMACAddress());

                        }else hostToSyn.remove(sourceMac);
                    } else {
                        // Si no est�, agregarlo al map de contadores SYN, SYN-ACK y al de tiempo (con la hora actual)
                        hostToSyn.put(sourceMac, scannedPort);
                        hostToSynAck.put(sourceMac, scannedPort);
                        hostToTimestamp.put(sourceMac, System.nanoTime());
                    }
                }
                // si es TRUE, continuear el pipeline, si es FALSE, DROP

                // 2. Caso TCP SYN-ACK | RESPUESTA DEL SERVIDOR -> "CONTADOR DE VECES RESPONDE UNA SOLICITUD TCP"
                if (tcp.getFlags() == (short) 0x12) {
                    // Revisar si la MAC origen est�n al MAP de contadores SYN
                    if (hostToSyn.containsKey(sourceMac)) {
                        // Si est�, incrementar el contador SYN-ACK
                        int currentCount = hostToSynAck.get(sourceMac);
                        hostToSynAck.put(sourceMac, currentCount + 1);
                        ret = Command.CONTINUE;
                    }

                }
            }
        }

        return ret;
    }

    protected class PortScanSuspect{
        MacAddress sourceMACAddress;
        MacAddress destMACAddress;
        Integer ackCounter;
        Integer synAckCounter;

        public MacAddress getSourceMACAddress() {
            return sourceMACAddress;
        }

        public void setSourceMACAddress(MacAddress sourceMACAddress) {
            this.sourceMACAddress = sourceMACAddress;
        }

        public MacAddress getDestMACAddress() {
            return destMACAddress;
        }

        public void setDestMACAddress(MacAddress destMACAddress) {
            this.destMACAddress = destMACAddress;
        }

        public Integer getAckCounter() {
            return ackCounter;
        }

        public void setAckCounter(Integer ackCounter) {
            this.ackCounter = ackCounter;
        }

        public Integer getSynAckCounter() {
            return synAckCounter;
        }

        public void setSynAckCounter(Integer synAckCounter) {
            this.synAckCounter = synAckCounter;
        }

        private long startTime;

        public long getStartTime() {
            return startTime;
        }

        public void setStartTime(long startTime) {
            this.startTime = startTime;
        }
    }

}