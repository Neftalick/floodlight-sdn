package net.floodlightcontroller.circuittree;


import java.util.List;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.routing.Route;

public interface ICircuitTreeService extends IFloodlightService{
	public void addNewMice(String ipadd);
	public void handleNewMice(IDevice device);
	public void egressSwitchFlows(DatapathId swid, MacAddress serverMac);
	/*public OFFlowMod.Builder flowMod(EthType ethType, MacAddress macAddress,
			IPv4Address ip, OFPort forPort, MacAddress serverMac, int matchType,String identifier);
	*/
	public OFFlowMod.Builder flowMod(EthType ethType, MacAddress macAddress,
			IPv4Address ip, OFPort forPort, MacAddress serverMac, int matchType,DatapathId dpid);
	
	public List<DatapathId> accessSwitches(SwitchPort[] ap);
	//public void accessSwitches(SwitchPort[] ap);
	public Route findRoute(DatapathId longSrcDpid, OFPort shortSrcPort,
			DatapathId longDstDpid, OFPort shortDstPort) ;
	public IPv4Address queryServer(IPv4Address ip);
	public Integer getSwID(DatapathId sw);
}
