package net.floodlightcontroller.virtualnetwork;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IVirtualNetworkService extends IFloodlightService {
	/**
	 * Creates a new virtual network. This can also be called to modify a
	 * virtual network.
	 * 
	 */
	public void createNetwork(String guid, String network);

	/**
	 * Deletes a virtual network.
	 * 
	 * @param guid
	 *            The ID (not name) of virtual network to delete.
	 */
	public void deleteNetwork(String guid);
	/**
	 * Blocks traffic to/from a network
	 * @param networks
	 * 				The ID's of the blocked networks
	 */
	public void blockNetworks(String vnid, String networks, Integer block);
	/**
	 * Gets blocked networks for a network
	 * @param networks
	 * 				The ID's of the blocked networks
	 */
	public List<Short> getBlockedNetworks(String vnid);

	/**
	 * Adds a host to a virtual network. If a mapping already exists the new one
	 * will override the old mapping.
	 * 
	 * @param mac
	 *            The MAC address of the host to add.
	 * @param network
	 *            The network to add the host to.
	 * @param port
	 *            The logical port name to attach the host to. Must be unique.
	 */
	
	public void addVlanRule(Integer type, String match, String vnid);

	/**
	 * Deletes a host from a virtual network. Either the MAC or Port must be
	 * specified.
	 * 
	 * @param mac
	 *            The MAC address to delete.
	 * @param port
	 *            The logical port the host is attached to.
	 */
	public void deleteVlanRule(String id, String vnid, Integer type);

	/**
	 * Return list of all virtual networks.
	 * 
	 * @return Collection <VirtualNetwork>
	 */
	public Collection<VirtualNetwork> listNetworks();

	public Map<String, VlanRule> listVlanRule();

	public Map<String, VlanRule> listVlanRuleByVnid(String vnid);

	public Map<String, VlanRule> listVlanRuleByVnidAndType(String vnid,
                                                           Integer type);
	
	public Map<DatapathId,Set<OFPort>> getSwitchPortsFromVlan(String id);

}