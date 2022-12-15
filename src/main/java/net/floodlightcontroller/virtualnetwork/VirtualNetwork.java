/**
 *    Copyright 2013, Big Switch Networks, Inc.
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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.devicemanager.SwitchPort;

/**
 * Data structure for storing and outputing information of a virtual network created
 * by VirtualNetworkFilter
 * 
 * @author KC Wang
 */

@JsonSerialize(using=VirtualNetworkSerializer.class)
public class VirtualNetwork{
    protected String name; // network name
    protected String guid; // network id
	protected Map<MacAddress,Integer> hosts; //host's mac address connected
	protected Map<DatapathId,Set<OFPort>> switch2ports;
    /**
     * Constructor requires network name and id
     * @param name: network name
     * @param guid: network id 
     */
    public VirtualNetwork(String name, String guid) {
        this.name = name;
        this.guid = guid;
		this.hosts = new ConcurrentHashMap<MacAddress,Integer>();
		this.switch2ports = new ConcurrentHashMap<DatapathId,Set<OFPort>>();
        return;        
    }

    /**
     * Sets network name
     * @param gateway: IP address as String
     */
    public void setName(String name){
        this.name = name;
        return;                
    }
    
    /**
     * Adds a host to this network record
     * @param host: MAC address as MACAddress
     */
    public void addHost(MacAddress host,Integer type, SwitchPort swports){
        this.hosts.put(host,type); // ignore old mapping
        if(this.switch2ports.get(swports.getSwitchDPID())!=null){
        	this.switch2ports.get(swports.getSwitchDPID()).add(swports.getPort());
        }else{
        	Set<OFPort> portList = new HashSet<OFPort>();
        	portList.add(swports.getPort());
        	this.switch2ports.put(swports.getSwitchDPID(), portList);
        }
        return;
    }
    
    /**
     * Removes a host from this network record
     * @param host: MAC address as MACAddress
     * @return boolean: true: removed, false: host not found
     */
    public boolean removeHost(MacAddress mac,Integer type, SwitchPort swport){
    	Integer l=null;
    	if(type==0){
    		l=this.hosts.remove(mac);
    		this.switch2ports.get(swport.getSwitchDPID()).remove(swport);
    	}
    	//If it is different from 0, we remove only if rule type matches
    	else if(type!=0){
    		for (Entry<MacAddress,Integer > entry : this.hosts.entrySet()) {
    			if (entry.getValue().equals(type)&&entry.getKey().equals(mac)){
    				l= this.hosts.remove(entry.getKey());
    				this.switch2ports.get(swport.getSwitchDPID()).remove(swport);
    				return true;
    			}
    		}
    	}
    	return l==null?false:true;
    }
    
    /**
     * Removes all hosts from this network record
     */
    public void clearHosts(){
		this.hosts.clear();
    }
    
    /**Returns a map of hosts
     * 
     * @return
     */
    public Set<MacAddress> getHosts(){
    	return this.hosts.keySet();
    	
    }
    
    public Map<DatapathId,Set<OFPort>> getAps(){
    	return this.switch2ports;
    }
    
    /*
     public List<MacAddress> getHosts(){
    	List<MacAddress> list= new ArrayList<MacAddress>();
    	 list.addAll(this.hosts.keySet());
    	 return list;
    	    }
     */
}
