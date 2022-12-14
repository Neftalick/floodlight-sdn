package net.floodlightcontroller.antiportscan;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Host {

    private IPv4Address ipv4;
    //guarda Mac/Array de puerto que consulto
    private Map<MacAddress, ArrayList<Integer>> mapSynRequests = new ConcurrentHashMap<MacAddress, ArrayList<Integer>>();
    //map sourceMac/startTime en ns
    private Map<MacAddress, Long> mapMacTime = new ConcurrentHashMap<MacAddress, Long>();

    public IPv4Address getIpv4() {
        return ipv4;
    }

    public void setIpv4(IPv4Address ipv4) {
        this.ipv4 = ipv4;
    }

    public Map<MacAddress, ArrayList<Integer>> getMapSynRequests() {
        return mapSynRequests;
    }

    public void setMapSynRequests(Map<MacAddress, ArrayList<Integer>> mapSynRequests) {
        this.mapSynRequests = mapSynRequests;
    }

    public Map<MacAddress, Long> getMapMacTime() {
        return mapMacTime;
    }

    public void setMapMacTime(Map<MacAddress, Long> mapMacTime) {
        this.mapMacTime = mapMacTime;
    }

}
