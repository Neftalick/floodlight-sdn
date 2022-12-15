package net.floodlightcontroller.virtualnetwork;

public class VlanRule {

	protected Integer type;
	protected String vnid;
	protected String match;
	
	public VlanRule(Integer type,String match, String vnid){
		this.type=type;
		this.vnid=vnid;
		this.match=match;		
	}
	public Integer getType() {
		return type;
	}
	public String getMatch() {
		return match;
	}
	public String getVnid() {
		return vnid;
	}
}
