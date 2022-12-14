package net.floodlightcontroller.mactracker;
import java.util.Set;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface MACTrackerService extends IFloodlightService{
	public Set<Long> getMacAddresses();
}
