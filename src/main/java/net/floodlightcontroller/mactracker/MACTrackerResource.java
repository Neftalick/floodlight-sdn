package net.floodlightcontroller.mactracker;
import java.util.*;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

public class MACTrackerResource extends ServerResource {
	@Get("json")
	public List<Long> retrieve() {
		MACTrackerService pihr = (MACTrackerService)getContext().getAttributes().get(MACTrackerService.class.getCanonicalName());
	    List<Long> l = new ArrayList<Long>();
	    l.addAll(pihr.getMacAddresses());
	    return l;
	}
}
