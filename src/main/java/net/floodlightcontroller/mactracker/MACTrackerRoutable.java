package net.floodlightcontroller.mactracker;
import org.restlet.*;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class MACTrackerRoutable implements RestletRoutable {
	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/all/json", MACTrackerResource.class);
		return router;
	}
	
	@Override
	public String basePath() {
		return "/wm/mactracker";
	}
}
