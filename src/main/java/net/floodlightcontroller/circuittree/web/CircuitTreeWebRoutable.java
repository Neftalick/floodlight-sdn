package net.floodlightcontroller.circuittree.web;


import net.floodlightcontroller.restserver.RestletRoutable;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

public class CircuitTreeWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
		// TODO Auto-generated method stub
		 Router router = new Router(context);
	     router.attach("/mice", CircuitTreeResource.class); // POST
	     return router;
	}

	@Override
	public String basePath() {
		// TODO Auto-generated method stub
		return "/trafficManager";
	}
	

}
