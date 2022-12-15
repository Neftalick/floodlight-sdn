package net.floodlightcontroller.virtualnetwork;

import java.io.IOException;
import java.util.List;

import org.restlet.data.Status;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class IsolatingResource extends ServerResource {

	protected static Logger log = LoggerFactory
			.getLogger(IsolatingResource.class);

	public class IsolatingDefinition {
		public String type;
		public String vnid = null;
		public String nets = null;
	}

	protected void jsonToIsolatingDefinition(String json,
			IsolatingDefinition isolating) throws IOException {
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;

		try {
			jp = f.createJsonParser(json);
		} catch (JsonParseException e) {
			throw new IOException(e);
		}

		jp.nextToken();
		if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
			throw new IOException("Expected START_OBJECT");
		}

		while (jp.nextToken() != JsonToken.END_OBJECT) {
			if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
				throw new IOException("Expected FIELD_NAME");
			}
			String n = jp.getCurrentName();
			jp.nextToken();
			if (jp.getText().equals(""))
				continue;
			else if (n.equals("isolate")) {
				while (jp.nextToken() != JsonToken.END_OBJECT) {
					String field = jp.getCurrentName();
					if (field == null)
						continue;
					if (field.equals("type")) {
						isolating.type = jp.getText();
					} else if (field.equals("vnid")) {
						isolating.vnid = jp.getText();
					} else if (field.equals("nets")) {
						isolating.nets = jp.getText();
					} else {
						log.warn("Unrecognized field {} in "
								+ "parsing network definition", jp.getText());
					}
				}

			}
		}
		jp.close();
	}
	
	@Get("json")
    public List<Short> retrieve() {
        IVirtualNetworkService vns =
                (IVirtualNetworkService)getContext().getAttributes().
                    get(IVirtualNetworkService.class.getCanonicalName());
        String vnid = (String) getRequestAttributes().get("network");
        return vns.getBlockedNetworks(vnid);               
    }
	
	@Put
    @Post
    public String isolateNetwork(String postData) {        
        IsolatingDefinition isolating = new IsolatingDefinition();
        try {
            jsonToIsolatingDefinition(postData, isolating);
        } catch (IOException e) {
            log.error("Could not parse JSON {}", e.getMessage());
        }
        
        
        IVirtualNetworkService vns =
                (IVirtualNetworkService)getContext().getAttributes().
                    get(IVirtualNetworkService.class.getCanonicalName());

        vns.blockNetworks(isolating.vnid, isolating.nets, Integer.parseInt(isolating.type));
        setStatus(Status.SUCCESS_OK);
        return "{\"status\":\"ok\"}";
    }
}
