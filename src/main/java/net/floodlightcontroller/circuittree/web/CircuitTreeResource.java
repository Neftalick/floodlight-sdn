package net.floodlightcontroller.circuittree.web;

import java.io.IOException;

import net.floodlightcontroller.circuittree.ICircuitTreeService;

import org.restlet.data.Status;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;


public class CircuitTreeResource extends ServerResource{
	protected static Logger log = LoggerFactory
			.getLogger(CircuitTreeResource.class);
	
	public class MiceDefinition{
		public String ip=null;
		
	}
	protected void jsonToNetworkDefinition(String json, MiceDefinition mice) throws IOException{
		MappingJsonFactory f= new MappingJsonFactory();
		JsonParser jp;
		
		try{
			jp=f.createJsonParser(json);
		}catch (JsonParseException e){
			throw new IOException(e);
			
		}
		jp.nextToken();
		if(jp.getCurrentToken()!=JsonToken.START_OBJECT){
			throw new IOException("Expected START_OBJECT");
		}
			
		while(jp.nextToken()!=JsonToken.END_OBJECT){
			if(jp.getCurrentToken()!=JsonToken.FIELD_NAME){
				throw new IOException("Expected FIELD_NAME");
			}
			String n= jp.getCurrentName();
			jp.nextToken();
			if(jp.getText().equals(""))
				continue;
			else if(n.equals("mice")){
				while(jp.nextToken()!=JsonToken.END_OBJECT){
					String field=jp.getCurrentName();
					if(field==null) continue;
					if(field.equals("ipadd")){
						mice.ip=jp.getText();
					}else{
						log.warn("Unrecognized field {} in " +
                        		"parsing network definition", 
                        		jp.getText());
				}
				
			}
		}
		}
		jp.close();
	}
	
	 @Put
	    @Post
	    public String createMice(String postData) {        
	        MiceDefinition mice = new MiceDefinition();
	        try {
	            jsonToNetworkDefinition(postData, mice);
	        } catch (IOException e) {
	            log.error("Could not parse JSON {}", e.getMessage());
	        }
	        // We try to get the ID from the URI only if it's not
	        // in the POST data 
	        /*if (mice.ip == null) {
		        String ip = (String) getRequestAttributes().get("ipadd");
		        if ((ip != null) && (!ip.equals("null")))
		        	mice.ip= ip;
	        }
	        */
	        ICircuitTreeService mm =
	                (ICircuitTreeService) getContext().getAttributes().
	                    get(ICircuitTreeService.class.getCanonicalName());

	        mm.addNewMice(mice.ip);
	        setStatus(Status.SUCCESS_OK);
	        return "{\"status\":\"ok\"}";
	    }
}
