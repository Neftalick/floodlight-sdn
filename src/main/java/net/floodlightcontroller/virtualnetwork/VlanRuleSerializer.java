package net.floodlightcontroller.virtualnetwork;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class VlanRuleSerializer extends JsonSerializer<VlanRule> {

	@Override
	public void serialize(VlanRule rule, JsonGenerator jGen,
			SerializerProvider serializer) throws IOException,
			JsonProcessingException {
		jGen.writeStartObject();
        
        jGen.writeStringField("type", rule.getType().toString());
        jGen.writeStringField("vnid", rule.getVnid());
        jGen.writeStringField("match", rule.getMatch());
        jGen.writeEndObject();
		
	}

}
