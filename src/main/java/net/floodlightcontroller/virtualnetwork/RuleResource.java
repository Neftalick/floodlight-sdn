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

import java.io.IOException;
import java.util.Map;

import org.restlet.data.Status;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Put;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class RuleResource extends org.restlet.resource.ServerResource {
	protected static Logger log = LoggerFactory.getLogger(RuleResource.class);

	public class HostDefinition {
		String vnid = null; // Network ID
		String match = null; // match field
		String type = null; // type number
		String id = null; // numero del host en un type y en una vlan
	}

	protected void jsonToHostDefinition(String json, HostDefinition host)
			throws IOException {
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
			else if (n.equals("attachment")) {
				while (jp.nextToken() != JsonToken.END_OBJECT) {
					String field = jp.getCurrentName();
					if (field.equals("type")) {
						host.type = jp.getText();
					} else if (field.equals("vnid")) {
						host.vnid = jp.getText();
					} else if (field.equals("match")) {
						host.match = jp.getText();
					} else if (field.equals("id")) {
						host.id = jp.getText();
					}
				}
			}
		}

		jp.close();
	}

	@Get("json")
	public Map<String, VlanRule> retrieve() {
		IVirtualNetworkService vns = (IVirtualNetworkService) getContext()
				.getAttributes().get(
						IVirtualNetworkService.class.getCanonicalName());
		String type = (String) getRequestAttributes().get("type");
		String vnid = (String) getRequestAttributes().get("vnid");
		if (vnid.equals("all") && type.equals("all")) {
			return vns.listVlanRule();
		} else if (type.equals("all")) {
			return vns.listVlanRuleByVnid(vnid);
		} else {
			return vns.listVlanRuleByVnidAndType(vnid, Integer.parseInt(type));
		}
	}

	@Put
	public String addHost(String postData) {
		IVirtualNetworkService vns = (IVirtualNetworkService) getContext()
				.getAttributes().get(
						IVirtualNetworkService.class.getCanonicalName());
		HostDefinition host = new HostDefinition();
		try {
			jsonToHostDefinition(postData, host);
		} catch (IOException e) {
			log.error("Could not parse JSON {}", e.getMessage());
		}
		// host.type = (String) getRequestAttributes().get("type");
		// host.vnid = (String) getRequestAttributes().get("network");
		vns.addVlanRule(Integer.parseInt(host.type), host.match, host.vnid);
		setStatus(Status.SUCCESS_OK);
		return "{\"status\":\"ok\"}";
	}

	@Delete
	public String deleteHost(String postData) {
		HostDefinition host = new HostDefinition();
		// Integer type = (Integer) getRequestAttributes().get("type");
		// String vnid = (String) getRequestAttributes().get("vnid");
		try {
			jsonToHostDefinition(postData, host);
		} catch (IOException e) {
			log.error("Could not parse JSON {}", e.getMessage());
		}
		// We try to get the ID from the URI only if it's not
		// in the POST data como en create Network
		IVirtualNetworkService vns = (IVirtualNetworkService) getContext()
				.getAttributes().get(
						IVirtualNetworkService.class.getCanonicalName());
		vns.deleteVlanRule(host.id, host.vnid, Integer.parseInt(host.type));
		setStatus(Status.SUCCESS_OK);
		return "{\"status\":\"ok\"}";
	}

}
