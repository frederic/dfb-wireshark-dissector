#include "packet-directfb.h"

void proto_register_dfb(void)
{
	static hf_register_info hf[] = {
        { &hf_dfb_pkt_hdr_magic,
            { "Voodoo Packet Magic", "dfb.magic",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_pkt_hdr_size,
            { "Voodoo Packet Size", "dfb.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
		{ &hf_dfb_pkt_hdr_flags,
            { "Voodoo Packet Flags", "dfb.flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
		{ &hf_dfb_pkt_hdr_uncompressed,
            { "Voodoo Packet Uncompressed Size", "dfb.uncompressed",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
		{ &hf_dfb_pkt_hdr_align,
            { "Voodoo Packet Align", "dfb.align",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_pkt_data,
            { "Voodoo Packet Data", "dfb.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
		{ &hf_dfb_pkt_padding,
            { "Voodoo Packet Padding", "dfb.padding",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_size,
            { "Voodoo Message Size", "dfb.msg.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_serial,
            { "Voodoo Message Serial", "dfb.msg.serial",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_type,
            { "Voodoo Message Type", "dfb.msg.type",
            FT_UINT8, BASE_DEC,
            VALS(messagetypenames), 0x0,
            NULL, HFILL }
        },
		{ &hf_dfb_msg_super_ifname,
            { "Super Interface Name", "dfb.msg.super.ifname",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_req_instanceid,
            { "Request Instance Id", "dfb.msg.req.instanceid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_req_methodid,
            { "Request Method Id", "dfb.msg.req.methodid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_req_flags,
            { "Request flags", "dfb.msg.req.flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_resp_serial,
            { "Response serial", "dfb.msg.resp.serial",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_resp_result,
            { "Response result", "dfb.msg.resp.result",
            FT_UINT32, BASE_DEC,
            VALS(response_results), 0x0,
            NULL, HFILL }
        },
        { &hf_dfb_msg_resp_instanceid,
            { "Response Instance Id", "dfb.msg.resp.instanceid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        }
    };
    
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dfb,
        &ett_msg
    };

    proto_dfb = proto_register_protocol (
        "DirectFB Voodoo Protocol", /* name       */
        "DFB",      /* short name */
        "dfb"       /* abbrev     */
        );
        
    proto_register_field_array(proto_dfb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static dfb_conn_data_t* init_conversation_data(conversation_t  *conversation){
	dfb_conn_data_t* conn_data = wmem_new(wmem_file_scope(), dfb_conn_data_t);
	conn_data->mode = MODE_RAW;
	conversation_add_proto_data(conversation, proto_dfb, conn_data);
	conn_data->instances = wmem_tree_new(wmem_file_scope());
	conn_data->interfaces = wmem_tree_new(wmem_file_scope());
	return conn_data;
}

static int dissect_dfb_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	tvbuff_t *msg_tvb;
	gint offset = 0;
	guint32 pkt_data_len, flags, orig_size;
	dfb_conn_data_t  *conn_data;
	conversation_t  *conversation;
	
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DFB");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
	
    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *dfb_tree = NULL;
        
		ti = proto_tree_add_item(tree, proto_dfb, tvb, 0, -1, ENC_NA);
		dfb_tree = proto_item_add_subtree(ti, ett_dfb);
		
		conversation = find_or_create_conversation(pinfo);
		conn_data = (dfb_conn_data_t *)conversation_get_proto_data(conversation, proto_dfb);
		if(!conn_data){
			conn_data = init_conversation_data(conversation);
			if (tvb_get_letohl(tvb, 0) == MAGIC_PACKET_MODE){
				conn_data->mode = MODE_PACKET;
			}else{
				conn_data->mode = MODE_RAW;
			}
		}
		
		if (conn_data->mode == MODE_PACKET){
			if (tvb_get_letohl(tvb, 0) == MAGIC_PACKET_MODE){//present in first packet only
				proto_tree_add_item(dfb_tree, hf_dfb_pkt_hdr_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			
			proto_tree_add_item(dfb_tree, hf_dfb_pkt_hdr_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			pkt_data_len = tvb_get_letohl(tvb, offset);
			offset += 4;
			
			proto_tree_add_item(dfb_tree, hf_dfb_pkt_hdr_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			flags = tvb_get_letohl(tvb, offset);
			offset += 4;
			
			proto_tree_add_item(dfb_tree, hf_dfb_pkt_hdr_uncompressed, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			orig_size = tvb_get_letohl(tvb, offset);
			offset += 4;
			
			proto_tree_add_item(dfb_tree, hf_dfb_pkt_hdr_align, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			proto_tree_add_item(dfb_tree, hf_dfb_pkt_data, tvb, offset, (((pkt_data_len) + 3) & ~3), ENC_NA);
			
			if (flags & 0x00000001) {
				guchar *decompressed_buffer = (guchar*)g_malloc(orig_size);
				fastlz_decompress(tvb_get_ptr(tvb, offset, pkt_data_len), pkt_data_len, decompressed_buffer, orig_size);
				msg_tvb = tvb_new_child_real_data(tvb, decompressed_buffer, orig_size, orig_size);
				tvb_set_free_cb(msg_tvb, g_free);
				add_new_data_source(pinfo, msg_tvb, "Decompressed Packet");
			} else {
				msg_tvb = tvb_new_subset_remaining(tvb, offset);
			}
			
			offset += dissect_dfb_message(msg_tvb, pinfo, dfb_tree, conn_data); //TODO : not sure about that
			offset += (((pkt_data_len) + 3) & ~3); //TODO : not sure about that
		}else{
			offset += dissect_dfb_message(tvb, pinfo, dfb_tree, conn_data);
		}
    }
    return offset;
}

static int dissect_dfb_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, dfb_conn_data_t *conn_data)
{
	gint offset = 0;
	gint returned_interface_id;
	guint32 msg_len, msg_serial, msg_type, msg_resp_serial, msg_result, msg_instanceid, msg_methodid;
	gchar *msg_super_ifname;
	voodoo_interface_s *if_instance;
	proto_item *msg_item = NULL;
	proto_item *proto_req_instanceid = NULL;
	proto_item *proto_req_methodid = NULL;
	proto_tree *msg_tree = NULL;
	
	if (tree) { /* we are being asked for details */
		offset = 0;
		msg_item = proto_tree_add_text(tree, tvb, offset, tvb_length(tvb), "Message");
		msg_tree = proto_item_add_subtree(msg_item, ett_msg);
		
		proto_tree_add_item(msg_tree, hf_dfb_msg_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		msg_len = tvb_get_letohl(tvb, offset);
		offset += 4;
		
		proto_tree_add_item(msg_tree, hf_dfb_msg_serial, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		msg_serial = tvb_get_letohl(tvb, offset);
		offset += 4;
		
		proto_tree_add_item(msg_tree, hf_dfb_msg_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		msg_type = tvb_get_letohl(tvb, offset);
		offset += 4;
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message type: %s",
             val_to_str(msg_type, messagetypenames, "Unknown (0x%02x)"));
		
		switch(msg_type) {
			
			case VMSG_SUPER:
				proto_tree_add_item(msg_tree, hf_dfb_msg_super_ifname, tvb, offset, msg_len - offset, ENC_LITTLE_ENDIAN);
				msg_super_ifname = tvb_get_string(wmem_file_scope(), tvb, offset, msg_len - offset);
				if_instance = (voodoo_interface_s*)lookup_voodoo_interface(msg_super_ifname);
				if(if_instance){
					wmem_tree_insert32(conn_data->interfaces, msg_serial, if_instance);
				}
				offset = msg_len;
				break;
			
			case VMSG_REQUEST:
				proto_req_instanceid = proto_tree_add_item(msg_tree, hf_dfb_msg_req_instanceid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				msg_instanceid = tvb_get_letohl(tvb, offset);
				if_instance = (voodoo_interface_s*) wmem_tree_lookup32(conn_data->instances, msg_instanceid);
				if(if_instance){
					proto_item_append_text(proto_req_instanceid, " (%s)", if_instance->if_name);
				}
				offset += 4;

				proto_req_methodid = proto_tree_add_item(msg_tree, hf_dfb_msg_req_methodid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				msg_methodid = tvb_get_letohl(tvb, offset);
				if(if_instance && msg_methodid < if_instance->if_methods_cnt){
					proto_item_append_text(proto_req_methodid, " (%s)", if_instance->if_methods[msg_methodid].method_name);
					returned_interface_id = if_instance->if_methods[msg_methodid].returned_interface_id;
					if(returned_interface_id >= 0){
						wmem_tree_insert32(conn_data->interfaces, msg_serial, (struct voodoo_interface_s *)&if_idirectfb_interfaces[returned_interface_id]);
					}
				}
				offset += 4;

				proto_tree_add_item(msg_tree, hf_dfb_msg_req_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				
				break;
			
			case VMSG_RESPONSE:
				proto_tree_add_item(msg_tree, hf_dfb_msg_resp_serial, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				msg_resp_serial = tvb_get_letohl(tvb, offset);
				offset += 4;
				
				proto_tree_add_item(msg_tree, hf_dfb_msg_resp_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				msg_result = tvb_get_letohl(tvb, offset);
				offset += 4;
				
				proto_tree_add_item(msg_tree, hf_dfb_msg_resp_instanceid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				msg_instanceid = tvb_get_letohl(tvb, offset);
				offset += 4;
				
				if(msg_result == 0 && msg_instanceid != 0){
					if_instance = (voodoo_interface_s*) wmem_tree_lookup32(conn_data->interfaces, msg_resp_serial);
					if(if_instance){
						wmem_tree_insert32(conn_data->instances, msg_instanceid, if_instance);
						
					}
				}
				break;
			
			default:
				
				break;
		}
	}
	return offset;
}

static const voodoo_interface_s* lookup_voodoo_interface(const gchar* if_name){
	guint i;
	for(i = 0; i < sizeof(if_idirectfb_interfaces); i++){
		if(!strcmp(if_idirectfb_interfaces[i].if_name, if_name)){
			return &if_idirectfb_interfaces[i];
		}
	}
	return NULL;
}

static guint get_dfb_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	guint32 msg_size;
	dfb_conn_data_t  *conn_data;
	conversation_t  *conversation = find_or_create_conversation(pinfo);
	conn_data= (dfb_conn_data_t *)conversation_get_proto_data(conversation, proto_dfb);
	if(!conn_data){
		conn_data = init_conversation_data(conversation);
	}
	
	msg_size = tvb_get_letohl(tvb, offset);
	if(msg_size == MAGIC_PACKET_MODE) {
		msg_size = tvb_get_letohl(tvb, offset + 4) + 4;
		conn_data->mode = MODE_PACKET;
	}
	
	if(conn_data->mode){ //PACKET MODE
		return (((msg_size) + 3) & ~3) + PKT_HDR_SIZE;
	}else{ //RAW MODE
		return (((msg_size) + 3) & ~3);
	}
}

static void dissect_dfb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	unsigned int MIN_LEN = 8;
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_LEN, get_dfb_message_len, dissect_dfb_packet, NULL);
}

void proto_reg_handoff_dfb(void)
{
    static dissector_handle_t dfb_handle;

    dfb_handle = create_dissector_handle(dissect_dfb, proto_dfb);
    dissector_add_uint("tcp.port", DFB_PORT, dfb_handle);
}
