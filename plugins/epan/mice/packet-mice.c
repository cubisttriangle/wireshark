#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

// Miracast MICE sink server port.
#define MICE_PORT 7250

// Minimum message length, if no TLVs are specified.
#define MICE_MSG_MIN_LEN 4

static int  proto_mice       = -1;
static int  hf_mice_msg_size = -1;
static int  hf_mice_msg_ver  = -1;
static int  hf_mice_msg_cmd  = -1;
static gint ett_mice         = -1;

static int  proto_tlv_arr    = -1;

static int  proto_tlv        = -1;
static int  hf_mice_tlv_type = -1;
static int  hf_mice_tlv_len  = -1;
static int  hf_mice_tlv_val  = -1;
static gint ett_tlv          = -1;

static const value_string cmd_names[] =
{
    { 1, "Source Ready" },
    { 2, "Stop Projection" },
    { 3, "Security Handshake" },
    { 4, "Session Request" },
    { 5, "PIN Challenge" },
    { 6, "PIN Response" },
    { 0, NULL }
};

static const value_string tlv_types[] =
{
    { 0, "Friendly Name" },
    /* Yes. 1 is really skipped. */
    { 2, "Rtsp Port" },
    { 3, "Source ID" },
    { 4, "Security Token" },
    { 5, "Security Options" },
    { 6, "PIN Challenge" },
    { 7, "PIN Response Reason" }
};

static int dissect_mice_msg( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_ )
{
    // Get the mice message packet length.
    guint16 pkt_len = tvb_get_guint16( tvb, 0, ENC_BIG_ENDIAN );

    // Get the command type.
    guint8 cmd_type = tvb_get_guint8( tvb, 3 );

    // Set the protocol name column.
    col_set_str( pinfo->cinfo, COL_PROTOCOL, "MICE" );

    // Clear out stuff in the info column.
    col_clear( pinfo->cinfo, COL_INFO );

    // Populate info column with command type.
    col_add_fstr( pinfo->cinfo, COL_INFO, "%s",
                  val_to_str( cmd_type, cmd_names, "Unknown (0x%02x)" ) );

    proto_item* ti = proto_tree_add_item( tree, proto_mice, tvb, 0, -1, ENC_NA );
    proto_tree* mice_tree = proto_item_add_subtree( ti, ett_mice );
    proto_tree_add_item( mice_tree, hf_mice_msg_size, tvb, 0, 2, ENC_BIG_ENDIAN );
    proto_tree_add_item( mice_tree, hf_mice_msg_ver, tvb, 2, 1, ENC_BIG_ENDIAN );
    proto_tree_add_item( mice_tree, hf_mice_msg_cmd, tvb, 3, 1, ENC_BIG_ENDIAN );

    guint16 pos = MICE_MSG_MIN_LEN;

    if ( pkt_len > MICE_MSG_MIN_LEN )
    {
        // Add TLV array subtree
        proto_item* tlv_arr_item = proto_tree_add_item( mice_tree, proto_tlv_arr,
                                                        tvb, pos, -1, ENC_NA );
        proto_tree* tlv_arr_tree = proto_item_add_subtree( tlv_arr_item, ett_mice );

        while ( pos < pkt_len )
        {
            guint8 type = tvb_get_guint8( tvb, pos );
            guint16 len = tvb_get_guint16( tvb, pos+1, ENC_BIG_ENDIAN );
            //const guint8* val = tvb_get_ptr( tvb, pos+3, len );

            proto_item* tlv_item = proto_tree_add_item( tlv_arr_tree, proto_tlv,
                                                        tvb, pos, -1, ENC_NA );
            proto_tree* tlv_tree = proto_item_add_subtree( tlv_item, ett_mice );

            // Add and retrieve TLV type. Increment position.
            proto_tree_add_item( tlv_tree, hf_mice_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN );
            ++pos;

            // Add and retrieve TLV length. Increment position.
            proto_tree_add_item( tlv_tree, hf_mice_tlv_len, tvb, pos, 2, ENC_BIG_ENDIAN );
            pos += 2;

            switch ( type )
            {
            case 0: 
            {
                // Friendly name
                proto_item_append_text( tlv_item, " Friendly Name" );

                guint8* name = tvb_get_string_enc( wmem_packet_scope(), tvb, pos, len,
                                                   ENC_UTF_16|ENC_LITTLE_ENDIAN );

                proto_tree_add_bytes_format_value( tlv_tree, hf_mice_tlv_val, tvb,
                                                   pos, len, &len, name );
            }
                break;
            case 2:
            {
                // Rtsp port
                proto_item_append_text( tlv_item, " RTSP Port" );
                guint16 port = tvb_get_guint16( tvb, pos, ENC_BIG_ENDIAN );
                proto_tree_add_bytes_format_value( tlv_tree, hf_mice_tlv_val, tvb,
                                                   pos, len, &len, "%u", port );
            }
                break;
            case 3:
                // Source ID
                proto_item_append_text( tlv_item, " Source ID" );
                proto_tree_add_item( tlv_tree, hf_mice_tlv_val, tvb, pos, len, ENC_NA );
                break;
            case 4:
                // Security token
                proto_item_append_text( tlv_item, " Security Token" );
                proto_tree_add_item( tlv_tree, hf_mice_tlv_val, tvb, pos, len, ENC_NA );
                break;
            case 5:
                // Security options
                proto_item_append_text( tlv_item, " Security Options" );
                proto_tree_add_item( tlv_tree, hf_mice_tlv_val, tvb, pos, len, ENC_NA );
                break;
            case 6:
                // PIN challenge
                proto_item_append_text( tlv_item, " PIN Challenge" );
                proto_tree_add_item( tlv_tree, hf_mice_tlv_val, tvb, pos, len, ENC_NA );
                break;
            case 7:
                // PIN response reason
                proto_item_append_text( tlv_item, " PIN Response Reason" );
                proto_tree_add_item( tlv_tree, hf_mice_tlv_val, tvb, pos, len, ENC_NA );
                break;
            }
           
            pos += len;

        }
    }

    return tvb_captured_length( tvb );
}

static int get_mice_msg_len( packet_info* pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_ )
{
    return tvb_get_guint16( tvb, offset, ENC_BIG_ENDIAN );
    
}

static int dissect_mice( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_ )
{
    // Get the mice message packet length.

    tcp_dissect_pdus( tvb, pinfo, tree, TRUE, 2, get_mice_msg_len, dissect_mice_msg, data );

    return tvb_captured_length( tvb );
}

void proto_reg_handoff_mice( void )
{
    static dissector_handle_t mice_handle;

    mice_handle = create_dissector_handle( dissect_mice, proto_mice );
    dissector_add_uint( "tcp.port", MICE_PORT, mice_handle );
}

void proto_register_mice( void )
{
    // Setup our MICE protocol data unit (PDU).
    static hf_register_info main_hf[] =
    {
      {
        &hf_mice_msg_size,
        {
          "Length", "mice.len",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           NULL, HFILL
        }
      },
      {
        &hf_mice_msg_ver,
        {
          "Version", "mice.ver",
           FT_UINT8, BASE_DEC,
           NULL, 0x0,
           NULL, HFILL
        }
      },
      {
        &hf_mice_msg_cmd,
        {
          "Command", "mice.cmd",
           FT_UINT8, BASE_DEC,
           VALS( cmd_names ), 0x0,
           NULL, HFILL
        }
      }
    };

    static hf_register_info tlv_hf[] =
    {
      {
        &hf_mice_tlv_type,
        {
          "Type", "mice.tlv.type",
           FT_UINT8, BASE_DEC,
           VALS( tlv_types ), 0x0,
           NULL, HFILL
        }
      },
      {
        &hf_mice_tlv_len,
        {
          "Length", "mice.tlv.len",
           FT_UINT16, BASE_DEC,
           NULL, 0x0,
           NULL, HFILL
        }
      },
      {
        &hf_mice_tlv_val,
        {
          "Value", "mice.tlv.val",
           FT_BYTES, BASE_NONE,
           NULL, 0x0,
           NULL, HFILL
        }
      }
    };

    // Setup protocol subtree array.
    static gint* ett[] = {
        &ett_mice,
        &ett_tlv
    };

    proto_mice = proto_register_protocol (
        "Miracast Infrastructure Connection Establishment Protocol", /* name */
        "MICE",      /* short name */
        "mice"       /* abbrev     */
    );

    proto_tlv_arr = proto_register_protocol (
        "TLV Array",
        "TLVs",
        "tlvs"
    );

    proto_tlv = proto_register_protocol (
        "TLV",
        "TLV",
        "tlv"
    );

    proto_register_field_array( proto_mice, main_hf, array_length( main_hf ) );
    proto_register_field_array( proto_tlv_arr, NULL, 0 );
    proto_register_field_array( proto_tlv, tlv_hf, array_length( tlv_hf ) );

    // Register subtree array.
    proto_register_subtree_array( ett, array_length( ett ) );
}
