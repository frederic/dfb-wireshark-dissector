#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/wmem/wmem_tree.h>
#include "flz.c"

#define DFB_PORT 2323
#define PKT_HDR_SIZE 16
#define MSG_HDR_SIZE 12

#define MAGIC_PACKET_MODE	0x80008676
#define MODE_RAW	0
#define MODE_PACKET	1

static int proto_dfb = -1;
static int hf_dfb_pkt_hdr_magic = -1;
static int hf_dfb_pkt_hdr_size = -1;
static int hf_dfb_pkt_hdr_flags = -1;
static int hf_dfb_pkt_hdr_uncompressed = -1;
static int hf_dfb_pkt_hdr_align = -1;
static int hf_dfb_pkt_data = -1;
static int hf_dfb_pkt_padding = -1;

static int hf_dfb_msg_size = -1;
static int hf_dfb_msg_serial = -1;
static int hf_dfb_msg_type = -1;

static int hf_dfb_msg_super_ifname = -1;

static int hf_dfb_msg_req_instanceid = -1;
static int hf_dfb_msg_req_methodid = -1;
static int hf_dfb_msg_req_flags = -1;

static int hf_dfb_msg_resp_serial = -1;
static int hf_dfb_msg_resp_result = -1;
static int hf_dfb_msg_resp_instanceid = -1;

static gint ett_dfb = -1;
static gint ett_msg = -1;

typedef enum {
     VMSG_SUPER,
     VMSG_REQUEST,
     VMSG_RESPONSE
} VoodooMessageType;

static const value_string messagetypenames[] = {
    { VMSG_SUPER, "VMSG_SUPER" },
    { VMSG_REQUEST, "VMSG_REQUEST" },
    { VMSG_RESPONSE, "VMSG_RESPONSE" },
    { 0, NULL }
};

static const value_string response_results[] = {
     { 0, "DR_OK" },              /* No error occured */
     { 1, "DR_FAILURE" },         /* A general or unknown error occured */
     { 2, "DR_INIT" },            /* A general initialization error occured */
     { 3, "DR_BUG" },             /* Internal bug or inconsistency has been detected */
     { 4, "DR_DEAD" },            /* Interface has a zero reference counter (available in debug mode) */
     { 5, "DR_UNSUPPORTED" },     /* The requested operation or an argument is (currently) not supported */
     { 6, "DR_UNIMPLEMENTED" },   /* The requested operation is not implemented, yet */
     { 7, "DR_ACCESSDENIED" },    /* Access to the resource is denied */
     { 8, "DR_INVAREA" },         /* An invalid area has been specified or detected */
     { 9, "DR_INVARG" },          /* An invalid argument has been specified */
     { 10, "DR_NOLOCALMEMORY" },   /* There's not enough local system memory */
     { 11, "DR_NOSHAREDMEMORY" },  /* There's not enough shared system memory */
     { 12, "DR_LOCKED" },          /* The resource is (already) locked */
     { 13, "DR_BUFFEREMPTY" },     /* The buffer is empty */
     { 14, "DR_FILENOTFOUND" },    /* The specified file has not been found */
     { 15, "DR_IO" },              /* A general I/O error occured */
     { 16, "DR_BUSY" },            /* The resource or device is busy */
     { 17, "DR_NOIMPL" },          /* No implementation for this interface or content type has been found */
     { 18, "DR_TIMEOUT" },         /* The operation timed out */
     { 19, "DR_THIZNULL" },        /* 'thiz' pointer is NULL */
     { 20, "DR_IDNOTFOUND" },      /* No resource has been found by the specified id */
     { 21, "DR_DESTROYED" },       /* The requested object has been destroyed */
     { 22, "DR_FUSION" },          /* Internal fusion error detected, most likely related to IPC resources */
     { 23, "DR_BUFFERTOOLARGE" },  /* Buffer is too large */
     { 24, "DR_INTERRUPTED" },     /* The operation has been interrupted */
     { 25, "DR_NOCONTEXT" },       /* No context available */
     { 26, "DR_TEMPUNAVAIL" },     /* Temporarily unavailable */
     { 27, "DR_LIMITEXCEEDED" },   /* Attempted to exceed limit, i.e. any kind of maximum size, count etc */
     { 28, "DR_NOSUCHMETHOD" },    /* Requested method is not known */
     { 29, "DR_NOSUCHINSTANCE" },  /* Requested instance is not known */
     { 30, "DR_ITEMNOTFOUND" },    /* No such item found */
     { 31, "DR_VERSIONMISMATCH" }, /* Some versions didn't match */
     { 32, "DR_EOF" },             /* Reached end of file */
     { 33, "DR_SUSPENDED" },       /* The requested object is suspended */
     { 34, "DR_INCOMPLETE" },      /* The operation has been executed, but not completely */
     { 35, "DR_NOCORE" },          /* Core part not available */
     { 36, "DR_SIGNALLED" },       /* Received a signal, e.g. while waiting */
     { 37, "DR_TASK_NOT_FOUND" },  /* The corresponding task has not been found */
     { 38, "DR__RESULT_END" }
} ;

typedef struct voodoo_method voodoo_method_s;

typedef struct voodoo_interface voodoo_interface_s;

struct voodoo_method{
	const gchar *method_name;
	const gint32 returned_interface_id;
};

struct voodoo_interface{
	const gchar *if_name;
	const voodoo_method_s *if_methods;
	const guint32 if_methods_cnt;
};


#define IDIRECTFB_ID				0
#define IDIRECTFBDATABUFFER_ID		1
#define IDIRECTFBSURFACE_ID			2
#define IDIRECTFBPALETTE_ID			3
#define IDIRECTFBSCREEN_ID			4
#define IDIRECTFBDISPLAYLAYER_ID	5
#define IDIRECTFBINPUTDEVICE_ID		6
#define IDIRECTFBIMAGEPROVIDER_ID	7
#define IDIRECTFBFONT_ID			8
#define IDIRECTFBWINDOW_ID			9
#define IDIRECTFBEVENTBUFFER_ID		10

static const voodoo_method_s if_idirectfb_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"SetCooperativeLevel", -1},
	{"GetDeviceDescription", -1},
	{"EnumVideoModes", -1},
	{"SetVideoMode", -1},
	{"CreateSurface", IDIRECTFBSURFACE_ID},
	{"CreatePalette", IDIRECTFBPALETTE_ID},
	{"EnumScreens", -1},
	{"GetScreen", IDIRECTFBSCREEN_ID},
	{"EnumDisplayLayers", -1},
	{"GetDisplayLayer", IDIRECTFBDISPLAYLAYER_ID},
	{"EnumInputDevices", -1},
	{"GetInputDevice", -1},
	{"CreateEventBuffer", -1}, //TODO: return IDirectFBEventBuffer	 ?
	{"CreateInputEventBuffer", -1},//TODO: return IDirectFBEventBuffer	 ?
	{"CreateImageProvider", IDIRECTFBIMAGEPROVIDER_ID},
	{"CreateVideoProvider", -1},
	{"CreateFont", IDIRECTFBFONT_ID},
	{"CreateDataBuffer", IDIRECTFBDATABUFFER_ID},
	{"SetClipboardData", -1},
	{"GetClipboardData", -1},
	{"GetClipboardTimeStamp", -1},
	{"Suspend", -1},
	{"Resume", -1},
	{"WaitIdle", -1},
	{"WaitForSync", -1},
	{"GetInterface", -1},
};

static const voodoo_method_s if_idirectfbdatabuffer_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"Flush", -1},
	{"Finish", -1},
	{"SeekTo", -1},
	{"GetPosition", -1},
	{"GetLength", -1},
	{"WaitForData", -1},
	{"WaitForDataWithTimeout", -1},
	{"GetData", -1},
	{"PeekData", -1},
	{"HasData", -1},
	{"PutData", -1},
	{"CreateImageProvider", -1}
};

static const voodoo_method_s if_idirectfbsurface_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetCapabilities", -1},
	{"GetSize", -1},
	{"GetVisibleRectangle", -1},
	{"GetPixelFormat", -1},
	{"GetAccelerationMask", -1},
	{"GetPalette", -1},
	{"SetPalette", -1},
	{"Lock", -1},
	{"Unlock", -1},
	{"Flip", -1},
	{"SetField", -1},
	{"Clear", -1},
	{"SetClip", -1},
	{"SetColor", -1},
	{"SetColorIndex", -1},
	{"SetSrcBlendFunction", -1},
	{"SetDstBlendFunction", -1},
	{"SetPorterDuff", -1},
	{"SetSrcColorKey", -1},
	{"SetSrcColorKeyIndex", -1},
	{"SetDstColorKey", -1},
	{"SetDstColorKeyIndex", -1},
	{"SetBlittingFlags", -1},
	{"Blit", -1},
	{"TileBlit", -1},
	{"BatchBlit", -1},
	{"StretchBlit", -1},
	{"TextureTriangles", -1},
	{"SetDrawingFlags", -1},
	{"FillRectangle", -1},
	{"DrawLine", -1},
	{"DrawLines", -1},
	{"DrawRectangle", -1},
	{"FillTriangle", -1},
	{"SetFont", -1},
	{"GetFont", -1},
	{"DrawString", -1},
	{"DrawGlyph", -1},
	{"GetSubSurface", -1},
	{"GetGL", -1},
	{"Dump", -1},
	{"FillRectangles", -1},
	{"FillSpans", -1},
	{"GetPosition", -1},
	{"SetEncoding", -1},
	{"DisableAcceleration", -1},
	{"ReleaseSource", -1},
	{"SetIndexTranslation", -1},
	{"SetRenderOptions", -1},
	{"SetMatrix", -1},
	{"SetSourceMask", -1},
	{"MakeSubSurface", -1},
	{"Write", -1},
	{"Read", -1},
	{"SetColors", -1},
	{"BatchBlit2", -1},
	{"SetRemoteInstance", -1},
	{"FillTrapezoids", -1}
};

static const voodoo_method_s if_idirectfbpalette_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetCapabilities", -1},
	{"GetSize", -1},
	{"SetEntries", -1},
	{"GetEntries", -1},
	{"FindBestMatch", -1},
	{"CreateCopy", -1}
};

static const voodoo_method_s if_idirectfbscreen_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetID", -1},
	{"GetDescription", -1},
	{"GetSize", -1},
	{"EnumDisplayLayers", -1},
	{"SetPowerMode", -1},
	{"WaitForSync", -1},
	{"GetMixerDescriptions", -1},
	{"GetMixerConfiguration", -1},
	{"TestMixerConfiguration", -1},
	{"SetMixerConfiguration", -1},
	{"GetEncoderDescriptions", -1},
	{"GetEncoderConfiguration", -1},
	{"TestEncoderConfiguration", -1},
	{"SetEncoderConfiguration", -1},
	{"GetOutputDescriptions", -1},
	{"GetOutputConfiguration", -1},
	{"TestOutputConfiguration", -1},
	{"SetOutputConfiguration", -1}
};

static const voodoo_method_s if_idirectfbdisplaylayer_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetID", -1},
	{"GetDescription", -1},
	{"GetSurface", -1},
	{"GetScreen", -1},
	{"SetCooperativeLevel", -1},
	{"SetOpacity", -1},
	{"GetCurrentOutputField", -1},
	{"SetScreenLocation", -1},
	{"SetSrcColorKey", -1},
	{"SetDstColorKey", -1},
	{"GetLevel", -1},
	{"SetLevel", -1},
	{"GetConfiguration", -1},
	{"TestConfiguration", -1},
	{"SetConfiguration", -1},
	{"SetBackgroundMode", -1},
	{"SetBackgroundColor", -1},
	{"SetBackgroundImage", -1},
	{"GetColorAdjustment", -1},
	{"SetColorAdjustment", -1},
	{"CreateWindow", IDIRECTFBWINDOW_ID},
	{"GetWindow", -1},
	{"WarpCursor", -1},
	{"SetCursorAcceleration", -1},
	{"EnableCursor", -1},
	{"GetCursorPosition", -1},
	{"SetCursorShape", -1},
	{"SetCursorOpacity", -1},
	{"SetFieldParity", -1},
	{"WaitForSync", -1},
	{"GetWindowByResourceID", -1},
	{"GetRotation", -1}
};	

static const voodoo_method_s if_idirectfbinputdevice_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetID", -1},
	{"GetDescription", -1},
	{"GetKeymapEntry", -1},
	{"CreateEventBuffer", -1},
	{"AttachEventBuffer", -1},
	{"GetKeyState", -1},
	{"GetModifiers", -1},
	{"GetLockState", -1},
	{"GetButtons", -1},
	{"GetButtonState", -1},
	{"GetAxis", -1},
	{"GetXY", -1},
	{"DetachEventBuffer", -1}
};

static const voodoo_method_s if_idirectfbimageprovider_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetSurfaceDescription", -1},
	{"GetImageDescription", -1},
	{"RenderTo", -1},
	{"SetRenderCallback", -1}
};

static const voodoo_method_s if_idirectfbfont_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"GetAscender", -1},
	{"GetDescender", -1},
	{"GetHeight", -1},
	{"GetMaxAdvance", -1},
	{"GetKerning", -1},
	{"GetStringWidth", -1},
	{"GetStringExtents", -1},
	{"GetGlyphExtents", -1}
};

static const voodoo_method_s if_idirectfbwindow_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"CreateEventBuffer", -1},
	{"AttachEventBuffer", -1},
	{"EnableEvents", -1},
	{"DisableEvents", -1},
	{"GetID", -1},
	{"GetPosition", -1},
	{"GetSize", -1},
	{"GetSurface", IDIRECTFBSURFACE_ID},
	{"SetOptions", -1},
	{"GetOptions", -1},
	{"SetColorKey", -1},
	{"SetColorKeyIndex", -1},
	{"SetOpaqueRegion", -1},
	{"SetOpacity", -1},
	{"GetOpacity", -1},
	{"SetCursorShape", -1},
	{"RequestFocus", -1},
	{"GrabKeyboard", -1},
	{"UngrabKeyboard", -1},
	{"GrabPointer", -1},
	{"UngrabPointer", -1},
	{"GrabKey", -1},
	{"UngrabKey", -1},
	{"Move", -1},
	{"MoveTo", -1},
	{"Resize", -1},
	{"SetStackingClass", -1},
	{"Raise", -1},
	{"Lower", -1},
	{"RaiseToTop", -1},
	{"LowerToBottom", -1},
	{"PutAtop", -1},
	{"PutBelow", -1},
	{"Close", -1},
	{"Destroy", -1},
	{"DetachEventBuffer", -1},
	{"SetBounds", -1},
	{"ResizeSurface", -1},
	{"Bind", -1},
	{"Unbind", -1},
	{"SetKeySelection", -1},
	{"GrabUnselectedKeys", -1},
	{"UngrabUnselectedKeys", -1},
	{"SetSrcGeometry", -1},
	{"SetDstGeometry", -1},
	{"SetProperty", -1},
	{"GetProperty", -1},
	{"RemoveProperty", -1},
	{"SetRotation", -1},
	{"SetAssociation", -1},
	{"BeginUpdates", -1},
	{"SetCursorFlags", -1},
	{"SetCursorResolution", -1},
	{"SetCursorPosition", -1},
	{"SendEvent", -1}
};

static const voodoo_method_s if_idirectfbeventbuffer_methods[] = {
	{NULL, -1},
	{"AddRef", -1},
	{"Release", -1},
	{"Reset", -1},
	{"WaitForEvent", -1},
	{"WaitForEventWithTimeout", -1},
	{"GetEvent", -1},
	{"PeekEvent", -1},
	{"HasEvent", -1},
	{"PostEvent", -1},
	{"WakeUp", -1},
	{"CreateFileDescriptor", -1}
};

static const voodoo_interface_s if_idirectfb_interfaces[] = {
	{"IDirectFB", if_idirectfb_methods, 29},
	{"IDirectFBDataBuffer", if_idirectfbdatabuffer_methods, 15},
	{"IDirectFBSurface", if_idirectfbsurface_methods, 61},
	{"IDirectFBPalette", if_idirectfbpalette_methods, 9},
	{"IDirectFBScreen", if_idirectfbscreen_methods, 21},
	{"IDirectFBDisplayLayer", if_idirectfbdisplaylayer_methods, 35},
	{"IDirectFBInputDevice", if_idirectfbinputdevice_methods, 16},
	{"IDirectFBImageProvider", if_idirectfbimageprovider_methods, 7},
	{"IDirectFBFont", if_idirectfbfont_methods, 11},
	{"IDirectFBWindow", if_idirectfbwindow_methods, 58},
	{"IDirectFBEventBuffer", if_idirectfbeventbuffer_methods, 12}
};

typedef struct dfb_conn_data {
	guint32 mode;
	wmem_tree_t *interfaces; //(msg_serial:  voodoo_interface_s*)
	wmem_tree_t *instances;  //(instance_id: voodoo_interface_s*)
} dfb_conn_data_t;

static int dissect_dfb_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static int dissect_dfb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dfb_conn_data_t *conn_data);

static const voodoo_interface_s* lookup_voodoo_interface(const gchar* if_name);
