/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: api/listener/listener.proto */

#ifndef PROTOBUF_C_api_2flistener_2flistener_2eproto__INCLUDED
#define PROTOBUF_C_api_2flistener_2flistener_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "listener/listener_components.pb-c.h"
#include "core/address.pb-c.h"
#include "core/base.pb-c.h"

typedef struct Listener__Listener Listener__Listener;


/* --- enums --- */


/* --- messages --- */

struct  Listener__Listener
{
  ProtobufCMessage base;
  Core__ApiStatus api_status;
  char *name;
  Core__SocketAddress *address;
  size_t n_filter_chains;
  Listener__FilterChain **filter_chains;
};
#define LISTENER__LISTENER__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&listener__listener__descriptor) \
    , CORE__API_STATUS__NONE, (char *)protobuf_c_empty_string, NULL, 0,NULL }


/* Listener__Listener methods */
void   listener__listener__init
                     (Listener__Listener         *message);
size_t listener__listener__get_packed_size
                     (const Listener__Listener   *message);
size_t listener__listener__pack
                     (const Listener__Listener   *message,
                      uint8_t             *out);
size_t listener__listener__pack_to_buffer
                     (const Listener__Listener   *message,
                      ProtobufCBuffer     *buffer);
Listener__Listener *
       listener__listener__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   listener__listener__free_unpacked
                     (Listener__Listener *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Listener__Listener_Closure)
                 (const Listener__Listener *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor listener__listener__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_api_2flistener_2flistener_2eproto__INCLUDED */
