#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ndpi_api.h"

struct rs_ndpi {
  struct ndpi_detection_module_struct *mod;
};

struct rs_ndpi *rs_ndpi_new(void) {
  struct rs_ndpi *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) {
    return NULL;
  }
  ctx->mod = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
  if (!ctx->mod) {
    free(ctx);
    return NULL;
  }
  if (ndpi_finalize_initialization(ctx->mod) != 0) {
    ndpi_exit_detection_module(ctx->mod);
    free(ctx);
    return NULL;
  }
  return ctx;
}

void rs_ndpi_free(struct rs_ndpi *ctx) {
  if (!ctx) {
    return;
  }
  if (ctx->mod) {
    ndpi_exit_detection_module(ctx->mod);
  }
  free(ctx);
}

void *rs_ndpi_flow_new(void) {
  size_t n = SIZEOF_FLOW_STRUCT;
  void *flow = ndpi_flow_malloc(n);
  if (flow) {
    memset(flow, 0, n);
  }
  return flow;
}

void rs_ndpi_flow_free(void *flow) {
  if (flow) {
    ndpi_free_flow(flow);
  }
}

int rs_ndpi_inspect(struct rs_ndpi *ctx, void *flow, const uint8_t *ip,
                    uint16_t len, uint64_t time_ms, char *app, size_t app_len,
                    char *category, size_t cat_len) {
  ndpi_protocol proto;
  u_int16_t id;
  const char *name;
  const char *cat;

  if (!ctx || !ctx->mod || !flow || !ip || len == 0 || !app || app_len == 0) {
    return 0;
  }
  proto = ndpi_detection_process_packet(ctx->mod, flow, ip, len, time_ms, NULL);
  id = proto.proto.app_protocol;
  if (id == NDPI_PROTOCOL_UNKNOWN) {
    id = proto.proto.master_protocol;
  }
  if (id == NDPI_PROTOCOL_UNKNOWN) {
    proto = ndpi_detection_giveup(ctx->mod, flow);
    id = proto.proto.app_protocol;
    if (id == NDPI_PROTOCOL_UNKNOWN) {
      id = proto.proto.master_protocol;
    }
  }
  if (id == NDPI_PROTOCOL_UNKNOWN) {
    return 0;
  }
  name = ndpi_get_proto_name(ctx->mod, id);
  if (!name) {
    return 0;
  }
  strncpy(app, name, app_len - 1);
  app[app_len - 1] = 0;
  if (category && cat_len > 0) {
    cat = ndpi_category_get_name(ctx->mod, proto.category);
    if (cat) {
      strncpy(category, cat, cat_len - 1);
      category[cat_len - 1] = 0;
    } else {
      category[0] = 0;
    }
  }
  return 1;
}
