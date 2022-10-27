/*
 * Copyright (C) 2009-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PPC_RELOCATOR_H__
#define __GUM_PPC_RELOCATOR_H__

#include "gumPPCwriter.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumPPCRelocator GumPPCRelocator;

struct _GumPPCRelocator
{
  volatile gint ref_count;

  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  GumAddress input_pc;
  cs_insn ** input_insns;
  GumPPCWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

GUM_API GumPPCRelocator * gum_ppc_relocator_new (gconstpointer input_code,
    GumPPCWriter * output);
GUM_API GumPPCRelocator * gum_ppc_relocator_ref (GumPPCRelocator * relocator);
GUM_API void gum_ppc_relocator_unref (GumPPCRelocator * relocator);

GUM_API void gum_ppc_relocator_init (GumPPCRelocator * relocator,
    gconstpointer input_code, GumPPCWriter * output);
GUM_API void gum_ppc_relocator_clear (GumPPCRelocator * relocator);

GUM_API void gum_ppc_relocator_reset (GumPPCRelocator * relocator,
    gconstpointer input_code, GumPPCWriter * output);

GUM_API guint gum_ppc_relocator_read_one (GumPPCRelocator * self,
    const cs_insn ** instruction);

GUM_API cs_insn * gum_ppc_relocator_peek_next_write_insn (
    GumPPCRelocator * self);
GUM_API gpointer gum_ppc_relocator_peek_next_write_source (
    GumPPCRelocator * self);
GUM_API void gum_ppc_relocator_skip_one (GumPPCRelocator * self);
GUM_API void gum_ppc_relocator_skip_one_no_label (GumPPCRelocator * self);
GUM_API gboolean gum_ppc_relocator_write_one (GumPPCRelocator * self);
GUM_API gboolean gum_ppc_relocator_write_one_no_label (GumPPCRelocator * self);
GUM_API void gum_ppc_relocator_write_all (GumPPCRelocator * self);

GUM_API gboolean gum_ppc_relocator_eob (GumPPCRelocator * self);
GUM_API gboolean gum_ppc_relocator_eoi (GumPPCRelocator * self);

GUM_API gboolean gum_ppc_relocator_can_relocate (gpointer address,
    guint min_bytes, guint * maximum);
GUM_API guint gum_ppc_relocator_relocate (gpointer from, guint min_bytes,
    gpointer to);

G_END_DECLS

#endif
