/*
 * Copyright (C) 2009-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PPC_RELOCATOR_H__
#define __GUM_PPC_RELOCATOR_H__

#include "gumppcwriter.h"

#include <capstone.h>

G_BEGIN_DECLS

typedef struct _GumPpcRelocator GumPpcRelocator;

struct _GumPpcRelocator
{
  volatile gint ref_count;

  csh capstone;

  const guint8 * input_start;
  const guint8 * input_cur;
  GumAddress input_pc;
  cs_insn ** input_insns;
  GumPpcWriter * output;

  guint inpos;
  guint outpos;

  gboolean eob;
  gboolean eoi;
};

GUM_API GumPpcRelocator * gum_ppc_relocator_new (gconstpointer input_code,
    GumPpcWriter * output);
GUM_API GumPpcRelocator * gum_ppc_relocator_ref (GumPpcRelocator * relocator);
GUM_API void gum_ppc_relocator_unref (GumPpcRelocator * relocator);

GUM_API void gum_ppc_relocator_init (GumPpcRelocator * relocator,
    gconstpointer input_code, GumPpcWriter * output);
GUM_API void gum_ppc_relocator_clear (GumPpcRelocator * relocator);

GUM_API void gum_ppc_relocator_reset (GumPpcRelocator * relocator,
    gconstpointer input_code, GumPpcWriter * output);

GUM_API guint gum_ppc_relocator_read_one (GumPpcRelocator * self,
    const cs_insn ** instruction);

GUM_API cs_insn * gum_ppc_relocator_peek_next_write_insn (
    GumPpcRelocator * self);
GUM_API gpointer gum_ppc_relocator_peek_next_write_source (
    GumPpcRelocator * self);
GUM_API void gum_ppc_relocator_skip_one (GumPpcRelocator * self);
GUM_API void gum_ppc_relocator_skip_one_no_label (GumPpcRelocator * self);
GUM_API gboolean gum_ppc_relocator_write_one (GumPpcRelocator * self);
GUM_API gboolean gum_ppc_relocator_write_one_no_label (GumPpcRelocator * self);
GUM_API void gum_ppc_relocator_write_all (GumPpcRelocator * self);

GUM_API gboolean gum_ppc_relocator_eob (GumPpcRelocator * self);
GUM_API gboolean gum_ppc_relocator_eoi (GumPpcRelocator * self);

GUM_API gboolean gum_ppc_relocator_can_relocate (gpointer address,
    guint min_bytes, guint * maximum, ppc_reg * available_scratch_reg);
GUM_API guint gum_ppc_relocator_relocate (gpointer from, guint min_bytes,
    gpointer to);

G_END_DECLS

#endif
