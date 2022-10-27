/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PPC_WRITER_H__
#define __GUM_PPC_WRITER_H__

#include <capstone.h>
#include <gum/gumdefs.h>
#include <gum/gummetalarray.h>
#include <gum/gummetalhash.h>

#define GUM_PPC_B_MAX_DISTANCE 0x01fffffc

G_BEGIN_DECLS

typedef struct _GumPpcWriter GumPpcWriter;

struct _GumPpcWriter
{
  volatile gint ref_count;
  gboolean flush_on_destroy;

  guint32 * base;
  guint32 * code;
  GumAddress pc;


  GumMetalHashTable * label_defs;
  GumMetalArray label_refs;
};


GUM_API GumPpcWriter * gum_ppc_writer_new (gpointer code_address);
GUM_API GumPpcWriter * gum_ppc_writer_ref (GumPpcWriter * writer);
GUM_API void gum_ppc_writer_unref (GumPpcWriter * writer);

GUM_API void gum_ppc_writer_init (GumPpcWriter * writer, gpointer code_address);
GUM_API void gum_ppc_writer_clear (GumPpcWriter * writer);
GUM_API void gum_ppc_writer_reset (GumPpcWriter * writer,
    gpointer code_address);

GUM_API gpointer gum_ppc_writer_cur (GumPpcWriter * self);
GUM_API guint gum_ppc_writer_offset (GumPpcWriter * self);
GUM_API void gum_ppc_writer_skip (GumPpcWriter * self, guint n_bytes);

GUM_API gboolean gum_ppc_writer_flush (GumPpcWriter * self);
GUM_API gboolean gum_ppc_writer_put_label (GumPpcWriter * self,
    gconstpointer id);


GUM_API void gum_ppc_writer_put_call_address_with_arguments (
    GumPpcWriter * self, GumAddress func, guint n_args, ...);
GUM_API void gum_ppc_writer_put_call_address_with_arguments_array (
    GumPpcWriter * self, GumAddress func, guint n_args,
    const GumArgument * args);
GUM_API void gum_ppc_writer_put_call_reg (GumPpcWriter * self, ppc_reg reg);
GUM_API void gum_ppc_writer_put_call_reg_with_arguments (GumPpcWriter * self,
    ppc_reg reg, guint n_args, ...);
GUM_API void gum_ppc_writer_put_call_reg_with_arguments_array (
    GumPpcWriter * self, ppc_reg reg, guint n_args, const GumArgument * args);

GUM_API void gum_ppc_writer_put_branch_address (GumPpcWriter * self,
    GumAddress address);

GUM_API gboolean gum_ppc_writer_can_branch_directly_between (
    GumPpcWriter * self, GumAddress from, GumAddress to);
GUM_API gboolean gum_ppc_writer_put_b_imm (GumPpcWriter * self,
    GumAddress target);
GUM_API gboolean gum_ppc_writer_put_b_cond_imm (GumPpcWriter * self,
    ppc_cc cc, GumAddress target);
GUM_API void gum_ppc_writer_put_b_label (GumPpcWriter * self,
    gconstpointer label_id);
GUM_API void gum_ppc_writer_put_b_cond_label (GumPpcWriter * self,
    ppc_cc cc, gconstpointer label_id);




















G_END_DECLS