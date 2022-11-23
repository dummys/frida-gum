/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2022 PMC, JOB
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_PPC_WRITER_H__
#define __GUM_PPC_WRITER_H__

#include <gum/gumdefs.h>
#include <gum/gummetalarray.h>
#include <gum/gummetalhash.h>

#include <capstone.h>


#define GUM_PPC_B_MAX_DISTANCE 0x3fffffc

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

/*
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

GUM_API gboolean gum_ppc_writer_can_branch_directly_between (
    GumPpcWriter * self, GumAddress from, GumAddress to);
*/

GUM_API gboolean gum_ppc_writer_put_li32_reg_address (GumPpcWriter * self, 
    ppc_reg reg, GumAddress address);
GUM_API gboolean gum_ppc_writer_put_lis_reg_imm (GumPpcWriter * self, ppc_reg reg, 
    guint imm);
GUM_API gboolean gum_ppc_writer_put_addis_reg_reg_imm (GumPpcWriter * self, 
    ppc_reg dst_reg, ppc_reg src_reg, gint16 imm);
GUM_API gboolean gum_ppc_writer_put_stwu_reg_reg_imm (GumPpcWriter * self, 
    ppc_reg ptr_reg, ppc_reg src_reg, gint16 imm);
GUM_API gboolean gum_ppc_writer_put_push_reg (GumPpcWriter * self, ppc_reg src_reg);
GUM_API gboolean gum_ppc_writer_put_ori_reg_reg_imm (GumPpcWriter * self, 
    ppc_reg dst_reg, ppc_reg src_reg, guint16 imm);
GUM_API gboolean gum_ppc_writer_put_mtctr_reg (GumPpcWriter * self, ppc_reg src_reg);
GUM_API gboolean gum_ppc_writer_put_bctr_offset (GumPpcWriter * self);
GUM_API gboolean gum_ppc_writer_put_b_offset (GumPpcWriter * self, gint32 offset);

GUM_API gboolean gum_ppc_writer_put_push_fpreg (GumPpcWriter * self, ppc_reg src_reg);
GUM_API gboolean gum_ppc_writer_put_stfdu_reg_reg_imm (GumPpcWriter * self,
    ppc_reg ptr_reg, ppc_reg src_reg, gint16 imm);


GUM_API gboolean gum_ppc_writer_put_dform_reg_reg_imm (GumPpcWriter * self, 
    guint8 opcode, ppc_reg rts_reg, ppc_reg ra_reg, guint16 imm);

GUM_API guint gum_ppc_writer_offset (GumPpcWriter * self);

GUM_API gboolean gum_ppc_writer_put_nop (GumPpcWriter * self);
GUM_API gboolean gum_ppc_writer_put_instruction (GumPpcWriter * self, guint32 insn);
GUM_API gboolean gum_ppc_writer_put_bytes (GumPpcWriter * self, const guint8 * data,
    guint n);

G_END_DECLS

#endif
