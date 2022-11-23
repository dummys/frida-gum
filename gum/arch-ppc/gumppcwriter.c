/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2022 PMC, JOB
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumppcwriter.h"

#include "gumlibc.h"
#include "gummemory.h"

typedef struct _GumPpcLabelRef GumPpcLabelRef;
typedef struct _GumPpcRegInfo GumPpcRegInfo;

struct _GumPpcLabelRef
{
  gconstpointer id;
  guint32 * insn;
};

struct _GumPpcRegInfo
{
  guint width;
  guint index;
};

GumPpcWriter *
gum_ppc_writer_new (gpointer code_address)
{
  GumPpcWriter * writer;

  writer = g_slice_new (GumPpcWriter);

  gum_ppc_writer_init (writer, code_address);

  return writer;
}

GumPpcWriter *
gum_ppc_writer_ref (GumPpcWriter * writer)
{
  g_atomic_int_inc (&writer->ref_count);

  return writer;
}

void
gum_ppc_writer_unref (GumPpcWriter * writer)
{
  if (g_atomic_int_dec_and_test (&writer->ref_count))
  {
    gum_ppc_writer_clear (writer);

    g_slice_free (GumPpcWriter, writer);
  }
}

void
gum_ppc_writer_init (GumPpcWriter * writer,
                      gpointer code_address)
{
  writer->ref_count = 1;
  writer->flush_on_destroy = TRUE;

  writer->label_defs = NULL;
  writer->label_refs.data = NULL;

  gum_ppc_writer_reset (writer, code_address);
}

static gboolean
gum_ppc_writer_has_label_defs (GumPpcWriter * self)
{
  return self->label_defs != NULL;
}

static gboolean
gum_ppc_writer_has_label_refs (GumPpcWriter * self)
{
  return self->label_refs.data != NULL;
}

void
gum_ppc_writer_clear (GumPpcWriter * writer)
{
  if (writer->flush_on_destroy)
    gum_ppc_writer_flush (writer);

  if (gum_ppc_writer_has_label_defs (writer))
    gum_metal_hash_table_unref (writer->label_defs);

  if (gum_ppc_writer_has_label_refs (writer))
    gum_metal_array_free (&writer->label_refs);
}

gboolean
gum_ppc_writer_put_label (GumPpcWriter * self,
                          gconstpointer id)
{
  if (!gum_ppc_writer_has_label_defs (self))
    self->label_defs = gum_metal_hash_table_new (NULL, NULL);

  if (gum_metal_hash_table_lookup (self->label_defs, id) != NULL)
    return FALSE;

  gum_metal_hash_table_insert (self->label_defs, (gpointer) id, self->code);

  return TRUE;
}

void
gum_ppc_writer_reset (GumPpcWriter * writer,
                      gpointer code_address)
{

  writer->base = code_address;
  writer->code = code_address;
  writer->pc = GUM_ADDRESS (code_address);

  if (gum_ppc_writer_has_label_defs (writer))
    gum_metal_hash_table_remove_all (writer->label_defs);

  if (gum_ppc_writer_has_label_refs (writer))
    gum_metal_array_remove_all (&writer->label_refs);
}

gpointer
gum_ppc_writer_cur (GumPpcWriter * self)
{
  return self->code;
}

guint
gum_ppc_writer_offset (GumPpcWriter * self)
{
  return self->code - self->base;
}

void
gum_ppc_writer_skip (GumPpcWriter * self,
                     guint n_bytes)
{
  self->code = (guint32 *) (((guint8 *) self->code) + n_bytes);
  self->pc += n_bytes;
}

gboolean
gum_ppc_writer_flush (GumPpcWriter * self)
{
    return TRUE;
}

static void
gum_ppc_writer_describe_reg (GumPpcWriter * self,
                             ppc_reg reg,
                             GumPpcRegInfo * ri)
{
  if (reg >= PPC_REG_R0 && reg <= PPC_REG_R31)
  {
    ri->width = GLIB_SIZEOF_VOID_P * 8;
    ri->index = reg - PPC_REG_R0;
  }
  else if (reg >= PPC_REG_F0 && reg <= PPC_REG_F31)
  {
    ri->width = 2 * (GLIB_SIZEOF_VOID_P * 8);
    ri->index = reg - PPC_REG_F0;
  }
  else
  {
    g_assert_not_reached ();
  }
}


/* Load 32bit immediate shifted, pseudo instruction */
gboolean
gum_ppc_writer_put_li32_reg_address (GumPpcWriter * self,
                                     ppc_reg reg,
                                     GumAddress address)
{
  if(!gum_ppc_writer_put_lis_reg_imm (self, reg, address >> 16))
    return FALSE;
  return gum_ppc_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
}


/* Load 16bit immediate shifted (mnemonic, uses addis) */
gboolean
gum_ppc_writer_put_lis_reg_imm (GumPpcWriter * self,
                                ppc_reg reg,
                                guint imm)
{
  /* R0 -> uses value 0 */
  return gum_ppc_writer_put_addis_reg_reg_imm(self, reg, PPC_REG_R0, imm);
}


/* ADDIS: add reg and shifted 16bit immediate. TODO: signed? */
gboolean
gum_ppc_writer_put_addis_reg_reg_imm (GumPpcWriter * self,
                                      ppc_reg dst_reg,
                                      ppc_reg src_reg,
                                      gint16 imm)
{
  /* ADDIS rt, ra, simm -> (15) 0011 11TT TTTA AAAA IIII IIII IIII IIII */
  return gum_ppc_writer_put_dform_reg_reg_imm (self, 15, dst_reg, src_reg, (guint16)imm);
}


/* STWU: store reg to memory */
gboolean
gum_ppc_writer_put_stwu_reg_reg_imm (GumPpcWriter * self,
                                   ppc_reg ptr_reg,
                                   ppc_reg src_reg,
                                   gint16 imm)
{
  /* STWU rs, d(ra) -> (37) 100101 SSSSSA AAAA IIII IIII IIII IIII */
  return gum_ppc_writer_put_dform_reg_reg_imm (self, 37, src_reg, ptr_reg, (guint16)imm);
}


/* PUSH: push reg to stack (mnemonic, uses stwu rx, -4(r1))*/
gboolean
gum_ppc_writer_put_push_reg (GumPpcWriter * self,
                             ppc_reg src_reg)
{
  return gum_ppc_writer_put_stwu_reg_reg_imm (self, PPC_REG_R1, src_reg, -4);
}


/* ORI: reg OR 16bit immediate */
gboolean
gum_ppc_writer_put_ori_reg_reg_imm (GumPpcWriter * self,
                                    ppc_reg dst_reg,
                                    ppc_reg src_reg,
                                    guint16 imm)
{
  /* ORI ra, rs, imm -> (24) 0110 00SS SSSA AAAA IIII IIII IIII IIII */
  return gum_ppc_writer_put_dform_reg_reg_imm (self, 24, src_reg, dst_reg, imm);
}


/* MTCTR: move reg to CTR (mnemonic, uses mtspr 9, Rx)*/
gboolean
gum_ppc_writer_put_mtctr_reg (GumPpcWriter * self,
                              ppc_reg src_reg)
{
  GumPpcRegInfo rs;

  gum_ppc_writer_describe_reg (self, src_reg, &rs);

  /* MTCTR ra, rs, imm -> (31) 011111 SSSSS CCCCCCCCCC 0111010011 # */
  return gum_ppc_writer_put_instruction (self, 0x7c000000 | (rs.index << 21) |
      (9 << 11) | (467 << 1));
}


/* BCTR: branch to CTR (mnemonic, uses bcctr)*/
gboolean
gum_ppc_writer_put_bctr_offset (GumPpcWriter * self)
{
  /* BCCTR -> (19) 010011 BBBBB bbbbb ### HH 10000 10000  L */
  /* BCTR  -> (19) 010011 10100 00000 000 00 10000 10000  0 */ 
  return gum_ppc_writer_put_instruction (self, 0x4e800000 | (528 << 1));
}


/* B: branch to relative offset */
gboolean
gum_ppc_writer_put_b_offset (GumPpcWriter * self,
                             gint32 offset)
{
  /* B offset -> (18) 0100 10II IIII IIII IIII IIII IIAL */
  return gum_ppc_writer_put_instruction (self, 0x48000000 | 
      (((offset >> 2) & 0xffffff) << 2));
}


/* (FP) PUSH: push fpreg to stack (mnemonic, uses stfdu fprx, -4(r1))*/
gboolean
gum_ppc_writer_put_push_fpreg (GumPpcWriter * self,
                               ppc_reg src_reg)
{
  return gum_ppc_writer_put_stfdu_reg_reg_imm (self, PPC_REG_R1, src_reg, -4);
}

/* (FP) STFDU: store fpreg to memory */
gboolean
gum_ppc_writer_put_stfdu_reg_reg_imm (GumPpcWriter * self,
                                      ppc_reg ptr_reg,
                                      ppc_reg src_reg,
                                      gint16 imm)
{
  // STFDU frs, d(ra) -> (55) 
  return gum_ppc_writer_put_dform_reg_reg_imm (self, 55, src_reg, ptr_reg, (guint16)imm);
}



/* D-Form instuctions */
gboolean
gum_ppc_writer_put_dform_reg_reg_imm (GumPpcWriter * self,
                                      guint8 opcode,
                                      ppc_reg rts_reg,
                                      ppc_reg ra_reg,
                                      guint16 imm)
{
  GumPpcRegInfo rts, ra;

  gum_ppc_writer_describe_reg (self, rts_reg, &ra);
  gum_ppc_writer_describe_reg (self, ra_reg, &rts);

    /* OP ra, rts, imm -> (24) PPPP PPTT TTTA AAAA IIII IIII IIII IIII */
  return gum_ppc_writer_put_instruction (self, (opcode << 26) | (rts.index << 21) |
      (ra.index << 16) | (imm & 0xffff));

}


gboolean
gum_ppc_writer_put_nop (GumPpcWriter * self)
{
  gum_ppc_writer_put_ori_reg_reg_imm (self, PPC_REG_R0, PPC_REG_R0, 0x0);
  return TRUE;
}

gboolean
gum_ppc_writer_put_instruction (GumPpcWriter * self,
                                 guint32 insn)
{
  *self->code++ = insn;
  self->pc += 4;
  return TRUE;
}

gboolean
gum_ppc_writer_put_bytes (GumPpcWriter * self,
                           const guint8 * data,
                           guint n)
{
  if (n % 4 != 0)
    return FALSE;

  gum_memcpy (self->code, data, n);
  self->code += n / sizeof (guint32);
  self->pc += n;

  return TRUE;
}
