/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
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
  /* GumPpcMetaReg meta; */
  guint width;
  guint index;
};

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


/* Load 32bit immediate shifted, pseudo instruction */
void
gum_ppc_writer_put_li32_reg_address (GumPpcWriter * self,
                                     ppc_reg reg,
                                     GumAddress address)
{
#if GLIB_SIZEOF_VOID_P == 8
  /* PPC64: TODO */
  g_assert_not_reached ();
#else
  gum_ppc_writer_put_lis_reg_imm (self, reg, address >> 16);
  gum_ppc_writer_put_ori_reg_reg_imm (self, reg, reg, address & 0xffff);
#endif
}


/* Load 16bit immediate shifted (mnemonic, uses addis) */
void
gum_ppc_writer_put_lis_reg_imm (GumPpcWriter * self,
                                ppc_reg reg,
                                guint imm)
{
  /* R0 -> uses value 0 */
  gum_ppc_writer_put_addis_reg_reg_imm(self, reg, PPC_REG_R0, imm);
}


/* ADDIS: add reg and shifted 16bit immediate. TODO: signed? */
void
gum_ppc_writer_put_addis_reg_reg_imm (GumPpcWriter * self,
                                      ppc_reg dst_reg,
                                      ppc_reg src_reg,
                                      guint imm)
{
  GumPpcRegInfo rt, ra;

  gum_ppc_writer_describe_reg (self, dst_reg, &rt);
  gum_ppc_writer_describe_reg (self, src_reg, &ra);

  /* ADDIS rt, ra, imm -> (15) 0011 11TT TTTA AAAA IIII IIII IIII IIII */
  gum_ppc_writer_put_instruction (self, 0x3c000000 | (rt.index << 21) |
      (ra.index << 16) | (imm & 0xffff));
}


/* ORI: reg OR 16bit immediate */
void
gum_ppc_writer_put_ori_reg_reg_imm (GumPpcWriter * self,
                                    ppc_reg dst_reg,
                                    ppc_reg src_reg,
                                    guint imm)
{
  GumPpcRegInfo rs, ra;

  gum_ppc_writer_describe_reg (self, dst_reg, &ra);
  gum_ppc_writer_describe_reg (self, src_reg, &rs);

  /* ORI ra, rs, imm -> (24) 0110 00SS SSSA AAAA IIII IIII IIII IIII */
  gum_ppc_writer_put_instruction (self, 0x60000000 | (rs.index << 21) |
      (ra.index << 16) | (imm & 0xffff));
}


/* MTCTR: move reg to CTR (mnemonic, uses mtspr 9, Rx)*/
void
gum_ppc_writer_put_mtctr_reg (GumPpcWriter * self,
                              ppc_reg src_reg)
{
  GumPpcRegInfo rs;

  gum_ppc_writer_describe_reg (self, src_reg, &rs);

  /* MTCTR ra, rs, imm -> (31) 011111 SSSSS CCCCCCCCCC 0111010011 # */
  gum_ppc_writer_put_instruction (self, 0x7c000000 | (rs.index << 21) |
      (9 << 11) | (467 << 1));
}


/* BCTR: branch to CTR (mnemonic, uses bcctr)*/
void
gum_ppc_writer_put_bctr_offset (GumPpcWriter * self)
{
  /* BCCTR -> (19) 010011 BBBBB bbbbb ### HH 10000 10000  L */
  /* BCTR  -> (19) 010011 10100 00000 000 00 10000 10000  0 */ 
  gum_ppc_writer_put_instruction (self, 0x4e800000 | (528 << 1));
}


/* B: branch to relative offset */
void
gum_ppc_writer_put_b_offset (GumPpcWriter * self,
                             gint32 offset)
{
  /* B offset -> (18) 0100 10II IIII IIII IIII IIII IIAL */
  gum_ppc_writer_put_instruction (self, 0x48000000 | 
      (((offset >> 2) & 0xffffff) << 2));
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
  else
  {
    g_assert_not_reached ();
  }
}
