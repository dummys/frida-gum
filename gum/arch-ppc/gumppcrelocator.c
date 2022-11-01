/*
 * Copyright (C) 2009-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumppcrelocator.h"

#include "gumlibc.h"
#include "gummemory.h"

// TODO
#include <string.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)
#if GLIB_SIZEOF_VOID_P == 4
# define GUM_DEFAULT_PPC_MODE CS_MODE_32
#else
# define GUM_DEFAULT_PPC_MODE CS_MODE_64
#endif

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  cs_insn * insn;
  GumAddress pc;

  GumPpcWriter * code_writer;
};

static gboolean gum_ppc_relocator_write_one_instruction (
    GumPpcRelocator * self);
static void gum_ppc_relocator_put_label_for (GumPpcRelocator * self,
    cs_insn * insn);
static gboolean gum_ppc_relocator_rewrite_unconditional_branch (
    GumPpcRelocator * self, GumCodeGenCtx * ctx);

void
gum_ppc_relocator_init (GumPpcRelocator * relocator,
                        gconstpointer input_code,
                        GumPpcWriter * output)
{
  relocator->ref_count = 1;

  cs_open (CS_ARCH_PPC, GUM_DEFAULT_PPC_MODE | GUM_DEFAULT_CS_ENDIAN,
      &relocator->capstone);
  cs_option (relocator->capstone, CS_OPT_DETAIL, CS_OPT_ON);
  relocator->input_insns = g_new0 (cs_insn *, GUM_MAX_INPUT_INSN_COUNT);

  relocator->output = NULL;

  gum_ppc_relocator_reset (relocator, input_code, output);
}

gboolean
gum_ppc_relocator_eob (GumPpcRelocator * self)
{
  return self->eob;
}

gboolean
gum_ppc_relocator_eoi (GumPpcRelocator * self)
{
  return self->eoi;
}
gboolean
gum_ppc_relocator_can_relocate (gpointer address,
                                guint min_bytes,
                                guint * maximum,
                                ppc_reg * available_scratch_reg)
{
  guint n = 0;
  guint8 * buf;
  GumPpcWriter cw;
  GumPpcRelocator rl;
  guint reloc_bytes;

  buf = g_alloca (3 * min_bytes);
  gum_ppc_writer_init (&cw, buf);

  gum_ppc_relocator_init (&rl, address, &cw);

  do
  {
    reloc_bytes = gum_ppc_relocator_read_one (&rl, NULL);
    if (reloc_bytes == 0)
      break;

    n = reloc_bytes;
  }
  while (reloc_bytes < min_bytes);

  /* TODO: search for available scratch register (see MIPS code) */
  available_scratch_reg = PPC_REG_R0;

  gum_ppc_relocator_clear (&rl);

  gum_ppc_writer_clear (&cw);

  if (maximum != NULL)
    *maximum = n;

  return n >= min_bytes;
}

void
gum_ppc_relocator_reset (GumPpcRelocator * relocator,
                          gconstpointer input_code,
                          GumPpcWriter * output)
{
  relocator->input_start = input_code;
  relocator->input_cur = input_code;
  relocator->input_pc = GUM_ADDRESS (input_code);

  if (output != NULL)
    gum_ppc_writer_ref (output);
  if (relocator->output != NULL)
    gum_ppc_writer_unref (relocator->output);
  relocator->output = output;

  relocator->inpos = 0;
  relocator->outpos = 0;

  // TODO
  // end of block
  // end of input
  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}

static guint
gum_ppc_relocator_inpos (GumPpcRelocator * self)
{
  return self->inpos % GUM_MAX_INPUT_INSN_COUNT;
}

static guint
gum_ppc_relocator_outpos (GumPpcRelocator * self)
{
  return self->outpos % GUM_MAX_INPUT_INSN_COUNT;
}

static void
gum_ppc_relocator_increment_inpos (GumPpcRelocator * self)
{
  self->inpos++;
  g_assert (self->inpos > self->outpos);
}

static void
gum_ppc_relocator_increment_outpos (GumPpcRelocator * self)
{
  self->outpos++;
  g_assert (self->outpos <= self->inpos);
}

guint
gum_ppc_relocator_read_one (GumPpcRelocator * self,
                            const cs_insn ** instruction)
{
  cs_insn ** insn_ptr, * insn;
  const uint8_t * code;
  size_t size;
  uint64_t address;

  if (self->eoi)
    return 0;

  insn_ptr = &self->input_insns[gum_ppc_relocator_inpos (self)];

  if (*insn_ptr == NULL)
    *insn_ptr = cs_malloc (self->capstone);

  code = self->input_cur;
  size = 4;
  address = self->input_pc;
  insn = *insn_ptr;

  if (!cs_disasm_iter (self->capstone, &code, &size, &address, insn))
    return 0;

  switch (insn->id)
  {
    
    /* unconditional branch: eob + eoi */
    /* conditional branch/branch with link: eob */

    /* Here we are defining which instruction do an end of block */
    /* ret like instructions */
    case PPC_INS_BL:
    case PPC_INS_BLA:
    case PPC_INS_BLE:
    case PPC_INS_BLEA:
    case PPC_INS_BLECTR:
    case PPC_INS_BLECTRL:
    case PPC_INS_BLEL:
    case PPC_INS_BLELA:
    case PPC_INS_BLELR:
    case PPC_INS_BLELRL:
    case PPC_INS_BLR:
    case PPC_INS_BLRL:
    case PPC_INS_BLT:
    case PPC_INS_BLTA:
    case PPC_INS_BLTCTR:
    case PPC_INS_BLTCTRL:
    case PPC_INS_BLTL:
    case PPC_INS_BLTLA:
    case PPC_INS_BLTLR:
    case PPC_INS_BLTLRL:
    case PPC_INS_BCA:
    case PPC_INS_BCCTR:
    case PPC_INS_BCCTRL:
    case PPC_INS_BCDCFN:
    case PPC_INS_BCDCFSQ:
    case PPC_INS_BCDCFZ:
    case PPC_INS_BCDCPSGN:
    case PPC_INS_BCDCTN:
    case PPC_INS_BCDCTSQ:
    case PPC_INS_BCDCTZ:
    case PPC_INS_BCDS:
    case PPC_INS_BCDSETSGN:
    case PPC_INS_BCDSR:
    case PPC_INS_BCDTRUNC:
    case PPC_INS_BCDUS:
    case PPC_INS_BCDUTRUNC:
    case PPC_INS_BCL:
    case PPC_INS_BCLA:
    case PPC_INS_BCLR:
    case PPC_INS_BCLRL:
    case PPC_INS_BCTR:
    case PPC_INS_BCTRL:
      self->eob = TRUE;
      break;
     
    case PPC_INS_B:
    case PPC_INS_BA:
      self->eob = TRUE;
      self->eoi = TRUE;
      break;
  }

  gum_ppc_relocator_increment_inpos (self);

  if (instruction != NULL)
    *instruction = insn;

  self->input_cur = code;
  self->input_pc = address;

  return self->input_cur - self->input_start;
}

cs_insn *
gum_ppc_relocator_peek_next_write_insn (GumPpcRelocator * self)
{
  if (self->outpos == self->inpos)
    return NULL;

  return self->input_insns[gum_ppc_relocator_outpos (self)];
}

gboolean
gum_ppc_relocator_write_one (GumPpcRelocator * self)
{
  cs_insn * cur;

  if ((cur = gum_ppc_relocator_peek_next_write_insn (self)) == NULL)
    return FALSE;

  gum_ppc_relocator_put_label_for (self, cur);
  
  switch (insn->id)
  {
    default:
      rewritten = FALSE;
      break;
  }

  if (!rewritten)
    gum_ppc_writer_put_bytes (ctx.output, insn->bytes, insn->size);
}
