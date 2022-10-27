/*
 * Copyright (C) 2009-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumppcrelocator.h"

#include "gumlibc.h"
#include "gummemory.h"
#include "gumppcreader.h"

// TODO
#include <string.h>

#define GUM_MAX_INPUT_INSN_COUNT (100)

typedef struct _GumCodeGenCtx GumCodeGenCtx;

struct _GumCodeGenCtx
{
  cs_insn * insn;
  GumAddress pc;

  GumPPCWriter * code_writer;
};

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
gum_ppc_relocator_can_relocate (gpointer address,
                                guint min_bytes,
                                guint * maximum)
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

  relocator->eob = FALSE;
  relocator->eoi = FALSE;
}