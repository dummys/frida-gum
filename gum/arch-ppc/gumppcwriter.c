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

struct _GumPpcLabelRef
{
  gconstpointer id;
  guint32 * insn;
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