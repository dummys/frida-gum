/*
 * Copyright (C) 2014-2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdefs.h"

#if GLIB_SIZEOF_VOID_P == 4

gpointer
gum_cpu_context_get_nth_argument (GumCpuContext * self,
                                  guint n)
{
  if (n < 8)
  {
    switch (n)
    {
      case 0:
        return (gpointer) self->r[3];
      case 1:
        return (gpointer) self->r[4];
      case 2:
        return (gpointer) self->r[5];
      case 3:
        return (gpointer) self->r[6];
      case 4:
        return (gpointer) self->r[7];
      case 5:
        return (gpointer) self->r[8];
      case 6:
        return (gpointer) self->r[9];
      case 7:
        return (gpointer) self->r[10];
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) (self->r[1] + 0xb4);

    return stack_argument[n - 8];
  }

  return NULL;
}

void
gum_cpu_context_replace_nth_argument (GumCpuContext * self,
                                      guint n,
                                      gpointer value)
{
  if (n < 8)
  {
    switch (n)
    {
      case 0:
        self->r[3] = (guint32) value;
        break;
      case 1:
        self->r[4] = (guint32) value;
        break;
      case 2:
        self->r[5] = (guint32) value;
        break;
      case 3:
        self->r[6] = (guint32) value;
        break;
      case 4:
        self->r[7] = (guint32) value;
        break;
      case 5:
        self->r[8] = (guint32) value;
        break;
      case 6:
        self->r[9] = (guint32) value;
        break;
      case 7:
        self->r[10] = (guint32) value;
        break;
    }
  }
  else
  {
    gpointer * stack_argument = (gpointer *) (self->r[1] + 0xb4);

    stack_argument[n - 8] = value;
  }
}

// todo
/*
 * On PPC64
 */
#endif

gpointer
gum_cpu_context_get_return_value (GumCpuContext * self)
{
  return GSIZE_TO_POINTER (self->r[3]);
}

void
gum_cpu_context_replace_return_value (GumCpuContext * self,
                                      gpointer value)
{
  self->r[3] = GPOINTER_TO_SIZE (value);
}
